"""Nuclei template catalog refresher.

Clones (or ``git pull``s) the public ProjectDiscovery nuclei-templates
repo under ``FORGE_DATA_DIR/nuclei-templates`` and summarizes templates
modified in the last ``max_age_days`` days (default 7).

Each recent template contributes a compact record with id, severity,
tags, and CVE references. We never execute templates here; this is a
catalog refresher only.

Output: ``imports/nuclei-templates-update.local.json`` with ``_meta``,
parsed ``items`` (recent templates), and ``cve_ids``/``severities``
summaries. Falls back to ``status=error`` when ``git`` is unavailable.
"""

from __future__ import annotations

import os
import re
import subprocess  # noqa: S404 — git invoked with fixed argv, no shell
import time
from pathlib import Path
from typing import Any

from forge.feeds.base import BaseFeedFetcher


_NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
_REPO_DIRNAME = "nuclei-templates"

# Hard caps so a surprise huge template file does not spike memory or
# an operator cannot force an unbounded recent-file list.
_MAX_FILE_BYTES = 1 * 1024 * 1024
_MAX_RECENT_FILES = 5000

# git pull/clone timeout. Fail-closed if git is slow instead of blocking
# the autopilot loop.
_GIT_TIMEOUT_SECONDS = 300

# Minimal front-matter patterns. Nuclei templates are YAML, but we do
# not want a hard yaml dependency when the stdlib form is enough for
# the handful of fields we need. These regexes are intentionally scoped
# to the top-level ``info`` block.
_ID_PATTERN = re.compile(r"^\s*id:\s*([A-Za-z0-9_\-./]+)\s*$", re.MULTILINE)
_INFO_BLOCK = re.compile(r"^info:\s*\n((?:[ \t].*\n?)+)", re.MULTILINE)
_SEVERITY_PATTERN = re.compile(r"^\s*severity:\s*([A-Za-z]+)", re.MULTILINE)
_TAGS_PATTERN = re.compile(r"^\s*tags:\s*(.+)$", re.MULTILINE)
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NucleiTemplateFetcher(BaseFeedFetcher):
    """Refresh and summarize recent nuclei templates."""

    source_id = "nuclei_templates"
    feed_class = "template_metadata"
    source_url = _NUCLEI_TEMPLATES_REPO
    output_filename = "nuclei-templates-update.local.json"
    schema_version = "forge.feeds.nuclei_templates.v1"
    rate_limit_seconds = 0.0

    def __init__(
        self,
        data_dir: Path | str,
        *,
        imports_dir: Path | str | None = None,
        max_age_days: int = 7,
        **kwargs: Any,
    ) -> None:
        # NucleiTemplateFetcher is unusual: it writes its summary to
        # imports_dir but clones the repo under data_dir. Fall back to
        # ``data_dir.parent / "imports"`` so the orchestrator can
        # construct this with just a data_dir.
        resolved_imports = (
            Path(imports_dir)
            if imports_dir is not None
            else Path(data_dir).parent / "imports"
        )
        super().__init__(resolved_imports, **kwargs)
        self.data_dir = Path(data_dir)
        self.repo_path = self.data_dir / _REPO_DIRNAME
        self.max_age_days = max(1, int(max_age_days))

    def _fetch(self, *, timeout: int) -> dict[str, Any]:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        git_binary = _which_git()
        if git_binary is None:
            raise ValueError("git_not_found_on_path")

        action = _refresh_repo(
            git_binary, self.repo_path, timeout=min(timeout, _GIT_TIMEOUT_SECONDS)
        )

        cutoff = time.time() - (self.max_age_days * 24 * 60 * 60)
        recent_files = _iter_recent_files(self.repo_path, cutoff=cutoff)

        items: list[dict[str, Any]] = []
        cve_counter: dict[str, int] = {}
        severity_counter: dict[str, int] = {}
        for template_path in recent_files[:_MAX_RECENT_FILES]:
            parsed = _parse_template(template_path, repo_root=self.repo_path)
            if parsed is None:
                continue
            items.append(parsed)
            for cve in parsed.get("cves", []):
                cve_counter[cve] = cve_counter.get(cve, 0) + 1
            severity = parsed.get("severity")
            if isinstance(severity, str) and severity:
                severity_counter[severity] = severity_counter.get(severity, 0) + 1

        return {
            "items": items,
            "cve_ids": sorted(cve_counter.keys()),
            "severities": dict(sorted(severity_counter.items())),
            "_meta_extra": {
                "repo_path": str(self.repo_path),
                "repo_action": action,
                "max_age_days": self.max_age_days,
                "scanned_file_count": len(recent_files),
            },
        }


def _which_git() -> str | None:
    """Return the path to ``git`` on PATH, or ``None`` when absent."""
    from shutil import which  # noqa: PLC0415 — only needed here

    return which("git")


def _refresh_repo(
    git_binary: str,
    repo_path: Path,
    *,
    timeout: int,
) -> str:
    """Clone ``nuclei-templates`` if missing, otherwise fast-forward pull.

    Returns a short label (``"cloned"``, ``"pulled"``, ``"skipped"``)
    for the ``_meta`` block.
    """
    if (repo_path / ".git").is_dir():
        try:
            subprocess.run(  # noqa: S603
                [git_binary, "-C", str(repo_path), "pull", "--ff-only"],
                check=True,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace")[:240]
            raise ValueError(f"git_pull_failed:{stderr}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("git_pull_timeout") from exc
        return "pulled"

    repo_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(  # noqa: S603
            [
                git_binary,
                "clone",
                "--depth",
                "1",
                _NUCLEI_TEMPLATES_REPO,
                str(repo_path),
            ],
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace")[:240]
        raise ValueError(f"git_clone_failed:{stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git_clone_timeout") from exc
    return "cloned"


def _iter_recent_files(repo_path: Path, *, cutoff: float) -> list[Path]:
    """List ``.yaml``/``.yml`` templates modified at or after ``cutoff``.

    Walks the entire repo but skips ``.git`` to keep the scan bounded.
    """
    recent: list[Path] = []
    for root, dirs, files in os.walk(repo_path):
        if ".git" in dirs:
            dirs.remove(".git")
        for filename in files:
            if not filename.endswith((".yaml", ".yml")):
                continue
            full_path = Path(root) / filename
            try:
                mtime = full_path.stat().st_mtime
            except OSError:
                continue
            if mtime >= cutoff:
                recent.append(full_path)
    recent.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return recent


def _parse_template(path: Path, *, repo_root: Path) -> dict[str, Any] | None:
    """Extract id/severity/tags/CVE references from a nuclei template."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _MAX_FILE_BYTES:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    template_id_match = _ID_PATTERN.search(text)
    template_id = template_id_match.group(1).strip() if template_id_match else ""

    info_match = _INFO_BLOCK.search(text)
    info_block = info_match.group(1) if info_match else ""

    severity = ""
    tags: list[str] = []
    cves: list[str] = []
    if info_block:
        severity_match = _SEVERITY_PATTERN.search(info_block)
        if severity_match:
            severity = severity_match.group(1).strip().lower()
        tags_match = _TAGS_PATTERN.search(info_block)
        if tags_match:
            tags = _split_tags(tags_match.group(1))

    for cve_match in _CVE_IN_TEXT.finditer(text):
        value = cve_match.group(0).upper()
        if value not in cves:
            cves.append(value)
        if len(cves) >= 50:
            break

    rel_path = ""
    try:
        rel_path = str(path.relative_to(repo_root))
    except ValueError:
        rel_path = path.name

    return {
        "template_id": template_id or path.stem,
        "path": rel_path,
        "severity": severity,
        "tags": tags[:50],
        "cves": cves,
        "modified_at": path.stat().st_mtime,
    }


def _split_tags(raw: str) -> list[str]:
    """Normalize a ``tags:`` value which may be comma or whitespace separated."""
    cleaned = raw.strip().strip("[]'\"")
    if not cleaned:
        return []
    parts = re.split(r"[,\s]+", cleaned)
    out: list[str] = []
    for part in parts:
        value = part.strip().strip("'\"")
        if value and value not in out:
            out.append(value)
    return out


__all__ = ["NucleiTemplateFetcher"]
