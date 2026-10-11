"""FORGE first-run setup helper.

``forge setup`` creates the local operator state needed to run the
autopilot straight out of the box:

- Verifies Python >= 3.11 (the project's minimum interpreter).
- Writes ``.env`` from ``.env.example`` if it is missing.
- Ensures ``FORGE_ROE_ID``, ``FORGE_SAFE_MODE=0``, ``FORGE_OPERATOR``,
  and ``FORGE_SCOPE_MANIFEST`` are set in that ``.env``.
- Creates the data/imports/reports/manifests directory structure.
- Copies the shipped ``manifests/default.json`` scope manifest template
  (if missing) and the ``imports/starter-targets.example.json`` feed
  example so new operators have working references.
- Runs ``forge feeds fetch`` to pull free threat intel — NVD CVE,
  CISA KEV, EPSS, Security RSS, nuclei-templates, URLScan public.
  Bounded and best-effort: if the feeds are fresh or the network is
  unavailable, setup records the result and keeps going.
- Runs ``forge doctor --json`` to report readiness state.

The command is intentionally non-destructive: existing ``.env`` files,
existing manifests, and existing feed files are left untouched. The
only writes are missing-file creations and additive ``.env`` key
inserts.

Nothing in this module launches live outbound work besides the bounded
KB fetch. ``forge doctor`` runs read-only; the autopilot is advertised
at the end but not auto-started.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from forge.autopilot.defaults import AutopilotDefaults


SETUP_SCHEMA_VERSION = "forge.setup.v1"

#: Minimum supported Python interpreter version (matches ``pyproject.toml``).
MIN_PYTHON = (3, 11)

#: Default callsign recorded in every audit_log entry when the operator
#: has not already set one. ``.env.example`` ships with
#: ``FORGE_OPERATOR=operator``; ``forge setup`` seeds the same default
#: when the key is missing or empty, and preserves any operator-chosen
#: value on re-run.
DEFAULT_OPERATOR = "operator"


@dataclass
class SetupAction:
    """One recorded setup action.

    ``status`` is one of:

    - ``created`` — file written.
    - ``updated`` — existing file modified.
    - ``exists`` — file already present, no change.
    - ``missing_source`` — a template source file was expected but
      not found. The setup continues and records the gap.
    - ``skipped`` — operator-controlled skip or best-effort step that
      declined to run (e.g. KB sync when offline).
    - ``error`` — an exception occurred.
    """

    name: str
    status: str
    path: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "path": self.path,
            "detail": self.detail,
        }


@dataclass
class SetupResult:
    schema_version: str = SETUP_SCHEMA_VERSION
    actions: list[SetupAction] = field(default_factory=list)
    doctor: dict[str, Any] | None = None
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "actions": [a.to_dict() for a in self.actions],
            "doctor": self.doctor,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Python version
# ---------------------------------------------------------------------------


def check_python_version(
    version: tuple[int, int, int] | None = None,
) -> SetupAction:
    """Verify the Python interpreter satisfies :data:`MIN_PYTHON`.

    Returns a ``SetupAction`` with status ``exists`` on success or
    ``error`` on failure. Does not raise — the caller decides what to
    do with a failed check so the JSON payload remains consistent.

    Args:
        version: Optional ``(major, minor, micro)`` override for tests.
            Defaults to the running interpreter.
    """
    major, minor, micro = version or (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    label = f"Python {major}.{minor}.{micro}"
    if (major, minor) >= MIN_PYTHON:
        return SetupAction(
            name="python_version",
            status="exists",
            detail=f"{label} (>= {MIN_PYTHON[0]}.{MIN_PYTHON[1]} required)",
        )
    return SetupAction(
        name="python_version",
        status="error",
        detail=(
            f"{label} is below the required "
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+. "
            "Install a newer interpreter and re-run `forge setup`."
        ),
    )


# ---------------------------------------------------------------------------
# Env file helpers
# ---------------------------------------------------------------------------


def _read_env_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []


def _parse_env_keys(lines: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def _upsert_env_key(lines: list[str], key: str, value: str) -> tuple[list[str], str]:
    """Insert or replace a ``KEY=value`` line.

    Returns the updated line list and ``"updated"`` or ``"created"``.
    """
    seen = False
    out: list[str] = []
    status = "created"
    for raw in lines:
        stripped = raw.strip()
        if (
            not stripped.startswith("#")
            and "=" in stripped
            and stripped.split("=", 1)[0].strip() == key
        ):
            if not seen:
                out.append(f"{key}={value}")
                status = "updated"
                seen = True
            continue
        out.append(raw)
    if not seen:
        out.append(f"{key}={value}")
    return out, status


def ensure_env_file(
    *,
    root: Path,
    env_path: Path,
    example_path: Path,
    required_keys: Mapping[str, str],
) -> list[SetupAction]:
    """Create ``.env`` from ``.env.example`` and enforce required keys.

    Returns the list of recorded :class:`SetupAction` entries so the
    caller can report what changed.
    """
    actions: list[SetupAction] = []
    created_file = False
    if not env_path.exists():
        if example_path.exists():
            env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
            actions.append(
                SetupAction(
                    name="env_file_create",
                    status="created",
                    path=str(env_path),
                    detail=f"copied from {example_path.name}",
                )
            )
            created_file = True
        else:
            env_path.write_text("", encoding="utf-8")
            actions.append(
                SetupAction(
                    name="env_file_create",
                    status="created",
                    path=str(env_path),
                    detail="empty — .env.example missing",
                )
            )
            created_file = True
    else:
        actions.append(
            SetupAction(
                name="env_file_create",
                status="exists",
                path=str(env_path),
            )
        )

    lines = _read_env_lines(env_path)
    existing = _parse_env_keys(lines)
    updates = 0
    for key, value in required_keys.items():
        current = existing.get(key, "")
        if current == value:
            continue
        if current:
            # Preserve a non-empty value the operator chose, EXCEPT when
            # the value violates the autopilot contract (SAFE_MODE must
            # be 0 for the loop to run live). Record a diagnostic action.
            if key == "FORGE_SAFE_MODE" and current not in ("0", "false", "no", "off"):
                lines, status = _upsert_env_key(lines, key, value)
                actions.append(
                    SetupAction(
                        name=f"env_key:{key}",
                        status=status,
                        path=str(env_path),
                        detail=(
                            f"forced {key}={value} (was {current!r}); "
                            "FORGE_SAFE_MODE=1 blocks the autopilot loop"
                        ),
                    )
                )
                updates += 1
                continue
            actions.append(
                SetupAction(
                    name=f"env_key:{key}",
                    status="exists",
                    path=str(env_path),
                    detail=f"existing value preserved",
                )
            )
            continue
        lines, status = _upsert_env_key(lines, key, value)
        actions.append(
            SetupAction(
                name=f"env_key:{key}",
                status=status,
                path=str(env_path),
                detail=f"set to {value}",
            )
        )
        updates += 1
    if updates > 0 or created_file:
        env_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return actions


# ---------------------------------------------------------------------------
# Directory and template helpers
# ---------------------------------------------------------------------------


def ensure_directories(paths: Iterable[Path]) -> list[SetupAction]:
    actions: list[SetupAction] = []
    for path in paths:
        if path.exists():
            actions.append(
                SetupAction(
                    name=f"dir:{path.name}",
                    status="exists",
                    path=str(path),
                )
            )
            continue
        try:
            path.mkdir(parents=True, exist_ok=True)
            actions.append(
                SetupAction(
                    name=f"dir:{path.name}",
                    status="created",
                    path=str(path),
                )
            )
        except OSError as exc:
            actions.append(
                SetupAction(
                    name=f"dir:{path.name}",
                    status="error",
                    path=str(path),
                    detail=str(exc),
                )
            )
    return actions


def ensure_template(
    *,
    name: str,
    source: Path,
    destination: Path,
) -> SetupAction:
    """Copy ``source`` to ``destination`` if the destination is missing."""
    if destination.exists():
        return SetupAction(
            name=name, status="exists", path=str(destination)
        )
    if not source.exists():
        return SetupAction(
            name=name,
            status="missing_source",
            path=str(source),
            detail=f"template missing — expected at {source}",
        )
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        return SetupAction(
            name=name,
            status="created",
            path=str(destination),
            detail=f"copied from {source.name}",
        )
    except OSError as exc:
        return SetupAction(
            name=name,
            status="error",
            path=str(destination),
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# forge.feeds fetch — the "free threat intel" pull
# ---------------------------------------------------------------------------


#: Free threat-intel feeds exercised by :class:`forge.feeds.FeedFetcher`.
#: Kept in sync with ``FeedFetcher.fetchers`` so the boxed summary
#: reflects what actually gets fetched.
FREE_FEED_SOURCES = (
    "NVD CVE",
    "CISA KEV",
    "EPSS",
    "Security RSS",
    "nuclei-templates",
    "URLScan public",
)


#: Per-source HTTP timeout used by ``forge setup``. The autopilot's
#: feed_fetch phase uses the default 60 seconds; setup is more
#: aggressive so a fresh install never blocks on a slow mirror.
SETUP_FEED_TIMEOUT_SECONDS = 20


def run_feeds_fetch(
    *,
    imports_dir: Path,
    data_dir: Path,
    timeout_per_source: int = SETUP_FEED_TIMEOUT_SECONDS,
    max_age_days: int = 7,
) -> SetupAction:
    """Best-effort free-threat-intel refresh (equivalent to ``forge feeds fetch``).

    Returns a :class:`SetupAction`:

    - ``updated`` when the orchestrator reports ``overall_status`` ok
      or partial and at least one source succeeded.
    - ``skipped`` when the whole run was skipped (every source was
      already fresh and declined to re-fetch) or when the orchestrator
      could not be imported.
    - ``error`` when every source failed.

    The function never raises — any failure is contained and recorded.
    """
    try:
        from forge.feeds import FeedFetcher  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        return SetupAction(
            name="feeds_fetch",
            status="skipped",
            detail=f"forge.feeds import failed: {exc.__class__.__name__}: {str(exc)[:120]}",
        )

    try:
        fetcher = FeedFetcher(
            imports_dir=imports_dir,
            data_dir=data_dir,
            max_age_days=max_age_days,
        )
        payload = fetcher.fetch_all(timeout_per_source=timeout_per_source)
    except Exception as exc:  # noqa: BLE001
        return SetupAction(
            name="feeds_fetch",
            status="skipped",
            detail=f"best-effort — {exc.__class__.__name__}: {str(exc)[:120]}",
        )

    overall = str(payload.get("overall_status", "unknown"))
    status_counts = payload.get("status_counts", {}) or {}
    ok_count = int(status_counts.get("ok", 0))
    error_count = int(status_counts.get("error", 0))
    skipped_count = int(status_counts.get("skipped", 0))
    total_items = int(payload.get("total_item_count", 0))

    counts_label = (
        f"{ok_count} ok, {error_count} error, {skipped_count} skipped"
        f" ({total_items} items)"
    )

    if overall == "ok":
        return SetupAction(
            name="feeds_fetch",
            status="updated",
            detail=f"pulled free threat intel: {counts_label}",
        )
    if overall == "partial":
        return SetupAction(
            name="feeds_fetch",
            status="updated",
            detail=f"partial feeds refresh: {counts_label}",
        )
    if overall == "skipped":
        return SetupAction(
            name="feeds_fetch",
            status="skipped",
            detail=f"feeds already fresh: {counts_label}",
        )
    if overall == "error":
        return SetupAction(
            name="feeds_fetch",
            status="skipped",
            detail=f"every source errored: {counts_label}",
        )
    return SetupAction(
        name="feeds_fetch",
        status="skipped",
        detail=f"overall_status={overall!r}: {counts_label}",
    )


# ---------------------------------------------------------------------------
# Doctor integration
# ---------------------------------------------------------------------------


def _run_doctor_summary() -> dict[str, Any] | None:
    """Run ``forge doctor`` in JSON mode and return the parsed payload.

    Returns ``None`` on import failure; errors in the doctor payload
    are left in the payload so the caller can surface them.
    """
    try:
        from forge.doctor import collect_doctor_checks, doctor_payload_json
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": f"doctor_import_failed:{exc}"}
    try:
        checks = collect_doctor_checks(live_provider_probes=False)
        payload = json.loads(doctor_payload_json(checks))
        return payload
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": f"doctor_run_failed:{exc}"}


# ---------------------------------------------------------------------------
# Public API — ``forge setup``
# ---------------------------------------------------------------------------


def run_first_run_setup(
    *,
    root: Path | None = None,
    data_dir: Path | None = None,
    skip_doctor: bool = False,
    skip_feeds_fetch: bool = False,
    defaults: AutopilotDefaults | None = None,
    env: Mapping[str, str] | None = None,
) -> SetupResult:
    """Idempotent first-run setup.

    Steps:

    1. Verify Python >= 3.11.
    2. Write a non-destructive ``.env`` from ``.env.example`` and
       enforce the autopilot's required keys.
    3. Create data/imports/reports/manifests directories.
    4. Copy the shipped scope-manifest and starter target feed to the
       operator's local tree (idempotent).
    5. Pull free threat-intel feeds via ``forge.feeds.FeedFetcher``
       unless ``skip_feeds_fetch`` is set.
    6. Run ``forge doctor`` in JSON mode unless ``skip_doctor`` is set.

    Args:
        root: Repository root (defaults to CWD).
        data_dir: ``FORGE_DATA_DIR`` to ensure. Defaults to
            ``<root>/.forge_data`` when unset.
        skip_doctor: If True, skip the readiness probe.
        skip_feeds_fetch: If True, skip the bounded feeds refresh.
        defaults: Autopilot defaults to seed required env keys from.
        env: Environment mapping override for testing.

    Returns:
        A :class:`SetupResult` with every recorded action.
    """
    root_path = Path(root) if root else Path.cwd()
    environ = env if env is not None else os.environ
    autopilot_defaults = defaults or AutopilotDefaults()

    env_path = root_path / ".env"
    example_path = root_path / ".env.example"
    data_dir_path = Path(
        data_dir
        or environ.get("FORGE_DATA_DIR", "")
        or (root_path / ".forge_data")
    )
    imports_dir = root_path / "imports"
    reports_dir = root_path / "reports"
    manifests_dir = root_path / "manifests"

    result = SetupResult()

    # 1. Python version.
    result.actions.append(check_python_version())

    # 2. .env + required keys.
    required_env = {
        "FORGE_ROE_ID": autopilot_defaults.default_roe_id or "ROE-1",
        "FORGE_SAFE_MODE": "0",
        "FORGE_OPERATOR": environ.get("FORGE_OPERATOR") or DEFAULT_OPERATOR,
        "FORGE_SCOPE_MANIFEST": "manifests/default.json",
    }
    result.actions.extend(
        ensure_env_file(
            root=root_path,
            env_path=env_path,
            example_path=example_path,
            required_keys=required_env,
        )
    )

    # 3. Directories.
    result.actions.extend(
        ensure_directories(
            [
                data_dir_path,
                imports_dir,
                reports_dir,
                manifests_dir,
                data_dir_path / "engagements",
            ]
        )
    )

    # 4. Templates. Scope manifest template ships with all exploitation
    # permissions enabled by the goal lock v2 contract; the operator
    # must still populate domains/urls/ip_ranges before launching live
    # scans.
    shipped_manifest = root_path / "manifests" / "default.json"
    local_manifest = manifests_dir / "default.json"
    if shipped_manifest.resolve() == local_manifest.resolve():
        result.actions.append(
            SetupAction(
                name="scope_manifest_template",
                status="exists" if local_manifest.exists() else "missing_source",
                path=str(local_manifest),
            )
        )
    else:
        result.actions.append(
            ensure_template(
                name="scope_manifest_template",
                source=shipped_manifest,
                destination=local_manifest,
            )
        )

    # Starter target-feed example sits beside the operator-maintained
    # ``target-feed.json`` as a reference shape ``forge targets import``
    # will accept.
    shipped_feed = root_path / "imports" / "starter-targets.example.json"
    local_feed_example = imports_dir / "starter-targets.example.json"
    if shipped_feed.resolve() == local_feed_example.resolve():
        result.actions.append(
            SetupAction(
                name="starter_feed_example",
                status="exists" if local_feed_example.exists() else "missing_source",
                path=str(local_feed_example),
            )
        )
    else:
        result.actions.append(
            ensure_template(
                name="starter_feed_example",
                source=shipped_feed,
                destination=local_feed_example,
            )
        )

    # 5. Free threat intel — forge.feeds fetch, bounded and best-effort.
    if not skip_feeds_fetch:
        result.actions.append(
            run_feeds_fetch(
                imports_dir=imports_dir,
                data_dir=data_dir_path,
            )
        )
    else:
        result.actions.append(
            SetupAction(
                name="feeds_fetch",
                status="skipped",
                detail="--skip-feeds-fetch requested",
            )
        )

    # 6. Doctor.
    if not skip_doctor:
        result.doctor = _run_doctor_summary()

    # Summary surface — reused by the boxed CLI output and consumers
    # that read the JSON payload.
    result.summary = _build_summary(
        root=root_path,
        env_path=env_path,
        data_dir=data_dir_path,
        required_env=required_env,
        actions=result.actions,
    )

    return result


def _build_summary(
    *,
    root: Path,
    env_path: Path,
    data_dir: Path,
    required_env: Mapping[str, str],
    actions: Iterable[SetupAction],
) -> dict[str, Any]:
    """Compact summary of the setup state for the boxed output."""
    env_values = _parse_env_keys(_read_env_lines(env_path))
    feeds_action = next((a for a in actions if a.name == "feeds_fetch"), None)
    feeds_status = feeds_action.status if feeds_action else "skipped"
    feeds_detail = feeds_action.detail if feeds_action else ""
    safe_mode_value = env_values.get("FORGE_SAFE_MODE", required_env["FORGE_SAFE_MODE"])
    safe_mode_label = "OFF" if safe_mode_value in ("0", "false", "no", "off") else "ON"
    return {
        "root": str(root),
        "env_file": str(env_path),
        "roe_id": env_values.get("FORGE_ROE_ID", required_env["FORGE_ROE_ID"]),
        "safe_mode": safe_mode_label,
        "operator": env_values.get("FORGE_OPERATOR", required_env["FORGE_OPERATOR"]),
        "scope_manifest": env_values.get(
            "FORGE_SCOPE_MANIFEST", required_env["FORGE_SCOPE_MANIFEST"]
        ),
        "data_dir": str(data_dir),
        "feed_sources": list(FREE_FEED_SOURCES),
        "feed_source_count": len(FREE_FEED_SOURCES),
        "feeds_fetch_status": feeds_status,
        "feeds_fetch_detail": feeds_detail,
    }


__all__ = [
    "DEFAULT_OPERATOR",
    "FREE_FEED_SOURCES",
    "MIN_PYTHON",
    "SETUP_FEED_TIMEOUT_SECONDS",
    "SETUP_SCHEMA_VERSION",
    "SetupAction",
    "SetupResult",
    "check_python_version",
    "ensure_env_file",
    "ensure_directories",
    "ensure_template",
    "run_first_run_setup",
    "run_feeds_fetch",
]
