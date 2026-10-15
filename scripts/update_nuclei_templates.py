#!/usr/bin/env python3
"""Refresh the vendored ProjectDiscovery nuclei templates safely.

FORGE's nuclei connector does not use nuclei's default ~/.nuclei-templates
tree. It passes each configured --template value as a separate `-t VALUE`;
the repository vendor can be selected explicitly (for example,
`--template nuclei-templates/`). The vendor includes all upstream top-level
template categories. We recommend only the ProjectDiscovery curated repository:
third-party bundles are not included without a template-by-template review.

Run from the repository root: `python scripts/update_nuclei_templates.py`.
Review the generated diff before committing. Recommended refresh cadence:
weekly. Use --destination to test in a temporary directory; --source-dir is
provided for offline fixture-based validation.

The updater excludes the 23 known key payloads (the 22-file CVE-2023-34039
directory and CVE-2024-47575 w00t_key.bin) and includes all five upstream
root dotfiles. It verifies YAML template counts by category before replacing
the destination and writes upstream commit/date provenance to VENDORED.md.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path


REPOSITORY = "https://github.com/projectdiscovery/nuclei-templates.git"
DEFAULT_DESTINATION = Path("nuclei-templates")
EXCLUDED_KEY_PATHS = {
    Path("helpers/payloads/cve-2023-34039-keys"),
    Path("helpers/payloads/cve-2024-47575-keys/w00t_key.bin"),
}
EXPECTED_ROOT_DOTFILES = {
    ".new-additions",
    ".nuclei-ignore",
    ".pre-commit-config.yml",
    ".review-bot",
    ".yamllint",
}
UPSTREAM_TOP_LEVEL = {
    "cloud", "code", "dast", "dns", "file", "headless", "helpers",
    "http", "javascript", "network", "profiles", "ssl", "workflows",
}


def _run_git(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _category_counts(root: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        relative = path.relative_to(root)
        if _is_excluded(relative):
            continue
        if relative.parts[0] in UPSTREAM_TOP_LEVEL:
            counts[relative.parts[0]] += 1
    return counts


def _is_excluded(relative: Path) -> bool:
    return any(relative == excluded or excluded in relative.parents for excluded in EXCLUDED_KEY_PATHS)


def _copy_source(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for item in source.iterdir():
        if item.name == ".git":
            continue
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(
                item,
                target,
                ignore=lambda directory, names: [
                    name for name in names
                    if _is_excluded((Path(directory).relative_to(source) / name))
                ],
            )
        elif not _is_excluded(Path(item.name)):
            shutil.copy2(item, target)


def _validate(source: Path, destination: Path) -> Counter[str]:
    expected = _category_counts(source)
    actual = _category_counts(destination)
    categories = set(expected) | set(actual)
    missing = UPSTREAM_TOP_LEVEL - {path.name for path in source.iterdir() if path.is_dir()}
    if missing:
        raise RuntimeError(f"upstream category directories missing: {sorted(missing)}")
    if expected != actual:
        differences = {
            category: (expected[category], actual[category])
            for category in sorted(categories)
            if expected[category] != actual[category]
        }
        raise RuntimeError(f"template category count mismatch (upstream, vendored): {differences}")
    dotfiles = {path.name for path in destination.iterdir() if path.is_file() and path.name.startswith(".")}
    missing_dotfiles = EXPECTED_ROOT_DOTFILES - dotfiles
    if missing_dotfiles:
        raise RuntimeError(f"expected upstream root dotfiles missing: {sorted(missing_dotfiles)}")
    for relative in EXCLUDED_KEY_PATHS:
        if (destination / relative).exists():
            raise RuntimeError(f"excluded key payload path copied: {relative}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--source-dir", type=Path, help="local upstream checkout for offline validation")
    parser.add_argument("--commit", help="upstream commit id (for --source-dir fixtures)")
    parser.add_argument("--date", help="upstream commit date YYYY-MM-DD (for --source-dir fixtures)")
    args = parser.parse_args()
    destination = args.destination.resolve()

    with tempfile.TemporaryDirectory(prefix="forge-nuclei-update-") as temporary:
        temporary_root = Path(temporary)
        if args.source_dir:
            source = args.source_dir.resolve()
            commit = args.commit or _run_git("rev-parse", "HEAD", cwd=source)
            vendored_date = args.date or _run_git("show", "-s", "--format=%cs", "HEAD", cwd=source)
        else:
            source = temporary_root / "upstream"
            _run_git("clone", "--depth", "1", REPOSITORY, str(source), cwd=temporary_root)
            commit = _run_git("rev-parse", "HEAD", cwd=source)
            vendored_date = _run_git("show", "-s", "--format=%cs", "HEAD", cwd=source)

        staged = temporary_root / "staged-vendor"
        _copy_source(source, staged)
        counts = _validate(source, staged)
        provenance = (
            "# Vendored nuclei-templates\n\n"
            f"- Upstream remote: {REPOSITORY}\n"
            f"- Upstream commit: {commit}\n"
            f"- Vendoring date: {date.today().isoformat()}\n"
            f"- Upstream commit date: {vendored_date}\n\n"
            "The nested `.git` directory and 23 key payloads were excluded; "
            "the five upstream root dotfiles are included. Templates are vendored "
            "here as plain files.\n"
        )
        (staged / "VENDORED.md").write_text(provenance, encoding="utf-8")
        destination.parent.mkdir(parents=True, exist_ok=True)
        _copy_source(staged, destination)
        verified = _validate(source, destination)
        if verified != counts:
            raise RuntimeError("post-copy template counts differ from staged counts")

    print(f"Updated {destination} from {REPOSITORY}@{commit} (commit date {vendored_date}).")
    print("YAML templates by category: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    print("Verified five root dotfiles included and all 23 key payloads excluded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
