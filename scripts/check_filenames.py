#!/usr/bin/env python3
"""
scripts/check_filenames.py — CI filename hygiene guard.

Fails with exit code 1 if any canonical (non-obfuscated) filename or
directory name is found within the obfuscated directory tree.

Canonical → obfuscated mapping is authoritative in forge/config.py:
  forge/config.OBFUSCATED_DIR_MAP
  forge/config.BANNED_CANONICAL_NAMES

Usage (from repo root):
    python scripts/check_filenames.py
    python scripts/check_filenames.py --root /path/to/forge-toolkit
    python scripts/check_filenames.py --verbose

CI integration (GitHub Actions):
    - name: OPSEC filename check
      run: python scripts/check_filenames.py

Exit codes:
    0 — all clear; no banned names detected
    1 — one or more banned canonical names found; blocks merge

Design notes:
  - Only inspects directories mapped in OBFUSCATED_DIR_MAP; the rest of
    the tree (phase0/, phase1/, phase3/, phase4/, phase6/) are not
    obfuscated and do not require screening.
  - Operates on filename stems only (no content scanning).
  - Symlinks are not followed to avoid infinite traversal.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Reproduce mapping inline to avoid import issues in CI before deps installed
# ---------------------------------------------------------------------------

# Obfuscated directory roots (relative to forge/ package root).
_OBFUSCATED_DIRS: tuple[str, ...] = (
    "utils/intel",  # canonical: phase2/
    "utils/post",   # canonical: phase5/
)

# Canonical basenames (without path) that must not appear inside obfuscated dirs.
_BANNED_BASENAMES: frozenset[str] = frozenset({
    # Phase 2 module canonical names
    "breach_db.py",
    "credential_validator.py",
    "dehashed.py",
    "xposedornot.py",
    "theharvester.py",
    "emailrep.py",
    "epieos.py",
    "username_enum.py",
    "key_scanner.py",
    # Phase 5 module canonical names
    "reverse_shell.py",
    "c2_generator.py",
    "exfiltration.py",
    "persistence.py",
    "lateral_movement.py",
    "scope_gate.py",
    # Phase 4 module canonical names
    "idor_scanner.py",
    "firebase_agneyastra.py",
    "firebase_extract.py",
    "supabase_scanner.py",
    # DB files
    "exploit_cache.db",
    # Directory names that must not appear under obfuscated roots
    "exfiltrated_data",
    "agents",
    "payloads",
    # Canonical phase directory names (belt-and-suspenders)
    "phase2",
    "phase5",
})

# Additional canonical directory names that must not appear ANYWHERE in the
# forge/ package tree (top-level check).
_BANNED_TOPLEVEL_DIRS: frozenset[str] = frozenset({
    "phase2",
    "phase5",
    "breach_query_log",  # table name; should not appear as a dir
})


# ---------------------------------------------------------------------------
# Violation record
# ---------------------------------------------------------------------------

class Violation:
    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason

    def __str__(self) -> str:
        return f"  BANNED  {self.path}  →  {self.reason}"


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_obfuscated_dirs(forge_root: Path, verbose: bool) -> list[Violation]:
    """
    Walk each obfuscated directory and flag any file or subdirectory whose
    name matches a canonical banned basename.

    :param forge_root: Path to the forge/ package directory.
    :param verbose: If True, print each path inspected.
    :returns: List of violations found.
    """
    violations: list[Violation] = []

    for obfuscated_rel in _OBFUSCATED_DIRS:
        target_dir = forge_root / obfuscated_rel
        if not target_dir.exists():
            if verbose:
                print(f"  SKIP (not found): {target_dir}")
            continue

        for path in target_dir.rglob("*"):
            if path.is_symlink():
                continue  # Never follow symlinks

            name = path.name
            if verbose:
                print(f"  CHECK: {path.relative_to(forge_root)}")

            if name in _BANNED_BASENAMES:
                violations.append(
                    Violation(
                        path=path.relative_to(forge_root),
                        reason=(
                            f"Canonical name '{name}' found inside obfuscated "
                            f"directory '{obfuscated_rel}'. "
                            f"Rename to obfuscated form per PRD §12.6."
                        ),
                    )
                )

    return violations


def check_toplevel_dirs(forge_root: Path, verbose: bool) -> list[Violation]:
    """
    Check that banned canonical directory names do not appear directly under
    the forge/ package root.

    :param forge_root: Path to the forge/ package directory.
    :param verbose: If True, print each path inspected.
    :returns: List of violations found.
    """
    violations: list[Violation] = []

    for entry in forge_root.iterdir():
        if entry.is_symlink():
            continue
        if verbose:
            print(f"  TOP-CHECK: {entry.name}")
        if entry.is_dir() and entry.name in _BANNED_TOPLEVEL_DIRS:
            violations.append(
                Violation(
                    path=entry.relative_to(forge_root.parent),
                    reason=(
                        f"Canonical directory name '{entry.name}' found at "
                        f"forge/ package root. Must be obfuscated per PRD §12.6."
                    ),
                )
            )

    return violations


def check_data_dir(repo_root: Path, verbose: bool) -> list[Violation]:
    """
    Verify the data/ directory uses the obfuscated DB filename (ref_cache.db)
    and not the canonical exploit_cache.db.

    :param repo_root: Path to the repository root (parent of forge/).
    :param verbose: If True, print check status.
    :returns: List of violations found.
    """
    violations: list[Violation] = []
    data_dir = repo_root / "data"

    if not data_dir.exists():
        return violations

    canonical_db = data_dir / "exploit_cache.db"
    if canonical_db.exists():
        violations.append(
            Violation(
                path=canonical_db.relative_to(repo_root),
                reason=(
                    "Canonical DB filename 'exploit_cache.db' found in data/. "
                    "Rename to 'ref_cache.db' per PRD §12.6."
                ),
            )
        )

    if verbose:
        obfuscated_db = data_dir / "ref_cache.db"
        status = "present" if obfuscated_db.exists() else "absent (not yet generated)"
        print(f"  DATA-CHECK: ref_cache.db → {status}")

    return violations


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CI: fail if canonical filenames appear in obfuscated directories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root directory (default: current working directory).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each path inspected.",
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.root).resolve()
    forge_root = repo_root / "forge"

    if not forge_root.is_dir():
        print(
            f"ERROR: forge/ package directory not found under {repo_root}.\n"
            "Run from the repository root or pass --root <path>.",
            file=sys.stderr,
        )
        return 2

    print(f"FORGE filename hygiene check — repo root: {repo_root}")
    if args.verbose:
        print(f"  forge/ package: {forge_root}")
        print()

    all_violations: list[Violation] = []

    all_violations += check_toplevel_dirs(forge_root, args.verbose)
    all_violations += check_obfuscated_dirs(forge_root, args.verbose)
    all_violations += check_data_dir(repo_root, args.verbose)

    if not all_violations:
        print("OK — no canonical names detected in obfuscated directories.")
        return 0

    print(f"\nFAILED — {len(all_violations)} violation(s) detected:\n")
    for v in all_violations:
        print(str(v))
    print(
        "\nAction required: rename flagged files/directories to their obfuscated "
        "equivalents per PRD v7.2 §12.6 before merging."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
