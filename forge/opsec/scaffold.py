"""
forge/opsec/scaffold.py — Obfuscated directory structure generator.

Generates the full FORGE directory tree with obfuscated Phase 2/5 paths.
Called by `forge scaffold` command to prepare a new FORGE deployment
without revealing canonical offensive tool names on disk.

OPSEC contract (PRD v7.2 §12.6):
  - Phase 2 modules live at forge/utils/intel/ (not forge/phase2/).
  - Phase 5 modules live at forge/utils/post/  (not forge/phase5/).
  - Canonical names (breach_db.py, reverse_shell.py, etc.) must NEVER
    appear on disk inside obfuscated directories.
  - The scaffold only creates directory structure and .gitkeep sentinels.
    It does not copy or write any module source files.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Directory manifest
# ---------------------------------------------------------------------------

_SCAFFOLD_DIRS: tuple[str, ...] = (
    # Core package
    "forge",
    "forge/db",
    "forge/models",
    "forge/opsec",
    # Knowledge base (Phase 0)
    "forge/phase0",
    # Reconnaissance (Phase 1)
    "forge/phase1",
    # OSINT & Credential Intelligence — obfuscated (Phase 2)
    "forge/utils",
    "forge/utils/intel",
    "forge/utils/intel/data",
    "forge/utils/intel/auth_adapters",
    # Evasion & Payload Generation (Phase 3)
    "forge/phase3",
    "forge/phase3/templates",
    # Exploit Correlation & Vulnerability Discovery (Phase 4)
    "forge/phase4",
    # Post-Exploitation — obfuscated (Phase 5)
    "forge/utils/post",
    "forge/utils/post/channels",
    "forge/utils/post/collectors",
    "forge/utils/post/staging",
    # LLM-Assisted Reporting (Phase 6)
    "forge/phase6",
    "forge/phase6/templates",
    # Data directory (offline KB, engagement DBs)
    "data",
    "data/engagements",
    # Test suite
    "tests",
    "tests/cassettes",
    "tests/cassettes/keyscan",
    "tests/cassettes/dehashed",
    "tests/cassettes/xposed",
    "tests/cassettes/firebase",
    "tests/cassettes/supabase",
    "tests/integration",
    "tests/opsec",
    "tests/phase0",
    "tests/phase1",
    "tests/phase2",
    "tests/phase3",
    "tests/phase4",
    "tests/phase5",
    "tests/phase6",
    # CI / GitHub Actions
    ".github",
    ".github/workflows",
    # Scripts (Phase 0 importers, build helpers)
    "scripts",
)

# Files to touch (empty sentinels) inside each created directory.
_GITKEEP = ".gitkeep"

# Files that must NOT exist in obfuscated directories.
BANNED_NAMES_IN_OBFUSCATED: frozenset[str] = frozenset(
    {
        "breach_db.py",
        "credential_validator.py",
        "dehashed.py",
        "xposedornot.py",
        "theharvester.py",
        "emailrep.py",
        "epieos.py",
        "username_enum.py",
        "key_scanner.py",
        "idor_scanner.py",
        "firebase_agneyastra.py",
        "firebase_extract.py",
        "supabase_scanner.py",
        "reverse_shell.py",
        "c2_generator.py",
        "exfiltration.py",
        "persistence.py",
        "lateral_movement.py",
        "scope_gate.py",
        # Directory names
        "phase2",
        "phase5",
        "payloads",
        "agents",
        "exfiltrated_data",
        "breach_query_log",
    }
)

_OBFUSCATED_ROOTS: tuple[str, ...] = (
    "forge/utils/intel",
    "forge/utils/post",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_scaffold(output_dir: str = ".") -> None:
    """
    Create the full obfuscated FORGE scaffold under *output_dir*.

    For each directory in the manifest:
      1. Creates the directory (parents=True, exist_ok=True).
      2. Touches a ``.gitkeep`` sentinel so the directory is tracked by git.

    Then runs a post-generation sanity check to ensure no banned canonical
    filenames are present under obfuscated roots.

    :param output_dir: Root path for the scaffold. Defaults to current directory.
    """
    base = Path(output_dir).resolve()
    created = 0
    skipped = 0

    for rel in _SCAFFOLD_DIRS:
        d = base / rel
        try:
            d.mkdir(parents=True, exist_ok=True)
            sentinel = d / _GITKEEP
            if not sentinel.exists():
                sentinel.touch()
            created += 1
        except OSError as exc:
            print(f"[forge scaffold] WARNING: could not create {d}: {exc}")
            skipped += 1

    print(
        f"[forge scaffold] Created {created} director{'y' if created == 1 else 'ies'}"
        f"{f', {skipped} skipped' if skipped else ''} under {base}"
    )

    violations = _audit_obfuscated_roots(base)
    if violations:
        print(
            f"\n[forge scaffold] ⚠  OPSEC WARNING: {len(violations)} banned filename(s) "
            f"found in obfuscated directories:"
        )
        for v in violations:
            print(f"    {v}")
        print(
            "  These files expose canonical offensive tool names on disk. "
            "Rename them using the obfuscation mapping in forge/config.py."
        )
    else:
        print("[forge scaffold] OPSEC check passed — no banned names in obfuscated roots.")


def verify_scaffold(output_dir: str = ".") -> list[str]:
    """
    Audit an existing directory for OPSEC violations (banned canonical names
    in obfuscated roots). Returns a list of offending paths; empty = clean.

    :param output_dir: Root path of the FORGE deployment to audit.
    :returns: List of relative path strings for each violation found.
    """
    base = Path(output_dir).resolve()
    return _audit_obfuscated_roots(base)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _audit_obfuscated_roots(base: Path) -> list[str]:
    """Return a list of offending path strings (relative to *base*)."""
    violations: list[str] = []
    for root_rel in _OBFUSCATED_ROOTS:
        root = base / root_rel
        if not root.exists():
            continue
        for child in root.rglob("*"):
            if child.is_file() and child.name in BANNED_NAMES_IN_OBFUSCATED:
                violations.append(str(child.relative_to(base)))
            elif child.is_dir() and child.name in BANNED_NAMES_IN_OBFUSCATED:
                violations.append(str(child.relative_to(base)) + "/")
    return violations
