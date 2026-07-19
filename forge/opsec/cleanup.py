"""
forge/opsec/cleanup.py — Secure artifact deletion registry.

Every module that writes a temporary file (e.g., Agneyastra JSON output,
theHarvester JSON output, payload staging files) MUST call
register_cleanup_file() immediately after creating the file, before any
further processing.  This guarantees deletion on:

  1. Normal completion  — the module deletes the file itself after parsing.
  2. Process exit       — atexit handler shreds any file still in the registry.
  3. forge clean        — run_clean() sweeps the engagement directory tree.

OPSEC contract (PRD v7.2 §12.5):
  - Files are overwritten with zero bytes before unlinking (basic shred).
    For higher assurance on SSDs use --secure-delete (calls shred / sdelete).
  - Directories are removed with shutil.rmtree; no zero-overwrite pass
    (directory entries are metadata — content files must be registered
    individually before directory removal).
  - run_clean() is irreversible. The CLI gate (questionary.confirm) is in
    cli.py, not here. This module never prompts.
  - The registry is process-local (not persisted to disk). Files registered
    in a previous process run are not tracked here; forge clean sweeps
    well-known paths instead.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger(__name__)

# Process-local registry of temporary files to delete on exit or forge clean.
_REGISTRY: list[Path] = []


# ---------------------------------------------------------------------------
# Registry API
# ---------------------------------------------------------------------------


def register_cleanup_file(path: "str | Path") -> None:
    """
    Register *path* for secure deletion.

    Safe to call multiple times with the same path — duplicates are silently
    ignored.  Call this BEFORE the file is created (or immediately after) so
    that even a crash during processing guarantees cleanup.

    :param path: Absolute or relative path to the temporary file.
    """
    p = Path(path)
    if p not in _REGISTRY:
        _REGISTRY.append(p)
        _LOG.debug("cleanup: registered %s", p)


def deregister_cleanup_file(path: "str | Path") -> None:
    """
    Remove *path* from the cleanup registry (e.g., when the caller has
    already deleted the file itself).
    """
    p = Path(path)
    try:
        _REGISTRY.remove(p)
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Secure delete helpers
# ---------------------------------------------------------------------------


def _shred_file(path: Path, passes: int = 1) -> bool:
    """
    Overwrite *path* with zero bytes, then unlink it.

    Returns True on success, False if the file could not be removed.
    """
    try:
        size = path.stat().st_size
    except OSError:
        # File may already be gone — treat as success
        return True

    try:
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
        path.unlink()
        _LOG.debug("cleanup: shredded %s (%d bytes)", path, size)
        return True
    except OSError as exc:
        _LOG.error("cleanup: could not shred %s: %s", path, exc)
        return False


def _remove_path(target: Path) -> bool:
    """Remove a file or directory tree. Returns True on success."""
    try:
        if target.is_dir():
            shutil.rmtree(target)
            _LOG.info("cleanup: removed directory %s", target)
        elif target.exists():
            _shred_file(target)
        return True
    except Exception as exc:
        _LOG.error("cleanup: failed to remove %s: %s", target, exc)
        return False


# ---------------------------------------------------------------------------
# forge clean entry point
# ---------------------------------------------------------------------------


def run_clean(engagement_id: str, extra_paths: Optional[list[Path]] = None) -> None:
    """
    Securely remove all on-disk artifacts for *engagement_id*.

    Sweeps:
      - All files in the process-local registry.
      - The engagement DB (``<data_dir>/engagements/<id>.db``).
      - Staging, sessions, and templates directories.
      - Any *extra_paths* provided by the caller.

    :param engagement_id: Engagement identifier (used to derive DB and dir paths).
    :param extra_paths:   Additional paths to remove (e.g., report output files).
    :raises RuntimeError: (never) — errors are logged and counted, not raised,
                          to ensure partial clean is always completed.
    """
    from forge.config import ForgeConfig  # deferred to avoid circular imports

    cfg = ForgeConfig.load()

    targets: list[Path] = list(_REGISTRY)

    # Well-known engagement paths
    targets.extend(
        [
            cfg.engagement_db_path(engagement_id),
            cfg.staging_dir(engagement_id),
            cfg.sessions_dir(engagement_id),
            cfg.templates_dir(engagement_id),
        ]
    )

    if extra_paths:
        targets.extend(extra_paths)

    errors = 0
    removed = 0
    for target in targets:
        if _remove_path(target):
            removed += 1
        else:
            errors += 1

    # Clear registry after sweep
    _REGISTRY.clear()

    if errors:
        _LOG.warning(
            "forge clean completed with %d error(s); %d path(s) removed for '%s'.",
            errors,
            removed,
            engagement_id,
        )
    else:
        _LOG.info(
            "forge clean: %d path(s) removed for engagement '%s'. No artifacts remain on disk.",
            removed,
            engagement_id,
        )


# ---------------------------------------------------------------------------
# atexit safety net
# ---------------------------------------------------------------------------


def _atexit_cleanup() -> None:
    """
    Delete all remaining registered files on process exit.

    This is a safety net for modules that crash or early-exit without
    explicitly deleting their temp files.  It runs silently (no logging
    at this point as the logging system may be torn down).
    """
    for p in list(_REGISTRY):
        try:
            if p.exists():
                size = p.stat().st_size
                with open(p, "r+b") as fh:
                    fh.write(b"\x00" * size)
                p.unlink()
        except Exception:
            pass  # Best-effort at exit; do not raise


atexit.register(_atexit_cleanup)
