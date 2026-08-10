"""
forge/opsec/tor.py — Tor daemon management.

Provides a standalone manager for the Tor Expert Bundle routing daemon.
Ensures the local SOCKS5 proxy (127.0.0.1:9050) is available for outbound
requests without requiring persistent background services.

PRD v7.2 §12.4 (Strict Fault Isolation):
  - Tor must execute entirely within user space.
  - Startup must block until bootstrap reaches 100%.
  - Process must be terminated on exit to prevent ghost listeners.

Migration policy (audit-cleanup-and-chaos, item A / Requirements 2.3–2.7):
  The Tor Expert Bundle now lives under ``<repo_root>/vendor/tor/`` — the
  ``Vendor_Tor_Directory``. ``TorManager`` searches this directory only.

  The previous ``Path.cwd()`` fallback has been removed. Any already-
  extracted ``tor.exe`` at ``<repo_root>/tor/`` (a ``Legacy_Tor_Cache``
  left behind by earlier versions of this module) is no longer consulted.
  When such a cache is detected, ``TorManager`` emits exactly one WARN
  log line per ``_find_tor_exe`` invocation naming the offending path
  and recommending its removal. To silence the warning, delete
  ``<repo_root>/tor/``.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Optional


_LOG = logging.getLogger(__name__)

# Vendored location for the Tor Expert Bundle. See module docstring for
# migration notes and Requirements 2.1–2.7.
_VENDOR_TOR_DIR = Path("vendor") / "tor"

# Legacy on-disk cache produced by the pre-migration extractor. This
# directory is intentionally NOT searched; its presence produces a WARN
# per Requirement 2.7.
_LEGACY_TOR_CACHE_DIR = Path("tor")

_ARCHIVE_PATTERNS: tuple[str, ...] = (
    "tor-expert-bundle-*.tar.gz",
    "tor-expert-bundle-*.tgz",
    "tor-expert-bundle-*.zip",
    "tor*.zip",
    "tor*.tar.gz",
    "tor*.tgz",
)


def _safe_tar_extractall(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract tar members, rejecting any path that escapes the destination directory."""
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        member_dest = (dest_resolved / member.name).resolve()
        if (
            not str(member_dest).startswith(str(dest_resolved) + os.sep)
            and member_dest != dest_resolved
        ):
            raise RuntimeError(
                f"Refusing unsafe tar member (path traversal attempt): {member.name!r}"
            )
    tar.extractall(dest)


class TorManager:
    """Manages the lifecycle of the portable Tor daemon."""

    def __init__(self, tor_exe: Optional[Path] = None):
        self._tor_exe = tor_exe or self._ensure_tor_available()
        self._process: Optional[subprocess.Popen[str]] = None

    @staticmethod
    def _ensure_tor_available() -> Path:
        """Ensure tor.exe is available, unzipping it if necessary."""
        try:
            return TorManager._find_tor_exe()
        except FileNotFoundError:
            _LOG.info("tor.exe not found. Attempting to extract from archive...")
            if TorManager._extract_tor_archive():
                return TorManager._find_tor_exe()
            raise

    @classmethod
    def _search_roots(cls) -> list[Path]:
        """Directories to search for ``tor.exe``.

        Primary root: ``<cwd>/vendor/tor`` — supports operators running
        forge from the repo root.

        Fallback root: ``<repo_root>/vendor/tor`` where ``<repo_root>`` is
        computed from ``__file__`` (two parents up from ``forge/opsec/tor.py``).
        Added 2026-07-06 so ``forge scaffold`` and other commands invoked
        from a non-repo cwd can still locate the bundled Tor Expert Bundle.

        Legacy ``<cwd>/tor/`` remains explicitly ignored per Requirement 2.7
        — see :meth:`_warn_if_legacy_tor_cache_present`.
        """
        roots: list[Path] = [Path.cwd() / _VENDOR_TOR_DIR]
        # Repo-relative fallback: forge/opsec/tor.py -> forge/opsec -> forge -> <repo>
        repo_root = Path(__file__).resolve().parent.parent.parent
        repo_vendor = repo_root / _VENDOR_TOR_DIR
        if repo_vendor not in roots:
            roots.append(repo_vendor)
        return roots

    @staticmethod
    def _warn_if_legacy_tor_cache_present() -> None:
        """Emit exactly one WARN log line if a Legacy_Tor_Cache is present.

        The Legacy_Tor_Cache is ``<repo_root>/tor/`` (an artefact of the
        pre-migration ``Path.cwd()``-based extractor). This helper does
        not search or otherwise use it; it only advises the operator to
        remove it so the warning stops.
        """
        legacy = Path.cwd() / _LEGACY_TOR_CACHE_DIR
        if legacy.exists():
            _LOG.warning(
                "Legacy_Tor_Cache detected at %s — this directory is no "
                "longer searched or used; remove it (e.g. "
                "`Remove-Item -Recurse -Force %s`) to silence this warning.",
                legacy,
                legacy,
            )

    @classmethod
    def _find_tor_exe(cls) -> Path:
        """Locate ``tor.exe`` under ``Vendor_Tor_Directory`` only.

        Iterates every root returned by :meth:`_search_roots`, ``rglob``\\ s
        for ``tor.exe`` inside each root, filters candidates whose path
        contains ``/tor/`` or ``tor-expert-bundle`` (case-insensitive,
        forward-slash normalised), and returns the shortest matching path
        deterministically (Requirements 2.3, 2.4).

        A Legacy_Tor_Cache at ``<repo_root>/tor/``, if present, produces
        exactly one WARN log line per call and is otherwise ignored
        (Requirement 2.7).

        Raises:
            FileNotFoundError: If no matching ``tor.exe`` is found in the
                Vendor_Tor_Directory. The message names ``Vendor_Tor_Directory``
                and the literal path ``vendor/tor`` and instructs the
                caller to place a Tor Expert Bundle archive there.
        """
        cls._warn_if_legacy_tor_cache_present()

        for root in cls._search_roots():
            if not root.exists():
                continue
            candidates: list[Path] = []
            for path in root.rglob("tor.exe"):
                lower = str(path).lower().replace("\\", "/")
                if "/tor/" in lower or "tor-expert-bundle" in lower:
                    candidates.append(path)
            if candidates:
                candidates.sort(key=lambda p: len(str(p)))
                return candidates[0]

        vendor_dir = Path.cwd() / _VENDOR_TOR_DIR
        raise FileNotFoundError(
            "Tor Expert Bundle (tor.exe) not found in Vendor_Tor_Directory "
            f"({vendor_dir}). Place a `tor-expert-bundle-*.{{tar.gz,tgz,zip}}` "
            "archive inside `vendor/tor/` (relative to the repository root) "
            "so it can be located and extracted there."
        )

    @classmethod
    def _extract_tor_archive(cls) -> bool:
        """Discover and extract a Tor archive inside ``Vendor_Tor_Directory``.

        Archives are discovered inside :meth:`_search_roots` only — i.e.
        ``Vendor_Tor_Directory`` — sorted by modification time descending
        (newest first), and extracted INTO the same directory they were
        found in (Requirement 2.5). Archive discovery and extraction never
        touch any other directory.

        Every tar-format extraction is routed through
        :func:`_safe_tar_extractall`, preserving the path-traversal guard
        (Requirement 2.6).
        """
        archives: list[tuple[Path, Path]] = []  # (archive_path, extract_dest)
        seen: set[Path] = set()
        for search_root in cls._search_roots():
            if not search_root.exists():
                continue
            for pattern in _ARCHIVE_PATTERNS:
                for path in search_root.glob(pattern):
                    if path in seen:
                        continue
                    seen.add(path)
                    archives.append((path, search_root))

        archives.sort(key=lambda t: t[0].stat().st_mtime, reverse=True)

        for archive_path, dest in archives:
            _LOG.info("Extracting %s into %s...", archive_path.name, dest)
            try:
                if archive_path.suffix.lower() == ".zip":
                    with zipfile.ZipFile(archive_path, "r") as zip_ref:
                        zip_ref.extractall(dest)
                    if TorManager._find_tor_exe():
                        return True
                elif (
                    archive_path.name.lower().endswith(".tar.gz")
                    or archive_path.suffix.lower() == ".tgz"
                ):
                    with tarfile.open(archive_path, "r:gz") as tar_ref:
                        _safe_tar_extractall(tar_ref, dest)
                    if TorManager._find_tor_exe():
                        return True
            except FileNotFoundError:
                continue
            except Exception as e:
                _LOG.error("Failed to extract %s: %s", archive_path.name, e)

        _LOG.error(
            "No usable Tor archive found in Vendor_Tor_Directory: %s.",
            [str(r) for r in cls._search_roots()],
        )
        return False

    @staticmethod
    def _is_port_open(host: str, port: int) -> bool:
        """Check if a port is currently open and listening."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((host, port))
                return True
            except (ConnectionRefusedError, TimeoutError, socket.timeout):
                return False

    def start(self, wait_for_bootstrap: bool = True) -> bool:
        """Start the Tor daemon.

        Args:
            wait_for_bootstrap: If True, block until Tor is 100% bootstrapped.

        Returns:
            True if started successfully, False otherwise.
        """
        if self.is_running:
            _LOG.debug("Tor daemon is already running (process tracked).")
            return True

        if self._is_port_open("127.0.0.1", 9050):
            _LOG.info("Tor (or another SOCKS5 proxy) is already listening on 127.0.0.1:9050.")
            return True

        _LOG.info("Starting Tor daemon from %s...", self._tor_exe)

        # Start Tor with stdout/stderr piped so we can monitor bootstrap
        try:
            self._process = subprocess.Popen(
                [str(self._tor_exe)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except Exception as e:
            _LOG.error("Failed to start Tor: %s", e)
            return False

        if wait_for_bootstrap:
            return self._wait_for_bootstrap()

        return True

    def _wait_for_bootstrap(self, timeout: int = 60) -> bool:
        """Monitor Tor output for the 100% bootstrap message."""
        if not self._process or not self._process.stdout:
            return False

        start_time = time.time()
        _LOG.info("Waiting for Tor to bootstrap...")

        while time.time() - start_time < timeout:
            line = self._process.stdout.readline()
            if not line:
                break

            # Tor log format: [notice] Bootstrapped 100% (done): Done
            if "Bootstrapped 100% (done)" in line:
                _LOG.info("Tor is ready (100% bootstrapped).")
                return True

            if "ERROR" in line.upper():
                _LOG.error("Tor error: %s", line.strip())
                return False

        _LOG.error("Tor failed to bootstrap within %d seconds.", timeout)
        self.stop()
        return False

    def stop(self) -> None:
        """Terminate the Tor daemon process."""
        if self._process:
            _LOG.info("Stopping Tor daemon...")
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
            _LOG.info("Tor daemon stopped.")

    @property
    def is_running(self) -> bool:
        """Check if the Tor process is currently running."""
        return self._process is not None and self._process.poll() is None
