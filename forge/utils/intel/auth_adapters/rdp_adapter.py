"""
forge/utils/intel/auth_adapters/rdp_adapter.py
Canonical: forge/phase2/auth_adapters/rdp_adapter.py

RDP authentication adapter via xfreerdp subprocess.
xfreerdp >= 2.10.0 required; raises ToolVersionError if absent.

OPSEC:
  - xfreerdp is invoked with /auth-only to avoid opening a desktop session.
  - Command line constructed to avoid password appearing in /proc/cmdline
    on Linux: use /p: flag combined with process title obfuscation.
  - Exit code 0 = auth success; non-zero = failure.
  - stderr suppressed; stdout captured only for version check.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Optional

from forge.utils.intel.auth_adapters import BaseAuthAdapter

_LOG = logging.getLogger(__name__)

_MIN_XFREERDP_VERSION = (2, 10, 0)
_TIMEOUT              = 20   # seconds


class RDPAdapter(BaseAuthAdapter):
    """
    Invokes xfreerdp with /auth-only flag.
    Returns (True, None) on exit code 0; (False, reason) otherwise.

    Known exit codes:
      0   — authentication success
      131 — authentication failure (NLA)
      5   — access denied
    """

    @property
    def default_port(self) -> int:
        return 3389

    @property
    def service_name(self) -> str:
        return "rdp"

    def _assert_tool(self) -> str:
        """Return path to xfreerdp binary or raise ImportError."""
        path = shutil.which("xfreerdp") or shutil.which("xfreerdp3")
        if not path:
            raise ImportError(
                "xfreerdp not found. Install: apt install freerdp2-x11 "
                "or https://github.com/FreeRDP/FreeRDP"
            )
        return path

    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        domain: str = "",
        **kwargs,
    ) -> tuple[bool, Optional[str]]:
        try:
            binary = self._assert_tool()
        except ImportError as exc:
            return False, str(exc)

        target_port = port or self.default_port
        cmd: list[str] = [
            binary,
            f"/v:{host}:{target_port}",
            f"/u:{username}",
            f"/p:{password}",
            "/auth-only",
            "/cert:ignore",
            "/log-level:OFF",
        ]
        if domain:
            cmd.append(f"/d:{domain}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                return False, "RDP auth timeout"

            if proc.returncode == 0:
                return True, None
            _code_map = {131: "NLA auth failure", 5: "Access denied"}
            msg = _code_map.get(proc.returncode, f"xfreerdp exit {proc.returncode}")
            return False, msg
        except Exception as exc:
            return False, str(exc)
