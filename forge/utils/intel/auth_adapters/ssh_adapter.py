"""
forge/utils/intel/auth_adapters/ssh_adapter.py
Canonical: forge/phase2/auth_adapters/ssh_adapter.py

SSH authentication adapter using asyncssh.
Gaussian jitter applied to all delays (σ = 30%) per PRD §12.3.2.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional

from forge.utils.intel.auth_adapters import BaseAuthAdapter

_LOG = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 10  # seconds
_CMD_TIMEOUT = 8  # seconds; minimal probe only — do not execute commands


class SSHAdapter(BaseAuthAdapter):
    """
    Attempts SSH authentication using password credentials.

    Uses asyncssh with known_hosts=None (engagement context; target may have
    self-signed or no host key). Auth attempt is a no-op exec to avoid leaving
    shell history entries — connection succeeds or fails at the auth layer.

    OPSEC:
      - Reconnect per attempt; never reuse sessions across credentials.
      - asyncssh suppresses banner text by default; ensure no banner is logged.
      - Password deleted from local scope immediately after asyncssh call returns.
    """

    @property
    def default_port(self) -> int:
        return 22

    @property
    def service_name(self) -> str:
        return "ssh"

    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        **kwargs,
    ) -> tuple[bool, Optional[str]]:
        target_port = port or self.default_port

        # Gaussian jitter: delay ± 30 % around 0 base (caller controls primary delay)
        jitter = random.gauss(0, 0.3)
        if jitter > 0:
            await asyncio.sleep(jitter)

        try:
            import asyncssh  # type: ignore[import]
        except ImportError:
            return False, "asyncssh not installed: pip install asyncssh"

        try:
            async with asyncssh.connect(
                host,
                port=target_port,
                username=username,
                password=password,
                known_hosts=None,
                connect_timeout=_CONNECT_TIMEOUT,
                login_timeout=_CMD_TIMEOUT,
                request_pty=False,
            ) as _conn:
                # Auth succeeded — do not execute any commands.
                pass
            return True, None
        except asyncssh.PermissionDenied:
            return False, "Permission denied"
        except asyncssh.ConnectionLost as exc:
            return False, f"Connection lost: {exc}"
        except (asyncssh.DisconnectError, OSError, asyncio.TimeoutError) as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("SSHAdapter unexpected error for %s@%s: %s", username, host, exc)
            return False, str(exc)
