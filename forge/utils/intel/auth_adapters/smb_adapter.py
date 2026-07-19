"""
forge/utils/intel/auth_adapters/smb_adapter.py
Canonical: forge/phase2/auth_adapters/smb_adapter.py

SMB authentication adapter using smbprotocol.
Performs authentication by attempting to create a session; does not
enumerate shares or read files — auth probe only.

OPSEC:
  - smbprotocol logs to its own logger; suppress below WARNING.
  - Each attempt uses a fresh Connection object to avoid session reuse.
  - Lockout risk: SMB auth failures are logged by Domain Controllers and
    Windows Event Log 4625. The caller's lockout_tracker must enforce
    the 3-failure threshold per (host, username) tuple.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from forge.utils.intel.auth_adapters import BaseAuthAdapter

_LOG = logging.getLogger(__name__)
logging.getLogger("smbprotocol").setLevel(logging.WARNING)

_TIMEOUT = 15


class SMBAdapter(BaseAuthAdapter):
    """
    Authenticates over SMB2/3 using smbprotocol.
    Returns (True, None) on successful session; (False, reason) otherwise.
    """

    @property
    def default_port(self) -> int:
        return 445

    @property
    def service_name(self) -> str:
        return "smb"

    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        domain: str = "",
        **kwargs,
    ) -> tuple[bool, Optional[str]]:
        target_port = port or self.default_port

        def _sync_attempt() -> tuple[bool, Optional[str]]:
            try:
                import smbprotocol.connection as smbconn  # type: ignore[import]
                import smbprotocol.session as smbsess     # type: ignore[import]
                import uuid as _uuid
            except ImportError:
                return False, "smbprotocol not installed: pip install smbprotocol"

            conn_id = _uuid.uuid4()
            conn = smbconn.Connection(conn_id, host, target_port)
            try:
                conn.connect(timeout=_TIMEOUT)
                session = smbsess.Session(
                    conn,
                    username=f"{domain}\\{username}" if domain else username,
                    password=password,
                )
                session.connect()
                # Auth succeeded — disconnect cleanly.
                session.disconnect()
                return True, None
            except Exception as exc:
                msg = str(exc)
                if "STATUS_LOGON_FAILURE" in msg or "invalid credentials" in msg.lower():
                    return False, "Invalid credentials"
                if "STATUS_ACCOUNT_LOCKED_OUT" in msg:
                    return False, "ACCOUNT_LOCKED_OUT"
                return False, msg
            finally:
                try:
                    conn.disconnect()
                except Exception:
                    pass

        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, _sync_attempt),
                timeout=_TIMEOUT + 5,
            )
            return result
        except asyncio.TimeoutError:
            return False, "SMB connection timeout"
        except Exception as exc:
            return False, str(exc)
