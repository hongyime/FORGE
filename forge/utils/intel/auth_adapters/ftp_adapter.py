"""
forge/utils/intel/auth_adapters/ftp_adapter.py
Canonical: forge/phase2/auth_adapters/ftp_adapter.py

FTP authentication adapter using stdlib ftplib.
Passive mode only; no data connection or directory listing.
"""

from __future__ import annotations

import asyncio
import ftplib
import logging
from typing import Optional

from forge.utils.intel.auth_adapters import BaseAuthAdapter

_LOG = logging.getLogger(__name__)
_TIMEOUT = 10


class FTPAdapter(BaseAuthAdapter):
    """
    Connects to FTP and attempts login with supplied credentials.
    QUIT is sent immediately on success — no directory or file access.

    OPSEC: FTP credentials and auth failures are logged server-side.
    FTP transmits credentials in plaintext; use only on internal
    engagements where traffic is already monitored/authorised.
    """

    @property
    def default_port(self) -> int:
        return 21

    @property
    def service_name(self) -> str:
        return "ftp"

    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        **kwargs,
    ) -> tuple[bool, Optional[str]]:
        target_port = port or self.default_port

        def _sync() -> tuple[bool, Optional[str]]:
            try:
                ftp = ftplib.FTP(timeout=_TIMEOUT)
                ftp.connect(host, target_port, timeout=_TIMEOUT)
                try:
                    ftp.login(user=username, passwd=password)
                    ftp.quit()
                    return True, None
                except ftplib.error_perm as exc:
                    code = str(exc)[:3]
                    if code == "530":
                        return False, "Login incorrect (530)"
                    return False, str(exc)
                except ftplib.all_errors as exc:
                    return False, str(exc)
                finally:
                    try:
                        ftp.close()
                    except Exception:
                        pass
            except (OSError, ftplib.all_errors) as exc:
                return False, str(exc)

        try:
            return await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, _sync),
                timeout=_TIMEOUT + 5,
            )
        except asyncio.TimeoutError:
            return False, "FTP connection timeout"
