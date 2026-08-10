"""
forge/utils/intel/auth_adapters/dbms_adapter.py
Canonical: forge/phase2/auth_adapters/dbms_adapter.py

DBMS authentication adapter for MySQL and PostgreSQL.
Dispatches based on `service` kwarg ('mysql' | 'postgres').
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from forge.utils.intel.auth_adapters import BaseAuthAdapter

_LOG = logging.getLogger(__name__)
_TIMEOUT = 10


class DBMSAdapter(BaseAuthAdapter):
    """
    Tries to establish a database connection with supplied credentials.
    No queries are executed — auth probe only.

    OPSEC:
      - MySQL: uses PyMySQL; connect() raises OperationalError on auth fail.
      - PostgreSQL: uses psycopg2; connect() raises OperationalError on auth fail.
      - Both drivers raise immediately on bad password without requiring a query.
      - Connection closed immediately on success; no data access.
    """

    @property
    def default_port(self) -> int:
        return 3306  # MySQL default; postgres overrides to 5432

    @property
    def service_name(self) -> str:
        return "dbms"

    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        service: str = "mysql",  # 'mysql' | 'postgres'
        database: str = "",
        **kwargs,
    ) -> tuple[bool, Optional[str]]:
        if service == "postgres":
            return await self._try_postgres(host, username, password, port or 5432, database)
        return await self._try_mysql(host, username, password, port or 3306, database)

    async def _try_mysql(
        self, host: str, username: str, password: str, port: int, database: str
    ) -> tuple[bool, Optional[str]]:
        def _sync() -> tuple[bool, Optional[str]]:
            try:
                import pymysql  # type: ignore[import]
            except ImportError:
                return False, "pymysql not installed: pip install pymysql"
            try:
                conn = pymysql.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    database=database or None,
                    connect_timeout=_TIMEOUT,
                )
                conn.close()
                return True, None
            except pymysql.err.OperationalError as exc:
                code = exc.args[0]
                if code in (1045, 1044):
                    return False, "Access denied"
                return False, f"MySQL error {code}: {exc.args[1]}"
            except Exception as exc:
                return False, str(exc)

        try:
            return await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, _sync),
                timeout=_TIMEOUT + 5,
            )
        except asyncio.TimeoutError:
            return False, "MySQL connection timeout"

    async def _try_postgres(
        self, host: str, username: str, password: str, port: int, database: str
    ) -> tuple[bool, Optional[str]]:
        def _sync() -> tuple[bool, Optional[str]]:
            try:
                import psycopg2  # type: ignore[import]
            except ImportError:
                return False, "psycopg2 not installed: pip install psycopg2-binary"
            try:
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    dbname=database or "postgres",
                    connect_timeout=_TIMEOUT,
                )
                conn.close()
                return True, None
            except psycopg2.OperationalError as exc:
                msg = str(exc).lower()
                if "password authentication failed" in msg or "role" in msg:
                    return False, "Authentication failed"
                return False, str(exc)
            except Exception as exc:
                return False, str(exc)

        try:
            return await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, _sync),
                timeout=_TIMEOUT + 5,
            )
        except asyncio.TimeoutError:
            return False, "PostgreSQL connection timeout"
