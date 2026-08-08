"""
tests/conftest.py - Top-level pytest fixtures shared across the test suite.

The default forge state-store backend is now Postgres (sprint #4). Tests
that previously created a per-test SQLite file now get a per-test Postgres
SCHEMA on the shared ``forge-postgres`` container brought up by
``docker compose -f docker/docker-compose.dev.yml up postgres``.

Schema isolation lets hundreds of tests run in parallel against one DB
without interfering with each other - each test gets its own DDL namespace
and never sees another test's tables.

The fixture skips gracefully when ``forge-postgres`` isn't reachable, so
local dev that hasn't started the stack still gets a clean failure
("docker compose -f docker/docker-compose.dev.yml up -d postgres") rather than a
mysterious connection error.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Postgres DB URL fixture
# ---------------------------------------------------------------------------


_DEFAULT_PG_HOST = "localhost"
_DEFAULT_PG_PORT = 5433
_DEFAULT_PG_USER = "forge"
_DEFAULT_PG_PASS = "forge_dev_only"
_DEFAULT_PG_DB = "forge"


def _pg_reachable(host: str, port: int) -> bool:
    """TCP-level reachability probe with a short timeout."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _build_pg_base_url() -> str:
    """Resolve the base Postgres URL from env or fall back to dev-stack defaults."""
    explicit = os.environ.get("FORGE_TEST_POSTGRES_URL")
    if explicit:
        return explicit
    host = os.environ.get("FORGE_TEST_POSTGRES_HOST", _DEFAULT_PG_HOST)
    port = int(os.environ.get("FORGE_TEST_POSTGRES_PORT", _DEFAULT_PG_PORT))
    user = os.environ.get("FORGE_TEST_POSTGRES_USER", _DEFAULT_PG_USER)
    pw = os.environ.get("FORGE_TEST_POSTGRES_PASSWORD", _DEFAULT_PG_PASS)
    db = os.environ.get("FORGE_TEST_POSTGRES_DB", _DEFAULT_PG_DB)
    return f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db}"


def _strip_async_for_alembic(url: str) -> str:
    if url.startswith("postgresql+asyncpg:"):
        return url.replace("postgresql+asyncpg:", "postgresql+psycopg:", 1)
    if url.startswith("sqlite+aiosqlite:"):
        return url.replace("sqlite+aiosqlite:", "sqlite:", 1)
    return url


@pytest.fixture(scope="session")
def pg_base_url() -> str:
    """Session-scoped base URL pointing at forge-postgres.

    Skips the entire test session if Postgres isn't reachable - tests that
    need a state store can't run without it now that SQLite has been
    retired as the default.
    """
    base = _build_pg_base_url()
    # Parse host/port out for the reachability probe.
    try:
        # Strip "postgresql+asyncpg://" prefix and the user:pass@ chunk.
        rest = base.split("@", 1)[-1]
        host_port, _ = rest.split("/", 1)
        host, port_str = host_port.split(":")
        port = int(port_str)
    except (ValueError, IndexError):
        host, port = _DEFAULT_PG_HOST, _DEFAULT_PG_PORT
    if not _pg_reachable(host, port):
        pytest.skip(
            f"forge-postgres not reachable at {host}:{port}. "
            "Run `docker compose -f docker/docker-compose.dev.yml up -d postgres` "
            "and retry."
        )
    return base


@pytest.fixture
def postgres_db_url(pg_base_url: str) -> Iterator[str]:
    """Per-test Postgres URL with a unique SCHEMA scoped to this test.

    Yields a URL string identical to ``pg_base_url`` but with a
    ``?options=-csearch_path%3D<schema>`` query param so every connection
    automatically uses an isolated schema. The schema is created before the
    test runs and dropped after.
    """
    schema = f"t_{uuid.uuid4().hex[:16]}"

    # Run schema creation/teardown via psycopg sync (alembic-compatible URL).
    sync_url = _strip_async_for_alembic(pg_base_url)
    _exec_sync(sync_url, f'CREATE SCHEMA IF NOT EXISTS "{schema}"')

    # Use the forge-internal ``forge_schema=X`` query param. The state
    # store strips it out and translates it into asyncpg connect_args.
    sep = "&" if "?" in pg_base_url else "?"
    scoped_url = f"{pg_base_url}{sep}forge_schema={schema}"

    try:
        yield scoped_url
    finally:
        _exec_sync(sync_url, f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def _exec_sync(sync_url: str, sql: str) -> None:
    """Run a single DDL statement via psycopg in autocommit mode."""
    try:
        import psycopg  # noqa: PLC0415
    except ImportError:
        pytest.skip("psycopg not installed; pip install 'psycopg[binary]'")
    with psycopg.connect(sync_url.replace("postgresql+psycopg://", "postgresql://"), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)


# ---------------------------------------------------------------------------
# Backwards-compat: legacy `db_url` fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def db_url(postgres_db_url: str) -> str:
    """Drop-in replacement for tests that previously hardcoded sqlite paths.

    Test files used to do::

        db_url = f"sqlite:///{tmp_path / 'mvp.db'}"

    They can now request the ``db_url`` fixture and get a per-test Postgres
    schema URL automatically.
    """
    return postgres_db_url



# ---------------------------------------------------------------------------
# P2-B08: autouse fixture scrubbing FORGE_ env vars from the test environment
# ---------------------------------------------------------------------------
#
# Developers commonly export FORGE_ROE_ID / FORGE_SCOPE_MANIFEST /
# FORGE_REQUIRE_SCOPE_MANIFEST for a live-run experiment, then run
# `pytest` in the same shell. Without this fixture, kill-chain tests that
# assert `raise typer.BadParameter(...)` for missing ROE will silently
# PASS because the CLI reads the env var fallback. That's a silent
# false-negative on the ROE gate coverage.
#
# The autouse fixture uses monkeypatch.delenv() so each test starts with
# these vars unset. Individual tests can still `monkeypatch.setenv()`
# them when they want a specific value.


@pytest.fixture(autouse=True)
def _forge_env_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scrub FORGE_ROE_ID / FORGE_SCOPE_MANIFEST / FORGE_REQUIRE_SCOPE_MANIFEST
    from every test's env so shell-level exports don't silently pass tests
    that were supposed to fail. Tests that need these vars set can call
    ``monkeypatch.setenv(...)`` themselves.
    """
    for name in (
        "FORGE_ROE_ID",
        "FORGE_SCOPE_MANIFEST",
        "FORGE_REQUIRE_SCOPE_MANIFEST",
    ):
        monkeypatch.delenv(name, raising=False)
