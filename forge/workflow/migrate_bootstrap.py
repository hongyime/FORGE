"""
forge/workflow/migrate_bootstrap.py - Idempotent migration bootstrap.

Solves the "existing deployments have tables but no alembic_version" problem.
Runs the right alembic command depending on what's already in the DB:

    * Fresh DB (no tables)                 -> alembic upgrade head
    * Pre-alembic DB (workflows table
      exists but no alembic_version)       -> alembic stamp 0001_baseline,
                                              then alembic upgrade head
    * Already-migrated DB (alembic_version
      table present)                       -> alembic upgrade head (no-op
                                              if already at head)

Idempotent: safe to run on every startup. The CLI form is
``python -m forge.workflow.migrate_bootstrap``; the programmatic form is
``await bootstrap_database(db_url)``.

Detection is done via SQLAlchemy inspector before any alembic command runs,
so we never see "table already exists" errors from a misconfigured upgrade.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

__all__ = [
    "BASELINE_REVISION",
    "BootstrapResult",
    "bootstrap_database",
    "main",
]

_LOG = logging.getLogger(__name__)

BASELINE_REVISION = "0001_baseline"
BASELINE_TABLES = {"workflow_state", "agent_loop_heartbeat"}


class BootstrapResult:
    """Outcome of a bootstrap run for caller logging / tests."""

    def __init__(
        self,
        *,
        action: str,
        from_revision: str | None,
        to_revision: str | None,
        tables_before: list[str],
        tables_after: list[str],
    ) -> None:
        self.action = action
        self.from_revision = from_revision
        self.to_revision = to_revision
        self.tables_before = tables_before
        self.tables_after = tables_after

    def __repr__(self) -> str:
        return (
            f"BootstrapResult(action={self.action!r}, "
            f"from={self.from_revision!r}, to={self.to_revision!r}, "
            f"tables_before={len(self.tables_before)}, "
            f"tables_after={len(self.tables_after)})"
        )


def _alembic_config(db_url: str) -> Config:
    """Build an alembic Config pointing at our project's alembic.ini.

    The ini file lives at the repo root; locate it relative to this module.
    """
    repo_root = Path(__file__).resolve().parents[2]
    cfg_path = repo_root / "alembic.ini"
    if not cfg_path.exists():
        raise FileNotFoundError(f"alembic.ini not found at {cfg_path}")
    cfg = Config(str(cfg_path))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    # configparser uses %-interpolation; escape any literal ``%`` in the URL
    # (notably the ``options=-csearch_path%3D<schema>`` form psycopg expects).
    cfg.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))
    return cfg


def _current_alembic_revision(db_url: str) -> str | None:
    """Return the current alembic_version row, or None if the table is absent.

    Inspects directly via SQLAlchemy to avoid alembic's noisy logging when
    the table doesn't exist yet.
    """
    engine = create_engine(db_url)
    try:
        insp = inspect(engine)
        if "alembic_version" not in insp.get_table_names():
            return None
        with engine.connect() as conn:
            row = conn.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).fetchone()
            if row is None:
                return None
            return str(row[0])
    finally:
        engine.dispose()


def _list_tables(db_url: str) -> list[str]:
    engine = create_engine(db_url)
    try:
        insp = inspect(engine)
        return sorted(insp.get_table_names())
    finally:
        engine.dispose()


def bootstrap_database(db_url: str) -> BootstrapResult:
    """Idempotently bring the DB at ``db_url`` to the latest schema revision.

    Args:
        db_url: SQLAlchemy URL (sync driver, e.g. ``sqlite:///forge.db``).
            The async drivers (``+aiosqlite``, ``+asyncpg``) are stripped
            since alembic uses the synchronous engine for migrations.

    Returns:
        :class:`BootstrapResult` summarising the action taken.
    """
    # alembic's engine_from_config doesn't support async drivers; strip them.
    if db_url.startswith("sqlite+aiosqlite:"):
        db_url = db_url.replace("sqlite+aiosqlite:", "sqlite:", 1)
    elif db_url.startswith("postgresql+asyncpg:"):
        db_url = db_url.replace("postgresql+asyncpg:", "postgresql+psycopg:", 1)

    # Strip the forge-internal ``forge_schema=`` query param. It's not a
    # valid libpq option name; we translate it into the standard libpq
    # ``options=-csearch_path%3D<schema>`` form so every psycopg connection
    # auto-SETs search_path to the right namespace. Use urllib so the URL
    # encoding is correct (configparser would mangle ``%``).
    schema: str | None = None
    if "?" in db_url:
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse  # noqa: PLC0415
        parsed = urlparse(db_url)
        params = parse_qsl(parsed.query)
        keep: list[tuple[str, str]] = []
        for k, v in params:
            if k == "forge_schema":
                schema = v
            else:
                keep.append((k, v))
        if schema is not None:
            keep.append(("options", f"-csearch_path={schema}"))
        new_qs = urlencode(keep)
        db_url = urlunparse(parsed._replace(query=new_qs))

    cfg = _alembic_config(db_url)
    tables_before = _list_tables(db_url)
    table_set = set(tables_before)
    current = _current_alembic_revision(db_url)

    if current is not None:
        # Already managed by alembic - just upgrade to head.
        action = "upgrade_existing"
        _LOG.info(
            "bootstrap: DB already at alembic revision %s; running upgrade head",
            current,
        )
        command.upgrade(cfg, "head")
    elif BASELINE_TABLES.issubset(table_set):
        # Pre-alembic deployment: tables exist, no alembic_version row.
        # Stamp at the baseline revision FIRST, then upgrade forward.
        action = "stamp_then_upgrade"
        _LOG.info(
            "bootstrap: pre-alembic DB detected (tables present, no version); "
            "stamping at %s then upgrading",
            BASELINE_REVISION,
        )
        command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, "head")
    else:
        # Fresh DB - run the full chain from zero.
        action = "fresh_upgrade"
        _LOG.info("bootstrap: fresh DB; running full upgrade chain")
        command.upgrade(cfg, "head")

    after = _current_alembic_revision(db_url)
    tables_after = _list_tables(db_url)
    return BootstrapResult(
        action=action,
        from_revision=current,
        to_revision=after,
        tables_before=tables_before,
        tables_after=tables_after,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry: ``python -m forge.workflow.migrate_bootstrap``."""
    parser = argparse.ArgumentParser(
        description="Idempotently bootstrap the forge state DB schema."
    )
    parser.add_argument(
        "--db-url",
        default=os.environ.get("FORGE_STATE_DB_URL"),
        help="SQLAlchemy URL. Defaults to FORGE_STATE_DB_URL env var.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational logging.",
    )
    args = parser.parse_args(argv)

    if not args.db_url:
        print(
            "ERROR: --db-url not provided and FORGE_STATE_DB_URL is not set.",
            file=sys.stderr,
        )
        return 2

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    result = bootstrap_database(args.db_url)
    print(f"action:        {result.action}")
    print(f"from revision: {result.from_revision}")
    print(f"to revision:   {result.to_revision}")
    print(f"tables before: {result.tables_before}")
    print(f"tables after:  {result.tables_after}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
