"""
alembic/env.py - Alembic environment for forge workflow state DB migrations.

Reads the target URL from (in priority order):
  1. ``-x url=...`` on the alembic CLI
  2. ``FORGE_STATE_DB_URL`` environment variable
  3. ``alembic.ini``'s sqlalchemy.url

Both online (live DB) and offline (SQL emit) modes are supported.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import the existing _Base + models so ``--autogenerate`` can diff. We import
# lazily to avoid importing the entire forge package when alembic is invoked
# in environments that lack runtime deps (e.g. CI image builds).
from forge.workflow.state_store import _Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = _Base.metadata


def _resolve_url() -> tuple[str, str | None]:
    x_args = context.get_x_argument(as_dictionary=True)
    if x_args.get("url"):
        url = str(x_args["url"])
    else:
        env_url = os.environ.get("FORGE_STATE_DB_URL")
        if env_url:
            url = env_url
        else:
            ini_url = config.get_main_option("sqlalchemy.url")
            if ini_url:
                url = ini_url
            else:
                raise RuntimeError(
                    "alembic: no DB URL provided. Pass -x url=... or set "
                    "FORGE_STATE_DB_URL."
                )
    # Strip the forge-internal ``forge_schema=`` query param if present.
    # Tests use it for per-test schema isolation; we apply it via SET
    # search_path after connect rather than as a libpq option (which
    # configparser mangles).
    schema: str | None = None
    if "?" in url:
        base, _, qs = url.partition("?")
        keep_parts: list[str] = []
        for part in qs.split("&"):
            if not part:
                continue
            if part.startswith("forge_schema="):
                schema = part.split("=", 1)[1]
            else:
                keep_parts.append(part)
        url = base
        if keep_parts:
            url = f"{url}?{'&'.join(keep_parts)}"
    # Alembic uses the SYNCHRONOUS SQLAlchemy engine for DDL. Strip async
    # driver suffixes so it falls back to the sync default driver.
    if url.startswith("sqlite+aiosqlite:"):
        url = url.replace("sqlite+aiosqlite:", "sqlite:", 1)
    elif url.startswith("postgresql+asyncpg:"):
        url = url.replace("postgresql+asyncpg:", "postgresql+psycopg:", 1)
    return url, schema


def run_migrations_offline() -> None:
    """Emit SQL without connecting to a DB."""
    url, _schema = _resolve_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    url, schema = _resolve_url()
    section = config.get_section(config.config_ini_section, {}) or {}
    section["sqlalchemy.url"] = url
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        if schema is not None:
            # Ensure the schema exists, then SET search_path so every DDL
            # alembic emits lands inside it. Idempotent.
            from sqlalchemy import text  # noqa: PLC0415
            connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
            connection.execute(text(f'SET search_path TO "{schema}"'))
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=url.startswith("sqlite"),
            version_table_schema=schema,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
