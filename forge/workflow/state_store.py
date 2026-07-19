"""
forge/workflow/state_store.py — Persistent workflow checkpoint store.

SQLAlchemy 2.0 async-style store for workflow execution state. Each
checkpoint records the current stage index, per-stage status, and the
intermediate results produced so far so that an interrupted workflow can
be resumed without re-running completed stages (Requirements 6.1, 6.2,
6.5). Stores both SQLite (development) and PostgreSQL (production)
backends — the URL scheme is auto-translated to its async dialect.

Engine creation is lazy: ``StateStore(url)`` performs no I/O. The first
call to :meth:`init_schema` (or any persistence method) opens the engine.
This keeps the public import surface free of optional drivers like
``aiosqlite`` until they are actually needed.

Hardening (P0/P1 fixes):

* Optimistic concurrency control via a monotonically-increasing
  ``version`` column. ``save_checkpoint(expected_version=v)`` performs a
  conditional update and raises :class:`ConcurrentCheckpointError` when
  another writer beat us to the row.
* Resume idempotency via ``resumed_at`` and the atomic
  :meth:`try_claim_for_resume` helper, so concurrent or repeated
  ``resume_incomplete_workflows`` invocations only re-publish each
  workflow once.
* Hard cap on the serialised intermediate-results size to prevent a
  runaway agent from filling the database with multi-gigabyte rows.
* SQLite WAL pragmas enabled on every connection for better
  concurrent-read tolerance and a 30s busy timeout.

Requirements: 5.3, 6.1, 6.2, 6.3, 6.4, 6.5
"""

from __future__ import annotations

import errno
import json
import logging
import re
import sqlite3
import time
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, Float, Integer, String, Text, delete, event, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from forge.core.errors import (
    CheckpointDiskFullError,
    CheckpointTooLargeError,
    ConcurrentCheckpointError,
)

# Case-insensitive pattern for the two SQLite/aiosqlite messages that
# indicate a disk-full or disk-I/O condition. Used by
# ``save_checkpoint`` to translate the raw OperationalError into a
# typed ``CheckpointDiskFullError``. Requirement 7 of
# ``.kiro/specs/chaos-harness-hardening/requirements.md``.
_SQLITE_DISK_FULL_RE = re.compile(
    r"database or disk is full|disk i/o error", re.IGNORECASE
)


def _is_disk_full_exc(exc: BaseException) -> bool:
    """Return True iff ``exc`` looks like a disk-full / ENOSPC event.

    Matches:
        * ``OSError`` with ``errno == errno.ENOSPC``.
        * ``sqlite3.OperationalError`` whose message matches
          ``_SQLITE_DISK_FULL_RE``.
        * ``DBAPIError`` whose ``.orig`` matches either of the above.
    """
    if isinstance(exc, OSError) and getattr(exc, "errno", None) == errno.ENOSPC:
        return True
    if isinstance(exc, sqlite3.OperationalError):
        if _SQLITE_DISK_FULL_RE.search(str(exc)) is not None:
            return True
    if isinstance(exc, DBAPIError):
        orig = getattr(exc, "orig", None)
        if orig is not None and _is_disk_full_exc(orig):
            return True
    return False

if TYPE_CHECKING:
    pass

_LOG = logging.getLogger(__name__)

# Per-stage status sentinel values.
STATUS_PENDING = "pending"
STATUS_IN_PROGRESS = "in_progress"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

# Hard cap on the JSON-encoded size of intermediate_results (P1-8).
# 10 MiB is generous for legitimate workloads; anything beyond signals a
# runaway producer or an attempt to wedge the state store.
MAX_INTERMEDIATE_RESULTS_BYTES: int = 10 * 1024 * 1024


class _Base(DeclarativeBase):
    """Declarative base for workflow tables."""


class WorkflowStateRow(_Base):
    """Persisted checkpoint of one workflow instance.

    Attributes:
        id: UUID primary key assigned at workflow start.
        definition_name: Name of the originating :class:`WorkflowDefinition`.
        definition_version: Version string of the definition snapshot.
        current_stage_index: Zero-based index into the definition's stages.
        stage_statuses: JSON-encoded mapping ``stage_name -> status``.
        intermediate_results: JSON-encoded mapping of stage outputs and
            internal bookkeeping (e.g. ``_retries``).
        started_at: Epoch seconds when the workflow began.
        updated_at: Epoch seconds of the most recent checkpoint write.
        is_complete: ``True`` once the final stage transitions to completed
            or the workflow is marked failed.
        failure_reason: Populated when ``is_complete`` AND the workflow
            terminated abnormally; ``None`` on clean completion.
        checkpoint_valid: Integrity flag toggled to ``False`` by
            :meth:`StateStore.mark_corrupted` when deserialisation fails
            (Requirement 6.4).
        version: Monotonically-increasing optimistic-concurrency token.
            Incremented on every successful update; mismatch on a
            conditional save raises :class:`ConcurrentCheckpointError`
            (P0-1).
        resumed_at: Epoch seconds of the most recent claim by
            :meth:`StateStore.try_claim_for_resume`. ``None`` until the
            row has been picked up by a resumer (P0-5).
    """

    __tablename__ = "workflow_state"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    definition_name: Mapped[str] = mapped_column(String(255), nullable=False)
    definition_version: Mapped[str] = mapped_column(String(64), nullable=False)
    current_stage_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stage_statuses: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    intermediate_results: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    started_at: Mapped[float] = mapped_column(Float, nullable=False)
    updated_at: Mapped[float] = mapped_column(Float, nullable=False)
    is_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    checkpoint_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resumed_at: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)


class HeartbeatRow(_Base):
    """Single-row heartbeat marker for the agent loop liveness probe."""

    __tablename__ = "agent_loop_heartbeat"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)


class WorkflowHistoryRow(_Base):
    """Append-only audit trail of every workflow state transition.

    Each successful ``save_checkpoint`` for an existing workflow appends one
    row capturing the before-state version, after-state version, stage
    delta, and a UTC timestamp. This gives forensic traceability without
    bloating the live ``workflows`` row, and supports ``--what-if`` style
    debugging by replaying the history.

    Designed to be append-only: rows are never UPDATEd or DELETEd.
    """

    __tablename__ = "workflow_history"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True,
    )
    workflow_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True,
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    from_stage_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    to_stage_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    from_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    to_version: Mapped[int] = mapped_column(Integer, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_at: Mapped[float] = mapped_column(Float, nullable=False)

def _to_async_url(db_url: str) -> str:
    """Translate sync URL schemes to their async equivalents.

    ``sqlite:///x.db`` becomes ``sqlite+aiosqlite:///x.db``;
    ``postgresql://...`` becomes ``postgresql+asyncpg://...``. URLs that
    already specify an async driver are returned unchanged.
    """
    if db_url.startswith("sqlite+") or db_url.startswith("postgresql+"):
        return db_url
    if db_url.startswith("sqlite:"):
        return db_url.replace("sqlite:", "sqlite+aiosqlite:", 1)
    if db_url.startswith("postgresql:") or db_url.startswith("postgres:"):
        rest = db_url.split(":", 1)[1]
        return f"postgresql+asyncpg:{rest}"
    return db_url


def _is_sqlite(async_url: str) -> bool:
    """Return ``True`` for SQLite URLs (sync or async dialect)."""
    return async_url.startswith("sqlite")


def _is_postgres(async_url: str) -> bool:
    """Return ``True`` for Postgres URLs (sync or async dialect)."""
    return async_url.startswith("postgresql")


def _install_sqlite_pragmas(engine: AsyncEngine) -> None:
    """Apply WAL pragmas to every new SQLite connection (P1-9).

    Runs ``PRAGMA journal_mode=WAL``, ``synchronous=NORMAL``, and
    ``busy_timeout=30000`` once per raw DBAPI connection. Skipped for
    non-SQLite engines.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
        finally:
            cursor.close()


# Postgres connection-pool defaults. Tuned for the platform's expected
# concurrency profile: bounded async workers (~10 concurrent) plus burst
# headroom. ``pool_pre_ping`` recycles dead connections before they're
# handed out, defending against idle-disconnect from cloud Postgres
# providers and proxy-fronted setups.
POSTGRES_POOL_KWARGS: dict[str, Any] = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_timeout": 30,
}


class StateStore:
    """Async SQLAlchemy-backed workflow state persistence.

    Args:
        db_url: Connection string. Sync schemes are auto-translated to
            their async dialect. Defaults to a local SQLite file.

    The engine is created lazily on first use so that constructing a
    ``StateStore`` does not require optional async drivers to be importable
    at module load time.
    """

    def __init__(
        self,
        db_url: str = "postgresql+asyncpg://forge:forge_dev_only@localhost:5433/forge",
    ) -> None:
        # Extract a forge-internal ``forge_schema=X`` query param if present.
        # This is the test-isolation mechanism: each test gets a unique
        # schema and we tell asyncpg to SET search_path on every connect.
        self._schema: str | None = None
        if "?" in db_url:
            base, _, qs = db_url.partition("?")
            keep_parts: list[str] = []
            for part in qs.split("&"):
                if not part:
                    continue
                if part.startswith("forge_schema="):
                    self._schema = part.split("=", 1)[1]
                else:
                    keep_parts.append(part)
            if keep_parts:
                db_url = f"{base}?{'&'.join(keep_parts)}"
            else:
                db_url = base
        self._db_url = _to_async_url(db_url)
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

    # ------------------------------------------------------------------
    # Engine lifecycle
    # ------------------------------------------------------------------

    def _ensure_engine(self) -> async_sessionmaker[AsyncSession]:
        """Create the engine and sessionmaker on first call; cache after."""
        if self._sessionmaker is None:
            engine_kwargs: dict[str, Any] = {"future": True}
            if _is_postgres(self._db_url):
                engine_kwargs.update(POSTGRES_POOL_KWARGS)
                if self._schema:
                    # asyncpg accepts server_settings as a dict via
                    # connect_args. Each fresh connection from the pool
                    # SETs search_path automatically.
                    engine_kwargs["connect_args"] = {
                        "server_settings": {"search_path": self._schema},
                    }
            self._engine = create_async_engine(self._db_url, **engine_kwargs)
            if _is_sqlite(self._db_url):
                _install_sqlite_pragmas(self._engine)
            self._sessionmaker = async_sessionmaker(
                self._engine, expire_on_commit=False, class_=AsyncSession,
            )
        return self._sessionmaker

    async def init_schema(self) -> None:
        """Create all workflow tables. Idempotent."""
        self._ensure_engine()
        assert self._engine is not None
        async with self._engine.begin() as conn:
            await conn.run_sync(_Base.metadata.create_all)

    async def close(self) -> None:
        """Dispose the engine and release pooled connections."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None

    # ------------------------------------------------------------------
    # Checkpoint persistence
    # ------------------------------------------------------------------

    async def save_checkpoint(
        self,
        workflow_id: str,
        current_stage_index: int,
        stage_statuses: dict[str, str],
        intermediate_results: dict[str, object],
        is_complete: bool = False,
        failure_reason: str | None = None,
        definition_name: str | None = None,
        definition_version: str | None = None,
        expected_version: int | None = None,
    ) -> None:
        """Insert or update the checkpoint row for ``workflow_id``.

        ``definition_name`` and ``definition_version`` are required on the
        very first write (when the row does not yet exist) and ignored on
        subsequent updates.

        ``expected_version`` enables optimistic concurrency control
        (P0-1). When provided, the update only succeeds if the persisted
        ``version`` column matches ``expected_version``; otherwise
        :class:`ConcurrentCheckpointError` is raised. ``None`` (the
        default) skips the check for backward-compatibility with callers
        that have not been retrofitted yet.

        Raises:
            CheckpointTooLargeError: The serialised intermediate_results
                exceeds :data:`MAX_INTERMEDIATE_RESULTS_BYTES`.
            ConcurrentCheckpointError: ``expected_version`` was supplied
                but did not match the persisted row's version.
            ValueError: The row does not yet exist and the caller did
                not provide ``definition_name``/``definition_version``.
        """
        sm = self._ensure_engine()
        now = time.time()
        stage_json = json.dumps(stage_statuses, sort_keys=True)
        results_json = json.dumps(intermediate_results, sort_keys=True, default=str)

        # P1-8: hard size cap. Reject before touching the database so a
        # runaway producer cannot blow up the row mid-write.
        results_size = len(results_json.encode("utf-8"))
        if results_size > MAX_INTERMEDIATE_RESULTS_BYTES:
            raise CheckpointTooLargeError(
                workflow_id, results_size, MAX_INTERMEDIATE_RESULTS_BYTES
            )

        # Requirement 7 of chaos-harness-hardening: translate any
        # underlying disk-full / ENOSPC condition observed during the
        # commit into ``CheckpointDiskFullError`` (a ``ForgeError``
        # subclass) so callers — production and the chaos harness —
        # can catch a typed exception rather than raw
        # ``OSError`` / ``sqlite3.OperationalError`` / SQLAlchemy
        # ``DBAPIError`` variants. Every other exception class is
        # re-raised unchanged so caller-visible semantics (e.g.
        # ``ConcurrentCheckpointError``) are preserved.
        try:
            async with sm() as session:
                async with session.begin():
                    row = await session.get(WorkflowStateRow, workflow_id)
                    # Capture pre-state for history row.
                    history_from_version: int | None = None
                    history_from_stage: int | None = None
                    if row is not None:
                        history_from_version = row.version
                        history_from_stage = row.current_stage_index
                    if row is None:
                        if definition_name is None or definition_version is None:
                            raise ValueError(
                                "definition_name and definition_version are required when "
                                "creating a new workflow checkpoint"
                            )
                        if expected_version is not None and expected_version != 0:
                            # The caller expected an existing row at a
                            # specific version; we have nothing to update.
                            raise ConcurrentCheckpointError(workflow_id, expected_version)
                        row = WorkflowStateRow(
                            id=workflow_id,
                            definition_name=definition_name,
                            definition_version=definition_version,
                            current_stage_index=current_stage_index,
                            stage_statuses=stage_json,
                            intermediate_results=results_json,
                            started_at=now,
                            updated_at=now,
                            is_complete=is_complete,
                            failure_reason=failure_reason,
                            checkpoint_valid=True,
                            version=1 if expected_version is None else expected_version + 1,
                            resumed_at=None,
                        )
                        session.add(row)
                        new_version = row.version
                        history_event = "created"
                    else:
                        if expected_version is not None:
                            # P0-1: optimistic concurrency. Conditional UPDATE
                            # so a concurrent writer cannot silently clobber
                            # us. Use a single statement with a WHERE clause
                            # on the version column.
                            stmt = (
                                update(WorkflowStateRow)
                                .where(
                                    WorkflowStateRow.id == workflow_id,
                                    WorkflowStateRow.version == expected_version,
                                )
                                .values(
                                    current_stage_index=current_stage_index,
                                    stage_statuses=stage_json,
                                    intermediate_results=results_json,
                                    updated_at=now,
                                    is_complete=is_complete,
                                    failure_reason=failure_reason,
                                    checkpoint_valid=True,
                                    version=expected_version + 1,
                                )
                            )
                            result = await session.execute(stmt)
                            if result.rowcount == 0:
                                raise ConcurrentCheckpointError(workflow_id, expected_version)
                            new_version = expected_version + 1
                        else:
                            row.current_stage_index = current_stage_index
                            row.stage_statuses = stage_json
                            row.intermediate_results = results_json
                            row.updated_at = now
                            row.is_complete = is_complete
                            row.failure_reason = failure_reason
                            row.checkpoint_valid = True
                            row.version = (row.version or 0) + 1
                            new_version = row.version
                        if is_complete:
                            history_event = "completed" if not failure_reason else "failed"
                        else:
                            history_event = "advanced"
                    # P3b: append immutable history row in the same txn.
                    session.add(
                        WorkflowHistoryRow(
                            workflow_id=workflow_id,
                            event_type=history_event,
                            from_stage_index=history_from_stage,
                            to_stage_index=current_stage_index,
                            from_version=history_from_version,
                            to_version=new_version,
                            actor=None,
                            detail=failure_reason,
                            recorded_at=now,
                        )
                    )
        except Exception as exc:
            # Requirement 7 of chaos-harness-hardening: any disk-full
            # variant becomes ``CheckpointDiskFullError`` with the
            # original exception attached via ``from exc``. Every
            # other exception class is re-raised unchanged.
            if _is_disk_full_exc(exc):
                raise CheckpointDiskFullError(
                    workflow_id=workflow_id,
                    path=self._db_url,
                    cause=exc,
                ) from exc
            raise
        _LOG.debug(
            "checkpoint saved id=%s stage=%d complete=%s",
            workflow_id,
            current_stage_index,
            is_complete,
        )

    async def load_workflow(self, workflow_id: str) -> WorkflowStateRow | None:
        """Return the checkpoint row for ``workflow_id`` or ``None``."""
        sm = self._ensure_engine()
        async with sm() as session:
            return await session.get(WorkflowStateRow, workflow_id)

    async def load_history(
        self,
        workflow_id: str,
        *,
        limit: int | None = None,
        since: float | None = None,
    ) -> list[WorkflowHistoryRow]:
        """Return immutable history rows for a workflow in chronological order.

        Args:
            workflow_id: ID of the workflow to query.
            limit: Optional cap on the number of rows returned.
                ``None`` returns all rows for that workflow.
            since: Optional epoch-second floor; rows recorded BEFORE this
                timestamp are excluded. Useful for tail-style queries.

        Returns:
            List of :class:`WorkflowHistoryRow`, ordered ascending by
            ``recorded_at``. Empty list when the workflow has no history.
        """
        sm = self._ensure_engine()
        async with sm() as session:
            stmt = select(WorkflowHistoryRow).where(
                WorkflowHistoryRow.workflow_id == workflow_id,
            )
            if since is not None:
                stmt = stmt.where(WorkflowHistoryRow.recorded_at >= float(since))
            stmt = stmt.order_by(
                WorkflowHistoryRow.recorded_at.asc(),
                WorkflowHistoryRow.id.asc(),
            )
            if limit is not None and limit > 0:
                stmt = stmt.limit(int(limit))
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def replay_workflow(self, workflow_id: str) -> list[dict[str, object]]:
        """Reconstruct chronological state snapshots for forensic replay.

        Returns a list of dicts, one per history row, each containing:

            * ``timestamp`` (float, epoch seconds, ISO-readable)
            * ``event_type`` (``created``, ``advanced``, ``completed``, ``failed``)
            * ``from_stage_index`` / ``to_stage_index``
            * ``from_version`` / ``to_version``
            * ``actor`` / ``detail`` (when populated)
            * ``elapsed_seconds_since_start`` for human-readable timeline

        The list is in chronological order. The first entry should be the
        ``created`` event when the workflow was started; subsequent entries
        describe each transition. Suitable for rendering a workflow
        timeline in incident reports / ops dashboards.
        """
        rows = await self.load_history(workflow_id)
        if not rows:
            return []
        start_ts = rows[0].recorded_at
        return [
            {
                "id": row.id,
                "timestamp": row.recorded_at,
                "elapsed_seconds_since_start": round(row.recorded_at - start_ts, 3),
                "event_type": row.event_type,
                "from_stage_index": row.from_stage_index,
                "to_stage_index": row.to_stage_index,
                "from_version": row.from_version,
                "to_version": row.to_version,
                "actor": row.actor,
                "detail": row.detail,
            }
            for row in rows
        ]

    async def purge_history(
        self,
        *,
        workflow_id: str | None = None,
        older_than_seconds: float | None = None,
        keep_last_n: int | None = None,
    ) -> int:
        """B2: bounded retention - delete old workflow_history rows.

        At least one of ``workflow_id``, ``older_than_seconds``, or
        ``keep_last_n`` must be supplied. They combine as filters; the
        union of matching rows is deleted.

        Args:
            workflow_id: When set, restricts deletion to this workflow.
            older_than_seconds: When set, deletes rows older than
                ``time.time() - older_than_seconds``.
            keep_last_n: When set together with ``workflow_id``, keeps the
                most recent N rows for that workflow and deletes the rest.
                Ignored when ``workflow_id`` is None (would be ambiguous
                across the whole table).

        Returns:
            Number of rows deleted.
        """
        if workflow_id is None and older_than_seconds is None:
            raise ValueError(
                "purge_history requires workflow_id and/or older_than_seconds"
            )
        sm = self._ensure_engine()
        async with sm() as session:
            async with session.begin():
                # Build the WHERE clause incrementally.
                stmt = delete(WorkflowHistoryRow)
                if workflow_id is not None:
                    stmt = stmt.where(WorkflowHistoryRow.workflow_id == workflow_id)
                if older_than_seconds is not None:
                    cutoff = time.time() - float(older_than_seconds)
                    stmt = stmt.where(WorkflowHistoryRow.recorded_at < cutoff)
                # If keep_last_n is set, build a sub-query of the IDs to KEEP
                # and exclude them.
                if keep_last_n is not None and workflow_id is not None and keep_last_n > 0:
                    # ORDER BY: primary is recorded_at DESC, secondary is
                    # id DESC. Without the id tiebreaker, events recorded
                    # within the same second (fast test loops or bulk
                    # writes) return in DB-implementation-defined order,
                    # which caused the "advanced != completed" flake on
                    # postgres. AUTOINCREMENT id is monotonic and stable.
                    keep_subq = (
                        select(WorkflowHistoryRow.id)
                        .where(WorkflowHistoryRow.workflow_id == workflow_id)
                        .order_by(
                            WorkflowHistoryRow.recorded_at.desc(),
                            WorkflowHistoryRow.id.desc(),
                        )
                        .limit(int(keep_last_n))
                        .scalar_subquery()
                    )
                    stmt = stmt.where(WorkflowHistoryRow.id.notin_(keep_subq))
                result = await session.execute(stmt)
                return int(result.rowcount or 0)

    async def load_incomplete_workflows(self) -> list[WorkflowStateRow]:
        """Return all rows where ``is_complete`` is ``False``.

        Used at startup to discover workflows that need to be resumed
        (Requirement 6.1).
        """
        sm = self._ensure_engine()
        async with sm() as session:
            stmt = select(WorkflowStateRow).where(
                WorkflowStateRow.is_complete.is_(False)
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_last_valid_checkpoint(
        self, workflow_id: str
    ) -> WorkflowStateRow | None:
        """Return the most recent valid checkpoint for ``workflow_id``.

        The current schema stores a single mutable row per workflow, so a
        valid checkpoint is simply the row when ``checkpoint_valid`` is
        ``True``. Returns ``None`` when the row is missing or marked
        corrupted (Requirement 6.4).
        """
        row = await self.load_workflow(workflow_id)
        if row is None or not row.checkpoint_valid:
            return None
        return row

    async def mark_corrupted(self, workflow_id: str) -> None:
        """Flag the checkpoint as corrupted without deleting its data.

        Subsequent calls to :meth:`get_last_valid_checkpoint` will return
        ``None`` until the row is rewritten by a fresh ``save_checkpoint``.
        """
        sm = self._ensure_engine()
        async with sm() as session:
            async with session.begin():
                row = await session.get(WorkflowStateRow, workflow_id)
                if row is not None:
                    row.checkpoint_valid = False
                    row.updated_at = time.time()

    async def try_claim_for_resume(
        self, workflow_id: str, claim_window_seconds: float = 60.0
    ) -> bool:
        """Atomically claim a workflow for resumption (P0-5).

        Performs a single conditional UPDATE that only succeeds when the
        row is incomplete AND either has never been claimed OR was last
        claimed more than ``claim_window_seconds`` ago. Returns ``True``
        when this caller wins the race (rows affected == 1) and ``False``
        otherwise — meaning another worker is already resuming, or the
        workflow is already complete, or the workflow does not exist.

        The claim window provides a stale-claim recovery mechanism: if a
        process crashes after claiming but before re-publishing, the next
        resumer can pick the workflow up after the window elapses.
        """
        sm = self._ensure_engine()
        now = time.time()
        cutoff = now - claim_window_seconds
        async with sm() as session:
            async with session.begin():
                stmt = (
                    update(WorkflowStateRow)
                    .where(
                        WorkflowStateRow.id == workflow_id,
                        WorkflowStateRow.is_complete.is_(False),
                        (
                            (WorkflowStateRow.resumed_at.is_(None))
                            | (WorkflowStateRow.resumed_at < cutoff)
                        ),
                    )
                    .values(resumed_at=now)
                )
                result = await session.execute(stmt)
                return bool(result.rowcount == 1)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def save_heartbeat(self, timestamp: float) -> None:
        """Upsert the agent loop heartbeat marker."""
        sm = self._ensure_engine()
        async with sm() as session:
            async with session.begin():
                row = await session.get(HeartbeatRow, "agent_loop")
                if row is None:
                    session.add(HeartbeatRow(id="agent_loop", timestamp=timestamp))
                else:
                    row.timestamp = timestamp
