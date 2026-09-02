"""Map collected access sessions (U6.1 Windows / U6.2 Linux) into the FORGE asset graph.

Sessions represent active access paths (RDP, SSH, console, WinRM). Each observed
session becomes an ``active_session`` relationship edge from a Computer node
(entity type ``host``) to a User node (entity type ``identity``).

Contract:

* Active / disconnected sessions -> upsert one ``active_session`` edge per
  (computer, user) pair, idempotent under repeated observation.
* Closed sessions -> remove any prior ``active_session`` edge for that pair.
* Missing Computer / User nodes are created on first observation via the shared
  ``upsert_asset_entity`` helper; existing nodes are updated in place, never
  duplicated.
* All session metadata (start/end time, session type, terminal, state, session
  id, extras) is preserved in the edge's ``evidence_json`` payload. Secret-
  bearing keys are dropped by the shared metadata sanitizer in ``assets``.

This module is intentionally passive: it does not collect sessions itself and
does not perform network I/O. It consumes ``SessionRecord`` instances produced
by the Windows and Linux session collectors and writes rows through the same
audited upsert path the rest of the graph uses.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from forge.graph.assets import upsert_asset_entity, upsert_asset_relationship

# Stable source_table for every session-derived row so ON CONFLICT dedup keys
# collapse repeated observations of the same (computer, user) pair.
SESSION_SOURCE_TABLE = "session_collector"

# States that keep the access edge live.
ACTIVE_SESSION_STATES: frozenset[str] = frozenset({"active", "disconnected"})
# States that terminate the access edge.
CLOSED_SESSION_STATES: frozenset[str] = frozenset({"closed", "logoff", "logout", "ended"})
# Recognized session types across Windows / Linux collectors.
_KNOWN_SESSION_TYPES: frozenset[str] = frozenset(
    {
        "console",
        "rdp",
        "ssh",
        "winrm",
        "network",
        "interactive",
        "remoteinteractive",
        "service",
        "batch",
        "cachedinteractive",
        "unknown",
    }
)


def _normalize_state(state: str) -> str:
    value = (state or "").strip().lower()
    if value in ACTIVE_SESSION_STATES or value in CLOSED_SESSION_STATES:
        return value
    return "active"


def _normalize_session_type(value: str) -> str:
    normalized = (value or "").strip().lower()
    if not normalized:
        return "unknown"
    return normalized if normalized in _KNOWN_SESSION_TYPES else "unknown"


def _normalize_ident(value: str) -> str:
    return (value or "").strip().lower()


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """One session observation from U6.1 (Windows) or U6.2 (Linux).

    ``computer`` and ``user`` are required. ``state`` is one of ``active``,
    ``disconnected``, or ``closed`` (aliases ``logoff``/``logout``/``ended``
    are treated as closed). Time fields are ISO 8601 strings owned by the
    collector; this module does not reformat them.
    """

    computer: str
    user: str
    session_type: str = "unknown"
    terminal: str | None = None
    session_start_time: str | None = None
    session_end_time: str | None = None
    state: str = "active"
    session_id: str | None = None
    source_host: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def normalized_computer(self) -> str:
        return _normalize_ident(self.computer)

    def normalized_user(self) -> str:
        return _normalize_ident(self.user)

    def normalized_state(self) -> str:
        return _normalize_state(self.state)

    def is_active(self) -> bool:
        return self.normalized_state() in ACTIVE_SESSION_STATES

    def is_closed(self) -> bool:
        return self.normalized_state() in CLOSED_SESSION_STATES

    def computer_entity_key(self) -> str:
        return f"host:{self.normalized_computer()}"

    def user_entity_key(self) -> str:
        return f"identity:user:{self.normalized_user()}"

    def edge_evidence(self) -> dict[str, Any]:
        """Metadata preserved on the graph edge.

        Sensitive keys (password/token/secret/authorization) are stripped by
        the shared metadata sanitizer inside ``upsert_asset_relationship``.
        """
        payload: dict[str, Any] = {
            "session_type": _normalize_session_type(self.session_type),
            "state": self.normalized_state(),
        }
        if self.terminal:
            payload["terminal"] = str(self.terminal)
        if self.session_start_time:
            payload["session_start_time"] = str(self.session_start_time)
        if self.session_end_time:
            payload["session_end_time"] = str(self.session_end_time)
        if self.session_id:
            payload["session_id"] = str(self.session_id)
        if self.source_host:
            payload["source_host"] = _normalize_ident(self.source_host)
        for key, value in (self.extra or {}).items():
            if key in payload:
                continue
            payload[str(key)] = value
        return payload


@dataclass(frozen=True, slots=True)
class SessionSyncResult:
    """Summary of a session -> graph sync operation."""

    edges_upserted: int = 0
    edges_removed: int = 0
    entities_touched: int = 0
    skipped: int = 0

    def merged(self, other: "SessionSyncResult") -> "SessionSyncResult":
        return SessionSyncResult(
            edges_upserted=self.edges_upserted + other.edges_upserted,
            edges_removed=self.edges_removed + other.edges_removed,
            entities_touched=self.entities_touched + other.entities_touched,
            skipped=self.skipped + other.skipped,
        )


def _validate(session: SessionRecord) -> None:
    if not session.normalized_computer():
        raise ValueError("SessionRecord.computer is required")
    if not session.normalized_user():
        raise ValueError("SessionRecord.user is required")


def _upsert_endpoints(
    con: sqlite3.Connection, *, engagement_id: int, session: SessionRecord
) -> tuple[int, int]:
    computer_id = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=session.computer_entity_key(),
        entity_type="host",
        label=session.computer.strip() or session.normalized_computer(),
        source_table=SESSION_SOURCE_TABLE,
        source_id=0,
        confidence=0.7,
        metadata={"origin": SESSION_SOURCE_TABLE, "hostname": session.normalized_computer()},
    )
    user_id = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=session.user_entity_key(),
        entity_type="identity",
        label=session.user.strip() or session.normalized_user(),
        source_table=SESSION_SOURCE_TABLE,
        source_id=0,
        confidence=0.7,
        metadata={"origin": SESSION_SOURCE_TABLE, "username": session.normalized_user()},
    )
    return computer_id, user_id


def _remove_edge(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    source_entity_id: int,
    target_entity_id: int,
) -> int:
    cursor = con.execute(
        """
        DELETE FROM asset_relationships
        WHERE engagement_id=?
          AND source_entity_id=?
          AND target_entity_id=?
          AND relationship_type='active_session'
          AND source_table=?
        """,
        (int(engagement_id), int(source_entity_id), int(target_entity_id), SESSION_SOURCE_TABLE),
    )
    return int(cursor.rowcount or 0)


def sync_session_to_graph(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    session: SessionRecord,
) -> SessionSyncResult:
    """Upsert or remove the ``active_session`` edge for a single session.

    Active / disconnected sessions upsert the edge (and the endpoint nodes if
    absent). Closed sessions ensure no live edge remains for that (computer,
    user) pair while preserving the endpoint nodes for historical context.
    """
    _validate(session)
    computer_id, user_id = _upsert_endpoints(
        con, engagement_id=engagement_id, session=session
    )
    if session.is_closed():
        removed = _remove_edge(
            con,
            engagement_id=engagement_id,
            source_entity_id=computer_id,
            target_entity_id=user_id,
        )
        return SessionSyncResult(
            edges_removed=removed,
            entities_touched=2,
            skipped=0 if removed else 1,
        )
    upsert_asset_relationship(
        con,
        engagement_id=engagement_id,
        source_entity_id=computer_id,
        target_entity_id=user_id,
        relationship_type="active_session",
        confidence=0.7,
        source_table=SESSION_SOURCE_TABLE,
        source_id=0,
        evidence=session.edge_evidence(),
    )
    return SessionSyncResult(edges_upserted=1, entities_touched=2)


def sync_sessions_to_graph(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    sessions: Iterable[SessionRecord],
) -> SessionSyncResult:
    """Batch variant. Each session is processed independently; invalid records
    are counted in ``skipped`` rather than aborting the batch."""
    total = SessionSyncResult()
    for record in sessions:
        try:
            _validate(record)
        except ValueError:
            total = total.merged(SessionSyncResult(skipped=1))
            continue
        total = total.merged(
            sync_session_to_graph(con, engagement_id=engagement_id, session=record)
        )
    return total


__all__ = [
    "ACTIVE_SESSION_STATES",
    "CLOSED_SESSION_STATES",
    "SESSION_SOURCE_TABLE",
    "SessionRecord",
    "SessionSyncResult",
    "sync_session_to_graph",
    "sync_sessions_to_graph",
]
