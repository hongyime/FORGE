"""Integration tests for session -> asset-graph mapping (U6.3).

Contract exercised:

* Sessions create Computer (host) and User (identity) nodes on first sight.
* Sessions create one ``active_session`` edge per (computer, user) pair.
* Duplicate sessions update the same edge, never create a second row.
* Closed sessions remove the live edge but preserve endpoint nodes.
* All session metadata is preserved in the edge's evidence JSON.
* Graph export (``list_asset_graph``) surfaces the new edges.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.graph.assets import list_asset_graph
from forge.graph.sessions import (
    ACTIVE_SESSION_STATES,
    CLOSED_SESSION_STATES,
    SESSION_SOURCE_TABLE,
    SessionRecord,
    sync_session_to_graph,
    sync_sessions_to_graph,
)


ENGAGEMENT_ID = 6301


def _build_db(path: Path) -> sqlite3.Connection:
    con = direct_connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (?, 'U6.3 Session Graph', '["session.example"]', 'ACTIVE', 'test-op')
        """,
        (ENGAGEMENT_ID,),
    )
    return con


@pytest.fixture()
def con(tmp_path: Path) -> sqlite3.Connection:
    connection = _build_db(tmp_path / "session_graph.db")
    try:
        yield connection
    finally:
        connection.close()


def _fetch_entity(con: sqlite3.Connection, entity_key: str) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, entity_type, label, metadata_json
        FROM asset_entities
        WHERE engagement_id=? AND entity_key=?
        """,
        (ENGAGEMENT_ID, entity_key),
    ).fetchone()


def _fetch_edges(
    con: sqlite3.Connection,
    *,
    source_entity_id: int | None = None,
    target_entity_id: int | None = None,
    relationship_type: str = "active_session",
) -> list[sqlite3.Row]:
    clauses = ["engagement_id=?", "relationship_type=?", "source_table=?"]
    params: list[object] = [ENGAGEMENT_ID, relationship_type, SESSION_SOURCE_TABLE]
    if source_entity_id is not None:
        clauses.append("source_entity_id=?")
        params.append(source_entity_id)
    if target_entity_id is not None:
        clauses.append("target_entity_id=?")
        params.append(target_entity_id)
    query = (
        "SELECT id, source_entity_id, target_entity_id, relationship_type, "
        "evidence_json, source_table FROM asset_relationships WHERE "
        + " AND ".join(clauses)
    )
    return list(con.execute(query, params).fetchall())


# ---------------------------------------------------------------------------
# Node creation
# ---------------------------------------------------------------------------


def test_session_creates_computer_and_user_nodes(con: sqlite3.Connection) -> None:
    """Given: engagement DB with no host / identity rows.
    When: sync an active session for (WORKSTATION-01, alice).
    Then: a host node and an identity node exist for that pair."""
    assert _fetch_entity(con, "host:workstation-01") is None
    assert _fetch_entity(con, "identity:user:alice") is None

    result = sync_session_to_graph(
        con,
        engagement_id=ENGAGEMENT_ID,
        session=SessionRecord(
            computer="WORKSTATION-01",
            user="alice",
            session_type="rdp",
            terminal="RDP-Tcp#1",
            session_start_time="2026-09-01T10:00:00Z",
            state="active",
            session_id="LogonId-42",
        ),
    )

    assert result.edges_upserted == 1
    computer = _fetch_entity(con, "host:workstation-01")
    user = _fetch_entity(con, "identity:user:alice")
    assert computer is not None
    assert computer["entity_type"] == "host"
    assert computer["label"] == "WORKSTATION-01"
    assert user is not None
    assert user["entity_type"] == "identity"
    assert user["label"] == "alice"


def test_existing_nodes_are_not_duplicated(con: sqlite3.Connection) -> None:
    """Given: a session already created the endpoint nodes.
    When: a second session for the same (computer, user) arrives.
    Then: exactly one row per entity_key remains."""
    session = SessionRecord(
        computer="host.example",
        user="bob",
        session_type="ssh",
        terminal="pts/0",
        session_start_time="2026-09-01T09:00:00Z",
        state="active",
    )
    sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=session)
    sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=session)

    computers = con.execute(
        "SELECT COUNT(*) FROM asset_entities WHERE engagement_id=? AND entity_key=?",
        (ENGAGEMENT_ID, "host:host.example"),
    ).fetchone()[0]
    users = con.execute(
        "SELECT COUNT(*) FROM asset_entities WHERE engagement_id=? AND entity_key=?",
        (ENGAGEMENT_ID, "identity:user:bob"),
    ).fetchone()[0]
    assert computers == 1
    assert users == 1


# ---------------------------------------------------------------------------
# Edge creation and dedup
# ---------------------------------------------------------------------------


def test_session_creates_active_session_edge(con: sqlite3.Connection) -> None:
    """Given: empty graph. When: active session arrives. Then: exactly one
    ``active_session`` edge exists from computer -> user."""
    sync_session_to_graph(
        con,
        engagement_id=ENGAGEMENT_ID,
        session=SessionRecord(
            computer="srv1", user="carol", session_type="winrm", state="active"
        ),
    )
    computer = _fetch_entity(con, "host:srv1")
    user = _fetch_entity(con, "identity:user:carol")
    assert computer is not None and user is not None

    edges = _fetch_edges(
        con, source_entity_id=int(computer["id"]), target_entity_id=int(user["id"])
    )
    assert len(edges) == 1
    assert edges[0]["relationship_type"] == "active_session"


def test_duplicate_session_updates_existing_edge(con: sqlite3.Connection) -> None:
    """Given: an active session already produced an edge.
    When: the same (computer, user) is observed again with newer metadata.
    Then: still exactly one edge, and its evidence reflects the newer data."""
    first = SessionRecord(
        computer="srv2",
        user="dave",
        session_type="ssh",
        terminal="pts/1",
        session_start_time="2026-09-01T08:00:00Z",
        state="active",
        session_id="pid-100",
    )
    second = SessionRecord(
        computer="srv2",
        user="dave",
        session_type="ssh",
        terminal="pts/1",
        session_start_time="2026-09-01T08:00:00Z",
        state="disconnected",
        session_id="pid-100",
        extra={"idle_seconds": 900},
    )
    sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=first)
    sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=second)

    computer = _fetch_entity(con, "host:srv2")
    user = _fetch_entity(con, "identity:user:dave")
    edges = _fetch_edges(
        con, source_entity_id=int(computer["id"]), target_entity_id=int(user["id"])
    )
    assert len(edges) == 1
    evidence = json.loads(edges[0]["evidence_json"])
    assert evidence["state"] == "disconnected"
    assert evidence["session_type"] == "ssh"
    assert evidence["terminal"] == "pts/1"
    assert evidence["idle_seconds"] == 900


def test_closed_session_removes_edge(con: sqlite3.Connection) -> None:
    """Given: an active-session edge exists.
    When: the same session is observed as ``closed``.
    Then: the edge is removed but both endpoint nodes remain."""
    active = SessionRecord(
        computer="srv3",
        user="erin",
        session_type="rdp",
        state="active",
        session_start_time="2026-09-01T07:00:00Z",
    )
    closed = SessionRecord(
        computer="srv3",
        user="erin",
        session_type="rdp",
        state="closed",
        session_start_time="2026-09-01T07:00:00Z",
        session_end_time="2026-09-01T07:45:00Z",
    )
    sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=active)
    computer = _fetch_entity(con, "host:srv3")
    user = _fetch_entity(con, "identity:user:erin")
    assert (
        len(
            _fetch_edges(
                con,
                source_entity_id=int(computer["id"]),
                target_entity_id=int(user["id"]),
            )
        )
        == 1
    )

    result = sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=closed)
    assert result.edges_removed == 1

    assert (
        _fetch_edges(
            con,
            source_entity_id=int(computer["id"]),
            target_entity_id=int(user["id"]),
        )
        == []
    )
    # Endpoints preserved for history.
    assert _fetch_entity(con, "host:srv3") is not None
    assert _fetch_entity(con, "identity:user:erin") is not None


def test_closed_session_without_prior_edge_is_noop(con: sqlite3.Connection) -> None:
    """Given: no prior edge. When: a closed session arrives.
    Then: nothing is removed, endpoints are still created for historical context."""
    result = sync_session_to_graph(
        con,
        engagement_id=ENGAGEMENT_ID,
        session=SessionRecord(
            computer="srv4",
            user="frank",
            session_type="ssh",
            state="closed",
            session_end_time="2026-09-01T06:00:00Z",
        ),
    )
    assert result.edges_removed == 0
    assert result.skipped == 1
    assert _fetch_entity(con, "host:srv4") is not None
    assert _fetch_entity(con, "identity:user:frank") is not None


# ---------------------------------------------------------------------------
# Metadata preservation
# ---------------------------------------------------------------------------


def test_all_session_metadata_preserved_in_edge_evidence(
    con: sqlite3.Connection,
) -> None:
    """Given: a session with every metadata field populated.
    When: it is synced.
    Then: every non-sensitive field lands in the edge evidence JSON."""
    session = SessionRecord(
        computer="host7.example",
        user="grace",
        session_type="rdp",
        terminal="RDP-Tcp#2",
        session_start_time="2026-09-01T05:00:00Z",
        state="active",
        session_id="LogonId-77",
        source_host="collector.example",
        extra={
            "logon_type": 10,
            "client_address": "10.0.0.5",
            "auth_package": "Kerberos",
        },
    )
    sync_session_to_graph(con, engagement_id=ENGAGEMENT_ID, session=session)
    computer = _fetch_entity(con, "host:host7.example")
    user = _fetch_entity(con, "identity:user:grace")
    edges = _fetch_edges(
        con, source_entity_id=int(computer["id"]), target_entity_id=int(user["id"])
    )
    evidence = json.loads(edges[0]["evidence_json"])
    assert evidence["session_type"] == "rdp"
    assert evidence["state"] == "active"
    assert evidence["terminal"] == "RDP-Tcp#2"
    assert evidence["session_start_time"] == "2026-09-01T05:00:00Z"
    assert evidence["session_id"] == "LogonId-77"
    assert evidence["source_host"] == "collector.example"
    assert evidence["logon_type"] == 10
    assert evidence["client_address"] == "10.0.0.5"
    assert evidence["auth_package"] == "Kerberos"


def test_sensitive_metadata_is_scrubbed(con: sqlite3.Connection) -> None:
    """Given: a session record with forbidden keys in extra.
    When: it is synced.
    Then: password/token/secret keys are dropped by the shared sanitizer."""
    sync_session_to_graph(
        con,
        engagement_id=ENGAGEMENT_ID,
        session=SessionRecord(
            computer="host8",
            user="heidi",
            session_type="ssh",
            state="active",
            extra={"password": "hunter2", "token": "abc", "note": "keep-me"},
        ),
    )
    computer = _fetch_entity(con, "host:host8")
    user = _fetch_entity(con, "identity:user:heidi")
    edges = _fetch_edges(
        con, source_entity_id=int(computer["id"]), target_entity_id=int(user["id"])
    )
    evidence_text = edges[0]["evidence_json"]
    assert "hunter2" not in evidence_text
    assert "abc" not in evidence_text or '"token"' not in evidence_text
    evidence = json.loads(evidence_text)
    assert "password" not in evidence
    assert "token" not in evidence
    assert evidence.get("note") == "keep-me"


# ---------------------------------------------------------------------------
# Batch + export
# ---------------------------------------------------------------------------


def test_batch_sync_reports_counts_and_skips_invalid(con: sqlite3.Connection) -> None:
    result = sync_sessions_to_graph(
        con,
        engagement_id=ENGAGEMENT_ID,
        sessions=[
            SessionRecord(computer="h1", user="u1", state="active"),
            SessionRecord(computer="h2", user="u2", state="active"),
            SessionRecord(computer="", user="u3", state="active"),  # invalid
            SessionRecord(computer="h4", user="", state="active"),  # invalid
        ],
    )
    assert result.edges_upserted == 2
    assert result.skipped == 2


def test_graph_export_surfaces_session_edges(con: sqlite3.Connection) -> None:
    """Given: an active session was synced.
    When: the canonical graph is listed via list_asset_graph.
    Then: the active_session edge is visible on the exported graph."""
    sync_session_to_graph(
        con,
        engagement_id=ENGAGEMENT_ID,
        session=SessionRecord(
            computer="exporthost",
            user="ivan",
            session_type="rdp",
            terminal="console",
            session_start_time="2026-09-01T04:00:00Z",
            state="active",
        ),
    )
    graph = list_asset_graph(con, engagement_id=ENGAGEMENT_ID)
    relationships = graph.get("relationships") or graph.get("edges") or []
    active = [
        rel
        for rel in relationships
        if str(rel.get("relationship_type") or rel.get("type") or "") == "active_session"
    ]
    assert active, f"active_session edge missing from exported graph: {graph!r}"


# ---------------------------------------------------------------------------
# Sanity: state constants stay in the documented set
# ---------------------------------------------------------------------------


def test_state_constants_are_disjoint() -> None:
    assert ACTIVE_SESSION_STATES.isdisjoint(CLOSED_SESSION_STATES)
    assert "active" in ACTIVE_SESSION_STATES
    assert "closed" in CLOSED_SESSION_STATES
