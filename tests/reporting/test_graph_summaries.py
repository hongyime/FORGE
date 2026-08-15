import json
import sqlite3
from typing import Any

from forge.reporting.graph_summaries import (
    GraphSummaryCallbacks,
    asset_graph_summary,
    empty_asset_graph_summary,
    empty_seed_graph_summary,
    seed_graph_summary,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


def _fetch_count(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> int:
    row = con.execute(sql, params).fetchone()
    return int(row[0] or 0) if row else 0


def _callbacks(
    *,
    ownership_conflicts: list[dict[str, Any]] | None = None,
    asset_graph: dict[str, Any] | None = None,
) -> GraphSummaryCallbacks:
    return GraphSummaryCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        fetch_count=_fetch_count,
        safe_json_loads=json.loads,
        ownership_conflicts_for_engagement=lambda _con, _engagement_id, *, limit: (
            ownership_conflicts or []
        )[:limit],
        list_asset_graph=lambda _con, _engagement_id, *, limit: asset_graph or {},
    )


def test_graph_summaries_return_empty_defaults_without_tables() -> None:
    con = _connect()

    assert seed_graph_summary(con, 1001, callbacks=_callbacks()) == (
        empty_seed_graph_summary()
    )
    assert asset_graph_summary(con, 1001, callbacks=_callbacks()) == (
        empty_asset_graph_summary()
    )


def test_seed_graph_summary_counts_seed_types_and_synthesis_bands() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            seed_type TEXT,
            depth INTEGER,
            metadata_json TEXT
        );
        CREATE TABLE seed_relations (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER
        );
        INSERT INTO engagement_seeds VALUES
            (1, 1001, 'domain', 0,
             '{"synthesis":{"confidence_band":"confirmed","corroborated":true}}'),
            (2, 1001, 'email', 2,
             '{"synthesis":{"confidence_band":"high","corroborated":false}}'),
            (3, 1001, 'email', 1,
             '{"synthesis":{"confidence_band":"medium","corroborated":true}}'),
            (4, 1002, 'domain', 9,
             '{"synthesis":{"confidence_band":"confirmed","corroborated":true}}');
        INSERT INTO seed_relations VALUES
            (1, 1001),
            (2, 1001),
            (3, 1002);
        """
    )

    summary = seed_graph_summary(con, 1001, callbacks=_callbacks())

    assert summary == {
        "total_seeds": 3,
        "corroborated_seeds": 2,
        "confirmed_seeds": 1,
        "high_confidence_seeds": 2,
        "max_depth": 2,
        "relations": 2,
        "seed_types": [("domain", 1), ("email", 2)],
    }


def test_asset_graph_summary_counts_types_ownership_and_attack_paths() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE asset_entities (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            entity_type TEXT
        );
        CREATE TABLE asset_relationships (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            relationship_type TEXT
        );
        CREATE TABLE asset_ownership_claims (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            owner_kind TEXT,
            owner_ref TEXT,
            status TEXT
        );
        INSERT INTO asset_entities VALUES
            (1, 1001, 'host'),
            (2, 1001, 'cloud'),
            (3, 1001, 'host'),
            (4, 1002, 'host');
        INSERT INTO asset_relationships VALUES
            (1, 1001, 'resolves_to'),
            (2, 1001, 'owns'),
            (3, 1001, 'owns'),
            (4, 1002, 'owns');
        INSERT INTO asset_ownership_claims VALUES
            (1, 1001, 'team', 'appsec', 'active'),
            (2, 1001, 'team', 'appsec', 'active'),
            (3, 1001, 'person', 'alice', 'retired'),
            (4, 1002, 'team', 'other', 'active');
        """
    )

    summary = asset_graph_summary(
        con,
        1001,
        callbacks=_callbacks(
            ownership_conflicts=[{"entity_key": "host:app.example"}],
            asset_graph={
                "attack_path_summary": {
                    "critical_asset_count": 2,
                    "path_count": 3,
                    "choke_point_count": 1,
                    "top_path_score": 9.7,
                    "top_path_tier": "critical",
                }
            },
        ),
    )

    assert summary == {
        "node_count": 3,
        "edge_count": 3,
        "ownership_claim_count": 3,
        "ownership_conflict_count": 1,
        "entity_types": {"host": 2, "cloud": 1},
        "relationship_types": {"owns": 2, "resolves_to": 1},
        "active_owner_count": 1,
        "critical_asset_count": 2,
        "attack_path_count": 3,
        "choke_point_count": 1,
        "top_path_score": 9.7,
        "top_path_tier": "critical",
    }
