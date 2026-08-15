import json
import sqlite3
from typing import Any

from forge.reporting.seed_graph_payloads import seed_graph_payload_for_engagement


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _create_engagement(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY,
            name TEXT
        )
        """
    )
    con.execute("INSERT INTO engagements VALUES (1001, 'Acme Example')")


def test_seed_graph_payload_returns_empty_without_seed_or_cloud_tables() -> None:
    con = _connect()

    assert seed_graph_payload_for_engagement(con, 1001) == (None, "")


def test_seed_graph_payload_synthesizes_seed_nodes_edges_and_safe_metadata() -> None:
    con = _connect()
    _create_engagement(con)
    con.executescript(
        """
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            seed_value TEXT,
            seed_type TEXT,
            source TEXT,
            status TEXT,
            depth INTEGER,
            confidence REAL,
            parent_seed_id INTEGER,
            metadata_json TEXT,
            discovered_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE seed_relations (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            source_seed_id INTEGER,
            target_seed_id INTEGER,
            relation_type TEXT,
            confidence REAL,
            evidence_json TEXT,
            discovered_at TEXT
        );
        """
    )
    con.execute(
        """
        INSERT INTO engagement_seeds VALUES
            (1, 1001, 'acme.example', 'domain', 'operator', 'active',
             0, 0.95, NULL, ?, '2026-08-12T01:00:00', '2026-08-12T01:10:00'),
            (2, 1001, 'owner@acme.example', 'email', 'crawl', 'active',
             1, 0.72, 1, ?, '2026-08-12T01:20:00', '2026-08-12T01:30:00'),
            (3, 1001, 'failed.example', 'domain', 'crawl', 'failed',
             1, 0.99, 1, '{}', '2026-08-12T01:40:00', '2026-08-12T01:50:00')
        """,
        (
            json.dumps(
                {
                    "source": "artifact-parser",
                    "custom": "kept",
                    "token": "hidden",
                    "synthesis": {
                        "confidence_band": "confirmed",
                        "corroborated": True,
                        "supporting_relations": 2,
                        "corroborating_seed_count": 1,
                    },
                },
                sort_keys=True,
            ),
            json.dumps(
                {
                    "depth": 99,
                    "owner": "alice",
                    "synthesis": {"confidence_band": "medium"},
                },
                sort_keys=True,
            ),
        ),
    )
    con.execute(
        """
        INSERT INTO seed_relations VALUES
            (1, 1001, 1, 2, 'email_at_domain', 0.8, ?, '2026-08-12T02:00:00')
        """,
        (
            json.dumps(
                {
                    "rule": "mx_contact",
                    "source_url": "https://acme.example/?token=hidden",
                    "secret": "hidden",
                },
                sort_keys=True,
            ),
        ),
    )

    payload, snapshot_at = seed_graph_payload_for_engagement(con, 1001)

    assert payload is not None
    assert payload["source"] == "engagement_seed_graph"
    assert payload["generated_at"] == "2026-08-12 02:00:00"
    assert snapshot_at == "2026-08-12T02:00:00"
    nodes = {node["node_id"]: node for node in payload["nodes"]}
    assert set(nodes) == {"ENGAGEMENT::1001", "SEED::1", "SEED::2"}
    assert nodes["SEED::1"]["node_type"] == "HOST"
    assert nodes["SEED::1"]["severity"] == "HIGH"
    assert nodes["SEED::1"]["metadata"]["source"] == "operator"
    assert nodes["SEED::1"]["metadata"]["discovery_source"] == "artifact-parser"
    assert nodes["SEED::1"]["metadata"]["custom"] == "kept"
    assert "token" not in nodes["SEED::1"]["metadata"]
    assert nodes["SEED::2"]["node_type"] == "CREDENTIAL"
    assert nodes["SEED::2"]["severity"] == "LOW"
    assert nodes["SEED::2"]["metadata"]["metadata_depth"] == 99
    assert nodes["SEED::2"]["metadata"]["owner"] == "alice"
    assert {
        (edge["source_node_id"], edge["target_node_id"], edge["edge_type"])
        for edge in payload["edges"]
    } == {
        ("ENGAGEMENT::1001", "SEED::1", "seed_root"),
        ("SEED::1", "SEED::2", "parent_seed"),
        ("SEED::1", "SEED::2", "email_at_domain"),
    }
    relation_edge = next(
        edge for edge in payload["edges"] if edge["edge_type"] == "email_at_domain"
    )
    assert relation_edge["metadata"]["rule"] == "mx_contact"
    assert "secret" not in relation_edge["metadata"]


def test_seed_graph_payload_synthesizes_cloud_asset_nodes_with_legacy_columns() -> None:
    con = _connect()
    _create_engagement(con)
    con.executescript(
        """
        CREATE TABLE cloud_assets (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            asset_type TEXT,
            identifier TEXT,
            provider_identifier TEXT,
            source TEXT,
            metadata_json TEXT,
            discovered_at TEXT
        );
        INSERT INTO cloud_assets VALUES (
            7,
            1001,
            's3',
            'legacy-assets',
            'LegacyAssetsExact',
            'crawler',
            '{"source":"artifact","format":"json","token":"hidden"}',
            '2026-08-12T03:00:00'
        );
        """
    )

    payload, snapshot_at = seed_graph_payload_for_engagement(con, 1001)

    assert payload is not None
    assert payload["generated_at"] == "2026-08-12 03:00:00"
    assert snapshot_at == "2026-08-12T03:00:00"
    nodes = {node["node_id"]: node for node in payload["nodes"]}
    assert set(nodes) == {"ENGAGEMENT::1001", "CLOUD::aws_s3::legacy-assets"}
    cloud = nodes["CLOUD::aws_s3::legacy-assets"]
    assert cloud["label"] == "aws_s3:LegacyAssetsExact"
    assert cloud["source_table"] == "cloud_assets"
    assert cloud["source_id"] == 7
    assert cloud["metadata"] == {
        "service": "aws_s3",
        "identifier": "legacy-assets",
        "provider_identifier": "LegacyAssetsExact",
        "source": "crawler",
        "asset_type_original": "s3",
        "format": "json",
        "metadata_source": "artifact",
    }
    assert payload["edges"] == [
        {
            "source_node_id": "ENGAGEMENT::1001",
            "target_node_id": "CLOUD::aws_s3::legacy-assets",
            "edge_type": "cloud_reference",
            "label": "cloud_reference",
            "weight": 15.0,
        }
    ]
