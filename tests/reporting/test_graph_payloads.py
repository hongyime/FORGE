import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.reporting.graph_payloads import (
    GraphPayloadCallbacks,
    filter_graph_payload_for_validation,
    graph_payload_for_engagement,
    graph_state_for_engagement,
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


def _callbacks(
    *,
    reportable_index: dict[tuple[str, str], bool] | None = None,
    validation_metadata_index: dict[tuple[str, str], dict[str, Any]] | None = None,
    seed_payload: dict[str, Any] | None = None,
    seed_snapshot_at: str = "",
) -> GraphPayloadCallbacks:
    return GraphPayloadCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        format_dt=lambda value: f"fmt:{value}" if value else "",
        reportable_cloud_validation_index=lambda _con, _engagement_id: (
            reportable_index or {}
        ),
        latest_cloud_validation_metadata_index=lambda _con, _engagement_id: (
            validation_metadata_index or {}
        ),
        seed_graph_payload_for_engagement=lambda _con, _engagement_id: (
            seed_payload,
            seed_snapshot_at,
        ),
    )


def test_graph_payload_for_engagement_prefers_snapshot_over_artifacts(
    tmp_path: Path,
) -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE attack_graph_snapshots (
            engagement_id INTEGER,
            snapshot_at TEXT,
            graph_json TEXT
        );
        """
    )
    con.execute(
        """
        INSERT INTO attack_graph_snapshots VALUES (?, ?, ?)
        """,
        (
            1001,
            "2026-08-12T01:02:03",
            json.dumps(
                {
                    "nodes": [
                        {
                            "node_id": "snapshot-node",
                            "label": "snapshot host",
                            "node_type": "HOST",
                        }
                    ],
                    "edges": [],
                },
                sort_keys=True,
            ),
        ),
    )
    json_artifact = tmp_path / "1001_attack_graph.json"
    json_artifact.write_text(
        json.dumps({"nodes": [{"node_id": "artifact-node"}], "edges": []}),
        encoding="utf-8",
    )

    payload, snapshot_at = graph_payload_for_engagement(
        con,
        1001,
        [json_artifact],
        callbacks=_callbacks(),
    )

    assert payload is not None
    assert payload["source"] == "attack_graph_snapshot"
    assert payload["generated_at"] == "fmt:2026-08-12T01:02:03"
    assert payload["nodes"][0]["node_id"] == "snapshot-node"
    assert snapshot_at == "2026-08-12T01:02:03"


def test_graph_payload_for_engagement_prefers_json_artifact_before_graphml_and_seed(
    tmp_path: Path,
) -> None:
    con = _connect()
    json_artifact = tmp_path / "1001_attack_graph.json"
    graphml_artifact = tmp_path / "1001_attack_graph.graphml"
    json_artifact.write_text(
        json.dumps({"nodes": [{"node_id": "json-node", "node_type": "HOST"}], "edges": []}),
        encoding="utf-8",
    )
    graphml_artifact.write_text(
        """
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns">
          <graph id="G" edgedefault="directed">
            <node id="graphml-node"><data key="label">graphml only</data></node>
          </graph>
        </graphml>
        """.strip(),
        encoding="utf-8",
    )
    seed_payload = {
        "nodes": [{"node_id": "seed-node", "node_type": "HOST"}],
        "edges": [],
        "source": "engagement_seed_graph",
    }

    payload, snapshot_at = graph_payload_for_engagement(
        con,
        1001,
        [graphml_artifact, json_artifact],
        callbacks=_callbacks(seed_payload=seed_payload, seed_snapshot_at="seed-at"),
    )

    assert payload is not None
    assert payload["source"] == "1001_attack_graph.json"
    assert payload["generated_at"].startswith("fmt:")
    assert payload["nodes"][0]["node_id"] == "json-node"
    assert snapshot_at == payload["generated_at"]


def test_graph_state_for_engagement_uses_seed_fallback_summary() -> None:
    con = _connect()
    seed_payload = {
        "nodes": [
            {
                "node_id": "seed-node",
                "label": "seed.example",
                "node_type": "HOST",
                "on_critical_path": True,
            }
        ],
        "edges": [],
        "critical_path_nodes": ["seed-node"],
        "critical_path_weight": 7.0,
        "source": "engagement_seed_graph",
    }

    summary, payload, snapshot_at = graph_state_for_engagement(
        con,
        1001,
        [],
        callbacks=_callbacks(seed_payload=seed_payload, seed_snapshot_at="seed-at"),
    )

    assert payload == seed_payload
    assert snapshot_at == "seed-at"
    assert summary["source"] == "engagement_seed_graph"
    assert summary["nodes"] == 1
    assert summary["critical_nodes"] == 1
    assert summary["critical_weight"] == 7.0


def test_filter_graph_payload_merges_cloud_aliases_and_removes_unreportable_nodes() -> None:
    con = _connect()
    payload = {
        "nodes": [
            {"node_id": "HOST::app", "label": "app.example", "node_type": "HOST"},
            {
                "node_id": "CLOUD::s3::legacy-assets",
                "node_type": "CLOUD",
                "source_table": "cloud_assets",
                "metadata": {
                    "service": "s3",
                    "identifier": "legacy-assets",
                    "provider_identifier": "LegacyAssetsExact",
                },
            },
            {
                "node_id": "CLOUD::aws_s3::legacy-assets",
                "node_type": "CLOUD",
                "source_table": "cloud_validation_results",
                "metadata": {
                    "validation_asset_type": "aws_s3",
                    "service": "aws_s3",
                    "identifier": "legacy-assets",
                },
            },
            {
                "node_id": "VULN::manual-note",
                "label": "Manual public S3 bucket exposure",
                "node_type": "VULN",
                "source_table": "vulnerability_findings",
                "metadata": {
                    "vuln_type": "DETERMINISTIC_CLOUD_EXPOSURE",
                    "validation_asset_type": "aws_s3",
                    "resource_id": "manual-note-bucket",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "HOST::app",
                "target_node_id": "CLOUD::s3::legacy-assets",
                "edge_type": "cloud_reference",
            },
            {
                "source_node_id": "HOST::app",
                "target_node_id": "CLOUD::aws_s3::legacy-assets",
                "edge_type": "cloud_reference",
            },
            {
                "source": "HOST::app",
                "target": "VULN::manual-note",
                "edge_type": "vuln_found",
            },
        ],
        "critical_path_nodes": [
            "HOST::app",
            "CLOUD::s3::legacy-assets",
            "CLOUD::aws_s3::legacy-assets",
            "VULN::manual-note",
        ],
    }

    filtered = filter_graph_payload_for_validation(
        con,
        1001,
        payload,
        callbacks=_callbacks(
            reportable_index={("aws_s3", "legacy-assets"): True},
            validation_metadata_index={
                ("aws_s3", "legacy-assets"): {
                    "validation_status": "VALIDATED",
                    "validation_reportable": True,
                }
            },
        ),
    )

    assert filtered is not None
    nodes = {node["node_id"]: node for node in filtered["nodes"]}
    assert set(nodes) == {"HOST::app", "CLOUD::aws_s3::legacy-assets"}
    cloud_metadata = nodes["CLOUD::aws_s3::legacy-assets"]["metadata"]
    assert cloud_metadata["service"] == "aws_s3"
    assert cloud_metadata["provider_identifier"] == "LegacyAssetsExact"
    assert cloud_metadata["asset_type_aliases"] == ["s3"]
    assert cloud_metadata["validation_status"] == "VALIDATED"
    assert filtered["edges"] == [
        {
            "source_node_id": "HOST::app",
            "target_node_id": "CLOUD::aws_s3::legacy-assets",
            "edge_type": "cloud_reference",
        }
    ]
    assert filtered["critical_path_nodes"] == [
        "HOST::app",
        "CLOUD::aws_s3::legacy-assets",
    ]
