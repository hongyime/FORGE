from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.reporting.dashboard import generate_dashboard

ENGAGEMENT_ID = 1001


def _build_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """,
            (ENGAGEMENT_ID,),
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, provider_identifier,
                 validation_status, validation_method, http_status, evidence,
                 notes, checked_at)
            VALUES
                (?, 'aws_s3', 'legacy-assets', 'LegacyAssetsExact', 'VALIDATED',
                 's3_list_bucket', 200,
                 '<ListBucketResult><Contents><Key>reports/customer-records.csv</Key></Contents></ListBucketResult>',
                 'Public object metadata observed',
                 '2026-07-15T09:30:00+00:00')
            """,
            (ENGAGEMENT_ID,),
        )
        con.execute(
            """
            INSERT INTO attack_graph_snapshots
                (engagement_id, snapshot_at, node_count, edge_count,
                 critical_path_weight, min_severity, pruned, graph_json,
                 mermaid_output, dot_output)
            VALUES (?, '2026-07-15T09:40:00+00:00', 3, 2, 20.0, 'LOW', 0,
                    ?, 'graph TD; host-->s3-->aws;', 'digraph G { host -> s3; }')
            """,
            (ENGAGEMENT_ID, json.dumps(_stale_alias_graph(), sort_keys=True)),
        )
        con.commit()
    finally:
        con.close()


def _stale_alias_graph() -> dict[str, object]:
    return {
        "nodes": [
            {
                "node_id": "HOST::app",
                "node_type": "HOST",
                "label": "app.acme.example",
                "metadata": {},
            },
            {
                "node_id": "CLOUD::s3::legacy-assets",
                "node_type": "CLOUD",
                "label": "s3:legacy-assets",
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
                "label": "aws_s3:LegacyAssetsExact",
                "source_table": "cloud_validation_results",
                "metadata": {
                    "validation_asset_type": "aws_s3",
                    "service": "aws_s3",
                    "identifier": "legacy-assets",
                    "provider_identifier": "LegacyAssetsExact",
                    "validation_status": "VALIDATED",
                    "validation_method": "s3_list_bucket",
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
        ],
        "critical_path_nodes": [
            "HOST::app",
            "CLOUD::s3::legacy-assets",
            "CLOUD::aws_s3::legacy-assets",
        ],
    }


def test_dashboard_merges_cloud_alias_nodes_in_imported_graph_payload(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    _build_db(db_root / f"{ENGAGEMENT_ID}.db")

    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )

    detail_path = (
        reports_dir
        / "dashboard"
        / "data"
        / "engagements"
        / "engagement-1001-acme-example.json"
    )
    detail_payload = json.loads(detail_path.read_text(encoding="utf-8"))
    graph_payload = detail_payload["graph_payload"]
    graph_nodes = {node["node_id"]: node for node in graph_payload["nodes"]}

    assert "CLOUD::s3::legacy-assets" not in graph_nodes
    assert "CLOUD::aws_s3::legacy-assets" in graph_nodes
    cloud_node = graph_nodes["CLOUD::aws_s3::legacy-assets"]
    assert cloud_node["metadata"]["service"] == "aws_s3"
    assert cloud_node["metadata"]["provider_identifier"] == "LegacyAssetsExact"
    assert cloud_node["metadata"]["asset_type_aliases"] == ["s3"]
    assert graph_payload["critical_path_nodes"] == [
        "HOST::app",
        "CLOUD::aws_s3::legacy-assets",
    ]
    assert graph_payload["edges"] == [
        {
            "source_node_id": "HOST::app",
            "target_node_id": "CLOUD::aws_s3::legacy-assets",
            "edge_type": "cloud_reference",
        }
    ]
