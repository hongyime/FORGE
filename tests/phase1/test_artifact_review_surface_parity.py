from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.phase4.attack_path import AttackGraphBuilder
from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
from tests.phase1.artifact_test_support import bootstrap_engagement


def _insert_seed(
    con: sqlite3.Connection,
    value: str,
    seed_type: str,
    *,
    parent_seed_id: int | None = None,
    metadata: dict[str, object] | None = None,
) -> int:
    con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth,
             confidence, parent_seed_id, metadata_json)
        VALUES (1001, ?, ?, 'artifact', 'completed', ?, 0.86, ?, ?)
        """,
        (
            value,
            seed_type,
            0 if parent_seed_id is None else 1,
            parent_seed_id,
            json.dumps(metadata or {}, sort_keys=True),
        ),
    )
    row = con.execute("SELECT last_insert_rowid()").fetchone()
    return int(row[0])


def _insert_relation(
    con: sqlite3.Connection,
    source_seed_id: int,
    target_seed_id: int,
    evidence: dict[str, object],
) -> None:
    con.execute(
        """
        INSERT INTO seed_relations
            (engagement_id, source_seed_id, target_seed_id, relation_type,
             confidence, evidence_json)
        VALUES (1001, ?, ?, 'derived_from', 0.88, ?)
        """,
        (source_seed_id, target_seed_id, json.dumps(evidence, sort_keys=True)),
    )


def test_artifact_pivots_surface_across_graph_dashboard_and_report_inventory(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = data_dir / "engagements" / "1001.db"
    reports_dir = tmp_path / "reports"
    db_path.parent.mkdir(parents=True)
    reports_dir.mkdir()
    bootstrap_engagement(db_path, name="Artifact Review Parity")

    con = sqlite3.connect(db_path)
    try:
        root_seed_id = _insert_seed(
            con,
            "https://downloads.acme.example/app.apk",
            "apk_url",
            metadata={"operator_scope": True},
        )
        rn_seed_id = _insert_seed(
            con,
            "rn-owner@acme.example",
            "email",
            parent_seed_id=root_seed_id,
            metadata={
                "artifact_provenance": True,
                "format": "react-native-bundle",
                "source_url": "https://cdn.acme.example/index.android.bundle",
            },
        )
        source_map_seed_id = _insert_seed(
            con,
            "https://cdn.acme.example/index.android.bundle.map",
            "url",
            parent_seed_id=root_seed_id,
            metadata={
                "artifact_provenance": True,
                "format": "source-map",
                "source_url": "https://cdn.acme.example/index.android.bundle",
            },
        )
        contact_seed_id = _insert_seed(
            con,
            "Alice Artifact",
            "name",
            parent_seed_id=root_seed_id,
            metadata={
                "artifact_contact_identity": True,
                "contact_field": "fn",
                "contact_title": "Security Lead",
                "format": "vcard",
                "source_url": "https://cdn.acme.example/contact.vcf",
            },
        )
        company_seed_id = _insert_seed(
            con,
            "Acme Artifact Labs",
            "company",
            parent_seed_id=root_seed_id,
            metadata={
                "artifact_contact_identity": True,
                "contact_field": "org",
                "format": "vcard",
                "source_url": "https://cdn.acme.example/contact.vcf",
            },
        )
        _insert_relation(
            con,
            root_seed_id,
            rn_seed_id,
            {
                "rule": "artifact_seed_provenance",
                "extract_rule": "react_native_bundle",
                "format": "react-native-bundle",
                "source_url": "https://cdn.acme.example/index.android.bundle",
                "payload_count": 2,
            },
        )
        _insert_relation(
            con,
            root_seed_id,
            source_map_seed_id,
            {
                "rule": "artifact_seed_provenance",
                "extract_rule": "artifact_text_discovered_artifact_queue",
                "format": "source-map",
                "source_url": "https://cdn.acme.example/index.android.bundle.map",
            },
        )
        for target_seed_id, contact_field in (
            (contact_seed_id, "fn"),
            (company_seed_id, "org"),
        ):
            _insert_relation(
                con,
                root_seed_id,
                target_seed_id,
                {
                    "rule": "artifact_seed_provenance",
                    "extract_rule": "contact_identity",
                    "format": "vcard",
                    "contact_field": contact_field,
                    "source_url": "https://cdn.acme.example/contact.vcf",
                },
            )
        con.executemany(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, artifact_type, discovered_from,
                 status, metadata_json)
            VALUES (1001, ?, 'config', ?, 'parsed', ?)
            """,
            [
                (
                    "https://cdn.acme.example/index.android.bundle",
                    "artifact",
                    json.dumps({"format": "react-native-bundle"}, sort_keys=True),
                ),
                (
                    "https://cdn.acme.example/index.android.bundle.map",
                    "artifact_text",
                    json.dumps(
                        {
                            "format": "source-map",
                            "rule": "artifact_text_discovered_artifact_queue",
                        },
                        sort_keys=True,
                    ),
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source)
            VALUES (1001, 'aws_lambda_function', ?, ?, 'artifact_aws_lambda_arn')
            """,
            (
                "arn:aws:lambda:us-east-1:123456789012:function:billing-worker:prod",
                "arn:aws:lambda:us-east-1:123456789012:function:Billing-Worker:prod",
            ),
        )
        con.commit()
    finally:
        con.close()

    graph = AttackGraphBuilder(engagement_id=1001, db_path=db_path).build()
    graph_nodes = {node.label: node for node in graph.nodes}
    assert graph_nodes["rn-owner@acme.example"].source_table == "engagement_seeds"
    assert graph_nodes["Alice Artifact"].metadata["contact_title"] == "Security Lead"
    assert any(
        node.source_table == "cloud_assets"
        and node.metadata["service"] == "aws_lambda_function"
        and "Billing-Worker" in node.metadata["provider_identifier"]
        for node in graph.nodes
    )
    assert any(
        edge.edge_type == "derived_from"
        and edge.metadata.get("extract_rule") == "react_native_bundle"
        for edge in graph.edges
    )

    ctx = ContextBuilder(db_path, 1001).build()
    rendered = ReportSynthesizer(
        db_path=db_path,
        output_dir=reports_dir,
        provider="template",
        assume_yes=True,
    )._render_skeleton(ctx)
    raw_rows = ReportSynthesizer._raw_export_csv_rows(ctx)
    cloud_asset_row = next(row for row in raw_rows if row["record_type"] == "cloud_asset")

    assert ctx.exploits.exploited == []
    assert ctx.cloud_validation_inventory == []
    assert ctx.cloud_asset_inventory[0]["validation_status"] == "UNVALIDATED"
    assert ctx.cloud_asset_inventory[0]["validation_reportable"] is False
    assert "### 5.0 Cloud Asset Inventory (Not Findings)" in rendered
    assert "arn:aws:lambda:us-east-1:123456789012:function:Billing-Worker:prod" in rendered
    assert "_No detailed validated findings in this window._" in rendered
    assert not any(row["record_type"] == "finding" for row in raw_rows)
    assert cloud_asset_row["validation_status"] == "UNVALIDATED"
    assert cloud_asset_row["validation_reportable"] == "False"
    assert cloud_asset_row["cloud_source"] == "artifact_aws_lambda_arn"

    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )
    overview = json.loads(
        (reports_dir / "dashboard" / "data" / "engagements.json").read_text(
            encoding="utf-8"
        )
    )
    slug = next(item["slug"] for item in overview["items"] if item["id"] == "1001")
    detail_payload = json.loads(
        (
            reports_dir
            / "dashboard"
            / "data"
            / "engagements"
            / f"{slug}.json"
        ).read_text(encoding="utf-8")
    )

    seed_values = {row["Seed"] for row in detail_payload["sections"]["engagement_seeds"]}
    assert {
        "rn-owner@acme.example",
        "https://cdn.acme.example/index.android.bundle.map",
        "Alice Artifact",
        "Acme Artifact Labs",
    }.issubset(seed_values)
    assert any(
        row["Origin"] == "artifact_text" and "source-map" in row["Meta"]
        for row in detail_payload["sections"]["artifact_queue"]
    )
    assert any(
        row["Type"] == "aws_lambda_function"
        and row["Validation"] == "UNVALIDATED"
        and row["Reportable"] == "no"
        for row in detail_payload["sections"]["cloud_assets"]
    )
    graph_payload = detail_payload["graph_payload"]
    assert any(
        node.get("source_table") == "cloud_assets"
        and node.get("node_type") == "CLOUD"
        and node.get("metadata", {}).get("service") == "aws_lambda_function"
        for node in graph_payload["nodes"]
    )
    assert any(
        node.get("label") == "Alice Artifact"
        and node.get("metadata", {}).get("contact_title") == "Security Lead"
        for node in graph_payload["nodes"]
    )
