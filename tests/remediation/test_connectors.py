from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.graph.assets import list_asset_graph, upsert_asset_entity, upsert_ownership_claim
from forge.graph.assets import upsert_asset_relationship
from forge.remediation import connectors as remediation_connectors
from forge.remediation.cli import register_remediation_commands
from forge.remediation.connectors import (
    import_remediation_ticket_statuses,
    remediation_integration_runbook,
    remediation_ticket_handoff_plan,
    sync_remediation_tickets,
)
from forge.remediation.runner import import_remediation_ticket_statuses_for_data_dir
from forge.remediation.workflow import (
    draft_remediation_from_asset_graph_candidates,
    propagate_asset_owners_to_remediation,
    remediation_review_queue,
    risk_acceptance_review_due,
    risk_acceptance_review_status,
)


def _build_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.execute(
        """
        INSERT INTO remediation_items
            (id, engagement_id, finding_table, finding_ref, title, severity,
             owner, sla_due_at, status, ticket_system, ticket_ref, updated_at)
        VALUES
            (10, 1001, 'monitoring_alerts', '42', 'Added exposed VPN', 'HIGH',
             'appsec', '2026-07-16T10:00:00Z', 'assigned', 'github', 'SEC-42',
             '2026-07-09T10:00:00Z')
        """
    )
    con.commit()
    return con


def _build_data_dir_db(data_dir: Path) -> Path:
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        validate_canonical_schema(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, status, ticket_system, updated_at)
            VALUES
                (10, 1001, 'manual', 'manual-1', 'Manual remediation', 'LOW',
                 'it-ops', 'open', 'local-jsonl', '2026-07-09T10:00:00Z')
            """
        )
        con.commit()
    finally:
        con.close()
    return db_path


def test_risk_acceptance_review_status_classifies_operator_queue() -> None:
    now = "2026-08-11T00:00:00Z"

    assert risk_acceptance_review_status("open", "", now=now) == ""
    assert risk_acceptance_review_status("risk_accepted", "", now=now) == "missing_expiry"
    assert (
        risk_acceptance_review_status("risk_accepted", "not-a-date", now=now)
        == "invalid_expiry"
    )
    assert (
        risk_acceptance_review_status("risk_accepted", "2026-08-10T23:59:59Z", now=now)
        == "expired"
    )
    assert (
        risk_acceptance_review_status("risk_accepted", "2026-08-20T00:00:00Z", now=now)
        == "expiring_soon"
    )
    assert (
        risk_acceptance_review_status("risk_accepted", "2026-12-31T00:00:00Z", now=now)
        == "current"
    )
    assert risk_acceptance_review_due("expired") is True
    assert risk_acceptance_review_due("current") is False


def test_remediation_review_queue_prioritizes_operator_attention(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, risk_acceptance_reason,
                 risk_acceptance_expires_at, retest_status, ticket_ref, metadata_json,
                 updated_at)
            VALUES
                (20, 1001, 'manual', 'ownerless', 'Assign missing owner', 'MEDIUM',
                 NULL, NULL, 'open', NULL, NULL, 'not_requested', NULL,
                 '{"raw_secret":"do-not-return"}', '2026-08-01T00:00:00Z'),
                (21, 1001, 'manual', 'accepted', 'Review accepted risk', 'LOW',
                 NULL, NULL, 'risk_accepted', 'business exception',
                 '2026-08-10T00:00:00Z', 'not_requested', NULL,
                 '{}', '2026-08-02T00:00:00Z'),
                (22, 1001, 'manual', 'retest', 'Verify fixed endpoint', 'HIGH',
                 'appsec', NULL, 'retest_pending', NULL, NULL, 'pending',
                 'SEC-22', '{}', '2026-08-03T00:00:00Z'),
                (23, 1001, 'manual', 'blocked', 'Blocked validation', 'CRITICAL',
                 'appsec', NULL, 'assigned', NULL, NULL, 'blocked',
                 'SEC-23', '{}', '2026-08-04T00:00:00Z'),
                (24, 1001, 'manual', 'resolved', 'Resolved without owner', 'HIGH',
                 NULL, NULL, 'resolved', NULL, NULL, 'not_requested',
                 NULL, '{}', '2026-08-05T00:00:00Z')
            """
        )
        con.commit()

        queue = remediation_review_queue(
            con,
            engagement_id=1001,
            now="2026-08-11T00:00:00Z",
            limit=3,
        )
    finally:
        con.close()

    assert queue["summary"]["total"] == 6
    assert queue["summary"]["active"] == 4
    assert queue["summary"]["attention_required"] == 5
    assert queue["summary"]["sla_overdue"] == 1
    assert queue["summary"]["missing_owner"] == 1
    assert queue["summary"]["missing_ticket"] == 1
    assert queue["summary"]["risk_acceptance_review_due"] == 1
    assert queue["summary"]["risk_acceptance_expired"] == 1
    assert queue["summary"]["retest_pending"] == 1
    assert queue["summary"]["retest_blocked"] == 1
    assert queue["returned_count"] == 3
    assert queue["truncated"] is True
    assert [item["id"] for item in queue["items"]] == [10, 21, 23]
    assert queue["items"][0]["queue_reason_labels"] == ["SLA overdue"]
    assert "metadata" not in queue["items"][1]
    assert "do-not-return" not in json.dumps(queue, sort_keys=True)


def test_remediation_review_queue_supports_legacy_missing_risk_expiry(
    tmp_path: Path,
) -> None:
    con = sqlite3.connect(tmp_path / "legacy-engagement.db")
    con.row_factory = sqlite3.Row
    try:
        con.executescript(
            """
            CREATE TABLE remediation_items (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                finding_table TEXT,
                finding_ref TEXT,
                title TEXT,
                severity TEXT,
                owner TEXT,
                sla_due_at TEXT,
                status TEXT,
                retest_status TEXT,
                ticket_ref TEXT,
                metadata_json TEXT,
                updated_at TEXT
            );
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, retest_status, ticket_ref,
                 metadata_json, updated_at)
            VALUES
                (1, 1001, 'manual', 'legacy-accepted', 'Legacy accepted risk',
                 'LOW', 'appsec', NULL, 'risk_accepted', 'not_requested',
                 'SEC-1', '{}', '2026-08-01T00:00:00Z');
            """
        )

        queue = remediation_review_queue(
            con,
            engagement_id=1001,
            now="2026-08-11T00:00:00Z",
            limit=10,
        )
    finally:
        con.close()

    assert queue["summary"]["total"] == 1
    assert queue["summary"]["attention_required"] == 1
    assert queue["summary"]["risk_acceptance_missing_expiry"] == 1
    assert queue["items"][0]["risk_acceptance_expires_at"] == ""
    assert queue["items"][0]["queue_reasons"] == ["risk_acceptance_missing_expiry"]


def test_draft_remediation_from_asset_graph_candidates_is_idempotent_and_reviewable(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        entry_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="asset:internet:public",
            entity_type="asset",
            label="Public Internet",
            confidence=0.95,
            metadata={"asset_role": "internet_entrypoint"},
        )
        finding_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:asset-graph-public-bucket",
            entity_type="finding",
            label="Public bucket exposure",
            confidence=0.9,
            metadata={
                "severity": "CRITICAL",
                "standards": {"cisa_kev": True, "attack_techniques": ["T1530"]},
                "evidence_url": "https://proof.example.test/path?token=do-not-store",
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=1001,
            source_entity_id=entry_id,
            target_entity_id=finding_id,
            relationship_type="has_finding",
            confidence=0.9,
            evidence={"match": "public_to_finding", "secret": "do-not-store-edge"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=finding_id,
            owner_ref="cloud-team",
            owner_kind="team",
            owner_display="Cloud Team",
            claim_type="explicit",
            confidence=0.9,
            source="test",
            evidence={"token": "do-not-store-owner"},
        )
        con.commit()

        first = draft_remediation_from_asset_graph_candidates(
            con,
            engagement_id=1001,
            operator="delta-one",
            now="2026-08-14T00:00:00Z",
        )
        second = draft_remediation_from_asset_graph_candidates(
            con,
            engagement_id=1001,
            operator="delta-one",
            now="2026-08-14T00:00:00Z",
        )
        rows = con.execute(
            """
            SELECT *
            FROM remediation_items
            WHERE engagement_id=1001 AND finding_table='asset_graph'
            """
        ).fetchall()
        queue = remediation_review_queue(
            con,
            engagement_id=1001,
            now="2026-08-15T00:00:00Z",
        )
        audit_rows = con.execute(
            """
            SELECT action, result, operator
            FROM audit_log
            WHERE engagement_id=1001 AND action='draft_from_asset_graph'
            """
        ).fetchall()
        graph = list_asset_graph(con, 1001, limit=100)
    finally:
        con.close()

    assert first["drafted_count"] >= 1
    assert first["graph_sync"]["source_counts"]["remediation"] >= first["drafted_count"]
    assert second["drafted_count"] == 0
    assert len(rows) == first["drafted_count"]
    item = next(
        row
        for row in rows
        if row["finding_ref"] == "finding:vulnerability:asset-graph-public-bucket"
    )
    assert item["severity"] == "CRITICAL"
    assert item["owner"] == "cloud-team"
    assert item["status"] == "assigned"
    assert item["sla_due_at"] == "2026-08-21T00:00:00Z"
    metadata = json.loads(item["metadata_json"])
    assert metadata["source"] == "asset_graph_candidate"
    assert metadata["candidate"]["reason"] == "remediate_highest_risk_finding"
    assert metadata["candidate"]["supporting_path_count"] >= 1
    assert metadata["candidate"]["recommended_actions"] == [
        "assign_remediation_owner",
        "open_or_update_ticket",
        "request_retest",
    ]
    assert any(
        queue_item["finding_table"] == "asset_graph"
        and queue_item["finding_ref"] == "finding:vulnerability:asset-graph-public-bucket"
        and "missing_ticket" in queue_item["queue_reasons"]
        for queue_item in queue["items"]
    )
    assert len(audit_rows) == 2
    assert {row["operator"] for row in audit_rows} == {"delta-one"}
    graph_nodes = {node["entity_key"]: node for node in graph["nodes"]}
    graph_key_by_id = {int(node["id"]): node["entity_key"] for node in graph["nodes"]}
    graph_edges = {
        (
            graph_key_by_id.get(int(edge["source_entity_id"])),
            graph_key_by_id.get(int(edge["target_entity_id"])),
            edge["relationship_type"],
        )
        for edge in graph["edges"]
    }
    remediation_key = f"remediation:{item['id']}"
    finding_key = "finding:vulnerability:asset-graph-public-bucket"
    assert remediation_key in graph_nodes
    assert graph_nodes[remediation_key]["entity_type"] == "remediation"
    assert (remediation_key, finding_key, "remediates") in graph_edges
    blob = json.dumps([dict(row) for row in rows], sort_keys=True)
    assert "do-not-store" not in blob


def test_remediation_review_queue_surfaces_latest_failed_ticket_sync(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    raw_destination = "https://hooks.example.test/tines/secret-path?token=sync-secret&team=appsec"
    raw_error = "POST https://hooks.example.test/tines/secret-path?token=sync-secret failed"
    try:
        con.execute(
            """
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at, attempt_count, last_error,
                 metadata_json, updated_at)
            VALUES
                (1001, 10, 'webhook', ?, 'update', 'failed',
                 '2026-07-09T10:00:00Z', 2, ?,
                 '{"operator":"ticket-sync","request_url":"https://hooks.example.test/tines/secret-path?token=sync-secret"}',
                 '2026-07-09T10:05:00Z')
            """,
            (raw_destination, raw_error),
        )
        con.commit()

        failed_queue = remediation_review_queue(
            con,
            engagement_id=1001,
            now="2026-07-10T00:00:00Z",
        )

        con.execute(
            """
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at, attempt_count, last_error,
                 delivered_at, metadata_json, updated_at)
            VALUES
                (1001, 10, 'webhook', ?, 'update', 'delivered',
                 '2026-07-09T10:01:00Z', 1, NULL,
                 '2026-07-09T10:20:00Z', '{"operator":"ticket-sync"}',
                 '2026-07-09T10:20:00Z')
            """,
            (raw_destination,),
        )
        con.commit()

        delivered_queue = remediation_review_queue(
            con,
            engagement_id=1001,
            now="2026-07-10T00:00:00Z",
        )
    finally:
        con.close()

    assert failed_queue["summary"]["attention_required"] == 1
    assert failed_queue["summary"]["ticket_sync_failed"] == 1
    assert failed_queue["summary"]["missing_ticket"] == 0
    item = failed_queue["items"][0]
    event = item["latest_ticket_event"]
    assert item["id"] == 10
    assert item["queue_reasons"] == ["ticket_sync_failed"]
    assert item["queue_reason_labels"] == ["ticket sync failed"]
    assert event["connector"] == "webhook"
    assert event["status"] == "failed"
    assert event["attempt_count"] == 2
    assert event["destination"] == "https://hooks.example.test/tines/secret-path?team=appsec"
    assert event["last_error"] == "POST https://hooks.example.test/tines/secret-path failed"
    blob = json.dumps(failed_queue, sort_keys=True)
    assert "sync-secret" not in blob
    assert "token=" not in blob

    assert delivered_queue["summary"]["attention_required"] == 0
    assert delivered_queue["summary"]["ticket_sync_failed"] == 0
    assert delivered_queue["items"] == []


def test_propagate_asset_owners_assigns_missing_remediation_owner_from_graph(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        finding_entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:55",
            entity_type="finding",
            label="Unauthenticated admin console",
            source_table="vulnerability_findings",
            source_id=55,
            confidence=0.8,
            metadata={"source": "test"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=finding_entity_id,
            owner_ref="product-security",
            owner_kind="team",
            owner_display="Product Security",
            claim_type="manual",
            confidence=0.94,
            source="operator",
            evidence={"reason": "service owner", "secret": "do-not-store"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=finding_entity_id,
            owner_ref="legacy-appsec",
            owner_kind="team",
            owner_display="Legacy AppSec",
            claim_type="inferred",
            confidence=0.6,
            source="import",
            evidence={"reason": "older inventory"},
        )
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_id, finding_ref,
                 title, severity, owner, status, metadata_json)
            VALUES
                (20, 1001, 'vulnerability_findings', 55, '55',
                 'Unauthenticated admin console', 'HIGH', NULL, 'open', '{"source":"unit"}'),
                (21, 1001, 'vulnerability_findings', 55, '55-explicit',
                 'Explicitly assigned finding', 'HIGH', 'appsec', 'open', '{}'),
                (22, 1001, 'vulnerability_findings', 55, '55-accepted',
                 'Accepted finding', 'HIGH', NULL, 'risk_accepted', '{}')
            """
        )
        con.commit()

        result = propagate_asset_owners_to_remediation(
            con,
            engagement_id=1001,
            operator="delta-one",
            now="2026-08-11T00:00:00Z",
        )
        assigned = con.execute(
            """
            SELECT owner, status, metadata_json
            FROM remediation_items
            WHERE id=20
            """
        ).fetchone()
        explicit_owner = con.execute("SELECT owner FROM remediation_items WHERE id=21").fetchone()[
            "owner"
        ]
        terminal_owner = con.execute("SELECT owner FROM remediation_items WHERE id=22").fetchone()[
            "owner"
        ]
        audit = con.execute(
            """
            SELECT action, result, operator
            FROM audit_log
            WHERE action='remediation_owner_propagation'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        con.close()

    metadata = json.loads(assigned["metadata_json"])
    assert result["assigned_count"] == 1
    assert result["skipped_existing_owner_count"] == 2
    assert result["skipped_terminal_count"] == 1
    assert assigned["owner"] == "product-security"
    assert assigned["status"] == "assigned"
    assert explicit_owner == "appsec"
    assert terminal_owner is None
    assert metadata["source"] == "unit"
    assert metadata["owner_source"] == "asset_graph"
    assert metadata["owner_conflict"] is True
    assert metadata["asset_owner"]["owner_ref"] == "product-security"
    assert metadata["asset_owner"]["entity_key"] == "finding:vulnerability:55"
    assert metadata["owner_propagation_history"][0]["propagated_by"] == "delta-one"
    assert "do-not-store" not in json.dumps(metadata, sort_keys=True)
    assert audit["operator"] == "delta-one"
    assert "assigned=1" in audit["result"]


def test_propagate_asset_owners_respects_conflict_and_confidence_policy(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        conflicted_entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:80",
            entity_type="finding",
            label="Conflicted owner finding",
            source_table="vulnerability_findings",
            source_id=80,
            confidence=0.8,
            metadata={"source": "test"},
        )
        low_confidence_entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:81",
            entity_type="finding",
            label="Low confidence owner finding",
            source_table="vulnerability_findings",
            source_id=81,
            confidence=0.8,
            metadata={"source": "test"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=conflicted_entity_id,
            owner_ref="product-security",
            owner_kind="team",
            confidence=0.91,
            source="operator",
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=conflicted_entity_id,
            owner_ref="platform",
            owner_kind="team",
            confidence=0.88,
            source="inventory",
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=low_confidence_entity_id,
            owner_ref="infra",
            owner_kind="team",
            confidence=0.55,
            source="inventory",
        )
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_id, finding_ref,
                 title, severity, owner, status, metadata_json)
            VALUES
                (80, 1001, 'vulnerability_findings', 80, '80',
                 'Conflicted owner finding', 'HIGH', NULL, 'open', '{}'),
                (81, 1001, 'vulnerability_findings', 81, '81',
                 'Low confidence owner finding', 'MEDIUM', NULL, 'open', '{}')
            """
        )
        con.commit()

        skipped = propagate_asset_owners_to_remediation(
            con,
            engagement_id=1001,
            conflict_policy="skip_conflicts",
            min_confidence=0.8,
            operator="policy-test",
        )
        assigned = propagate_asset_owners_to_remediation(
            con,
            engagement_id=1001,
            conflict_policy="highest_confidence",
            min_confidence=0.5,
            operator="policy-test",
        )
        rows = {
            int(row["id"]): dict(row)
            for row in con.execute(
                "SELECT id, owner, metadata_json FROM remediation_items WHERE id IN (80, 81)"
            ).fetchall()
        }
        audit = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE action='remediation_owner_propagation'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
    finally:
        con.close()

    assert skipped["assigned_count"] == 0
    assert skipped["skipped_conflict_count"] == 1
    assert skipped["skipped_low_confidence_count"] == 1
    assert skipped["conflict_policy"] == "skip_conflicts"
    assert skipped["min_confidence"] == 0.8
    assert assigned["assigned_count"] == 2
    assert rows[80]["owner"] == "product-security"
    assert rows[81]["owner"] == "infra"
    metadata = json.loads(rows[80]["metadata_json"])
    assert metadata["owner_propagation_policy"]["conflict_policy"] == "highest_confidence"
    assert metadata["owner_propagation_policy"]["min_confidence"] == 0.5
    assert "conflict_policy=highest_confidence" in audit["result"]
    assert "min_confidence=0.50" in audit["result"]


def test_propagate_asset_owners_overwrite_replaces_explicit_owner(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        secret_entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="secret:github:token:70",
            entity_type="secret",
            label="GitHub token",
            source_table="key_scanner_findings",
            source_id=70,
            confidence=0.9,
            metadata={"source": "test"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=secret_entity_id,
            owner_ref="platform",
            owner_kind="team",
            claim_type="manual",
            confidence=0.9,
            source="operator",
            evidence={"reason": "secret owner"},
        )
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_id, finding_ref,
                 title, severity, owner, status, metadata_json)
            VALUES
                (30, 1001, 'key_scanner_findings', 70, '70',
                 'Rotate GitHub token', 'HIGH', 'appsec', 'assigned', '{}')
            """
        )
        con.commit()

        skipped = propagate_asset_owners_to_remediation(con, engagement_id=1001)
        overwritten = propagate_asset_owners_to_remediation(
            con,
            engagement_id=1001,
            overwrite=True,
            operator="delta-one",
        )
        owner = con.execute("SELECT owner FROM remediation_items WHERE id=30").fetchone()["owner"]
    finally:
        con.close()

    assert skipped["assigned_count"] == 0
    assert overwritten["assigned_count"] == 1
    assert owner == "platform"


def test_sync_remediation_tickets_writes_jsonl_once_until_item_changes(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    jsonl_path = tmp_path / "tickets" / "remediation.jsonl"
    try:
        first = sync_remediation_tickets(
            con,
            engagement_id=1001,
            jsonl_path=jsonl_path,
            operator="ticket-test",
        )
        second = sync_remediation_tickets(
            con,
            engagement_id=1001,
            jsonl_path=jsonl_path,
            operator="ticket-test",
        )
        con.execute(
            """
            UPDATE remediation_items
            SET status='resolved', updated_at='2026-07-09T11:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        third = sync_remediation_tickets(
            con,
            engagement_id=1001,
            jsonl_path=jsonl_path,
            operator="ticket-test",
        )
        event_rows = con.execute(
            """
            SELECT connector, destination, action, status, attempt_count, item_updated_at
            FROM remediation_ticket_events
            ORDER BY id
            """
        ).fetchall()
    finally:
        con.close()

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    payloads = [json.loads(line) for line in lines]
    assert first["sync_count"] == 1
    assert second["sync_count"] == 0
    assert third["sync_count"] == 1
    assert len(lines) == 2
    assert payloads[0]["action"] == "update"
    assert payloads[0]["operator"] == "ticket-test"
    assert payloads[0]["remediation_item"]["ticket_ref"] == "SEC-42"
    assert payloads[1]["remediation_item"]["status"] == "resolved"
    assert [
        (row["connector"], row["action"], row["status"], row["attempt_count"], row["item_updated_at"])
        for row in event_rows
    ] == [
        ("jsonl", "update", "delivered", 1, "2026-07-09T10:00:00Z"),
        ("jsonl", "update", "delivered", 1, "2026-07-09T11:00:00Z"),
    ]


def test_sync_remediation_tickets_can_create_github_issue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []

    class _FakeResponse:
        status = 201

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"number": 123, "html_url": "https://github.com/acme/security/issues/123"}'

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        assert timeout == 10.0
        return _FakeResponse()

    monkeypatch.setenv("FORGE_GITHUB_TOKEN", "ghp_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system=NULL,
                ticket_ref=NULL,
                ticket_url=NULL,
                updated_at='2026-07-09T10:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("github_issues",),
            github_repo="acme/security",
            github_api_url="https://api.github.test",
            operator="github-ticket-test",
        )
        item = con.execute(
            """
            SELECT ticket_system, ticket_ref, ticket_url
            FROM remediation_items
            WHERE id=10
            """
        ).fetchone()
        event = con.execute(
            """
            SELECT connector, destination, action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    request = requests[0]
    body = json.loads(request.data.decode("utf-8"))
    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 1
    assert request.full_url == "https://api.github.test/repos/acme/security/issues"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer ghp_test_token"
    assert body["title"] == "[FORGE] HIGH Added exposed VPN"
    assert "FORGE remediation item" in body["body"]
    assert tuple(item) == (
        "github",
        "123",
        "https://github.com/acme/security/issues/123",
    )
    assert event["connector"] == "github_issues"
    assert event["destination"] == "https://api.github.test/repos/acme/security"
    assert event["action"] == "create"
    assert event["status"] == "delivered"
    assert metadata["github_issue_number"] == "123"
    assert metadata["github_repo"] == "acme/security"
    assert "ghp_test_token" not in event["metadata_json"]


def test_sync_remediation_tickets_can_update_existing_github_issue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []

    class _FakeResponse:
        status = 200

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"number": 123, "html_url": "https://github.com/acme/security/issues/123"}'

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        return _FakeResponse()

    monkeypatch.setenv("FORGE_GITHUB_TOKEN", "ghp_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system='github',
                ticket_ref='123',
                ticket_url='https://github.com/acme/security/issues/123',
                status='resolved',
                updated_at='2026-07-09T11:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("github_issues",),
            github_repo="acme/security",
            github_api_url="https://api.github.test",
            operator="github-ticket-test",
        )
        event = con.execute(
            """
            SELECT action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    request = requests[0]
    body = json.loads(request.data.decode("utf-8"))
    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 1
    assert request.full_url == "https://api.github.test/repos/acme/security/issues/123"
    assert request.get_method() == "PATCH"
    assert body["state"] == "closed"
    assert event["action"] == "update"
    assert event["status"] == "delivered"
    assert metadata["github_method"] == "PATCH"


def test_sync_remediation_tickets_records_missing_connector_secret_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")

    def fail_urlopen(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("missing connector token should not make a network call")

    monkeypatch.delenv("FORGE_GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fail_urlopen)
    try:
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("github_issues",),
            github_repo="acme/security",
            github_api_url="https://api.github.test",
            operator="github-ticket-test",
        )
        event = con.execute(
            """
            SELECT connector, destination, action, status, attempt_count,
                   last_error, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 0
    assert result["failure_count"] == 1
    assert event["connector"] == "github_issues"
    assert event["destination"] == "https://api.github.test/repos/acme/security"
    assert event["action"] == "update"
    assert event["status"] == "failed"
    assert event["attempt_count"] == 1
    assert event["last_error"] == "FORGE_GITHUB_TOKEN is required for GitHub Issues sync"
    assert metadata == {
        "error_type": "ValueError",
        "operator": "github-ticket-test",
    }


def test_sync_remediation_tickets_can_create_jira_issue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []

    class _FakeResponse:
        status = 201

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"key": "SEC-123", "self": "https://acme.atlassian.net/rest/api/3/issue/10001"}'

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        assert timeout == 10.0
        return _FakeResponse()

    monkeypatch.setenv("FORGE_JIRA_EMAIL", "forge@example.com")
    monkeypatch.setenv("FORGE_JIRA_API_TOKEN", "jira_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system=NULL,
                ticket_ref=NULL,
                ticket_url=NULL,
                updated_at='2026-07-09T10:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("jira",),
            jira_base_url="https://acme.atlassian.net",
            jira_project_key="SEC",
            operator="jira-ticket-test",
        )
        item = con.execute(
            """
            SELECT ticket_system, ticket_ref, ticket_url
            FROM remediation_items
            WHERE id=10
            """
        ).fetchone()
        event = con.execute(
            """
            SELECT connector, destination, action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    request = requests[0]
    body = json.loads(request.data.decode("utf-8"))
    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 1
    assert request.full_url == "https://acme.atlassian.net/rest/api/3/issue"
    assert request.get_method() == "POST"
    assert str(request.get_header("Authorization")).startswith("Basic ")
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["issuetype"]["name"] == "Task"
    assert body["fields"]["summary"] == "[FORGE] HIGH Added exposed VPN"
    assert body["fields"]["description"]["type"] == "doc"
    assert tuple(item) == (
        "jira",
        "SEC-123",
        "https://acme.atlassian.net/browse/SEC-123",
    )
    assert event["connector"] == "jira"
    assert event["destination"] == "https://acme.atlassian.net/rest/api/3/issue/SEC"
    assert event["action"] == "create"
    assert event["status"] == "delivered"
    assert metadata["jira_issue_key"] == "SEC-123"
    assert metadata["jira_project_key"] == "SEC"
    assert metadata["jira_method"] == "POST"
    assert "jira_test_token" not in event["metadata_json"]


def test_sync_remediation_tickets_can_update_existing_jira_issue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []

    class _FakeResponse:
        status = 204

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return b""

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        return _FakeResponse()

    monkeypatch.setenv("FORGE_JIRA_EMAIL", "forge@example.com")
    monkeypatch.setenv("FORGE_JIRA_API_TOKEN", "jira_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system='jira',
                ticket_ref='SEC-123',
                ticket_url='https://acme.atlassian.net/browse/SEC-123',
                status='resolved',
                updated_at='2026-07-09T11:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("jira",),
            jira_base_url="https://acme.atlassian.net",
            jira_project_key="SEC",
            operator="jira-ticket-test",
        )
        event = con.execute(
            """
            SELECT action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    request = requests[0]
    body = json.loads(request.data.decode("utf-8"))
    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 1
    assert request.full_url == "https://acme.atlassian.net/rest/api/3/issue/SEC-123"
    assert request.get_method() == "PUT"
    assert "transition" not in body
    assert body["fields"]["summary"] == "[FORGE] HIGH Added exposed VPN"
    assert body["fields"]["description"]["type"] == "doc"
    assert event["action"] == "update"
    assert event["status"] == "delivered"
    assert metadata["jira_method"] == "PUT"
    assert metadata["jira_issue_key"] == "SEC-123"


def test_sync_remediation_tickets_can_create_servicenow_incident(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []
    sys_id = "0123456789abcdef0123456789abcdef"

    class _FakeResponse:
        status = 201

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return (
                b'{"result": {"sys_id": "0123456789abcdef0123456789abcdef", '
                b'"number": "INC0012345"}}'
            )

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        assert timeout == 10.0
        return _FakeResponse()

    monkeypatch.setenv("FORGE_SERVICENOW_USERNAME", "forge-api")
    monkeypatch.setenv("FORGE_SERVICENOW_PASSWORD", "servicenow_test_password")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system=NULL,
                ticket_ref=NULL,
                ticket_url=NULL,
                updated_at='2026-07-09T10:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("servicenow",),
            servicenow_instance_url="https://acme.service-now.com",
            operator="servicenow-ticket-test",
        )
        item = con.execute(
            """
            SELECT ticket_system, ticket_ref, ticket_url
            FROM remediation_items
            WHERE id=10
            """
        ).fetchone()
        event = con.execute(
            """
            SELECT connector, destination, action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    request = requests[0]
    body = json.loads(request.data.decode("utf-8"))
    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 1
    assert request.full_url == "https://acme.service-now.com/api/now/table/incident"
    assert request.get_method() == "POST"
    assert str(request.get_header("Authorization")).startswith("Basic ")
    assert body["short_description"] == "[FORGE] HIGH Added exposed VPN"
    assert body["correlation_id"] == "forge:1001:10"
    assert tuple(item) == (
        "servicenow",
        "INC0012345",
        f"https://acme.service-now.com/nav_to.do?uri=incident.do%3Fsys_id%3D{sys_id}",
    )
    assert event["connector"] == "servicenow"
    assert event["destination"] == "https://acme.service-now.com/api/now/table/incident"
    assert event["action"] == "create"
    assert event["status"] == "delivered"
    assert metadata["servicenow_sys_id"] == sys_id
    assert metadata["servicenow_number"] == "INC0012345"
    assert metadata["servicenow_method"] == "POST"
    assert "servicenow_test_password" not in event["metadata_json"]


def test_sync_remediation_tickets_can_update_existing_servicenow_incident_by_number(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []
    sys_id = "0123456789abcdef0123456789abcdef"

    class _FakeResponse:
        def __init__(self, body: bytes, status: int = 200) -> None:
            self._body = body
            self.status = status

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return self._body

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        if request.get_method() == "GET":
            return _FakeResponse(
                b'{"result": [{"sys_id": "0123456789abcdef0123456789abcdef", '
                b'"number": "INC0012345"}]}'
            )
        return _FakeResponse(
            b'{"result": {"sys_id": "0123456789abcdef0123456789abcdef", '
            b'"number": "INC0012345"}}'
        )

    monkeypatch.setenv("FORGE_SERVICENOW_BEARER_TOKEN", "servicenow_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET ticket_system='servicenow',
                ticket_ref='INC0012345',
                ticket_url='https://acme.service-now.com/nav_to.do?uri=incident.do',
                status='resolved',
                updated_at='2026-07-09T11:00:00Z'
            WHERE id=10
            """
        )
        con.commit()
        result = sync_remediation_tickets(
            con,
            engagement_id=1001,
            connectors=("servicenow",),
            servicenow_instance_url="https://acme.service-now.com",
            servicenow_token_env="FORGE_SERVICENOW_BEARER_TOKEN",
            operator="servicenow-ticket-test",
        )
        event = con.execute(
            """
            SELECT action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            """
        ).fetchone()
    finally:
        con.close()

    lookup_request = requests[0]
    update_request = requests[1]
    body = json.loads(update_request.data.decode("utf-8"))
    metadata = json.loads(event["metadata_json"])
    assert result["sync_count"] == 1
    assert lookup_request.get_method() == "GET"
    assert lookup_request.full_url.startswith("https://acme.service-now.com/api/now/table/incident?")
    assert update_request.full_url == f"https://acme.service-now.com/api/now/table/incident/{sys_id}"
    assert update_request.get_method() == "PATCH"
    assert update_request.get_header("Authorization") == "Bearer servicenow_test_token"
    assert body["work_notes"].startswith("Forge remediation sync:")
    assert event["action"] == "update"
    assert event["status"] == "delivered"
    assert metadata["servicenow_method"] == "PATCH"
    assert metadata["servicenow_sys_id"] == sys_id
    assert "servicenow_test_token" not in event["metadata_json"]


def test_sync_remediation_tickets_can_deliver_to_soar_webhooks_and_splunk(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    requests: list[object] = []

    class _FakeResponse:
        status = 200

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"ok": true}'

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        assert timeout == 10.0
        return _FakeResponse()

    monkeypatch.setenv("FORGE_TINES_WEBHOOK_TOKEN", "tines_test_token")
    monkeypatch.setenv("FORGE_SPLUNK_HEC_TOKEN", "splunk_test_token")
    monkeypatch.setenv("FORGE_TORQ_WEBHOOK_TOKEN", "torq_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    try:
        sync_kwargs = {
            "engagement_id": 1001,
            "connectors": ("tines", "splunk_hec", "torq"),
            "tines_webhook_url": "https://tenant.tines.com/webhook/forge-secret?token=ignored",
            "splunk_hec_url": "https://splunk.example:8088/services/collector/event?token=bad",
            "splunk_index": "security",
            "splunk_source": "forge-test",
            "torq_webhook_url": "https://hooks.torq.io/v1/webhooks/abc123?foo=bar",
            "operator": "soar-ticket-test",
        }
        result = sync_remediation_tickets(
            con,
            **sync_kwargs,
        )
        second = sync_remediation_tickets(
            con,
            **sync_kwargs,
        )
        events = con.execute(
            """
            SELECT connector, destination, action, status, metadata_json
            FROM remediation_ticket_events
            WHERE remediation_item_id=10
            ORDER BY connector
            """
        ).fetchall()
    finally:
        con.close()

    tines_request, splunk_request, torq_request = requests
    tines_body = json.loads(tines_request.data.decode("utf-8"))
    splunk_body = json.loads(splunk_request.data.decode("utf-8"))
    torq_body = json.loads(torq_request.data.decode("utf-8"))
    metadata_by_connector = {row["connector"]: json.loads(row["metadata_json"]) for row in events}
    destinations = {row["connector"]: row["destination"] for row in events}

    assert result["sync_count"] == 3
    assert second["sync_count"] == 0
    assert len(requests) == 3
    assert tines_request.full_url == "https://tenant.tines.com/webhook/forge-secret?token=ignored"
    assert tines_request.get_header("Authorization") == "Bearer tines_test_token"
    assert tines_body["schema"] == "forge.remediation.automation_event.v1"
    assert tines_body["platform"] == "tines"
    assert tines_body["remediation_item"]["title"] == "Added exposed VPN"
    assert splunk_request.full_url == "https://splunk.example:8088/services/collector/event"
    assert splunk_request.get_header("Authorization") == "Splunk splunk_test_token"
    assert splunk_body["index"] == "security"
    assert splunk_body["source"] == "forge-test"
    assert splunk_body["sourcetype"] == "forge:remediation:ticket"
    assert splunk_body["event"]["event_type"] == "remediation.ticket"
    assert torq_request.full_url == "https://hooks.torq.io/v1/webhooks/abc123?foo=bar"
    assert torq_request.get_header("Authorization") == "Bearer torq_test_token"
    assert torq_body["platform"] == "torq"
    assert destinations["splunk_hec"] == "https://splunk.example:8088/services/collector/event"
    assert destinations["tines"].startswith("https://tenant.tines.com/redacted-webhook-path-")
    assert destinations["torq"].startswith("https://hooks.torq.io/redacted-webhook-path-")
    assert metadata_by_connector["tines"]["automation_platform"] == "tines"
    assert metadata_by_connector["splunk_hec"]["automation_platform"] == "splunk_hec"
    assert metadata_by_connector["torq"]["automation_platform"] == "torq"
    all_metadata = "\n".join(row["metadata_json"] for row in events)
    all_destinations = "\n".join(destinations.values())
    assert "forge-secret" not in all_destinations
    assert "abc123" not in all_destinations
    assert "tines_test_token" not in all_metadata
    assert "splunk_test_token" not in all_metadata
    assert "torq_test_token" not in all_metadata


def test_remediation_ticket_handoff_plan_previews_integrations_without_side_effects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    jsonl_path = tmp_path / "ticket-preview.jsonl"

    def fail_urlopen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("handoff plan must not call external connectors")

    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fail_urlopen)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET metadata_json=?
            WHERE id=10
            """,
            (
                json.dumps(
                    {
                        "source": "monitoring",
                        "escalation": "new_public_exposure",
                        "raw_secret": "do-not-preview",
                        "evidence_url": "https://proof.example/path?token=do-not-preview",
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.commit()

        plan = remediation_ticket_handoff_plan(
            con,
            engagement_id=1001,
            connectors=(
                "jsonl",
                "github_issues",
                "jira",
                "servicenow",
                "tines",
                "splunk_hec",
                "torq",
            ),
            jsonl_path=jsonl_path,
            github_repo="acme/security",
            jira_base_url="https://acme.atlassian.net",
            jira_project_key="SEC",
            servicenow_instance_url="https://acme.service-now.com",
            tines_webhook_url="https://tenant.tines.com/webhook/forge-secret?token=ignored",
            splunk_hec_url="https://splunk.example:8088/services/collector/event?token=bad",
            torq_webhook_url="https://hooks.torq.io/v1/webhooks/abc123?foo=bar",
            splunk_index="security",
            splunk_source="forge-test",
            operator="preview-operator",
        )
        event_count = con.execute("SELECT COUNT(*) FROM remediation_ticket_events").fetchone()[0]
    finally:
        con.close()

    by_connector = {entry["connector"]: entry for entry in plan["connectors"]}
    blob = json.dumps(plan, sort_keys=True)

    assert plan["mode"] == "review_only"
    assert plan["network"] == "disabled"
    assert plan["file_writes"] == "disabled"
    assert plan["item_template_count"] == 7
    assert event_count == 0
    assert not jsonl_path.exists()
    assert by_connector["github_issues"]["items"][0]["template"]["method"] == "POST"
    assert by_connector["github_issues"]["items"][0]["template"]["url"] == (
        "https://api.github.com/repos/acme/security/issues"
    )
    assert by_connector["jira"]["items"][0]["template"]["method"] == "PUT"
    assert by_connector["servicenow"]["items"][0]["template"]["method"] == "POST"
    assert by_connector["splunk_hec"]["items"][0]["template"]["body"]["index"] == "security"
    assert by_connector["tines"]["destination"].startswith(
        "https://tenant.tines.com/redacted-webhook-path-"
    )
    assert by_connector["torq"]["destination"].startswith(
        "https://hooks.torq.io/redacted-webhook-path-"
    )
    assert "forge-secret" not in blob
    assert "abc123" not in blob
    assert "token=bad" not in blob
    assert "do-not-preview" not in blob
    assert "raw_secret" not in blob
    assert "preview-operator" in blob


def test_remediation_integration_runbook_is_value_free_and_policy_aware() -> None:
    runbook = remediation_integration_runbook(
        systems=("github_issues", "jira", "servicenow", "tines", "splunk_hec"),
        close_policy="require_retest_for_resolved",
        status_file="exports/ticket-statuses.jsonl",
    )
    blob = json.dumps(runbook, sort_keys=True)
    systems = {entry["system"]: entry for entry in runbook["systems"]}

    assert runbook["schema"] == "forge.remediation.integration_runbook.v1"
    assert runbook["approval_policy"]["close_policy"] == "require_retest_for_resolved"
    assert runbook["approval_policy"]["requires_retest_for_external_closure"] is True
    assert runbook["safety"]["free_first_default"] is True
    assert runbook["safety"]["secrets_in_output"] is False
    assert runbook["safety"]["network_calls"] is False
    assert "FORGE_GITHUB_TOKEN" in systems["github_issues"]["setup"][0]
    assert "FORGE_JIRA_API_TOKEN" in systems["jira"]["setup"][0]
    assert "FORGE_SPLUNK_HEC_TOKEN" in systems["splunk_hec"]["setup"][0]
    assert "handoff-plan --engagement N --json" in blob
    assert "import-ticket-statuses --data-dir FORGE_DATA_DIR --file exports/ticket-statuses.jsonl --dry-run --json" in blob
    assert "do-not-print" not in blob.lower()
    assert "token=" not in blob.lower()


def test_remediation_cli_sync_tickets_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _build_data_dir_db(data_dir)
    jsonl_path = tmp_path / "cli-tickets.jsonl"

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "sync-tickets",
            "--data-dir",
            str(data_dir),
            "--jsonl-path",
            str(jsonl_path),
            "--operator",
            "cli-ticket-sync",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"sync_count": 1' in result.output
    assert '"failure_count": 0' in result.output
    payload = json.loads(jsonl_path.read_text(encoding="utf-8").splitlines()[0])
    assert payload["action"] == "create"
    assert payload["operator"] == "cli-ticket-sync"
    assert payload["remediation_item"]["owner"] == "it-ops"


def test_remediation_cli_handoff_plan_outputs_review_only_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    def fail_urlopen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("handoff plan must not call external connectors")

    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fail_urlopen)

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "handoff-plan",
            "--engagement",
            "1001",
            "--github-repo",
            "acme/security",
            "--tines-webhook-url",
            "https://tenant.tines.com/webhook/forge-secret?token=ignored",
            "--operator",
            "cli-handoff",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    blob = json.dumps(payload, sort_keys=True)
    assert payload["mode"] == "review_only"
    assert payload["network"] == "disabled"
    assert payload["file_writes"] == "disabled"
    assert payload["connector_count"] == 3
    assert payload["item_template_count"] == 3
    assert "forge-secret" not in blob
    assert "cli-handoff" in blob


def test_remediation_cli_integration_runbook_outputs_json() -> None:
    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "integration-runbook",
            "--system",
            "github_issues",
            "--system",
            "splunk_hec",
            "--close-policy",
            "require_retest_for_resolved",
            "--status-file",
            "exports/statuses.jsonl",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    blob = json.dumps(payload, sort_keys=True)
    assert [entry["system"] for entry in payload["systems"]] == ["github_issues", "splunk_hec"]
    assert payload["approval_policy"]["requires_retest_for_external_closure"] is True
    assert "exports/statuses.jsonl" in blob
    assert "token=" not in blob.lower()


def test_import_remediation_ticket_statuses_reconciles_free_first_exports(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        dry_run = import_remediation_ticket_statuses(
            con,
            engagement_id=1001,
            status_events=[
                {
                    "connector": "github_issues",
                    "remediation_item_id": 10,
                    "ticket_ref": "SEC-42",
                    "status": "closed",
                    "ticket_url": "https://github.com/acme/security/issues/42?token=do-not-store",
                }
            ],
            operator="ticket-import-test",
            dry_run=True,
        )
        unchanged_after_dry_run = con.execute(
            "SELECT status FROM remediation_items WHERE id=10"
        ).fetchone()["status"]
        audit_after_dry_run = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE action='remediation_ticket_status_import'
            """
        ).fetchone()[0]

        result = import_remediation_ticket_statuses(
            con,
            engagement_id=1001,
            status_events=[
                {
                    "connector": "github_issues",
                    "remediation_item_id": 10,
                    "ticket_ref": "SEC-42",
                    "status": "closed",
                    "ticket_url": "https://github.com/acme/security/issues/42?token=do-not-store",
                    "external_updated_at": "2026-08-14T10:00:00Z",
                },
                {
                    "connector": "jira",
                    "ticket_ref": "MISSING-1",
                    "status": "done",
                },
                {
                    "connector": "servicenow",
                    "remediation_item_id": 10,
                    "status": "needs manager review",
                },
            ],
            operator="ticket-import-test",
        )
        row = con.execute(
            """
            SELECT status, ticket_system, ticket_ref, ticket_url, metadata_json
            FROM remediation_items
            WHERE id=10
            """
        ).fetchone()
        audit_row = con.execute(
            """
            SELECT result, operator
            FROM audit_log
            WHERE action='remediation_ticket_status_import'
            """
        ).fetchone()
    finally:
        con.close()

    metadata = json.loads(row["metadata_json"])
    history = metadata["ticket_status_reconciliation"]
    blob = json.dumps(metadata, sort_keys=True)

    assert dry_run["mode"] == "dry_run"
    assert dry_run["summary"]["updated_count"] == 1
    assert dry_run["items"][0]["action"] == "would_update"
    assert unchanged_after_dry_run == "assigned"
    assert audit_after_dry_run == 0
    assert result["mode"] == "apply"
    assert result["summary"]["input_count"] == 3
    assert result["summary"]["matched_count"] == 2
    assert result["summary"]["updated_count"] == 1
    assert result["summary"]["review_count"] == 2
    assert row["status"] == "resolved"
    assert row["ticket_system"] == "github"
    assert row["ticket_ref"] == "SEC-42"
    assert row["ticket_url"] == "https://github.com/acme/security/issues/42"
    assert history[-1]["previous_status"] == "assigned"
    assert history[-1]["new_status"] == "resolved"
    assert history[-1]["external_status"] == "closed"
    assert audit_row["operator"] == "ticket-import-test"
    assert json.loads(audit_row["result"])["new_status"] == "resolved"
    assert "do-not-store" not in blob


def test_import_ticket_statuses_can_require_retest_for_external_closure(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        result = import_remediation_ticket_statuses(
            con,
            engagement_id=1001,
            status_events=[
                {
                    "connector": "github_issues",
                    "remediation_item_id": 10,
                    "ticket_ref": "SEC-42",
                    "status": "closed",
                }
            ],
            operator="ticket-policy-test",
            close_policy="require_retest_for_resolved",
        )
        row = con.execute(
            """
            SELECT status, retest_status, metadata_json
            FROM remediation_items
            WHERE id=10
            """
        ).fetchone()
    finally:
        con.close()

    metadata = json.loads(row["metadata_json"])
    history = metadata["ticket_status_reconciliation"]

    assert result["summary"]["updated_count"] == 1
    assert result["items"][0]["new_status"] == "retest_pending"
    assert result["items"][0]["policy_action"] == "external_close_requires_retest"
    assert row["status"] == "retest_pending"
    assert row["retest_status"] == "pending"
    assert history[-1]["external_status"] == "closed"
    assert history[-1]["new_status"] == "retest_pending"
    assert history[-1]["policy_action"] == "external_close_requires_retest"


def test_remediation_cli_import_ticket_statuses_supports_dry_run_and_apply(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    status_file = tmp_path / "ticket-statuses.jsonl"
    status_file.write_text(
        json.dumps(
            {
                "connector": "github_issues",
                "remediation_item_id": 10,
                "status": "closed",
                "ticket_ref": "99",
                "ticket_url": "https://github.com/acme/security/issues/99?token=bad",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    runner = CliRunner()

    dry_run = runner.invoke(
        app,
        [
            "remediation",
            "import-ticket-statuses",
            "--engagement",
            "1001",
            "--file",
            str(status_file),
            "--dry-run",
            "--json",
        ],
    )
    applied = runner.invoke(
        app,
        [
            "remediation",
            "import-ticket-statuses",
            "--engagement",
            "1001",
            "--file",
            str(status_file),
            "--operator",
            "cli-ticket-import",
            "--json",
        ],
    )
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            "SELECT status, ticket_ref, ticket_url FROM remediation_items WHERE id=10"
        ).fetchone()
    finally:
        con.close()

    assert dry_run.exit_code == 0, dry_run.output
    assert applied.exit_code == 0, applied.output
    dry_payload = json.loads(dry_run.output)
    applied_payload = json.loads(applied.output)
    assert dry_payload["mode"] == "dry_run"
    assert dry_payload["summary"]["updated_count"] == 1
    assert applied_payload["mode"] == "apply"
    assert applied_payload["summary"]["updated_count"] == 1
    assert row["status"] == "resolved"
    assert row["ticket_ref"] == "99"
    assert row["ticket_url"] == "https://github.com/acme/security/issues/99"


def test_remediation_cli_import_ticket_statuses_accepts_close_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    status_file = tmp_path / "ticket-statuses.jsonl"
    status_file.write_text(
        json.dumps(
            {
                "connector": "github_issues",
                "remediation_item_id": 10,
                "status": "closed",
                "ticket_ref": "100",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "import-ticket-statuses",
            "--engagement",
            "1001",
            "--file",
            str(status_file),
            "--close-policy",
            "require_retest_for_resolved",
            "--json",
        ],
    )
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            "SELECT status, retest_status FROM remediation_items WHERE id=10"
        ).fetchone()
    finally:
        con.close()

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["items"][0]["new_status"] == "retest_pending"
    assert payload["items"][0]["policy_action"] == "external_close_requires_retest"
    assert row["status"] == "retest_pending"
    assert row["retest_status"] == "pending"


def test_import_ticket_statuses_for_data_dir_batches_engagement_exports(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    status_file = tmp_path / "ticket-statuses.jsonl"
    status_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "engagement_id": 1001,
                        "connector": "github_issues",
                        "remediation_item_id": 10,
                        "status": "closed",
                        "ticket_ref": "101",
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "engagement_id": 9999,
                        "connector": "jira",
                        "ticket_ref": "SEC-9999",
                        "status": "done",
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    dry_run = import_remediation_ticket_statuses_for_data_dir(
        data_dir,
        status_file=status_file,
        operator="batch-ticket-import",
        dry_run=True,
    )
    apply = import_remediation_ticket_statuses_for_data_dir(
        data_dir,
        status_file=status_file,
        operator="batch-ticket-import",
    )
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT status, ticket_ref FROM remediation_items WHERE id=10").fetchone()
    finally:
        con.close()

    assert dry_run["mode"] == "dry_run"
    assert dry_run["db_count"] == 1
    assert dry_run["input_count"] == 2
    assert dry_run["updated_count"] == 1
    assert dry_run["review_count"] == 1
    assert apply["mode"] == "apply"
    assert apply["updated_count"] == 1
    assert apply["review_count"] == 1
    assert apply["db_results"][0]["review_events"][0]["reason"] == "engagement_not_in_db"
    assert row["status"] == "resolved"
    assert row["ticket_ref"] == "101"


def test_remediation_cli_import_ticket_statuses_can_run_data_dir_batch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    status_file = tmp_path / "ticket-statuses.jsonl"
    status_file.write_text(
        json.dumps(
            {
                "engagement_id": 1001,
                "connector": "github_issues",
                "remediation_item_id": 10,
                "status": "closed",
                "ticket_ref": "102",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / "unused"))

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "import-ticket-statuses",
            "--data-dir",
            str(data_dir),
            "--file",
            str(status_file),
            "--operator",
            "cli-batch-ticket-import",
            "--json",
        ],
    )
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT status, ticket_ref FROM remediation_items WHERE id=10").fetchone()
    finally:
        con.close()

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "apply"
    assert payload["db_count"] == 1
    assert payload["updated_count"] == 1
    assert row["status"] == "resolved"
    assert row["ticket_ref"] == "102"


def test_remediation_cli_request_retest_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / ".forge_data"
    _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "remediation",
            "request-retest",
            "--engagement",
            "1001",
            "--item-id",
            "10",
            "--target",
            "fixture://proof-packs/manual-fixed",
            "--target-kind",
            "fixture",
            "--method",
            "fix_verification",
            "--mode",
            "lab",
            "--approve",
            "--approved-by",
            "lead",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["remediation_item"]["status"] == "retest_pending"
    assert payload["remediation_item"]["retest_status"] == "pending"
    assert payload["active_validation_job"]["method"] == "fix_verification"
    assert payload["active_validation_job"]["mode"] == "lab"
    assert payload["active_validation_job"]["metadata"]["source"] == "remediation_retest"


def test_remediation_cli_propagate_owners_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:88",
            entity_type="finding",
            label="Exposed admin panel",
            source_table="vulnerability_findings",
            source_id=88,
            confidence=0.85,
            metadata={"source": "test"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="network-team",
            owner_kind="team",
            claim_type="manual",
            confidence=0.91,
            source="operator",
            evidence={"reason": "service route"},
        )
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_id, finding_ref,
                 title, severity, owner, status, metadata_json)
            VALUES
                (20, 1001, 'vulnerability_findings', 88, '88',
                 'Exposed admin panel', 'HIGH', NULL, 'open', '{}')
            """
        )
        con.commit()
    finally:
        con.close()

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "propagate-owners",
            "--engagement",
            "1001",
            "--operator",
            "cli-owner",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["assigned_count"] == 1
    assert payload["updated_items"][0]["owner"] == "network-team"
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT owner, status FROM remediation_items WHERE id=20").fetchone()
    finally:
        con.close()
    assert row["owner"] == "network-team"
    assert row["status"] == "assigned"


def test_remediation_cli_draft_from_asset_graph_outputs_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        entry_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="asset:internet:public",
            entity_type="asset",
            label="Public Internet",
            confidence=0.95,
            metadata={"asset_role": "internet_entrypoint"},
        )
        finding_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="finding:vulnerability:asset-graph-public-bucket",
            entity_type="finding",
            label="Public bucket exposure",
            confidence=0.9,
            metadata={
                "severity": "CRITICAL",
                "evidence_url": "https://proof.example.test/path?token=do-not-store",
            },
        )
        upsert_asset_relationship(
            con,
            engagement_id=1001,
            source_entity_id=entry_id,
            target_entity_id=finding_id,
            relationship_type="has_finding",
            confidence=0.9,
            evidence={"secret": "do-not-store-edge"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=finding_id,
            owner_ref="cloud-team",
            owner_kind="team",
            claim_type="explicit",
            confidence=0.9,
            source="operator",
            evidence={"token": "do-not-store-owner"},
        )
        con.commit()
    finally:
        con.close()

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    runner = CliRunner()
    first = runner.invoke(
        app,
        [
            "remediation",
            "draft-from-asset-graph",
            "--engagement",
            "1001",
            "--operator",
            "cli-graph",
            "--limit",
            "5",
            "--json",
        ],
    )
    second = runner.invoke(
        app,
        [
            "remediation",
            "draft-from-asset-graph",
            "--engagement",
            "1001",
            "--operator",
            "cli-graph",
            "--limit",
            "5",
            "--json",
        ],
    )

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    payload = json.loads(first.output)
    assert payload["candidate_count"] >= 1
    assert payload["drafted_count"] >= 1
    assert payload["items"][0]["finding_table"] == "asset_graph"
    assert payload["items"][0]["finding_ref"] == "finding:vulnerability:asset-graph-public-bucket"
    assert payload["items"][0]["owner"] == "cloud-team"
    assert payload["items"][0]["severity"] == "CRITICAL"
    assert "do-not-store" not in first.output
    assert "do-not-store" not in second.output

    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT finding_ref, owner, status
            FROM remediation_items
            WHERE engagement_id=1001 AND finding_table='asset_graph'
            """
        ).fetchall()
    finally:
        con.close()
    assert len(rows) == payload["drafted_count"]
    assert rows[0]["finding_ref"] == "finding:vulnerability:asset-graph-public-bucket"
    assert rows[0]["owner"] == "cloud-team"
    assert rows[0]["status"] == "assigned"
    assert all(not str(row["finding_ref"]).startswith("remediation:") for row in rows)


def test_remediation_cli_review_queue_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / ".forge_data"
    db_path = _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    con = direct_connect(db_path)
    try:
        con.execute(
            """
            UPDATE remediation_items
            SET owner=NULL,
                sla_due_at='2026-07-01T00:00:00Z',
                ticket_system=NULL,
                ticket_ref=NULL,
                ticket_url=NULL
            WHERE id=10
            """
        )
        con.commit()
    finally:
        con.close()

    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "review-queue",
            "--engagement",
            "1001",
            "--limit",
            "2",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["attention_required"] == 1
    assert payload["summary"]["sla_overdue"] == 1
    assert payload["summary"]["missing_owner"] == 1
    assert payload["summary"]["missing_ticket"] == 1
    assert payload["items"][0]["id"] == 10
    assert "SLA overdue" in payload["items"][0]["queue_reason_labels"]


def test_remediation_cli_sync_tickets_accepts_automation_connector_flags(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    _build_data_dir_db(data_dir)
    requests: list[object] = []

    class _FakeResponse:
        status = 200

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def read(self) -> bytes:
            return b'{"ok": true}'

    def fake_urlopen(request: object, timeout: float = 0) -> _FakeResponse:
        requests.append(request)
        return _FakeResponse()

    monkeypatch.setenv("FORGE_TINES_WEBHOOK_TOKEN", "tines_test_token")
    monkeypatch.setattr(remediation_connectors.urllib.request, "urlopen", fake_urlopen)
    app = typer.Typer()
    remediation_app = typer.Typer()
    register_remediation_commands(remediation_app)
    app.add_typer(remediation_app, name="remediation")
    result = CliRunner().invoke(
        app,
        [
            "remediation",
            "sync-tickets",
            "--data-dir",
            str(data_dir),
            "--tines-webhook-url",
            "https://tenant.tines.com/webhook/forge-secret",
            "--operator",
            "cli-ticket-sync",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert '"sync_count": 2' in result.output
    assert '"failure_count": 0' in result.output
    assert requests[0].full_url == "https://tenant.tines.com/webhook/forge-secret"
    assert requests[0].get_header("Authorization") == "Bearer tines_test_token"
    assert "forge-secret" not in result.output
