import sqlite3
from pathlib import Path
from typing import Any

import pytest

from forge.webui import remediation_routes as routes
from forge.webui.remediation_routes import (
    RemediationRouteError,
    RemediationRouteNotFound,
    create_remediation_payload,
    create_remediation_route_payload,
    draft_asset_graph_remediation_payload,
    draft_asset_graph_remediation_route_payload,
    list_remediation_payload,
    list_remediation_route_payload,
    propagate_remediation_owners_payload,
    propagate_remediation_owners_route_payload,
    remediation_draft_from_graph_permissions,
    remediation_export_payload,
    remediation_export_route_payload,
    remediation_propagate_permissions,
    remediation_retest_permissions,
    review_remediation_owner_payload,
    review_remediation_owner_route_payload,
    request_remediation_retest_payload,
    request_remediation_retest_route_payload,
    sync_remediation_ticket_payload,
    sync_remediation_ticket_route_payload,
    update_remediation_payload,
    update_remediation_route_payload,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase TEXT,
            module TEXT,
            action TEXT,
            target TEXT,
            result TEXT,
            operator TEXT
        );

        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            title TEXT,
            severity TEXT,
            target_url TEXT,
            parameter TEXT,
            vuln_type TEXT
        );

        CREATE TABLE monitoring_alerts (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            title TEXT,
            severity TEXT,
            alert_type TEXT
        );

        CREATE TABLE remediation_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            finding_table TEXT,
            finding_id INTEGER,
            finding_ref TEXT,
            title TEXT,
            severity TEXT,
            owner TEXT,
            sla_due_at TEXT,
            status TEXT,
            risk_acceptance_reason TEXT,
            risk_accepted_by TEXT,
            risk_accepted_at TEXT,
            risk_acceptance_expires_at TEXT,
            retest_status TEXT DEFAULT 'not_requested',
            retest_requested_at TEXT,
            retested_at TEXT,
            ticket_system TEXT,
            ticket_ref TEXT,
            ticket_url TEXT,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, finding_table, finding_ref)
        );
        """
    )
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (id, engagement_id, title, severity, target_url, parameter, vuln_type)
        VALUES
            (1, 1001, 'Validated Firebase data exposure', 'HIGH',
             'https://app.acme.example', 'firebase', 'FIREBASE_EXPOSURE')
        """
    )
    con.commit()
    return con


def test_create_list_and_export_payloads_preserve_remediation_contract(monkeypatch) -> None:
    con = _connect()
    monkeypatch.setattr(
        routes,
        "remediation_review_queue",
        lambda *_args, **_kwargs: {"summary": {"attention_required": 0}, "items": []},
    )

    payload = create_remediation_payload(
        con,
        engagement_id=1001,
        body={
            "finding_table": "vulnerability_findings",
            "finding_id": 1,
            "owner": "appsec",
            "sla_due_at": "2026-08-20T00:00:00",
            "status": "assigned",
            "ticket_ref": "SEC-1001",
            "metadata": {"source": "unit"},
        },
        operator="alice",
    )

    item = payload["item"]
    assert payload["status"] == "upserted"
    assert item["finding_ref"] == "1"
    assert item["title"] == "Validated Firebase data exposure"
    assert item["severity"] == "HIGH"
    assert item["owner"] == "appsec"
    assert item["ticket_ref"] == "SEC-1001"
    assert item["metadata"] == {"source": "unit"}

    listed = list_remediation_payload(con, engagement_id=1001)
    assert listed["summary"]["total"] == 1
    assert listed["summary"]["with_owner"] == 1
    assert listed["review_queue"]["summary"]["attention_required"] == 0
    assert list_remediation_route_payload(con, engagement_id=1001)["summary"]["total"] == 1

    csv_export = remediation_export_payload(
        con,
        engagement_id=1001,
        export_format="csv",
        operator="alice",
    )
    assert csv_export["filename"] == "engagement_1001_remediation.csv"
    assert "risk_acceptance_review_status" in str(csv_export["content"])
    assert "SEC-1001" in str(csv_export["content"])

    json_export = remediation_export_payload(
        con,
        engagement_id=1001,
        export_format="json",
        operator="alice",
    )
    assert json_export["content"]["summary"]["total"] == 1
    assert remediation_export_route_payload(
        con,
        engagement_id=1001,
        export_format="json",
        operator="alice",
    )["content"]["summary"]["total"] == 1

    actions = [
        row[0]
        for row in con.execute("SELECT action FROM audit_log ORDER BY id").fetchall()
    ]
    assert actions == [
        "remediation_upsert",
        "remediation_export",
        "remediation_export",
        "remediation_export",
    ]


def test_update_payload_merges_metadata_and_preserves_dynamic_permission_order() -> None:
    con = _connect()
    create_remediation_payload(
        con,
        engagement_id=1001,
        body={"finding_table": "vulnerability_findings", "finding_id": 1},
        operator="alice",
    )
    item_id = int(
        con.execute("SELECT id FROM remediation_items WHERE engagement_id=1001").fetchone()[0]
    )
    permissions: list[str] = []

    with pytest.raises(PermissionError):
        update_remediation_payload(
            con,
            engagement_id=1001,
            item_id=item_id,
            body={"status": "risk_accepted"},
            operator="bob",
            require_permission=lambda permission: (_ for _ in ()).throw(
                PermissionError(permission)
            ),
        )

    payload = update_remediation_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={
            "status": "risk_accepted",
            "risk_acceptance_reason": "Accepted through renewal.",
            "risk_acceptance_expires_at": "2026-12-31T00:00:00Z",
            "retest_status": "pending",
            "metadata": {"reviewer": "lead"},
        },
        operator="bob",
        require_permission=permissions.append,
    )

    assert permissions == ["remediation:accept", "remediation:retest"]
    item = payload["item"]
    assert item["status"] == "risk_accepted"
    assert item["risk_accepted_by"] == "bob"
    assert item["risk_acceptance_reason"] == "Accepted through renewal."
    assert item["risk_acceptance_expires_at"] == "2026-12-31T00:00:00Z"
    assert item["retest_status"] == "pending"
    assert item["metadata"] == {"reviewer": "lead"}
    assert update_remediation_route_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={"title": "Validated Firebase data exposure"},
        operator="bob",
    )["status"] == "updated"


def test_request_retest_payload_preserves_active_validation_gate_and_scope(monkeypatch) -> None:
    con = _connect()
    calls: list[tuple[sqlite3.Connection, dict[str, Any]]] = []

    def fake_request(con_arg: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        calls.append((con_arg, kwargs))
        return {"remediation_item": {"id": kwargs["remediation_item_id"]}}

    monkeypatch.setattr(routes, "request_active_validation_retest", fake_request)

    permissions: list[str] = []
    payload = request_remediation_retest_payload(
        con,
        engagement_id=1001,
        item_id=7,
        body={
            "target": "fixture://proof",
            "approve": True,
            "mode": "lab",
            "metadata": ["ignored"],
        },
        operator="alice",
        require_permission=permissions.append,
    )

    assert payload == {"status": "requested", "remediation_item": {"id": 7}}
    assert permissions == ["active_validation:approve"]
    assert remediation_retest_permissions() == (
        "remediation:write",
        "remediation:retest",
        "active_validation:write",
    )
    assert calls[0][1]["target_ref"] == "fixture://proof"
    assert calls[0][1]["approved_by"] == "alice"
    assert calls[0][1]["metadata"] == {}

    with pytest.raises(RemediationRouteError, match="read_only_live retest approval"):
        request_remediation_retest_payload(
            con,
            engagement_id=1001,
            item_id=7,
            body={"approve": True, "mode": "read_only_live"},
            operator="alice",
        )
    assert request_remediation_retest_route_payload(
        con,
        engagement_id=1001,
        item_id=7,
        body={"target": "fixture://proof", "mode": "lab"},
        operator="alice",
    )["status"] == "requested"


def test_draft_asset_graph_remediation_payload_refreshes_reviewable_state(
    monkeypatch,
) -> None:
    con = _connect()
    calls: list[tuple[sqlite3.Connection, dict[str, Any]]] = []

    def fake_draft(con_arg: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        calls.append((con_arg, kwargs))
        con_arg.execute(
            """
            INSERT INTO remediation_items
                (engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, metadata_json)
            VALUES
                (?, 'asset_graph', 'cloud_ref:aws_s3:public-data',
                 'Reduce public cloud exposure path', 'CRITICAL',
                 'cloud-team', '2026-08-21T00:00:00Z', 'assigned',
                 '{"source":"asset_graph"}')
            """,
            (kwargs["engagement_id"],),
        )
        con_arg.commit()
        return {
            "engagement_id": kwargs["engagement_id"],
            "candidate_count": 1,
            "drafted_count": 1,
            "skipped_count": 0,
        }

    monkeypatch.setattr(routes, "draft_remediation_from_asset_graph_candidates", fake_draft)
    monkeypatch.setattr(
        routes,
        "remediation_review_queue",
        lambda *_args, **_kwargs: {
            "summary": {"attention_required": 1},
            "items": [{"id": 1, "reason": "missing_ticket"}],
        },
    )

    payload = draft_asset_graph_remediation_payload(
        con,
        engagement_id=1001,
        body={"limit": "2"},
        operator="alice",
    )

    assert calls[0][0] is con
    assert calls[0][1]["engagement_id"] == 1001
    assert calls[0][1]["operator"] == "alice"
    assert calls[0][1]["limit"] == 2
    assert payload["status"] == "drafted"
    assert payload["drafted_count"] == 1
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["with_owner"] == 1
    assert payload["items"][0]["finding_table"] == "asset_graph"
    assert payload["items"][0]["metadata"] == {"source": "asset_graph"}
    assert payload["review_queue"]["summary"]["attention_required"] == 1
    assert remediation_draft_from_graph_permissions() == ("remediation:write", "assets:read")
    route_con = _connect()
    assert draft_asset_graph_remediation_route_payload(
        route_con,
        engagement_id=1001,
        body={"limit": "2"},
        operator="alice",
    )["status"] == "drafted"

    with pytest.raises(RemediationRouteError, match="limit must be an integer"):
        draft_asset_graph_remediation_payload(
            con,
            engagement_id=1001,
            body={"limit": "two"},
            operator="alice",
        )

    with pytest.raises(RemediationRouteError, match="limit must be at least 1"):
        draft_asset_graph_remediation_payload(
            con,
            engagement_id=1001,
            body={"limit": 0},
            operator="alice",
        )


def test_propagate_remediation_owners_payload_passes_policy_controls(monkeypatch) -> None:
    con = _connect()
    create_remediation_payload(
        con,
        engagement_id=1001,
        body={"finding_table": "vulnerability_findings", "finding_id": 1},
        operator="alice",
    )
    calls: list[tuple[sqlite3.Connection, dict[str, Any]]] = []

    def fake_propagate(con_arg: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        calls.append((con_arg, kwargs))
        return {
            "engagement_id": kwargs["engagement_id"],
            "scanned_count": 1,
            "assigned_count": 0,
            "unresolved_count": 0,
            "skipped_existing_owner_count": 0,
            "skipped_terminal_count": 0,
            "skipped_no_reference_count": 0,
            "skipped_conflict_count": 1,
            "skipped_low_confidence_count": 0,
            "overwrite": kwargs["overwrite"],
            "conflict_policy": kwargs["conflict_policy"],
            "min_confidence": kwargs["min_confidence"],
            "updated_items": [],
        }

    monkeypatch.setattr(routes, "propagate_asset_owners_to_remediation", fake_propagate)
    monkeypatch.setattr(
        routes,
        "remediation_review_queue",
        lambda *_args, **_kwargs: {"summary": {}, "items": []},
    )

    payload = propagate_remediation_owners_payload(
        con,
        engagement_id=1001,
        body={
            "overwrite": "yes",
            "conflict_policy": "skip_conflicts",
            "min_confidence": "0.75",
            "limit": "25",
        },
        operator="alice",
    )

    assert calls[0][0] is con
    assert calls[0][1]["engagement_id"] == 1001
    assert calls[0][1]["operator"] == "alice"
    assert calls[0][1]["overwrite"] is True
    assert calls[0][1]["conflict_policy"] == "skip_conflicts"
    assert calls[0][1]["min_confidence"] == 0.75
    assert calls[0][1]["limit"] == 25
    assert payload["status"] == "propagated"
    assert payload["skipped_conflict_count"] == 1
    assert payload["conflict_policy"] == "skip_conflicts"
    assert payload["min_confidence"] == 0.75
    assert remediation_propagate_permissions() == ("remediation:write", "assets:read")
    assert propagate_remediation_owners_route_payload(
        con,
        engagement_id=1001,
        body={"limit": "25"},
        operator="alice",
    )["status"] == "propagated"

    with pytest.raises(RemediationRouteError, match="min_confidence must be a number"):
        propagate_remediation_owners_payload(
            con,
            engagement_id=1001,
            body={"min_confidence": "high"},
            operator="alice",
        )

    with pytest.raises(RemediationRouteError, match="min_confidence must be between 0 and 1"):
        propagate_remediation_owners_payload(
            con,
            engagement_id=1001,
            body={"min_confidence": 1.5},
            operator="alice",
        )


def test_review_owner_payload_records_approval_history_and_reopens_rejections() -> None:
    con = _connect()
    create_remediation_payload(
        con,
        engagement_id=1001,
        body={
            "finding_table": "vulnerability_findings",
            "finding_id": 1,
            "owner": "appsec",
            "status": "assigned",
            "metadata": {"source": "unit"},
        },
        operator="alice",
    )
    item_id = int(
        con.execute("SELECT id FROM remediation_items WHERE engagement_id=1001").fetchone()[0]
    )

    approved = review_remediation_owner_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={"decision": "approved", "note": "owner confirmed"},
        operator="lead",
    )
    rejected = review_remediation_owner_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={"decision": "rejected", "note": "route changed"},
        operator="lead",
    )
    audit_rows = con.execute(
        """
        SELECT action, target, result, operator
        FROM audit_log
        WHERE action='remediation_owner_review'
        ORDER BY id
        """
    ).fetchall()

    assert approved["status"] == "reviewed"
    assert approved["decision"] == "approved"
    assert approved["item"]["owner"] == "appsec"
    assert approved["item"]["owner_approval"]["decision"] == "approved"
    assert approved["item"]["owner_approval"]["reviewed_by"] == "lead"
    assert approved["item"]["metadata"]["source"] == "unit"
    assert rejected["decision"] == "rejected"
    assert rejected["item"]["owner"] == ""
    assert rejected["item"]["status"] == "open"
    assert rejected["item"]["owner_approval"]["decision"] == "rejected"
    assert len(rejected["item"]["metadata"]["owner_approval_history"]) == 2
    assert rejected["summary"]["total"] == 1
    assert rejected["review_queue"]["summary"]["missing_owner"] == 1
    assert review_remediation_owner_route_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={"decision": "needs_review", "note": "double-check"},
        operator="lead",
    )["status"] == "reviewed"
    assert [row["operator"] for row in audit_rows] == ["lead", "lead"]
    assert audit_rows[0]["target"] == f"remediation_items:{item_id}"
    assert "decision=approved" in audit_rows[0]["result"]
    assert "decision=rejected" in audit_rows[1]["result"]

    with pytest.raises(RemediationRouteError, match="decision is required"):
        review_remediation_owner_payload(
            con,
            engagement_id=1001,
            item_id=item_id,
            body={},
            operator="lead",
        )

    with pytest.raises(RemediationRouteError, match="owner approval requires an assigned owner"):
        review_remediation_owner_payload(
            con,
            engagement_id=1001,
            item_id=item_id,
            body={"decision": "approved"},
            operator="lead",
        )


def test_sync_ticket_payload_builds_connectors_and_audits(monkeypatch, tmp_path: Path) -> None:
    con = _connect()
    create_remediation_payload(
        con,
        engagement_id=1001,
        body={"finding_table": "vulnerability_findings", "finding_id": 1},
        operator="alice",
    )
    item_id = int(
        con.execute("SELECT id FROM remediation_items WHERE engagement_id=1001").fetchone()[0]
    )
    calls: list[tuple[sqlite3.Connection, dict[str, Any]]] = []

    def fake_sync(con_arg: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        calls.append((con_arg, kwargs))
        return {"sync_count": 2, "failure_count": 0}

    monkeypatch.setattr(routes, "sync_remediation_tickets", fake_sync)

    payload = sync_remediation_ticket_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={
            "webhook_url": "https://hooks.example/forge",
            "github_repo": "acme/sec",
            "force": "yes",
        },
        operator="alice",
        data_dir=tmp_path,
        db_path=tmp_path / "engagement.db",
    )

    assert payload == {"status": "synced", "sync_count": 2, "failure_count": 0}
    assert calls[0][1]["connectors"] == ["jsonl", "webhook", "github_issues"]
    assert calls[0][1]["jsonl_path"] == tmp_path / "remediation_tickets.jsonl"
    assert calls[0][1]["force"] is True
    audit = con.execute(
        "SELECT target, result FROM audit_log WHERE action='remediation_ticket_sync'"
    ).fetchone()
    assert audit["target"] == str(item_id)
    assert audit["result"] == "synced=2 failures=0"
    assert sync_remediation_ticket_route_payload(
        con,
        engagement_id=1001,
        item_id=item_id,
        body={"force": True},
        operator="alice",
        data_dir=tmp_path,
        db_path=tmp_path / "engagement.db",
    )["status"] == "synced"

    with pytest.raises(RemediationRouteNotFound, match="Remediation item not found"):
        sync_remediation_ticket_payload(
            con,
            engagement_id=1001,
            item_id=999,
            body={},
            operator="alice",
            data_dir=tmp_path,
            db_path=tmp_path / "engagement.db",
        )
