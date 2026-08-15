from typing import Any

import pytest

from forge.webui import monitoring_routes as routes
from forge.webui.monitoring_routes import (
    MonitoringRouteError,
    add_monitoring_alert_suppression_payload,
    add_monitoring_alert_suppression_route_payload,
    create_monitoring_snapshot_payload,
    create_monitoring_snapshot_route_payload,
    escalate_monitoring_alert_to_remediation_payload,
    escalate_monitoring_alert_to_remediation_route_payload,
    monitoring_overview_payload,
    monitoring_overview_route_payload,
    run_due_monitoring_policies_payload,
    run_due_monitoring_policies_route_payload,
    update_monitoring_alert_payload,
    update_monitoring_alert_route_payload,
    upsert_monitoring_alert_route_payload,
    upsert_monitoring_alert_route_dispatch_payload,
    upsert_monitoring_policy_payload,
    upsert_monitoring_policy_route_payload,
)


class _FakeConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.executed.append((sql, params))

    def commit(self) -> None:
        self.commits += 1


def test_monitoring_overview_payload_adds_routes_and_suppressions(monkeypatch) -> None:
    calls: list[tuple[str, Any, dict[str, Any]]] = []

    def fake_overview(con: object, engagement_id: int) -> dict[str, Any]:
        calls.append(("overview", con, {"engagement_id": engagement_id}))
        return {"policies": []}

    def fake_routes(con: object, **kwargs: Any) -> list[dict[str, Any]]:
        calls.append(("routes", con, kwargs))
        return [{"name": "appsec-local"}]

    def fake_suppressions(con: object, **kwargs: Any) -> list[dict[str, Any]]:
        calls.append(("suppressions", con, kwargs))
        return [{"reason": "maintenance"}]

    monkeypatch.setattr(routes, "monitoring_overview", fake_overview)
    monkeypatch.setattr(routes, "list_monitoring_alert_routes", fake_routes)
    monkeypatch.setattr(routes, "list_monitoring_alert_suppressions", fake_suppressions)
    con = object()

    payload = monitoring_overview_payload(con, engagement_id=1001)

    assert payload == {
        "policies": [],
        "alert_routes": [{"name": "appsec-local"}],
        "alert_suppressions": [{"reason": "maintenance"}],
    }
    assert calls == [
        ("overview", con, {"engagement_id": 1001}),
        ("routes", con, {"engagement_id": 1001}),
        ("suppressions", con, {"engagement_id": 1001}),
    ]
    assert monitoring_overview_route_payload(con, engagement_id=1001) == payload


def test_upsert_policy_payload_normalizes_body_and_audits(monkeypatch) -> None:
    calls: list[tuple[_FakeConnection, dict[str, Any]]] = []

    def fake_upsert(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        calls.append((con, kwargs))
        return {"name": kwargs["name"], "enabled": kwargs["enabled"]}

    monkeypatch.setattr(routes, "upsert_monitoring_policy", fake_upsert)
    con = _FakeConnection()

    payload = upsert_monitoring_policy_payload(
        con,
        engagement_id=1001,
        body={
            "name": "Hourly passive",
            "enabled": "off",
            "interval_minutes": "60",
            "metadata": ["ignored"],
        },
        operator="alice",
    )

    assert payload == {
        "status": "upserted",
        "policy": {"name": "Hourly passive", "enabled": False},
    }
    assert calls == [
        (
            con,
            {
                "engagement_id": 1001,
                "name": "Hourly passive",
                "enabled": False,
                "schedule_interval_minutes": 60,
                "mode": "passive",
                "metadata": {},
            },
        )
    ]
    assert con.executed[-1][1] == (1001, "Hourly passive", "alice")
    assert con.commits == 1
    route_con = _FakeConnection()
    assert upsert_monitoring_policy_route_payload(
        route_con,
        engagement_id=1001,
        body={
            "name": "Hourly passive",
            "enabled": "off",
            "interval_minutes": "60",
            "metadata": ["ignored"],
        },
        operator="alice",
    )["status"] == "upserted"

    with pytest.raises(MonitoringRouteError, match="schedule_interval_minutes"):
        upsert_monitoring_policy_payload(
            _FakeConnection(),
            engagement_id=1001,
            body={"schedule_interval_minutes": "soon"},
            operator="alice",
        )


def test_alert_route_and_suppression_payloads_validate_and_audit(monkeypatch) -> None:
    route_calls: list[tuple[_FakeConnection, dict[str, Any]]] = []
    suppression_calls: list[tuple[_FakeConnection, dict[str, Any]]] = []

    def fake_route(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        route_calls.append((con, kwargs))
        return {
            "name": kwargs["name"],
            "channel": kwargs["channel"],
            "min_severity": kwargs["min_severity"],
        }

    def fake_suppression(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        suppression_calls.append((con, kwargs))
        return {
            "entity_key": kwargs["entity_key"],
            "entity_prefix": kwargs["entity_prefix"],
            "reason": kwargs["reason"],
        }

    monkeypatch.setattr(routes, "upsert_monitoring_alert_route", fake_route)
    monkeypatch.setattr(routes, "add_monitoring_alert_suppression", fake_suppression)

    with pytest.raises(MonitoringRouteError, match="destination is required"):
        upsert_monitoring_alert_route_payload(
            _FakeConnection(),
            engagement_id=1001,
            body={"name": "alerts", "channel": "webhook"},
            operator="alice",
        )

    route_con = _FakeConnection()
    assert upsert_monitoring_alert_route_payload(
        route_con,
        engagement_id=1001,
        body={
            "name": "appsec-local",
            "channel": "jsonl",
            "destination": "alerts.jsonl",
            "enabled": "no",
            "min_severity": "HIGH",
            "owner": "appsec",
        },
        operator="alice",
    )["status"] == "upserted"
    assert route_calls[0][1]["enabled"] is False
    assert route_calls[0][1]["owner"] == "appsec"
    assert route_con.executed[-1][1] == (
        1001,
        "appsec-local",
        "jsonl severity>=HIGH",
        "alice",
    )
    route_dispatch_con = _FakeConnection()
    assert upsert_monitoring_alert_route_dispatch_payload(
        route_dispatch_con,
        engagement_id=1001,
        body={
            "name": "appsec-local",
            "channel": "jsonl",
            "destination": "alerts.jsonl",
            "enabled": "no",
            "min_severity": "HIGH",
            "owner": "appsec",
        },
        operator="alice",
    )["status"] == "upserted"

    suppression_con = _FakeConnection()
    assert add_monitoring_alert_suppression_payload(
        suppression_con,
        engagement_id=1001,
        body={
            "entity_prefix": "host:maintenance.",
            "reason": "maintenance window",
            "expires_at": "",
        },
        operator="alice",
    )["status"] == "created"
    assert suppression_calls[0][1]["created_by"] == "alice"
    assert suppression_calls[0][1]["expires_at"] is None
    assert suppression_con.executed[-1][1] == (
        1001,
        "host:maintenance.",
        "maintenance window",
        "alice",
    )
    suppression_route_con = _FakeConnection()
    assert add_monitoring_alert_suppression_route_payload(
        suppression_route_con,
        engagement_id=1001,
        body={
            "entity_prefix": "host:maintenance.",
            "reason": "maintenance window",
            "expires_at": "",
        },
        operator="alice",
    )["status"] == "created"


def test_snapshot_and_run_due_payloads_parse_body_and_audit(monkeypatch) -> None:
    snapshot_calls: list[tuple[_FakeConnection, dict[str, Any]]] = []
    due_calls: list[tuple[_FakeConnection, dict[str, Any]]] = []

    def fake_snapshot(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        snapshot_calls.append((con, kwargs))
        return {"snapshot": {"id": 12}, "changes": [{}], "alerts": [{}, {}]}

    def fake_run_due(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        due_calls.append((con, kwargs))
        return {"run_count": 1}

    monkeypatch.setattr(routes, "create_monitoring_snapshot", fake_snapshot)
    monkeypatch.setattr(routes, "run_due_monitoring_policies", fake_run_due)

    with pytest.raises(MonitoringRouteError, match="policy_id"):
        create_monitoring_snapshot_payload(
            _FakeConnection(),
            engagement_id=1001,
            body={"policy_id": "abc"},
            operator="alice",
        )

    snapshot_con = _FakeConnection()
    payload = create_monitoring_snapshot_payload(
        snapshot_con,
        engagement_id=1001,
        body={"policy_id": "7", "snapshot_kind": "scheduled"},
        operator="alice",
    )
    assert payload["snapshot"]["id"] == 12
    assert snapshot_calls == [
        (
            snapshot_con,
            {
                "engagement_id": 1001,
                "policy_id": 7,
                "snapshot_kind": "scheduled",
            },
        )
    ]
    assert snapshot_con.executed[-1][1] == (1001, "12", "changes=1 alerts=2", "alice")
    snapshot_route_con = _FakeConnection()
    assert create_monitoring_snapshot_route_payload(
        snapshot_route_con,
        engagement_id=1001,
        body={"policy_id": "7", "snapshot_kind": "scheduled"},
        operator="alice",
    )["snapshot"]["id"] == 12

    due_con = _FakeConnection()
    assert run_due_monitoring_policies_payload(
        due_con,
        engagement_id=1001,
        body={"now": " 2026-07-09T10:00:00Z "},
        operator="scheduler",
    ) == {"run_count": 1}
    assert due_calls == [
        (
            due_con,
            {
                "engagement_id": 1001,
                "now": "2026-07-09T10:00:00Z",
                "operator": "scheduler",
            },
        )
    ]
    assert run_due_monitoring_policies_route_payload(
        _FakeConnection(),
        engagement_id=1001,
        body={"now": " 2026-07-09T10:00:00Z "},
        operator="scheduler",
    ) == {"run_count": 1}


def test_alert_update_and_remediation_payloads_preserve_error_and_audit_contract(
    monkeypatch,
) -> None:
    update_calls: list[tuple[_FakeConnection, dict[str, Any]]] = []
    remediation_calls: list[tuple[_FakeConnection, dict[str, Any]]] = []

    def fake_update(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        update_calls.append((con, kwargs))
        return {"id": kwargs["alert_id"], "status": kwargs["status"]}

    def fake_remediation(con: _FakeConnection, **kwargs: Any) -> dict[str, Any]:
        remediation_calls.append((con, kwargs))
        return {"id": 5, "owner": kwargs["owner"], "status": "assigned"}

    monkeypatch.setattr(routes, "update_monitoring_alert_status", fake_update)
    monkeypatch.setattr(routes, "upsert_monitoring_alert_remediation", fake_remediation)

    update_con = _FakeConnection()
    assert update_monitoring_alert_payload(
        update_con,
        engagement_id=1001,
        alert_id=42,
        body={"status": "resolved"},
        operator="alice",
    ) == {"status": "updated", "alert": {"id": 42, "status": "resolved"}}
    assert update_calls[0][1] == {
        "engagement_id": 1001,
        "alert_id": 42,
        "status": "resolved",
    }
    assert update_con.executed[-1][1] == (1001, "42", "resolved", "alice")
    update_route_con = _FakeConnection()
    assert update_monitoring_alert_route_payload(
        update_route_con,
        engagement_id=1001,
        alert_id=42,
        body={"status": "resolved"},
        operator="alice",
    ) == {"status": "updated", "alert": {"id": 42, "status": "resolved"}}

    remediation_con = _FakeConnection()
    assert escalate_monitoring_alert_to_remediation_payload(
        remediation_con,
        engagement_id=1001,
        alert_id=42,
        body={"owner": "appsec", "sla_days": 7, "metadata": ["ignored"]},
        operator="alice",
    ) == {"status": "upserted", "item": {"id": 5, "owner": "appsec", "status": "assigned"}}
    assert remediation_calls[0][1]["metadata"] == {}
    assert remediation_calls[0][1]["sla_days"] == 7
    assert remediation_con.executed[-1][1] == (
        1001,
        "monitoring_alerts:42",
        "owner=appsec status=assigned",
        "alice",
    )
    remediation_route_con = _FakeConnection()
    assert escalate_monitoring_alert_to_remediation_route_payload(
        remediation_route_con,
        engagement_id=1001,
        alert_id=42,
        body={"owner": "appsec", "sla_days": 7, "metadata": ["ignored"]},
        operator="alice",
    ) == {"status": "upserted", "item": {"id": 5, "owner": "appsec", "status": "assigned"}}

    monkeypatch.setattr(
        routes,
        "update_monitoring_alert_status",
        lambda *_, **__: (_ for _ in ()).throw(ValueError("bad status")),
    )
    with pytest.raises(MonitoringRouteError, match="bad status"):
        update_monitoring_alert_payload(
            _FakeConnection(),
            engagement_id=1001,
            alert_id=42,
            body={"status": "bad"},
            operator="alice",
        )
