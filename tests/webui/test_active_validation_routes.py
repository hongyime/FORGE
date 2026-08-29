from typing import Any

import pytest

from forge.webui import active_validation_routes as routes
from forge.webui.active_validation_routes import (
    ActiveValidationRouteError,
    active_validation_approval_requested,
    active_validation_list_payload,
    active_validation_list_route_payload,
    active_validation_live_requested,
    active_validation_run_permissions,
    active_validation_write_permissions,
    approve_active_validation_job_payload,
    approve_active_validation_route_payload,
    create_active_validation_job_payload,
    create_active_validation_route_payload,
    preview_active_validation_job_payload,
    preview_active_validation_route_payload,
    run_active_validation_job_payload,
    run_active_validation_route_payload,
)


def test_active_validation_approval_requested_accepts_approved_aliases() -> None:
    assert active_validation_approval_requested({"approved": True}) is True
    assert active_validation_approval_requested({"approve": True}) is True
    assert active_validation_approval_requested({"approved": False, "approve": False}) is False
    assert active_validation_approval_requested(None) is False
    assert active_validation_write_permissions({"approve": True}) == (
        "active_validation:write",
        "active_validation:approve",
    )
    assert active_validation_write_permissions({}) == ("active_validation:write",)
    assert active_validation_live_requested({"allow_live": True}) is True
    assert active_validation_run_permissions({"allow_live": True}) == (
        "active_validation:run",
        "active_validation:live",
    )
    assert active_validation_run_permissions({}) == ("active_validation:run",)


def test_list_payload_bounds_limit_and_builds_summary(monkeypatch) -> None:
    calls: dict[str, Any] = {}

    def fake_jobs(con: object, **kwargs: Any) -> list[dict[str, Any]]:
        calls["jobs"] = (con, kwargs)
        return [{"id": 1, "status": "queued"}]

    def fake_job_count(con: object, **kwargs: Any) -> int:
        calls["job_count"] = (con, kwargs)
        return 3

    def fake_runs(con: object, **kwargs: Any) -> list[dict[str, Any]]:
        calls["runs"] = (con, kwargs)
        return [{"id": 10, "status": "blocked"}, {"id": 11, "status": "completed"}]

    def fake_coverage(con: object, **kwargs: Any) -> dict[str, Any]:
        calls["coverage"] = (con, kwargs)
        return {
            "summary": {
                "states": {"blocked": 1},
                "attack_mapping_count": 2,
                "control_family_count": 3,
            }
        }

    monkeypatch.setattr(routes, "list_active_validation_jobs", fake_jobs)
    monkeypatch.setattr(routes, "count_active_validation_jobs", fake_job_count)
    monkeypatch.setattr(routes, "list_active_validation_runs", fake_runs)
    monkeypatch.setattr(routes, "active_validation_control_coverage", fake_coverage)
    monkeypatch.setattr(routes, "list_active_validation_methods", lambda: [{"id": "fixture_replay"}])
    monkeypatch.setattr(
        routes,
        "draft_active_validation_scenarios_from_asset_graph",
        lambda con, **kwargs: [{"target_ref": "cloud:bucket:public", "method": "control_simulation"}],
    )
    con = object()

    payload = active_validation_list_payload(
        con,
        engagement_id=1001,
        status=" queued ",
        job_id=7,
        limit=900,
    )

    assert calls["jobs"] == (
        con,
        {"engagement_id": 1001, "status": "queued", "limit": 500},
    )
    assert calls["job_count"] == (
        con,
        {"engagement_id": 1001, "status": "queued"},
    )
    assert calls["runs"] == (
        con,
        {"engagement_id": 1001, "job_id": 7, "limit": 500},
    )
    assert calls["coverage"] == (con, {"engagement_id": 1001})
    assert payload["summary"] == {
        "job_count": 1,
        "run_count": 2,
        "graph_scenario_count": 1,
        "blocked_run_count": 1,
        "completed_run_count": 1,
        "coverage_states": {"blocked": 1},
        "attack_mapping_count": 2,
        "control_family_count": 3,
    }
    assert payload["schema_version"] == "forge.active_validation.list.v1"
    assert payload["execution_policy"] == "read_only_active_validation_inventory_no_commands_executed"
    assert payload["total_count"] == 3
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 2
    assert payload["methods"] == [{"id": "fixture_replay"}]
    assert payload["graph_scenarios"] == [
        {"target_ref": "cloud:bucket:public", "method": "control_simulation"}
    ]
    assert active_validation_list_route_payload(
        con,
        engagement_id=1001,
        status=" queued ",
        job_id=7,
        limit=900,
    )["summary"] == payload["summary"]


def test_preview_payload_normalizes_body_and_wraps_validation_errors(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_preview(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"planned": True}

    monkeypatch.setattr(routes, "preview_active_validation_job", fake_preview)

    payload = preview_active_validation_job_payload(
        engagement_id=1001,
        body={
            "target": "host:app.acme.example",
            "approve": True,
            "mode": "lab",
            "max_steps": "",
            "metadata": ["ignored"],
        },
        requested_by="alice",
    )

    assert payload == {"status": "previewed", "preview": {"planned": True}}
    assert calls == [
        {
            "engagement_id": 1001,
            "target_ref": "host:app.acme.example",
            "target_kind": "asset",
            "method": "fixture_replay",
            "mode": "lab",
            "approved": True,
            "requested_by": "alice",
            "roe_id": "",
            "scope_manifest_ref": "",
            "safe_profile": "non_destructive",
            "max_steps": 1,
            "metadata": {},
        }
    ]
    assert preview_active_validation_route_payload(
        engagement_id=1001,
        body={
            "target": "host:app.acme.example",
            "approve": True,
            "mode": "lab",
            "max_steps": "",
            "metadata": ["ignored"],
        },
        requested_by="alice",
    ) == payload

    monkeypatch.setattr(
        routes,
        "preview_active_validation_job",
        lambda **_: (_ for _ in ()).throw(ValueError("target_ref is required")),
    )
    with pytest.raises(ActiveValidationRouteError, match="target_ref is required"):
        preview_active_validation_job_payload(
            engagement_id=1001,
            body={},
            requested_by="alice",
        )


def test_create_payload_preserves_live_scope_and_requested_by_contract(monkeypatch) -> None:
    calls: list[tuple[object, dict[str, Any]]] = []

    def fake_create(con: object, **kwargs: Any) -> dict[str, Any]:
        calls.append((con, kwargs))
        return {"id": 7, "status": "approved"}

    monkeypatch.setattr(routes, "create_active_validation_job", fake_create)

    with pytest.raises(ActiveValidationRouteError, match="read_only_live approval requires"):
        create_active_validation_job_payload(
            object(),
            engagement_id=1001,
            body={
                "target_ref": "https://app.acme.example",
                "mode": "read_only_live",
                "approved": True,
            },
            requested_by="alice",
        )

    con = object()
    payload = create_active_validation_job_payload(
        con,
        engagement_id=1001,
        body={
            "target_ref": "https://app.acme.example",
            "mode": "read_only_live",
            "approved": True,
            "approval_note": "ok",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": {"domains": ["app.acme.example"]},
            "max_steps": "2",
        },
        requested_by="alice",
    )

    assert payload == {"status": "created", "job": {"id": 7, "status": "approved"}}
    assert create_active_validation_route_payload(
        con,
        engagement_id=1001,
        body={
            "target_ref": "https://app.acme.example",
            "mode": "read_only_live",
            "approved": True,
            "approval_note": "ok",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": {"domains": ["app.acme.example"]},
            "max_steps": "2",
        },
        requested_by="alice",
    ) == payload
    expected_call = (
        con,
        {
            "engagement_id": 1001,
            "target_ref": "https://app.acme.example",
            "target_kind": "asset",
            "method": "fixture_replay",
            "mode": "read_only_live",
            "approved": True,
            "requested_by": "alice",
            "approved_by": "alice",
            "approval_note": "ok",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest_ref": "{'domains': ['app.acme.example']}",
            "safe_profile": "non_destructive",
            "max_steps": 2,
            "metadata": {},
        },
    )
    assert calls == [expected_call, expected_call]


def test_create_payload_forwards_graph_scenario_metadata(monkeypatch) -> None:
    calls: list[tuple[object, dict[str, Any]]] = []

    def fake_create(con: object, **kwargs: Any) -> dict[str, Any]:
        calls.append((con, kwargs))
        return {"id": 8, "metadata": kwargs["metadata"]}

    monkeypatch.setattr(routes, "create_active_validation_job", fake_create)
    con = object()

    payload = create_active_validation_job_payload(
        con,
        engagement_id=1001,
        body={
            "target_ref": "cloud:aws:s3:public",
            "target_kind": "cloud",
            "method": "control_simulation",
            "mode": "lab",
            "metadata": {
                "source": "asset_graph",
                "reason": "restrict_public_sensitive_data_asset",
                "expected_result": "expected_control_blocks_or_alerts",
                "graph": {"path_id": "path:1", "entity_key": "cloud:aws:s3:public"},
            },
        },
        requested_by="alice",
    )

    assert payload == {
        "status": "created",
        "job": {
            "id": 8,
            "metadata": {
                "source": "asset_graph",
                "reason": "restrict_public_sensitive_data_asset",
                "expected_result": "expected_control_blocks_or_alerts",
                "graph": {"path_id": "path:1", "entity_key": "cloud:aws:s3:public"},
            },
        },
    }
    assert calls[0][0] is con
    assert calls[0][1]["metadata"] == {
        "source": "asset_graph",
        "reason": "restrict_public_sensitive_data_asset",
        "expected_result": "expected_control_blocks_or_alerts",
        "graph": {"path_id": "path:1", "entity_key": "cloud:aws:s3:public"},
    }


def test_approve_payload_requires_explicit_live_scope_and_preserves_404(monkeypatch) -> None:
    approve_calls: list[tuple[object, dict[str, Any]]] = []

    def fake_get(con: object, **kwargs: Any) -> dict[str, Any]:
        return {"id": kwargs["job_id"], "mode": "read_only_live"}

    def fake_approve(con: object, **kwargs: Any) -> dict[str, Any]:
        approve_calls.append((con, kwargs))
        return {"id": kwargs["job_id"], "approved": True}

    monkeypatch.setattr(routes, "get_active_validation_job", fake_get)
    monkeypatch.setattr(routes, "approve_active_validation_job", fake_approve)

    with pytest.raises(ActiveValidationRouteError, match="read_only_live approval requires"):
        approve_active_validation_job_payload(
            object(),
            engagement_id=1001,
            job_id=7,
            body={},
            approved_by="alice",
        )
    assert approve_calls == []

    con = object()
    payload = approve_active_validation_job_payload(
        con,
        engagement_id=1001,
        job_id=7,
        body={
            "approval_note": "ok",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest_ref": "scope.json",
        },
        approved_by="alice",
    )

    assert payload == {"status": "approved", "job": {"id": 7, "approved": True}}
    assert approve_active_validation_route_payload(
        con,
        engagement_id=1001,
        job_id=7,
        body={
            "approval_note": "ok",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest_ref": "scope.json",
        },
        approved_by="alice",
    ) == payload
    expected_approve_call = (
        con,
        {
            "engagement_id": 1001,
            "job_id": 7,
            "approved_by": "alice",
            "approval_note": "ok",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest_ref": "scope.json",
        },
    )
    assert approve_calls == [expected_approve_call, expected_approve_call]

    monkeypatch.setattr(
        routes,
        "get_active_validation_job",
        lambda *_, **__: (_ for _ in ()).throw(LookupError("missing job")),
    )
    with pytest.raises(LookupError, match="missing job"):
        approve_active_validation_job_payload(
            object(),
            engagement_id=1001,
            job_id=404,
            body={},
            approved_by="alice",
        )


def test_run_payload_disables_environment_live_override(monkeypatch) -> None:
    calls: list[tuple[object, dict[str, Any]]] = []

    def fake_run(con: object, **kwargs: Any) -> dict[str, Any]:
        calls.append((con, kwargs))
        return {"id": 3, "status": "completed"}

    monkeypatch.setattr(routes, "run_active_validation_job", fake_run)
    con = object()

    payload = run_active_validation_job_payload(
        con,
        engagement_id=1001,
        job_id=7,
        operator="alice",
        allow_live=True,
    )

    assert payload == {"status": "ran", "run": {"id": 3, "status": "completed"}}
    assert run_active_validation_route_payload(
        con,
        engagement_id=1001,
        job_id=7,
        operator="alice",
        body={"allow_live": True},
    ) == payload
    expected_run_call = (
        con,
        {
            "engagement_id": 1001,
            "job_id": 7,
            "operator": "alice",
            "allow_live": True,
            "allow_env_live": False,
        },
    )
    assert calls == [expected_run_call, expected_run_call]
