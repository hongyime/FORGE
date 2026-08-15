from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from forge.db.control import connect_control_db, list_control_audit_events, verify_control_audit_chain
from forge.webui.app import create_app
from forge.webui.auth import mint_token, verify_principal


def _configure_webui_env(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")


def _headers(subject: str, *, role: str, workspace_id: str = "default") -> dict[str, str]:
    return {
        "Authorization": (
            "Bearer "
            + mint_token(
                subject,
                roles=(role,),
                workspace_id=workspace_id,
            )
        )
    }


def _token_headers(
    subject: str,
    *,
    workspace_id: str,
    permissions: tuple[str, ...],
) -> dict[str, str]:
    return {
        "Authorization": (
            "Bearer "
            + mint_token(
                subject,
                roles=(),
                permissions=permissions,
                workspace_id=workspace_id,
            )
        )
    }


def test_viewer_role_can_read_but_not_mutate_engagement_routes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        operator_headers = _headers("delta-one", role="operator")
        create_resp = client.post(
            "/api/engagements",
            json={
                "name": "Acme RBAC",
                "status": "ACTIVE",
                "seeds": ["acme.example"],
            },
            headers=operator_headers,
        )
        assert create_resp.status_code == 200, create_resp.text
        slug = create_resp.json()["slug"]

        viewer_headers = _headers("delta-one", role="viewer")
        detail_resp = client.get(f"/api/engagements/{slug}", headers=viewer_headers)
        assert detail_resp.status_code == 200, detail_resp.text

        seeds_resp = client.get(f"/api/engagements/{slug}/seeds", headers=viewer_headers)
        assert seeds_resp.status_code == 200, seeds_resp.text
        assert seeds_resp.json()["items"]
        viewer_principal = verify_principal(
            viewer_headers["Authorization"].removeprefix("Bearer ")
        )
        assert viewer_principal is not None
        assert viewer_principal.has_permission("retention:read")
        assert not viewer_principal.has_permission("retention:write")

        update_resp = client.patch(
            f"/api/engagements/{slug}",
            json={"status": "COMPLETE"},
            headers=viewer_headers,
        )
        assert update_resp.status_code == 403, update_resp.text
        assert update_resp.json()["detail"] == "Missing required permission: engagements:write"

        rebuild_resp = client.post(
            f"/api/engagements/{slug}/asset-graph/rebuild",
            headers=viewer_headers,
        )
        assert rebuild_resp.status_code == 403, rebuild_resp.text
        assert rebuild_resp.json()["detail"] == "Missing required permission: assets:write"


def test_connector_secret_routes_are_role_scoped_and_redacted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "e" * 48)

    app = create_app()
    with TestClient(app) as client:
        operator_headers = _headers("delta-one", role="operator")
        create_resp = client.post(
            "/api/engagements",
            json={
                "name": "Acme Connector Secrets",
                "status": "ACTIVE",
                "seeds": ["acme.example"],
            },
            headers=operator_headers,
        )
        assert create_resp.status_code == 200, create_resp.text
        created = create_resp.json()
        slug = str(created["slug"])
        db_path = Path(str(created["path"]))

        viewer_headers = _headers("delta-one", role="viewer")
        empty_resp = client.get(f"/api/engagements/{slug}/connector-secrets", headers=viewer_headers)
        assert empty_resp.status_code == 200, empty_resp.text
        assert empty_resp.json()["summary"]["count"] == 0

        unknown_secret_resp = client.get(
            f"/api/engagements/{slug}/connector-secrets?connector=unknown_connector",
            headers=viewer_headers,
        )
        assert unknown_secret_resp.status_code == 400, unknown_secret_resp.text

        raw_secret = "shodan-web-secret-do-not-return"
        viewer_post = client.post(
            f"/api/engagements/{slug}/connector-secrets",
            json={
                "connector_id": "shodan_host_lookup",
                "secret_name": "FORGE_SHODAN_API_KEY",
                "secret_value": raw_secret,
            },
            headers=viewer_headers,
        )
        assert viewer_post.status_code == 403, viewer_post.text
        assert viewer_post.json()["detail"] == "Missing required permission: connectors:write"

        unknown_post = client.post(
            f"/api/engagements/{slug}/connector-secrets",
            json={
                "connector_id": "unknown_connector",
                "secret_name": "FORGE_SHODAN_API_KEY",
                "secret_value": raw_secret,
            },
            headers=operator_headers,
        )
        assert unknown_post.status_code == 400, unknown_post.text

        wrong_name_resp = client.post(
            f"/api/engagements/{slug}/connector-secrets",
            json={
                "connector_id": "shodan_host_lookup",
                "secret_name": "FORGE_WRONG_API_KEY",
                "secret_value": raw_secret,
            },
            headers=operator_headers,
        )
        assert wrong_name_resp.status_code == 400, wrong_name_resp.text
        assert "connector secret name is not declared" in wrong_name_resp.json()["detail"]

        write_resp = client.post(
            f"/api/engagements/{slug}/connector-secrets",
            json={
                "connector_id": "shodan_host_lookup",
                "secret_name": "FORGE_SHODAN_API_KEY",
                "secret_value": raw_secret,
                "secret_ref": "env:FORGE_SHODAN_API_KEY",
                "metadata": {
                    "owner": "secops",
                    "api_key": raw_secret,
                    "note": f"issued {raw_secret}",
                },
            },
            headers=operator_headers,
        )
        assert write_resp.status_code == 200, write_resp.text
        assert raw_secret not in write_resp.text
        written = write_resp.json()["item"]
        assert written["connector_id"] == "shodan_host_lookup"
        assert written["secret_name"] == "FORGE_SHODAN_API_KEY"
        assert written["secret_ref"] == "env:FORGE_SHODAN_API_KEY"
        assert written["metadata"]["api_key"] == "[redacted]"
        assert written["metadata"]["note"] == "[redacted]"
        assert write_resp.json()["summary"]["count"] == 1

        read_resp = client.get(f"/api/engagements/{slug}/connector-secrets", headers=viewer_headers)
        assert read_resp.status_code == 200, read_resp.text
        assert raw_secret not in read_resp.text
        assert read_resp.json()["items"][0]["key_hint"].startswith("sha256:")

        catalog_resp = client.get(f"/api/engagements/{slug}/connectors", headers=viewer_headers)
        assert catalog_resp.status_code == 200, catalog_resp.text
        assert raw_secret not in catalog_resp.text
        catalog = {row["id"]: row for row in catalog_resp.json()["connectors"]}
        assert all(row["cost_profile"] != "optional_paid" for row in catalog.values())
        assert catalog["shodan_host_lookup"]["readiness"] == "configured"
        assert catalog["shodan_host_lookup"]["secret_store_configured"] is True
        assert catalog["shodan_host_lookup"]["secret_store_readiness"] == "stored_configured"
        assert catalog["shodan_host_lookup"]["stored_secret_names"] == ["FORGE_SHODAN_API_KEY"]
        assert catalog["shodan_host_lookup"]["stored_secret_statuses"] == [
            {"name": "FORGE_SHODAN_API_KEY", "status": "stored_configured"}
        ]
        assert catalog_resp.json()["summary"]["optional_paid_count"] == 0
        assert catalog_resp.json()["summary"]["secret_store_connector_count"] == 1

        paid_catalog_resp = client.get(
            f"/api/engagements/{slug}/connectors?include_paid=true",
            headers=viewer_headers,
        )
        assert paid_catalog_resp.status_code == 200, paid_catalog_resp.text
        assert paid_catalog_resp.json()["summary"]["optional_paid_count"] > 0

        unknown_domain_resp = client.get(
            f"/api/engagements/{slug}/connectors?domain=unknown_domain",
            headers=viewer_headers,
        )
        assert unknown_domain_resp.status_code == 400, unknown_domain_resp.text

        raw_secret_ref = "gitguardian-web-secret-do-not-return"
        unsafe_ref_resp = client.post(
            f"/api/engagements/{slug}/connector-secrets",
            json={
                "connector_id": "gitguardian_public_monitoring",
                "secret_name": "FORGE_GITGUARDIAN_API_KEY",
                "secret_value": raw_secret_ref,
                "secret_ref": f"https://token@provider.example/path?token={raw_secret_ref}",
                "metadata": {
                    "note": raw_secret_ref,
                    "session": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                },
            },
            headers=operator_headers,
        )
        assert unsafe_ref_resp.status_code == 200, unsafe_ref_resp.text
        assert raw_secret_ref not in unsafe_ref_resp.text
        unsafe_item = unsafe_ref_resp.json()["item"]
        assert unsafe_item["secret_ref"] == "api:request-body"
        assert unsafe_item["metadata"]["note"] == "[redacted]"
        assert unsafe_item["metadata"]["session"] == "[redacted]"

        write_only_headers = {
            "Authorization": (
                "Bearer " + mint_token("delta-one", permissions=("connectors:write",))
            )
        }
        denied_catalog = client.get(
            f"/api/engagements/{slug}/connectors",
            headers=write_only_headers,
        )
        assert denied_catalog.status_code == 403, denied_catalog.text
        assert denied_catalog.json()["detail"] == "Missing required permission: connectors:read"

        denied_read = client.get(
            f"/api/engagements/{slug}/connector-secrets",
            headers=write_only_headers,
        )
        assert denied_read.status_code == 403, denied_read.text
        assert denied_read.json()["detail"] == "Missing required permission: connectors:read"

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT secret_value_enc, metadata_json
            FROM connector_secrets
            WHERE connector_id='shodan_host_lookup'
            """
        ).fetchone()
        audit = con.execute(
            """
            SELECT target, result
            FROM audit_log
            WHERE action='connector_secret_store'
            """
        ).fetchone()
        leaked_unknown = con.execute(
            """
            SELECT 1
            FROM connector_secrets
            WHERE connector_id='unknown_connector'
            """
        ).fetchone()
        leaked_wrong_name = con.execute(
            """
            SELECT 1
            FROM connector_secrets
            WHERE secret_name='FORGE_WRONG_API_KEY'
            """
        ).fetchone()
        stored_rows = con.execute(
            """
            SELECT secret_value_enc, metadata_json
            FROM connector_secrets
            """
        ).fetchall()
        audit_rows = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE action='connector_secret_store'
            """
        ).fetchall()
    assert row is not None
    assert raw_secret not in row[0]
    assert raw_secret not in row[1]
    assert leaked_unknown is None
    assert leaked_wrong_name is None
    stored_blob = "\n".join(f"{secret_enc}\n{metadata_json}" for secret_enc, metadata_json in stored_rows)
    audit_blob = "\n".join(str(item[0]) for item in audit_rows)
    assert raw_secret not in stored_blob
    assert raw_secret_ref not in stored_blob
    assert raw_secret not in audit_blob
    assert raw_secret_ref not in audit_blob
    assert audit is not None
    assert audit[0] == "FORGE_SHODAN_API_KEY"
    assert raw_secret not in audit[1]


def test_connector_catalog_route_reports_invalid_plugin_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    plugin_dir = tmp_path / ".forge_data" / "connector_plugins"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "bad_active.json").write_text(
        json.dumps(
            {
                "schema": "forge.connector.plugin.v1",
                "id": "plugin_bad_active_adapter",
                "label": "Bad Active Adapter",
                "domain": "active_validation",
                "cost_profile": "free_local",
                "safety": "active_validation_gated",
                "description": "Missing live gate.",
                "capabilities": ["control_simulation"],
                "outputs": ["active_validation_runs"],
                "required_gates": ["approval", "roe_id", "scope_manifest"],
            }
        ),
        encoding="utf-8",
    )

    app = create_app()
    with TestClient(app) as client:
        operator_headers = _headers("delta-one", role="operator")
        create_resp = client.post(
            "/api/engagements",
            json={
                "name": "Acme Invalid Connector Plugin",
                "status": "ACTIVE",
                "seeds": ["acme.example"],
            },
            headers=operator_headers,
        )
        assert create_resp.status_code == 200, create_resp.text
        slug = create_resp.json()["slug"]

        viewer_headers = _headers("delta-one", role="viewer")
        catalog_resp = client.get(f"/api/engagements/{slug}/connectors", headers=viewer_headers)

    assert catalog_resp.status_code == 400, catalog_resp.text
    assert "live_gate" in catalog_resp.json()["detail"]


def test_workspace_admin_routes_are_permission_and_membership_scoped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        admin_headers = _headers("root-admin", role="admin")
        alpha_resp = client.post(
            "/api/workspaces",
            json={
                "workspace_id": "alpha",
                "name": "Alpha Team",
                "metadata": {"tier": "prod", "api_token": "alpha-secret-do-not-store"},
            },
            headers=admin_headers,
        )
        assert alpha_resp.status_code == 200, alpha_resp.text
        assert alpha_resp.json()["item"]["workspace_id"] == "alpha"
        assert alpha_resp.json()["item"]["metadata"] == {
            "tier": "prod",
            "api_token": "[redacted]",
        }

        beta_resp = client.post(
            "/api/workspaces",
            json={"workspace_id": "beta", "name": "Beta Team"},
            headers=admin_headers,
        )
        assert beta_resp.status_code == 200, beta_resp.text

        operator_create = client.post(
            "/api/workspaces",
            json={"workspace_id": "gamma"},
            headers=_headers("ordinary-operator", role="operator", workspace_id="gamma"),
        )
        assert operator_create.status_code == 403, operator_create.text
        assert operator_create.json()["detail"] == "Missing required permission: workspaces:write"

        admin_member = client.put(
            "/api/workspaces/alpha/members/alpha-manager",
            json={
                "role": "operator",
                "permissions": ["workspaces:read", "workspaces:members:write"],
            },
            headers=admin_headers,
        )
        assert admin_member.status_code == 200, admin_member.text
        assert admin_member.json()["item"]["subject"] == "alpha-manager"
        assert admin_member.json()["item"]["permissions"] == [
            "workspaces:read",
            "workspaces:members:write",
        ]

        admin_operator = client.put(
            "/api/workspaces/alpha/members/alpha-operator",
            json={"role": "operator"},
            headers=admin_headers,
        )
        assert admin_operator.status_code == 200, admin_operator.text
        assert "engagements:create" in admin_operator.json()["item"]["permissions"]

        alpha_operator_headers = _headers("alpha-operator", role="operator", workspace_id="alpha")
        alpha_workspaces = client.get("/api/workspaces", headers=alpha_operator_headers)
        assert alpha_workspaces.status_code == 200, alpha_workspaces.text
        assert [item["workspace_id"] for item in alpha_workspaces.json()["items"]] == ["alpha"]

        operator_mutation = client.put(
            "/api/workspaces/alpha/members/alpha-viewer",
            json={"role": "viewer"},
            headers=alpha_operator_headers,
        )
        assert operator_mutation.status_code == 403, operator_mutation.text
        assert operator_mutation.json()["detail"] == (
            "Missing required permission: workspaces:members:write"
        )

        manager_headers = {
            "Authorization": (
                "Bearer "
                + mint_token(
                    "alpha-manager",
                    workspace_id="alpha",
                    permissions=("workspaces:read", "workspaces:members:write"),
                )
            )
        }
        scoped_member = client.put(
            "/api/workspaces/alpha/members/alpha-viewer",
            json={"role": "viewer"},
            headers=manager_headers,
        )
        assert scoped_member.status_code == 200, scoped_member.text
        assert scoped_member.json()["item"]["role"] == "viewer"

        scoped_members = client.get("/api/workspaces/alpha/members", headers=manager_headers)
        assert scoped_members.status_code == 200, scoped_members.text
        assert {item["subject"] for item in scoped_members.json()["items"]} >= {
            "alpha-manager",
            "alpha-operator",
            "alpha-viewer",
        }

        cross_workspace = client.get("/api/workspaces/beta/members", headers=manager_headers)
        assert cross_workspace.status_code == 403, cross_workspace.text
        assert cross_workspace.json()["detail"] == "Workspace access denied."

        self_delete = client.delete(
            "/api/workspaces/alpha/members/alpha-manager",
            headers=manager_headers,
        )
        assert self_delete.status_code == 400, self_delete.text
        assert self_delete.json()["detail"] == "Cannot remove your own workspace membership."

        delete_viewer = client.delete(
            "/api/workspaces/alpha/members/alpha-viewer",
            headers=manager_headers,
        )
        assert delete_viewer.status_code == 200, delete_viewer.text
        assert delete_viewer.json()["status"] == "deleted"

        audit_resp = client.get("/api/workspaces/alpha/audit", headers=manager_headers)
        assert audit_resp.status_code == 200, audit_resp.text
        audit_items = audit_resp.json()["items"]
        assert [item["event_type"] for item in audit_items[:3]] == [
            "membership_delete",
            "membership_upsert",
            "membership_upsert",
        ]
        assert all(item["workspace_id"] == "alpha" for item in audit_items)
        assert all(item["source"] == "web_api" for item in audit_items)
        assert "alpha-secret-do-not-store" not in audit_resp.text
        workspace_events = [item for item in audit_items if item["event_type"] == "workspace_upsert"]
        assert workspace_events[0]["payload"]["metadata"]["api_token"] == "[redacted]"

        cross_audit = client.get("/api/workspaces/beta/audit", headers=manager_headers)
        assert cross_audit.status_code == 403, cross_audit.text

    con = connect_control_db(tmp_path / ".forge_data")
    try:
        assert verify_control_audit_chain(con)["valid"] is True
        assert not list_control_audit_events(con, workspace_id="gamma")
    finally:
        con.close()


def test_ctem_engagement_routes_are_workspace_isolated(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "e" * 48)

    ctem_permissions = (
        "engagements:read",
        "engagements:create",
        "engagements:write",
        "artifacts:read",
        "connectors:read",
        "connectors:write",
        "assets:read",
        "assets:write",
        "findings:read",
        "active_validation:read",
        "active_validation:write",
        "active_validation:approve",
        "active_validation:run",
        "logs:read",
        "remediation:read",
        "remediation:write",
        "remediation:export",
        "remediation:retest",
        "monitoring:read",
        "monitoring:write",
        "queue:read",
        "runs:read",
        "scans:read",
        "tasks:read",
        "workers:read",
    )

    app = create_app()
    with TestClient(app) as client:
        alpha_headers = _token_headers(
            "alpha-operator",
            workspace_id="alpha",
            permissions=ctem_permissions,
        )
        create_resp = client.post(
            "/api/engagements",
            json={
                "name": "Alpha CTEM Workspace",
                "status": "ACTIVE",
                "workspace_id": "alpha",
                "seeds": ["alpha.example"],
            },
            headers=alpha_headers,
        )
        assert create_resp.status_code == 200, create_resp.text
        create_payload = create_resp.json()
        engagement_id = int(create_payload["id"])
        slug = str(create_payload["slug"])

        reports_dir = tmp_path / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_name = f"engagement_{engagement_id}_report_20260815T000000.md"
        (reports_dir / report_name).write_text(
            "# Alpha CTEM Workspace\nalpha-only report body\n",
            encoding="utf-8",
        )
        logs_dir = tmp_path / ".forge_data" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_name = f"engagement_{engagement_id}_kill_chain_20260815T000000.log"
        (logs_dir / log_name).write_text("alpha-only log line\n", encoding="utf-8")

        visible_resp = client.get(f"/api/engagements/{slug}", headers=alpha_headers)
        assert visible_resp.status_code == 200, visible_resp.text
        visible_payload = visible_resp.json()
        assert visible_payload["workspace_id"] == "alpha"
        assert any(item["name"] == report_name for item in visible_payload["artifacts"])

        alpha_get_routes = (
            f"/api/engagements/{slug}/connectors",
            f"/api/engagements/{slug}/connector-secrets",
            f"/api/engagements/{slug}/asset-graph",
            f"/api/engagements/{slug}/active-validation",
            f"/api/engagements/{slug}/remediation",
            f"/api/engagements/{slug}/remediation/export",
            f"/api/engagements/{slug}/monitoring",
            f"/api/engagements/{slug}/runs",
            f"/api/engagements/{slug}/logs",
            f"/api/engagements/{slug}/logs/{log_name}/tail",
        )
        for route in alpha_get_routes:
            route_resp = client.get(route, headers=alpha_headers)
            assert route_resp.status_code == 200, route_resp.text

        alpha_artifact = client.get(
            f"/api/engagements/{slug}/artifacts/{report_name}",
            headers=alpha_headers,
        )
        assert alpha_artifact.status_code == 200, alpha_artifact.text
        assert "alpha-only report body" in alpha_artifact.text

        alpha_log = client.get(
            f"/api/engagements/{slug}/logs/{log_name}",
            headers=alpha_headers,
        )
        assert alpha_log.status_code == 200, alpha_log.text
        assert "alpha-only log line" in alpha_log.text

        alpha_numeric_get_routes = (
            f"/api/scans/{engagement_id}/progress",
            f"/api/tasks?engagement_id={engagement_id}",
            f"/api/workers?engagement_id={engagement_id}",
            f"/api/queue/metrics?engagement_id={engagement_id}",
            f"/api/engagements/{engagement_id}/assets",
            f"/api/engagements/{engagement_id}/vuln-summary",
            f"/api/engagements/{engagement_id}/asset-tree",
        )
        for route in alpha_numeric_get_routes:
            route_resp = client.get(route, headers=alpha_headers)
            assert route_resp.status_code == 200, route_resp.text

        beta_headers = _token_headers(
            "beta-operator",
            workspace_id="beta",
            permissions=ctem_permissions,
        )
        beta_token = mint_token(
            "beta-operator",
            roles=(),
            permissions=ctem_permissions,
            workspace_id="beta",
        )
        beta_list = client.get("/api/engagements", headers=beta_headers)
        assert beta_list.status_code == 200, beta_list.text
        assert slug not in beta_list.text
        assert "Alpha CTEM Workspace" not in beta_list.text

        cross_workspace_gets = (
            f"/api/engagements/{slug}",
            *alpha_get_routes,
            f"/api/engagements/{slug}/artifacts/{report_name}",
            f"/api/engagements/{slug}/logs/{log_name}",
            *alpha_numeric_get_routes,
        )
        for route in cross_workspace_gets:
            denied = client.get(route, headers=beta_headers)
            assert denied.status_code == 404, denied.text
            assert denied.json()["detail"] in {
                "Engagement not found.",
                "Artifact not found.",
            }
            assert slug not in denied.text
            assert "Alpha CTEM Workspace" not in denied.text
            assert "alpha-only" not in denied.text

        try:
            with client.websocket_connect(
                f"/ws/progress?engagement_id={engagement_id}&token={beta_token}"
            ):
                raise AssertionError("cross-workspace progress websocket must not connect")
        except WebSocketDisconnect as exc:
            assert exc.code == 1008

        cross_workspace_posts: tuple[tuple[str, dict[str, object] | None], ...] = (
            (f"/api/engagements/{slug}/connector-secrets", {
                "connector_id": "shodan_host_lookup",
                "secret_name": "FORGE_SHODAN_API_KEY",
                "secret_value": "beta-should-not-write-alpha",
            }),
            (f"/api/engagements/{slug}/asset-graph/rebuild", None),
            (f"/api/engagements/{slug}/asset-graph/ownership-claims", {
                "entity_key": "finding:alpha-only",
                "entity_type": "finding",
                "owner_ref": "beta@example.invalid",
                "owner_kind": "user",
                "confidence": 0.9,
            }),
            (f"/api/engagements/{slug}/active-validation/jobs", {
                "target_ref": "fixture://alpha-only",
                "target_kind": "fixture",
                "method": "fix_verification",
                "mode": "lab",
                "approved": True,
                "expected_result": "simulated_pass",
            }),
            (f"/api/engagements/{slug}/remediation", {
                "finding_ref": "finding:alpha-only",
                "title": "Beta must not write alpha remediation",
                "owner_ref": "beta@example.invalid",
                "sla_days": 7,
            }),
            (f"/api/engagements/{slug}/monitoring/policies", {
                "name": "Beta must not schedule alpha",
                "schedule_interval_minutes": 60,
            }),
        )
        for route, payload in cross_workspace_posts:
            denied = client.post(route, json=payload, headers=beta_headers)
            assert denied.status_code == 404, denied.text
            assert denied.json()["detail"] == "Engagement not found."
            assert slug not in denied.text
            assert "Alpha CTEM Workspace" not in denied.text


def test_bootstrap_token_route_mints_role_scoped_tokens_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    monkeypatch.setenv("FORGE_WEB_BOOTSTRAP_TOKEN", "bootstrap-secret")

    app = create_app()
    with TestClient(app) as client:
        missing_resp = client.get("/api/token?operator=delta-one")
        assert missing_resp.status_code == 401, missing_resp.text

        unsupported_resp = client.get(
            "/api/token?operator=delta-one&bootstrap_token=bootstrap-secret&role=superuser"
        )
        assert unsupported_resp.status_code == 400, unsupported_resp.text

        default_resp = client.get(
            "/api/token?operator=delta-one&bootstrap_token=bootstrap-secret"
        )
        assert default_resp.status_code == 200, default_resp.text
        default_payload = default_resp.json()
        assert default_payload["role"] == "operator"
        assert default_payload["workspace_id"] == "default"
        default_principal = verify_principal(default_payload["token"])
        assert default_principal is not None
        assert default_principal.roles == ("operator",)
        assert default_principal.workspace_id == "default"
        assert default_principal.has_permission("engagements:write")
        assert default_principal.has_permission("retention:write")
        assert not default_principal.has_permission("workspaces:any")
        assert "*" not in default_principal.permissions
        assert "workspaces:legacy" not in default_principal.permissions

        owner_resp = client.get(
            "/api/token?"
            "operator=delta-one&bootstrap_token=bootstrap-secret&role=owner&workspace_id=alpha"
        )
        assert owner_resp.status_code == 200, owner_resp.text
        owner_principal = verify_principal(owner_resp.json()["token"])
        assert owner_principal is not None
        assert owner_principal.roles == ("owner",)
        assert owner_principal.workspace_id == "alpha"
        assert owner_principal.has_permission("workspaces:any")
