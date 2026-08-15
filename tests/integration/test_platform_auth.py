from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forge.api.app import create_app
from forge.api.deps import reset_dependencies
from forge.db.control import connect_control_db, upsert_membership, upsert_workspace
from forge.webui.auth import mint_token


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FORGE_STATE_DB_URL", f"sqlite:///{tmp_path / 'state.db'}")
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_AUDIT_LOG_DISABLE", "1")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    _seed_membership(tmp_path, workspace_id="default", subject="platform-test")
    reset_dependencies()
    app = create_app()
    try:
        with TestClient(app) as c:
            yield c
    finally:
        reset_dependencies()


def _seed_membership(
    tmp_path: Path,
    *,
    workspace_id: str,
    subject: str,
    role: str = "operator",
) -> None:
    con = connect_control_db(tmp_path / ".forge_data")
    try:
        upsert_workspace(con, workspace_id=workspace_id)
        upsert_membership(
            con,
            workspace_id=workspace_id,
            subject=subject,
            role=role,
        )
        con.commit()
    finally:
        con.close()


def _headers(*permissions: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {mint_token('platform-test', permissions=permissions)}"
    }


def _role_headers(role: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {mint_token('platform-test', roles=(role,))}"
    }


def _workspace_headers(
    subject: str,
    workspace_id: str,
    *permissions: str,
) -> dict[str, str]:
    return {
        "Authorization": (
            "Bearer "
            + mint_token(
                subject,
                workspace_id=workspace_id,
                permissions=permissions,
            )
        )
    }


def test_health_and_ready_remain_public(client: TestClient) -> None:
    assert client.get("/ready").status_code == 200
    assert client.get("/health").status_code == 200


def test_workflow_write_requires_valid_write_token(client: TestClient) -> None:
    assert client.post("/workflows", json={}).status_code == 401
    assert (
        client.post(
            "/workflows",
            json={},
            headers={"Authorization": "Bearer not-a-jwt"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/workflows",
            json={},
            headers=_headers("workflows:read"),
        ).status_code
        == 403
    )

    response = client.post(
        "/workflows",
        json={"definition_name": "mvp_discovery_analysis_report"},
        headers=_headers("workflows:write", "workflows:read"),
    )

    assert response.status_code == 201, response.text
    workflow_id = response.json()["workflow_id"]
    status_response = client.get(
        f"/workflows/{workflow_id}/status",
        headers=_headers("workflows:read"),
    )
    assert status_response.status_code == 200, status_response.text


def test_platform_api_accepts_role_derived_permissions(client: TestClient) -> None:
    viewer_write = client.post(
        "/workflows",
        json={"definition_name": "mvp_discovery_analysis_report"},
        headers=_role_headers("viewer"),
    )
    assert viewer_write.status_code == 403, viewer_write.text

    operator_write = client.post(
        "/workflows",
        json={"definition_name": "mvp_discovery_analysis_report"},
        headers=_role_headers("operator"),
    )
    assert operator_write.status_code == 201, operator_write.text
    workflow_id = operator_write.json()["workflow_id"]

    viewer_status = client.get(
        f"/workflows/{workflow_id}/status",
        headers=_role_headers("viewer"),
    )
    assert viewer_status.status_code == 200, viewer_status.text


def test_platform_workflow_and_report_routes_are_workspace_scoped(
    client: TestClient,
    tmp_path: Path,
) -> None:
    _seed_membership(tmp_path, workspace_id="alpha", subject="alpha-user")
    _seed_membership(tmp_path, workspace_id="beta", subject="beta-user")
    alpha_headers = _workspace_headers(
        "alpha-user",
        "alpha",
        "workflows:write",
        "workflows:read",
        "reports:read",
    )
    beta_headers = _workspace_headers(
        "beta-user",
        "beta",
        "workflows:write",
        "workflows:read",
        "reports:read",
    )

    forbidden_create = client.post(
        "/workflows",
        json={
            "definition_name": "mvp_discovery_analysis_report",
            "params": {"workspace_id": "beta"},
        },
        headers=alpha_headers,
    )
    assert forbidden_create.status_code == 403, forbidden_create.text
    assert forbidden_create.json()["detail"] == "Workspace access denied."

    claim_only_headers = _workspace_headers(
        "alpha-claim-only",
        "alpha",
        "workflows:write",
        "workflows:read",
        "reports:read",
    )
    claim_only_create = client.post(
        "/workflows",
        json={
            "definition_name": "mvp_discovery_analysis_report",
            "params": {"workspace_id": "alpha", "target": "alpha.example"},
        },
        headers=claim_only_headers,
    )
    assert claim_only_create.status_code == 403, claim_only_create.text
    assert claim_only_create.json()["detail"] == "Workspace access denied."

    created = client.post(
        "/workflows",
        json={
            "definition_name": "mvp_discovery_analysis_report",
            "params": {"workspace_id": "alpha", "target": "alpha.example"},
        },
        headers=alpha_headers,
    )
    assert created.status_code == 201, created.text
    workflow_id = created.json()["workflow_id"]

    alpha_status = client.get(f"/workflows/{workflow_id}/status", headers=alpha_headers)
    assert alpha_status.status_code == 200, alpha_status.text

    beta_status = client.get(f"/workflows/{workflow_id}/status", headers=beta_headers)
    assert beta_status.status_code == 404, beta_status.text
    assert beta_status.json()["detail"] == f"workflow_not_found:{workflow_id}"

    beta_advance = client.post(
        f"/workflows/{workflow_id}/advance",
        json={"stage_result": {"cross_workspace": "denied"}},
        headers=beta_headers,
    )
    assert beta_advance.status_code == 404, beta_advance.text

    beta_history = client.get(f"/workflows/{workflow_id}/history", headers=beta_headers)
    assert beta_history.status_code == 404, beta_history.text
    assert beta_history.json()["detail"] == f"workflow_not_found:{workflow_id}"

    beta_replay = client.get(f"/workflows/{workflow_id}/replay", headers=beta_headers)
    assert beta_replay.status_code == 404, beta_replay.text
    assert beta_replay.json()["detail"] == f"workflow_not_found:{workflow_id}"

    beta_report = client.get(f"/reports/{workflow_id}", headers=beta_headers)
    assert beta_report.status_code == 404, beta_report.text
    assert beta_report.json()["detail"] == f"workflow_not_found:{workflow_id}"


def test_report_route_requires_report_read_permission(client: TestClient) -> None:
    assert client.get("/reports/missing-workflow").status_code == 401
    assert (
        client.get(
            "/reports/missing-workflow",
            headers=_headers("workflows:read"),
        ).status_code
        == 403
    )

    response = client.get(
        "/reports/missing-workflow",
        headers=_headers("reports:read"),
    )

    assert response.status_code == 404, response.text
