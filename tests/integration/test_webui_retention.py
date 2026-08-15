from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from forge.webui.app import create_app
from forge.webui.auth import mint_token


def _configure_webui_env(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
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


def _create_engagement(
    client: TestClient,
    *,
    headers: dict[str, str],
    name: str = "Acme Retention",
) -> dict[str, object]:
    response = client.post(
        "/api/engagements",
        json={
            "name": name,
            "status": "ACTIVE",
            "seeds": ["acme.example"],
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _seed_retention_rows(db_path: Path, *, legal_hold: bool = False) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            INSERT INTO monitoring_policies
                (id, engagement_id, name, enabled, schedule_interval_minutes,
                 mode, last_snapshot_id, next_run_at)
            VALUES (1, 1, 'Daily passive', 1, 1440, 'passive', 2, '2026-01-02T00:00:00Z');

            INSERT INTO monitoring_snapshots
                (id, engagement_id, policy_id, snapshot_kind, state_hash,
                 state_json, summary_json, created_at)
            VALUES
                (1, 1, 1, 'scheduled', 'old', '{}', '{}', '2025-01-01T00:00:00Z'),
                (2, 1, 1, 'scheduled', 'latest', '{}', '{}', '2025-01-02T00:00:00Z');

            INSERT INTO monitoring_trend_points
                (engagement_id, policy_id, snapshot_id, observed_at,
                 asset_count, finding_count, created_at, updated_at)
            VALUES
                (1, 1, 1, '2025-01-01T00:00:00Z', 2, 1,
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
                (1, 1, 2, '2025-01-01T00:00:00Z', 3, 1,
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');

            INSERT INTO monitoring_alerts
                (id, engagement_id, policy_id, snapshot_id, alert_type, severity,
                 title, status, created_at, updated_at)
            VALUES
                (1, 1, 1, 1, 'asset_added', 'HIGH', 'closed alert', 'resolved',
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
                (2, 1, 1, 1, 'asset_added', 'HIGH', 'open alert', 'open',
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');

            INSERT INTO monitoring_alert_deliveries
                (engagement_id, alert_id, channel, destination, status,
                 delivered_at, created_at, updated_at)
            VALUES
                (1, 1, 'jsonl', 'alerts.jsonl', 'delivered',
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
                (1, 2, 'jsonl', 'alerts.jsonl', 'delivered',
                 '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
            """
        )
        if legal_hold:
            con.execute(
                """
                INSERT INTO audit_reviews
                    (engagement_id, manifest_hash, review_status, reviewer,
                     comment, legal_hold, created_at)
                VALUES
                    (1, 'hold123', 'attested', 'legal', 'hold', 1,
                     '2025-12-01T00:00:00Z')
                """
            )
        con.commit()
    finally:
        con.close()


def test_retention_routes_are_role_scoped_and_apply_safe_pruning(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        operator_headers = _headers("delta-one", role="operator")
        created = _create_engagement(client, headers=operator_headers)
        slug = str(created["slug"])
        db_path = Path(str(created["path"]))
        _seed_retention_rows(db_path)

        viewer_headers = _headers("delta-one", role="viewer")
        overview = client.get(f"/api/engagements/{slug}/retention", headers=viewer_headers)
        assert overview.status_code == 200, overview.text
        assert overview.json()["policy"]["monitoring_days"] == 180

        viewer_policy = client.post(
            f"/api/engagements/{slug}/retention/policy",
            json={"monitoring_days": 30},
            headers=viewer_headers,
        )
        assert viewer_policy.status_code == 403, viewer_policy.text
        assert viewer_policy.json()["detail"] == "Missing required permission: retention:write"

        policy_response = client.post(
            f"/api/engagements/{slug}/retention/policy",
            json={"monitoring_days": 30, "audit_review_days": 30},
            headers=operator_headers,
        )
        assert policy_response.status_code == 200, policy_response.text
        assert policy_response.json()["policy"]["monitoring_days"] == 30

        preview = client.post(
            f"/api/engagements/{slug}/retention/preview",
            json={"now": "2026-01-01T00:00:00Z"},
            headers=operator_headers,
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["mode"] == "preview"
        assert preview.json()["summary"]["eligible_count"] == 2
        assert preview.json()["summary"]["deleted_count"] == 0

        missing_confirm = client.post(
            f"/api/engagements/{slug}/retention/apply",
            json={"now": "2026-01-01T00:00:00Z"},
            headers=operator_headers,
        )
        assert missing_confirm.status_code == 400, missing_confirm.text
        assert missing_confirm.json()["detail"] == "retention apply requires confirm=true"

        apply = client.post(
            f"/api/engagements/{slug}/retention/apply",
            json={"now": "2026-01-01T00:00:00Z", "confirm": True},
            headers=operator_headers,
        )
        assert apply.status_code == 200, apply.text
        assert apply.json()["status"] == "completed"
        assert apply.json()["summary"]["deleted_count"] == 2

        con = sqlite3.connect(db_path)
        try:
            assert con.execute("SELECT COUNT(*) FROM monitoring_trend_points").fetchone()[0] == 1
            assert con.execute("SELECT COUNT(*) FROM monitoring_alert_deliveries").fetchone()[0] == 1
            assert con.execute("SELECT alert_id FROM monitoring_alert_deliveries").fetchone()[0] == 2
        finally:
            con.close()


def test_retention_apply_route_respects_legal_hold(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        operator_headers = _headers("delta-one", role="operator")
        created = _create_engagement(client, headers=operator_headers, name="Acme Legal Hold")
        slug = str(created["slug"])
        db_path = Path(str(created["path"]))
        _seed_retention_rows(db_path, legal_hold=True)

        policy_response = client.post(
            f"/api/engagements/{slug}/retention/policy",
            json={"monitoring_days": 30, "audit_review_days": 30},
            headers=operator_headers,
        )
        assert policy_response.status_code == 200, policy_response.text

        apply = client.post(
            f"/api/engagements/{slug}/retention/apply",
            json={"now": "2026-01-01T00:00:00Z", "confirm": True},
            headers=operator_headers,
        )
        assert apply.status_code == 200, apply.text
        payload = apply.json()
        assert payload["status"] == "blocked"
        assert payload["legal_hold"] is True
        assert payload["summary"]["deleted_count"] == 0

        con = sqlite3.connect(db_path)
        try:
            assert con.execute("SELECT COUNT(*) FROM monitoring_trend_points").fetchone()[0] == 2
            assert con.execute("SELECT COUNT(*) FROM monitoring_alert_deliveries").fetchone()[0] == 2
        finally:
            con.close()


def test_retention_route_hides_cross_workspace_engagement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        alpha_headers = _headers("alpha-user", role="operator", workspace_id="alpha")
        created = _create_engagement(client, headers=alpha_headers, name="Acme Alpha")

        beta_headers = _headers("beta-user", role="operator", workspace_id="beta")
        response = client.get(
            f"/api/engagements/{created['slug']}/retention",
            headers=beta_headers,
        )

        assert response.status_code == 404, response.text
