from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.webui.app import create_app
from forge.webui.auth import mint_token


def _build_engagement_db(data_dir: Path) -> Path:
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
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
        con.commit()
    finally:
        con.close()
    return db_path


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _install_reachability_http_client(monkeypatch, responses):
    records = {"init_kwargs": [], "requests": []}
    queued_responses = list(responses)

    class _Response:
        def __init__(self, status_code: int, headers: dict[str, str]) -> None:
            self.status_code = status_code
            self.headers = headers

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            records["init_kwargs"].append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def request(self, method: str, url: str, *, headers=None):
            records["requests"].append(
                {"method": method, "url": url, "headers": dict(headers or {})}
            )
            status_code, response_headers = queued_responses.pop(0)
            return _Response(status_code, response_headers)

    monkeypatch.setattr("forge.active_validation.runner.httpx.Client", _Client)
    return records


def test_active_validation_api_permissions_and_fail_closed_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [
            (
                200,
                {
                    "content-type": "text/plain",
                    "content-length": "2",
                    "location": "https://app.acme.example/next?token=never&ok=1",
                },
            )
        ],
    )
    data_dir = tmp_path / ".forge_data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    monkeypatch.setenv("FORGE_ACTIVE_VALIDATION_ENABLE_LIVE", "1")
    _build_engagement_db(data_dir)
    app = create_app()
    denied_token = mint_token(
        "delta-one",
        permissions=("engagements:read", "workspaces:legacy"),
    )
    read_token = mint_token(
        "delta-one",
        permissions=("active_validation:read", "workspaces:legacy"),
    )
    write_token = mint_token(
        "delta-one",
        permissions=(
            "active_validation:read",
            "active_validation:write",
            "workspaces:legacy",
        ),
    )
    approve_run_token = mint_token(
        "delta-one",
        permissions=(
            "active_validation:read",
            "active_validation:write",
            "active_validation:approve",
            "active_validation:run",
            "workspaces:legacy",
        ),
    )
    live_token = mint_token(
        "delta-one",
        permissions=(
            "active_validation:read",
            "active_validation:approve",
            "active_validation:run",
            "active_validation:live",
            "workspaces:legacy",
        ),
    )
    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-1001",
            "authorized_seeds": ["https://app.acme.example/health"],
        }
    )
    with TestClient(app) as client:
        denied_list = client.get(
            "/api/engagements/1001/active-validation",
            headers=_headers(denied_token),
        )
        denied_create = client.post(
            "/api/engagements/1001/active-validation/jobs",
            headers=_headers(read_token),
            json={"target_ref": "host:app.acme.example"},
        )
        malformed_create = client.post(
            "/api/engagements/1001/active-validation/jobs",
            headers=_headers(write_token),
            json={"target_ref": "host:app.acme.example", "max_steps": []},
        )
        denied_preview = client.post(
            "/api/engagements/1001/active-validation/preview",
            headers=_headers(read_token),
            json={"target_ref": "host:app.acme.example"},
        )
        dry_preview = client.post(
            "/api/engagements/1001/active-validation/preview",
            headers=_headers(write_token),
            json={
                "target_ref": "https://app.acme.example/health?token=api-preview-token&ok=1",
                "target_kind": "service",
                "method": "http_reachability",
                "mode": "dry_run",
                "metadata": {"source": "api-test", "secret": "never-render"},
            },
        )
        live_preview_missing_scope = client.post(
            "/api/engagements/1001/active-validation/preview",
            headers=_headers(write_token),
            json={
                "target_ref": "https://app.acme.example/health",
                "target_kind": "service",
                "method": "http_reachability",
                "mode": "read_only_live",
                "roe_id": "ROE-1001",
            },
        )
        live_preview = client.post(
            "/api/engagements/1001/active-validation/preview",
            headers=_headers(approve_run_token),
            json={
                "target_ref": "https://app.acme.example/health",
                "target_kind": "service",
                "method": "http_reachability",
                "mode": "read_only_live",
                "approved": True,
                "roe_id": "ROE-1001",
                "scope_manifest": scope_manifest,
            },
        )
        approved_live_without_scope = client.post(
            "/api/engagements/1001/active-validation/jobs",
            headers=_headers(approve_run_token),
            json={
                "target_ref": "https://app.acme.example/health",
                "target_kind": "service",
                "method": "http_reachability",
                "mode": "read_only_live",
                "approved": True,
                "roe_id": "ROE-1001",
            },
        )
        dry_job = client.post(
            "/api/engagements/1001/active-validation/jobs",
            headers=_headers(write_token),
            json={
                "target_ref": "host:app.acme.example",
                "target_kind": "host",
                "method": "http_reachability",
                "mode": "dry_run",
                "metadata": {"source": "api-test", "token": "api-token-never-render"},
            },
        )
        dry_job_id = int(dry_job.json()["job"]["id"])
        denied_run = client.post(
            f"/api/engagements/1001/active-validation/jobs/{dry_job_id}/run",
            headers=_headers(write_token),
        )
        dry_run = client.post(
            f"/api/engagements/1001/active-validation/jobs/{dry_job_id}/run",
            headers=_headers(approve_run_token),
        )
        live_job = client.post(
            "/api/engagements/1001/active-validation/jobs",
            headers=_headers(write_token),
            json={
                "target_ref": "https://app.acme.example/health",
                "target_kind": "service",
                "method": "http_reachability",
                "mode": "read_only_live",
            },
        )
        live_job_id = int(live_job.json()["job"]["id"])
        denied_approval_without_scope = client.post(
            f"/api/engagements/1001/active-validation/jobs/{live_job_id}/approve",
            headers=_headers(approve_run_token),
            json={"roe_id": "ROE-1001"},
        )
        approved = client.post(
            f"/api/engagements/1001/active-validation/jobs/{live_job_id}/approve",
            headers=_headers(approve_run_token),
            json={
                "roe_id": "ROE-1001",
                "scope_manifest": scope_manifest,
                "approval_note": "read-only proof approved",
            },
        )
        denied_live_gate = client.post(
            f"/api/engagements/1001/active-validation/jobs/{live_job_id}/run",
            headers=_headers(approve_run_token),
            json={"allow_live": True},
        )
        env_live_bypass_blocked = client.post(
            f"/api/engagements/1001/active-validation/jobs/{live_job_id}/run",
            headers=_headers(approve_run_token),
            json={},
        )
        live_blocked = client.post(
            f"/api/engagements/1001/active-validation/jobs/{live_job_id}/run",
            headers=_headers(live_token),
            json={"allow_live": True},
        )
        listing = client.get(
            "/api/engagements/1001/active-validation",
            headers=_headers(read_token),
        )

    assert denied_list.status_code == 403
    assert denied_list.json()["detail"] == "Missing required permission: active_validation:read"
    assert denied_create.status_code == 403
    assert denied_create.json()["detail"] == "Missing required permission: active_validation:write"
    assert malformed_create.status_code == 400
    assert denied_preview.status_code == 403
    assert denied_preview.json()["detail"] == "Missing required permission: active_validation:write"
    assert dry_preview.status_code == 200, dry_preview.text
    assert dry_preview.json()["preview"]["status"] == "planned"
    assert dry_preview.json()["preview"]["plan"]["will_create_job"] is False
    assert "api-preview-token" not in str(dry_preview.json())
    assert "never-render" not in str(dry_preview.json())
    assert live_preview_missing_scope.status_code == 400
    assert "read_only_live preview requires explicit" in (
        live_preview_missing_scope.json()["detail"]
    )
    assert live_preview.status_code == 200, live_preview.text
    assert live_preview.json()["preview"]["status"] == "planned"
    preview_gates = {
        gate["id"]: gate["status"] for gate in live_preview.json()["preview"]["gates"]
    }
    assert preview_gates["approval"] == "passed"
    assert preview_gates["scope_manifest"] == "passed"
    assert preview_gates["live_gate"] == "required_at_run"
    assert live_preview.json()["preview"]["plan"]["will_execute_network"] is False
    assert "authorized_seeds" not in str(live_preview.json())
    assert approved_live_without_scope.status_code == 400
    assert "read_only_live approval requires explicit" in approved_live_without_scope.json()["detail"]
    assert dry_job.status_code == 200, dry_job.text
    assert dry_job.json()["job"]["status"] == "queued"
    assert "api-token-never-render" not in str(dry_job.json())
    assert denied_run.status_code == 403
    assert denied_run.json()["detail"] == "Missing required permission: active_validation:run"
    assert dry_run.status_code == 200, dry_run.text
    assert dry_run.json()["run"]["status"] == "completed"
    assert dry_run.json()["run"]["result"] == "planned"
    assert dry_run.json()["run"]["evidence"]["network_execution"] is False
    assert live_job.status_code == 200, live_job.text
    assert denied_approval_without_scope.status_code == 400
    assert "read_only_live approval requires explicit" in denied_approval_without_scope.json()["detail"]
    assert approved.status_code == 200, approved.text
    assert approved.json()["job"]["scope_manifest_ref"] == "inline_json"
    assert denied_live_gate.status_code == 403
    assert denied_live_gate.json()["detail"] == "Missing required permission: active_validation:live"
    assert env_live_bypass_blocked.status_code == 200, env_live_bypass_blocked.text
    assert env_live_bypass_blocked.json()["run"]["status"] == "blocked"
    assert env_live_bypass_blocked.json()["run"]["result"] == "live_disabled"
    assert env_live_bypass_blocked.json()["run"]["evidence"]["network_execution"] is False
    assert live_blocked.status_code == 200, live_blocked.text
    assert live_blocked.json()["run"]["status"] == "completed"
    assert live_blocked.json()["run"]["result"] == "reachable"
    assert live_blocked.json()["run"]["evidence"]["network_execution"] is True
    live_evidence = live_blocked.json()["run"]["evidence"]["live_validation"]
    assert live_evidence["request"]["method"] == "HEAD"
    assert live_evidence["request"]["follow_redirects"] is False
    assert live_evidence["response"]["status_code"] == 200
    assert live_evidence["response"]["redirect_location"] == "https://app.acme.example/next?ok=1"
    assert live_evidence["body_captured"] is False
    proof_summary = live_blocked.json()["run"]["evidence"]["proof_summary"]
    assert proof_summary["evidence"].startswith("HEAD 200")
    assert proof_summary["live_proof"].startswith("HEAD 200")
    assert "redirect=https://app.acme.example/next?ok=1" in proof_summary["live_proof"]
    assert proof_summary["fix_match"] == "-"
    assert records["requests"][0]["method"] == "HEAD"
    assert records["init_kwargs"][0]["follow_redirects"] is False
    assert records["init_kwargs"][0]["trust_env"] is False
    assert "never" not in str(live_blocked.json()["run"]["evidence"])
    assert listing.status_code == 200, listing.text
    payload = listing.json()
    assert payload["summary"]["job_count"] == 2
    assert payload["summary"]["run_count"] == 3
    assert payload["summary"]["blocked_run_count"] == 1
    assert payload["summary"]["coverage_states"] == {"passed": 1, "planned": 1}
    assert payload["summary"]["attack_mapping_count"] == 2
    assert payload["summary"]["control_family_count"] == 2
    assert payload["coverage"]["schema"] == "forge.active_validation.coverage.v1"
    assert payload["coverage"]["summary"]["run_count"] == 3
    assert payload["coverage"]["summary"]["states"] == {"passed": 1, "planned": 1}
    attack = {row["id"]: row for row in payload["coverage"]["attack_mappings"]}
    assert attack["TA0043"]["states"] == {"passed": 1, "planned": 1}
    assert any(
        run["evidence"]["proof_summary"]["live_proof"].startswith("HEAD 200")
        for run in payload["runs"]
    )
    methods = {item["id"]: item for item in payload["methods"]}
    assert methods["http_reachability"]["implementation_status"] == "implemented_read_only_live"
    assert payload["jobs"][0]["method_config"]["safety_profile"] == "non_destructive"
    assert "api-token-never-render" not in str(payload)
    assert "authorized_seeds" not in str(payload)


def test_active_validation_api_redacts_non_inline_scope_refs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    _build_engagement_db(data_dir)
    app = create_app()
    write_token = mint_token(
        "delta-one",
        permissions=(
            "active_validation:read",
            "active_validation:write",
            "workspaces:legacy",
        ),
    )
    scope_path = r"C:\tenant\private\roe-scope.json"

    with TestClient(app) as client:
        created = client.post(
            "/api/engagements/1001/active-validation/jobs",
            headers=_headers(write_token),
            json={
                "target_ref": "host:app.acme.example",
                "target_kind": "host",
                "method": "http_reachability",
                "mode": "dry_run",
                "roe_id": "ROE-PATH",
                "scope_manifest_ref": scope_path,
            },
        )
        listing = client.get(
            "/api/engagements/1001/active-validation",
            headers=_headers(write_token),
        )

    assert created.status_code == 200, created.text
    assert created.json()["job"]["scope_manifest_ref"] == "external_ref"
    assert created.json()["job"]["scope_manifest_hash"].startswith("sha256:")
    assert scope_path not in str(created.json())
    assert listing.status_code == 200, listing.text
    assert scope_path not in str(listing.json())
