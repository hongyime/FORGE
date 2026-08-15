from __future__ import annotations

import json
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


def _insert_run_manifest(db_path: Path, engagement_id: int) -> tuple[int, str]:
    manifest_hash = "f" * 64
    con = sqlite3.connect(db_path)
    try:
        cursor = con.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type,
                 seed_count, max_iterations, current_iteration, resume_enabled,
                 dry_run, attack_mode, metadata_json, completed_at)
            VALUES (?, 'kill_chain', 'completed', 'acme.example', 'domain',
                    1, 1, 1, 1, 1, 0, '{}', CURRENT_TIMESTAMP)
            """,
            (engagement_id,),
        )
        run_id = int(cursor.lastrowid)
        con.execute(
            """
            INSERT INTO run_audit_manifests
                (engagement_id, run_id, manifest_hash, previous_manifest_hash, manifest_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                run_id,
                manifest_hash,
                "0" * 64,
                json.dumps({"fixture": True}, sort_keys=True),
            ),
        )
        con.commit()
    finally:
        con.close()
    return run_id, manifest_hash


def test_audit_review_routes_are_role_scoped_and_annotate_runs(
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
                "name": "Acme Audit Review",
                "status": "ACTIVE",
                "seeds": ["acme.example"],
            },
            headers=operator_headers,
        )
        assert create_resp.status_code == 200, create_resp.text
        created = create_resp.json()
        slug = created["slug"]
        engagement_id = int(created["id"])
        run_id, manifest_hash = _insert_run_manifest(Path(created["path"]), engagement_id)

        viewer_headers = _headers("delta-one", role="viewer")
        empty_resp = client.get(
            f"/api/engagements/{slug}/audit-reviews",
            headers=viewer_headers,
        )
        assert empty_resp.status_code == 200, empty_resp.text
        assert empty_resp.json()["summary"]["review_status"] == "pending"

        viewer_post = client.post(
            f"/api/engagements/{slug}/audit-reviews",
            json={"run_id": run_id, "review_status": "approved"},
            headers=viewer_headers,
        )
        assert viewer_post.status_code == 403, viewer_post.text
        assert viewer_post.json()["detail"] == "Missing required permission: audit:review"

        post_resp = client.post(
            f"/api/engagements/{slug}/audit-reviews",
            json={
                "run_id": run_id,
                "manifest_hash": manifest_hash,
                "review_status": "attested",
                "comment": "Approved for customer delivery.",
                "attestation": {"checklist": "ok", "access_token": "do-not-return"},
                "legal_hold": True,
            },
            headers=operator_headers,
        )
        assert post_resp.status_code == 200, post_resp.text
        item = post_resp.json()["item"]
        assert item["review_status"] == "attested"
        assert item["manifest_hash"] == manifest_hash
        assert item["attestation"]["access_token"] == "[redacted]"
        assert post_resp.json()["summary"]["legal_hold"] is True

        list_resp = client.get(
            f"/api/engagements/{slug}/audit-reviews?run_id={run_id}",
            headers=viewer_headers,
        )
        assert list_resp.status_code == 200, list_resp.text
        assert list_resp.json()["items"][0]["id"] == item["id"]
        assert list_resp.json()["summary"]["review_status"] == "attested"

        runs_resp = client.get(
            f"/api/engagements/{slug}/runs?verify_manifests=false",
            headers=viewer_headers,
        )
        assert runs_resp.status_code == 200, runs_resp.text
        run_payload = runs_resp.json()["items"][0]
        assert run_payload["audit_review"]["review_status"] == "attested"
        assert run_payload["audit_manifest"]["review"]["legal_hold"] is True

        detail_resp = client.get(f"/api/engagements/{slug}", headers=viewer_headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        assert detail["run_summary"]["audit_review"]["review_status"] == "attested"
        assert detail["sections"]["audit_reviews"][0]["Status"] == "attested"
