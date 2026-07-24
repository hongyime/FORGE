from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from forge.webui.app import create_app
from forge.webui.auth import mint_token
from tests.integration.test_webui_engagement_api import _build_engagement


def _prepare(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    return _build_engagement(tmp_path)


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_token('operator-web')}"}


def _queued_count(db_path: Path) -> int:
    with sqlite3.connect(db_path) as con:
        return int(
            con.execute(
                "SELECT COUNT(*) FROM distributed_tasks WHERE engagement_id=1001"
            ).fetchone()[0]
        )


def _latest_denial(db_path: Path, module: str, action: str) -> tuple[str, str] | None:
    with sqlite3.connect(db_path) as con:
        return con.execute(
            """
            SELECT target, result
            FROM audit_log
            WHERE engagement_id=1001 AND module=? AND action=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (module, action),
        ).fetchone()


def test_task_enqueue_requires_roe_scope_context_before_queue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _prepare(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/tasks/enqueue",
            json={
                "engagement_id": 1001,
                "task_type": "crawl",
                "target": "https://app.acme.example",
            },
            headers=_auth_headers(),
        )

    assert response.status_code == 400, response.text
    assert "task scheduling requires roe_id and scope_manifest" in response.text
    assert _queued_count(db_path) == 0
    audit_row = _latest_denial(db_path, "scheduled_task", "scheduled_task_scope_denied")
    assert audit_row is not None
    assert audit_row[0] == "https://app.acme.example"
    assert "task_type=crawl" in audit_row[1]
    assert "requires roe_id and scope_manifest" in audit_row[1]


def test_task_enqueue_rejects_scope_manifest_denied_target_before_queue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _prepare(tmp_path, monkeypatch)
    scope_manifest = {
        "roe_id": "ROE-WEB-2026-07",
        "domains": ["app.acme.example"],
        "urls": ["https://app.acme.example/app/"],
    }

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/tasks/enqueue",
            json={
                "engagement_id": 1001,
                "task_type": "crawl",
                "target": "https://app.acme.example/admin",
                "roe_id": "ROE-WEB-2026-07",
                "scope_manifest": scope_manifest,
            },
            headers=_auth_headers(),
        )

    assert response.status_code == 400, response.text
    assert "scope_manifest_denied" in response.text
    assert _queued_count(db_path) == 0
    audit_row = _latest_denial(db_path, "scheduled_task", "scheduled_task_scope_denied")
    assert audit_row is not None
    assert audit_row[0] == "https://app.acme.example/admin"
    assert "task_type=crawl" in audit_row[1]
    assert "reason=scope_manifest_denied" in audit_row[1]


def test_task_enqueue_rejects_mismatched_scope_manifest_before_queue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _prepare(tmp_path, monkeypatch)

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/tasks/enqueue",
            json={
                "engagement_id": 1001,
                "task_type": "validate",
                "key_id": 81,
                "roe_id": "ROE-WEB-2026-07",
                "scope_manifest": {
                    "roe_id": "ROE-OTHER-2026-07",
                    "domains": ["app.acme.example"],
                },
            },
            headers=_auth_headers(),
        )

    assert response.status_code == 400, response.text
    assert "roe_id_scope_manifest_mismatch" in response.text
    assert _queued_count(db_path) == 0
    audit_row = _latest_denial(db_path, "scheduled_task", "scheduled_task_scope_denied")
    assert audit_row is not None
    assert "task_type=validate" in audit_row[1]
    assert "reason=roe_id_scope_manifest_mismatch" in audit_row[1]


def test_task_enqueue_preserves_roe_scope_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _prepare(tmp_path, monkeypatch)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["app.acme.example"]}

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/tasks/enqueue",
            json={
                "engagement_id": 1001,
                "task_type": "crawl",
                "target": "https://app.acme.example",
                "roe_id": "ROE-WEB-2026-07",
                "scope_manifest": scope_manifest,
                "depth": 1,
            },
            headers=_auth_headers(),
        )

    assert response.status_code == 200, response.text
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT task_key, payload
            FROM distributed_tasks
            WHERE engagement_id=1001
            """
        ).fetchone()
    assert row is not None
    assert row[0] == "crawl:https://app.acme.example"
    payload = json.loads(row[1])
    assert payload["target"] == "https://app.acme.example"
    assert payload["roe_id"] == "ROE-WEB-2026-07"
    assert payload["scope_manifest"] == scope_manifest
    assert payload["depth"] == 1


def _insert_command_center_crawl_action(db_path: Path) -> str:
    action_id = "cmd-crawl-scope"
    with sqlite3.connect(db_path) as con:
        con.execute(
            """
            INSERT INTO command_center_actions (
                action_id, engagement_id, target_type, target_ref, action_type,
                confidence_score, risk_level, requires_approval, status,
                created_at, updated_at, reasoning, opsec_warnings_json,
                params_json, execution_mode, policy_outcome, policy_reason
            )
            VALUES (?, 1001, 'url', 'https://app.acme.example', 'crawl',
                    75, 'medium', 0, 'suggested',
                    '2026-07-09T10:00:00+00:00',
                    '2026-07-09T10:00:00+00:00',
                    'operator requested crawl', '[]', ?, 'manual', 'suggest', '')
            """,
            (action_id, json.dumps({"target": "https://app.acme.example"})),
        )
        con.commit()
    return action_id


def test_command_center_execute_requires_roe_scope_context_before_queue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _prepare(tmp_path, monkeypatch)
    action_id = _insert_command_center_crawl_action(db_path)

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            f"/api/actions/{action_id}/execute",
            json={"engagement_id": 1001},
            headers=_auth_headers(),
        )

    assert response.status_code == 400, response.text
    assert "command center dispatch requires roe_id and scope_manifest" in response.text
    assert _queued_count(db_path) == 0
    audit_row = _latest_denial(db_path, "command_center", "command_center_scope_denied")
    assert audit_row is not None
    assert audit_row[0] == "https://app.acme.example"
    assert "task_type=crawl" in audit_row[1]
    assert "requires roe_id and scope_manifest" in audit_row[1]


def test_command_center_execute_preserves_roe_scope_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = _prepare(tmp_path, monkeypatch)
    action_id = _insert_command_center_crawl_action(db_path)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["app.acme.example"]}

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            f"/api/actions/{action_id}/execute",
            json={
                "engagement_id": 1001,
                "roe_id": "ROE-WEB-2026-07",
                "scope_manifest": scope_manifest,
            },
            headers=_auth_headers(),
        )

    assert response.status_code == 200, response.text
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT task_key, payload
            FROM distributed_tasks
            WHERE engagement_id=1001
            """
        ).fetchone()
    assert row is not None
    assert row[0] == "crawl:https://app.acme.example"
    payload = json.loads(row[1])
    assert payload["task_type"] == "crawl"
    assert payload["target"] == "https://app.acme.example"
    assert payload["action_id"] == action_id
    assert payload["roe_id"] == "ROE-WEB-2026-07"
    assert payload["scope_manifest"] == scope_manifest
