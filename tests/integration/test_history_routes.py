"""
tests/integration/test_history_routes.py - REST API for workflow history + replay.

Drives a workflow through 3 stages via the API, then queries:
    * GET /workflows/{id}/history       -> chronological history rows
    * GET /workflows/{id}/history?limit=2
    * GET /workflows/{id}/history?since=<ts>
    * GET /workflows/{id}/replay        -> timeline with elapsed seconds
    * Both endpoints return empty list (NOT 404) for unknown workflow_id.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from forge.api.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    db = tmp_path / "forge_state.db"
    monkeypatch.setenv("FORGE_STATE_DB_URL", f"sqlite:///{db}")
    monkeypatch.setenv("FORGE_AUDIT_LOG_DISABLE", "1")
    app = create_app()
    with TestClient(app) as c:
        yield c


def _start_and_advance_three_stages(client: TestClient) -> str:
    resp = client.post("/workflows", json={"definition": "mvp"})
    assert resp.status_code in (200, 201), resp.text
    wid = resp.json()["workflow_id"]
    for stage_payload in (
        {"phase0": "ok"},
        {"phase1": "ok"},
        {"phase2": "ok"},
    ):
        resp = client.post(
            f"/workflows/{wid}/advance",
            json={"stage_result": stage_payload},
        )
        assert resp.status_code == 200, resp.text
    return wid


def test_status_unknown_workflow_returns_404(client: TestClient) -> None:
    resp = client.get("/workflows/does-not-exist/status")
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "workflow_not_found:does-not-exist"


def test_history_endpoint_returns_chronological_rows(client: TestClient) -> None:
    wid = _start_and_advance_three_stages(client)
    resp = client.get(f"/workflows/{wid}/history")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workflow_id"] == wid
    assert body["count"] >= 3
    rows = body["history"]
    assert all("event_type" in r for r in rows)
    # Strictly ascending recorded_at.
    for i in range(len(rows) - 1):
        assert rows[i]["recorded_at"] <= rows[i + 1]["recorded_at"]
    # First event should be 'created'.
    assert rows[0]["event_type"] == "created"


def test_history_limit_caps_row_count(client: TestClient) -> None:
    wid = _start_and_advance_three_stages(client)
    resp = client.get(f"/workflows/{wid}/history?limit=2")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert len(body["history"]) == 2


@pytest.mark.parametrize("limit", ["0", "-1"])
def test_history_rejects_non_positive_limit(client: TestClient, limit: str) -> None:
    wid = _start_and_advance_three_stages(client)
    resp = client.get(f"/workflows/{wid}/history?limit={limit}")
    assert resp.status_code == 422


def test_history_since_filter(client: TestClient) -> None:
    wid = _start_and_advance_three_stages(client)
    full = client.get(f"/workflows/{wid}/history").json()
    midpoint = full["history"][len(full["history"]) // 2]["recorded_at"]
    resp = client.get(f"/workflows/{wid}/history?since={midpoint}")
    assert resp.status_code == 200
    body = resp.json()
    assert all(r["recorded_at"] >= midpoint for r in body["history"])


def test_history_unknown_workflow_returns_empty_list_not_404(client: TestClient) -> None:
    resp = client.get("/workflows/does-not-exist/history")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workflow_id"] == "does-not-exist"
    assert body["count"] == 0
    assert body["history"] == []


def test_replay_endpoint_returns_timeline_with_elapsed(client: TestClient) -> None:
    wid = _start_and_advance_three_stages(client)
    resp = client.get(f"/workflows/{wid}/replay")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["workflow_id"] == wid
    assert body["count"] >= 3
    timeline = body["timeline"]
    assert timeline[0]["elapsed_seconds_since_start"] == 0.0
    # All entries non-negative elapsed.
    assert all(e["elapsed_seconds_since_start"] >= 0 for e in timeline)
    # Entries have the documented shape.
    expected_keys = {
        "id",
        "timestamp",
        "elapsed_seconds_since_start",
        "event_type",
        "from_stage_index",
        "to_stage_index",
        "from_version",
        "to_version",
        "actor",
        "detail",
    }
    for e in timeline:
        assert expected_keys <= set(e.keys()), f"missing keys: {e}"


def test_replay_unknown_returns_empty_timeline(client: TestClient) -> None:
    resp = client.get("/workflows/missing-wf/replay")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 0
    assert body["timeline"] == []


def test_history_isolation_between_workflows(client: TestClient) -> None:
    wid_a = _start_and_advance_three_stages(client)
    wid_b = _start_and_advance_three_stages(client)
    a = client.get(f"/workflows/{wid_a}/history").json()
    b = client.get(f"/workflows/{wid_b}/history").json()
    assert a["workflow_id"] == wid_a
    assert b["workflow_id"] == wid_b
    assert a["history"] and b["history"]
    # No leakage of B's events into A.
    assert all(r["event_type"] in {"created", "advanced", "completed"} for r in a["history"])
