"""Integration tests for the artifact-queue status API."""
from __future__ import annotations

import sqlite3
import time
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
            + mint_token(subject, roles=(role,), workspace_id=workspace_id)
        )
    }


def _create_engagement(
    client: TestClient,
    *,
    headers: dict[str, str],
    name: str = "Acme ArtifactQueue",
) -> dict[str, object]:
    response = client.post(
        "/api/engagements",
        json={"name": name, "status": "ACTIVE", "seeds": ["acme.example"]},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _seed_artifact_queue(db_path: Path, *, engagement_id: int = 1) -> None:
    con = sqlite3.connect(db_path)
    try:
        rows = [
            # (source_url, artifact_type, status, notes)
            ("https://acme.example/a1.apk", "apk", "queued", ""),
            ("https://acme.example/a2.apk", "apk", "queued", ""),
            ("https://acme.example/b1.ipa", "ipa", "downloaded", ""),
            ("https://acme.example/c1.zip", "archive", "parsed", ""),
            ("https://acme.example/c2.zip", "archive", "parsed", ""),
            ("https://acme.example/c3.zip", "archive", "parsed", ""),
            ("https://acme.example/x1.bin", "binary", "failed", "parser crash: bad magic"),
            ("https://acme.example/x2.bin", "binary", "failed", "timeout"),
            ("https://acme.example/s1.cfg", "config", "skipped", ""),
        ]
        for idx, (url, atype, status, notes) in enumerate(rows):
            # Stagger updated_at so sort order is deterministic.
            timestamp = f"2026-01-01T00:00:{idx:02d}Z"
            con.execute(
                """
                INSERT INTO artifact_queue
                    (engagement_id, source_url, artifact_type, status,
                     discovered_from, notes, queued_at, updated_at)
                VALUES (?, ?, ?, ?, 'test', ?, ?, ?)
                """,
                (engagement_id, url, atype, status, notes, timestamp, timestamp),
            )
        con.commit()
    finally:
        con.close()


def test_artifact_queue_returns_counts_and_paginated_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    app = create_app()
    with TestClient(app) as client:
        operator = _headers("op-one", role="operator")
        created = _create_engagement(client, headers=operator)
        slug = str(created["slug"])
        db_path = Path(str(created["path"]))
        _seed_artifact_queue(db_path, engagement_id=int(created["id"]))

        resp = client.get(
            f"/api/engagements/{slug}/artifact-queue",
            headers=operator,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        # All five mandatory fields present.
        assert body["pending"] == 2
        assert body["processing"] == 1
        assert body["complete"] == 3
        assert body["failed"] == 2
        assert body["total"] == 9  # includes skipped

        # Default pagination returns all rows (<= 100).
        assert body["pagination"]["offset"] == 0
        assert body["pagination"]["limit"] == 100
        assert len(body["artifacts"]) == 9

        # Default sort is timestamp desc.
        timestamps = [row["timestamp"] for row in body["artifacts"]]
        assert timestamps == sorted(timestamps, reverse=True)

        # Row shape: name / parser / state / timestamp / error_msg all present.
        first = body["artifacts"][0]
        assert set(first) >= {"name", "parser", "state", "timestamp", "error_msg"}
        assert first["artifact_name"] == first["name"]
        assert "id" in first


def test_artifact_queue_pagination_offset_and_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    app = create_app()
    with TestClient(app) as client:
        operator = _headers("op-two", role="operator")
        created = _create_engagement(client, headers=operator, name="Acme Pag")
        slug = str(created["slug"])
        _seed_artifact_queue(Path(str(created["path"])), engagement_id=int(created["id"]))

        page1 = client.get(
            f"/api/engagements/{slug}/artifact-queue?offset=0&limit=3&sort=timestamp asc",
            headers=operator,
        ).json()
        page2 = client.get(
            f"/api/engagements/{slug}/artifact-queue?offset=3&limit=3&sort=timestamp asc",
            headers=operator,
        ).json()

        assert len(page1["artifacts"]) == 3
        assert len(page2["artifacts"]) == 3
        assert page1["artifacts"][0]["timestamp"] < page1["artifacts"][-1]["timestamp"]
        # No overlap between pages.
        names_page1 = {a["name"] for a in page1["artifacts"]}
        names_page2 = {a["name"] for a in page2["artifacts"]}
        assert names_page1.isdisjoint(names_page2)


def test_artifact_queue_filters_by_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    app = create_app()
    with TestClient(app) as client:
        operator = _headers("op-three", role="operator")
        created = _create_engagement(client, headers=operator, name="Acme Filter")
        slug = str(created["slug"])
        _seed_artifact_queue(Path(str(created["path"])), engagement_id=int(created["id"]))

        resp = client.get(
            f"/api/engagements/{slug}/artifact-queue?state=failed&sort=timestamp",
            headers=operator,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body["artifacts"]) == 2
        assert all(a["state"] == "failed" for a in body["artifacts"])
        assert all(a["error_msg"] for a in body["artifacts"])
        # Counts remain unfiltered totals.
        assert body["total"] == 9
        assert body["failed"] == 2
        # filtered_total reflects the subset.
        assert body["pagination"]["filtered_total"] == 2


def test_artifact_queue_rejects_invalid_params(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    app = create_app()
    with TestClient(app) as client:
        operator = _headers("op-four", role="operator")
        created = _create_engagement(client, headers=operator, name="Acme Reject")
        slug = str(created["slug"])
        _seed_artifact_queue(Path(str(created["path"])), engagement_id=int(created["id"]))

        # Negative offset -> 400
        neg_offset = client.get(
            f"/api/engagements/{slug}/artifact-queue?offset=-1",
            headers=operator,
        )
        assert neg_offset.status_code == 400
        assert "offset" in neg_offset.json()["detail"]

        # Zero/negative limit -> 400
        bad_limit = client.get(
            f"/api/engagements/{slug}/artifact-queue?limit=0",
            headers=operator,
        )
        assert bad_limit.status_code == 400

        # Limit above cap -> 400
        over_limit = client.get(
            f"/api/engagements/{slug}/artifact-queue?limit=100000",
            headers=operator,
        )
        assert over_limit.status_code == 400

        # Unknown state -> 400
        bad_state = client.get(
            f"/api/engagements/{slug}/artifact-queue?state=bogus",
            headers=operator,
        )
        assert bad_state.status_code == 400

        # SQL-injection attempt in sort must be rejected as unknown column.
        bad_sort = client.get(
            f"/api/engagements/{slug}/artifact-queue?sort=id; DROP TABLE artifact_queue--",
            headers=operator,
        )
        assert bad_sort.status_code == 400

        # Table still intact.
        con = sqlite3.connect(Path(str(created["path"])))
        try:
            count = con.execute("SELECT COUNT(*) FROM artifact_queue").fetchone()[0]
            assert count == 9
        finally:
            con.close()


def test_artifact_queue_performance_under_100_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    app = create_app()
    with TestClient(app) as client:
        operator = _headers("op-perf", role="operator")
        created = _create_engagement(client, headers=operator, name="Acme Perf")
        slug = str(created["slug"])
        db_path = Path(str(created["path"]))
        engagement_id = int(created["id"])

        con = sqlite3.connect(db_path)
        try:
            statuses = ["queued", "downloaded", "parsed", "failed", "skipped"]
            con.executemany(
                """
                INSERT INTO artifact_queue
                    (engagement_id, source_url, artifact_type, status,
                     discovered_from, notes, queued_at, updated_at)
                VALUES (?, ?, ?, ?, 'perf', '', ?, ?)
                """,
                [
                    (
                        engagement_id,
                        f"https://acme.example/perf/{i}.bin",
                        "binary",
                        statuses[i % len(statuses)],
                        f"2026-02-01T00:{i // 60:02d}:{i % 60:02d}Z",
                        f"2026-02-01T00:{i // 60:02d}:{i % 60:02d}Z",
                    )
                    for i in range(100)
                ],
            )
            con.commit()
        finally:
            con.close()

        start = time.perf_counter()
        resp = client.get(
            f"/api/engagements/{slug}/artifact-queue?limit=100",
            headers=operator,
        )
        elapsed = time.perf_counter() - start
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 100
        assert len(body["artifacts"]) == 100
        assert elapsed < 1.0, f"artifact-queue took {elapsed:.3f}s (>= 1s budget)"


def test_artifact_queue_requires_read_permission(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_webui_env(tmp_path, monkeypatch)
    app = create_app()
    with TestClient(app) as client:
        operator = _headers("op-rbac", role="operator")
        created = _create_engagement(client, headers=operator, name="Acme RBAC")
        slug = str(created["slug"])

        # viewer role has artifacts:read, so should succeed.
        viewer = _headers("op-rbac", role="viewer")
        ok = client.get(
            f"/api/engagements/{slug}/artifact-queue",
            headers=viewer,
        )
        assert ok.status_code == 200, ok.text
