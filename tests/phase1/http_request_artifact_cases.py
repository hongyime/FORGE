from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_http_request_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        @baseUrl = http-env.acme.example/api
        GET http-one.acme.example/v1/users HTTP/1.1
        POST https://http-two.acme.example/v2/session
        GET {{baseUrl}}/users
        Host: http-host.acme.example
        Content-Type: application/json
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_http_request_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._http_request_text_structured_payload_text(
        payload,
        source_hint="requests/session.http",
    )

    assert observed_candidate_batches == [
        [
            "http-env.acme.example/api",
            "http-one.acme.example/v1/users",
            "https://http-two.acme.example/v2/session",
            "{{baseUrl}}/users",
            "http-host.acme.example",
        ]
    ]
    assert result.splitlines() == [
        "https://http-env.acme.example/api",
        "https://http-one.acme.example/v1/users",
        "https://http-two.acme.example/v2/session",
        "https://http-host.acme.example",
    ]


def run_hurl_request_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        apiHost: hurl-env.acme.example/api
        GET hurl-one.acme.example/v1/users
        HTTP 200
        POST https://hurl-two.acme.example/v2/session
        GET {{apiHost}}/users
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_http_request_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._http_request_text_structured_payload_text(
        payload,
        source_hint="requests/session.hurl",
    )

    assert observed_candidate_batches == [
        [
            "hurl-env.acme.example/api",
            "hurl-one.acme.example/v1/users",
            "https://hurl-two.acme.example/v2/session",
            "{{apiHost}}/users",
        ]
    ]
    assert result.splitlines() == [
        "https://hurl-env.acme.example/api",
        "https://hurl-one.acme.example/v1/users",
        "https://hurl-two.acme.example/v2/session",
    ]
