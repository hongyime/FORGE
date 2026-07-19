from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_http_request_text_line_candidates_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        # request variables are passive local metadata.
        @baseUrl = http-env.acme.example/api
        GET http-one.acme.example/v1/users HTTP/1.1
        POST https://http-two.acme.example/v2/session
        GET {{baseUrl}}/users
        Host: http-host.acme.example
        """
    ).strip()
    observed_lines: list[str] = []
    observed_url_candidates: list[str] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_http_request_text_line_candidate_value":
            observed_lines.extend(str(item) for item in materialized)
        if getattr(worker, "__name__", "") == "_http_request_url_candidate_entry":
            observed_url_candidates.extend(str(item) for item in materialized)
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._http_request_text_structured_payload_text(
        payload,
        source_hint="requests/session.http",
    )

    assert observed_lines == payload.splitlines()
    assert observed_url_candidates == [
        "http-env.acme.example/api",
        "http-one.acme.example/v1/users",
        "https://http-two.acme.example/v2/session",
        "{{baseUrl}}/users",
        "http-host.acme.example",
    ]
    assert result.splitlines() == [
        "https://http-env.acme.example/api",
        "https://http-one.acme.example/v1/users",
        "https://http-two.acme.example/v2/session",
        "https://http-host.acme.example",
    ]
