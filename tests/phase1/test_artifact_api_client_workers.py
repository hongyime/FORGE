from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from forge.engagement_orchestrator import ArtifactQueueProcessor


@pytest.mark.parametrize(
    ("source_hint", "payload", "expected_family_batches", "expected_raw_values", "expected_lines"),
    [
        (
            ".dredd.yml",
            """
            endpoint: dredd-hostonly.acme.example/api
            api-description: https://dredd-docs.acme.example/openapi.yaml
            endpoint: https://${tenant}.acme.example/template
            """,
            [["dredd"], ["jmeter"]],
            [
                "dredd-hostonly.acme.example/api",
                "https://dredd-docs.acme.example/openapi.yaml",
                "https://${tenant}.acme.example/template",
            ],
            [
                "https://dredd-hostonly.acme.example/api",
                "https://dredd-docs.acme.example/openapi.yaml",
            ],
        ),
        (
            ".schemathesis.toml",
            """
            schema = "https://schemathesis-schema.acme.example/openapi.json"
            base-url = "schemathesis-hostonly.acme.example/api"
            endpoint = "https://${tenant}.acme.example/template"
            """,
            [["schemathesis"], ["jmeter"]],
            [
                "https://schemathesis-schema.acme.example/openapi.json",
                "schemathesis-hostonly.acme.example/api",
                "https://${tenant}.acme.example/template",
            ],
            [
                "https://schemathesis-schema.acme.example/openapi.json",
                "https://schemathesis-hostonly.acme.example/api",
            ],
        ),
        (
            "pactum.config.js",
            """
            const pactum = require('pactum');
            pactum.request.setBaseUrl('pactum-base.acme.example/api');
            module.exports = {
              baseUrl: 'https://pactum-config.acme.example/v1',
              endpoint: 'https://${tenant}.acme.example/template',
            };
            """,
            [["pactum", "fallback"], ["jmeter"]],
            [
                "pactum-base.acme.example/api",
                "https://pactum-config.acme.example/v1",
                "https://${tenant}.acme.example/template",
            ],
            [
                "https://pactum-base.acme.example/api",
                "https://pactum-config.acme.example/v1",
            ],
        ),
        (
            "k6-test.js",
            """
            import http from 'k6/http';
            import ws from 'k6/ws';
            export const options = { target: 'k6-target.acme.example/api' };
            export default function () {
              http.get('k6-hostonly.acme.example/api');
              http.post("https://k6-live.acme.example/events", "{}");
              http.request("GET", "k6-request.acme.example/v1");
              http.get("https://${tenant}.acme.example/template");
              http.get("/relative");
              ws.connect("wss://k6-ws.acme.example/socket", {}, function () {});
            }
            """,
            [["jmeter", "k6"]],
            [
                "k6-target.acme.example/api",
                "k6-hostonly.acme.example/api",
                "https://k6-live.acme.example/events",
                "k6-request.acme.example/v1",
                "https://${tenant}.acme.example/template",
                "/relative",
                "wss://k6-ws.acme.example/socket",
            ],
            [
                "https://k6-target.acme.example/api",
                "https://k6-hostonly.acme.example/api",
                "https://k6-live.acme.example/events",
                "https://k6-request.acme.example/v1",
                "https://k6-ws.acme.example/socket",
            ],
        ),
        (
            "locustfile.py",
            """
            from locust import HttpUser, task
            class WebsiteUser(HttpUser):
                host = "locust-hostonly.acme.example/api"
                @task
                def index(self):
                    self.client.get("/relative")
                    self.client.post("https://locust-live.acme.example/events")
                    self.client.request("GET", "locust-request.acme.example/v1")
                    self.client.get("https://${tenant}.acme.example/template")
            """,
            [["jmeter", "locust"]],
            [
                "locust-hostonly.acme.example/api",
                "/relative",
                "https://locust-live.acme.example/events",
                "locust-request.acme.example/v1",
                "https://${tenant}.acme.example/template",
            ],
            [
                "https://locust-hostonly.acme.example/api",
                "https://locust-live.acme.example/events",
                "https://locust-request.acme.example/v1",
            ],
        ),
        (
            "api.feature",
            """
            Feature: API
            Background:
              * url 'karate-hostonly.acme.example/api'
            Scenario: status
              And url 'https://karate-live.acme.example/events'
              * url 'https://${tenant}.acme.example/api'
            """,
            [["jmeter"], ["fallback"]],
            [
                "karate-hostonly.acme.example/api",
                "https://karate-live.acme.example/events",
                "https://${tenant}.acme.example/api",
            ],
            [
                "https://karate-hostonly.acme.example/api",
                "https://karate-live.acme.example/events",
            ],
        ),
    ],
)
def test_api_client_text_candidate_families_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
    source_hint: str,
    payload: str,
    expected_family_batches: list[list[str]],
    expected_raw_values: list[str],
    expected_lines: list[str],
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    observed_family_batches: list[list[str]] = []
    observed_url_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_client_text_candidate_family_values":
            observed_family_batches.append([str(item[0]) for item in materialized])
        if getattr(worker, "__name__", "") == "_api_client_url_candidate_entry":
            observed_url_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_client_text_structured_payload_text(
        dedent(payload).strip(),
        source_hint=source_hint,
    )

    assert observed_family_batches == expected_family_batches
    assert observed_url_batches == [expected_raw_values]
    assert result.splitlines() == expected_lines
