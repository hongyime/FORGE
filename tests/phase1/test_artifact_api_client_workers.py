from __future__ import annotations

import json
import threading
import time
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


def test_api_client_url_objects_default_host_path_to_https_without_protocol(
    tmp_path: Path,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = {
        "item": [
            {
                "request": {
                    "url": {
                        "host": ["api", "acme", "example"],
                        "path": ["v1", "users"],
                    }
                }
            },
            {
                "request": {
                    "url": {
                        "hostname": "admin.acme.example",
                        "pathname": "health",
                    }
                }
            },
            {"request": {"url": {"host": "metadata.acme.example"}}},
            {"request": {"url": {"host": "localhost", "path": "debug"}}},
        ]
    }

    result = processor._api_client_text_structured_payload_text(
        json.dumps(payload),
        source_hint="postman_collection.json",
    )

    assert result.splitlines() == [
        "https://api.acme.example/v1/users",
        "https://admin.acme.example/health",
    ]


@pytest.mark.parametrize(
    ("source_hint", "payload", "expected_lines"),
    [
        (
            ".dredd.yml",
            """
            endpoint: dredd-one.acme.example/api
            base-url: dredd-two.acme.example/v1
            api-description: https://dredd-three.acme.example/openapi.yaml?token=hidden&view=public
            api-url: https://${tenant}.acme.example/template
            blueprint: https://dredd-four.acme.example/blueprint.apib
            """,
            [
                "https://dredd-one.acme.example/api",
                "https://dredd-two.acme.example/v1",
                "https://dredd-three.acme.example/openapi.yaml?view=public",
                "https://dredd-four.acme.example/blueprint.apib",
            ],
        ),
        (
            ".schemathesis.toml",
            """
            schema = "https://schemathesis-one.acme.example/openapi.json"
            base-url = "schemathesis-two.acme.example/api"
            endpoint = "https://schemathesis-three.acme.example/path?signature=hidden&view=public"
            api-url = "https://${tenant}.acme.example/template"
            base-uri = "schemathesis-four.acme.example/base"
            """,
            [
                "https://schemathesis-one.acme.example/openapi.json",
                "https://schemathesis-two.acme.example/api",
                "https://schemathesis-three.acme.example/path?view=public",
                "https://schemathesis-four.acme.example/base",
            ],
        ),
    ],
)
def test_dredd_schemathesis_line_scanners_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
    source_hint: str,
    payload: str,
    expected_lines: list[str],
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    original_line = ArtifactQueueProcessor._api_client_api_config_line_candidate_value
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_line_candidate(
        self: ArtifactQueueProcessor,
        item: tuple[int, str, object],
    ) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_line(self, item)  # type: ignore[arg-type]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_api_client_api_config_line_candidate_value",
        _tracking_line_candidate,
    )

    result = processor._api_client_text_structured_payload_text(
        dedent(payload).strip(),
        source_hint=source_hint,
    )

    assert peak == 4
    assert result.splitlines() == expected_lines


def test_selenium_side_navigation_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = {
        "url": "selenium-base.acme.example/app?token=hidden&view=public",
        "test1": {"command": "open", "target": "/one?api_key=hidden&view=public"},
        "test2": {
            "command": "openWindow",
            "target": "https://two.acme.example/path?signature=hidden&view=public",
        },
        "test3": {"command": "open", "target": "//three.acme.example/path?token=hidden&view=public"},
        "test4": {"command": "open", "target": "https://${tenant}.acme.example/template"},
    }
    original_child = ArtifactQueueProcessor._api_client_selenium_side_navigation_child_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object, str],
    ) -> list[str]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_child(self, child_job)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_api_client_selenium_side_navigation_child_values",
        _tracking_child_values,
    )

    result = processor._api_client_text_structured_payload_text(
        json.dumps(payload),
        source_hint="login.side",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://selenium-base.acme.example/app?view=public",
        "https://selenium-base.acme.example/one?view=public",
        "https://two.acme.example/path?view=public",
        "https://three.acme.example/path?view=public",
    ]


def test_jmeter_sampler_blocks_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        <jmeterTestPlan version="1.2">
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.domain">jmeter-one.acme.example</stringProp>
            <stringProp name="HTTPSampler.protocol">https</stringProp>
            <stringProp name="HTTPSampler.path">/api/v1</stringProp>
          </HTTPSamplerProxy>
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.path">https://jmeter-two.acme.example/status</stringProp>
          </HTTPSamplerProxy>
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.domain">jmeter-three.acme.example</stringProp>
            <stringProp name="HTTPSampler.protocol">http</stringProp>
            <stringProp name="HTTPSampler.port">8080</stringProp>
            <stringProp name="HTTPSampler.path">/health</stringProp>
          </HTTPSamplerProxy>
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.path">https://jmeter-four.acme.example/path?token=hidden&amp;view=public&amp;api_key=hidden&amp;signature=hidden</stringProp>
          </HTTPSamplerProxy>
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.domain">${tenant}.acme.example</stringProp>
            <stringProp name="HTTPSampler.protocol">https</stringProp>
            <stringProp name="HTTPSampler.path">/template</stringProp>
          </HTTPSamplerProxy>
        </jmeterTestPlan>
        """
    ).strip()
    original_sampler = ArtifactQueueProcessor._api_client_jmeter_sampler_candidate_value
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_sampler_candidate(
        self: ArtifactQueueProcessor,
        body: str,
    ) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_sampler(self, body)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_api_client_jmeter_sampler_candidate_value",
        _tracking_sampler_candidate,
    )

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="load-test.jmx",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://jmeter-one.acme.example/api/v1",
        "https://jmeter-two.acme.example/status",
        "http://jmeter-three.acme.example:8080/health",
        "https://jmeter-four.acme.example/path?view=public",
    ]


def test_k6_pattern_scans_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        import http from 'k6/http';
        import ws from 'k6/ws';

        export const options = { target: 'k6-target.acme.example/api' };

        export default function () {
          http.get('k6-one.acme.example/api');
          http.request("GET", "k6-two.acme.example/v1");
          ws.connect("wss://k6-three.acme.example/socket", {}, function () {});
          http.post("https://k6-four.acme.example/path?token=hidden&view=public&api_key=hidden", "{}");
          http.get("https://${tenant}.acme.example/template");
        }
        """
    ).strip()
    original_pattern = ArtifactQueueProcessor._api_client_k6_pattern_candidate_entries
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_pattern_entries(
        self: ArtifactQueueProcessor,
        item: tuple[int, object, str],
    ) -> list[tuple[int, str]]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_pattern(self, item)  # type: ignore[arg-type]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_api_client_k6_pattern_candidate_entries",
        _tracking_pattern_entries,
    )

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="k6-test.js",
    )

    assert peak == 3
    assert result.splitlines() == [
        "https://k6-target.acme.example/api",
        "https://k6-one.acme.example/api",
        "https://k6-two.acme.example/v1",
        "https://k6-three.acme.example/socket",
        "https://k6-four.acme.example/path?view=public",
    ]


def test_locust_pattern_scans_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        from locust import HttpUser, task

        class WebsiteUser(HttpUser):
            host = "locust-host.acme.example/api"

            @task
            def index(self):
                self.client.get("/relative")
                self.client.post("https://locust-one.acme.example/events")
                self.client.request("GET", "locust-two.acme.example/v1")
                self.client.get("https://locust-three.acme.example/path?token=hidden&view=public")
                self.client.get("https://${tenant}.acme.example/template")
        """
    ).strip()
    original_pattern = ArtifactQueueProcessor._api_client_locust_pattern_candidate_entries
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_pattern_entries(
        self: ArtifactQueueProcessor,
        item: tuple[int, object, str],
    ) -> list[tuple[int, str]]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_pattern(self, item)  # type: ignore[arg-type]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_api_client_locust_pattern_candidate_entries",
        _tracking_pattern_entries,
    )

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="locustfile.py",
    )

    assert peak == 3
    assert result.splitlines() == [
        "https://locust-host.acme.example/api",
        "https://locust-one.acme.example/events",
        "https://locust-two.acme.example/v1",
        "https://locust-three.acme.example/path?view=public",
    ]
