from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = json.dumps(
        {
            "info": {"name": "Acme"},
            "variable": [
                {"key": "baseUrl", "value": "postman-env.acme.example/api"},
                {"key": "tenantName", "value": "ignored"},
                {"key": "docsUrl", "value": "https://postman-docs.acme.example/reference"},
            ],
            "environment": {
                "api_host": "postman-host-env.acme.example/status",
            },
            "item": [
                {
                    "request": {
                        "url": {
                            "protocol": "https",
                            "host": ["postman-one", "acme", "example"],
                            "path": ["api", "v1"],
                        }
                    }
                },
                {"request": {"url": "postman-two.acme.example/v2"}},
                {"request": {"url": "https://{tenant}.acme.example/v3"}},
            ],
        }
    )
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_client_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="postman_collection",
    )

    assert observed_candidate_batches == [
        [
            "postman-env.acme.example/api",
            "https://postman-docs.acme.example/reference",
            "postman-host-env.acme.example/status",
            "https://postman-one.acme.example/api/v1",
            "postman-two.acme.example/v2",
            "https://{tenant}.acme.example/v3",
        ]
    ]
    assert result.splitlines() == [
        "https://postman-env.acme.example/api",
        "https://postman-docs.acme.example/reference",
        "https://postman-host-env.acme.example/status",
        "https://postman-one.acme.example/api/v1",
        "https://postman-two.acme.example/v2",
    ]


def run_soapui_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        <con:soapui-project xmlns:con="http://eviware.com/soapui/config">
          <con:interface name="Acme">
            <con:endpoints>
              <con:endpoint>soapui-hostonly.acme.example/service</con:endpoint>
              <con:endpoint>https://soapui-live.acme.example/api</con:endpoint>
              <con:endpoint>https://{tenant}.acme.example/api</con:endpoint>
            </con:endpoints>
            <con:request endpoint="soapui-attr.acme.example/rpc" />
          </con:interface>
        </con:soapui-project>
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_client_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="soapui-project.xml",
    )

    assert observed_candidate_batches == [
        [
            "soapui-hostonly.acme.example/service",
            "https://soapui-live.acme.example/api",
            "https://{tenant}.acme.example/api",
            "soapui-attr.acme.example/rpc",
        ]
    ]
    assert result.splitlines() == [
        "https://soapui-hostonly.acme.example/service",
        "https://soapui-live.acme.example/api",
        "https://soapui-attr.acme.example/rpc",
    ]


def run_jmeter_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        <jmeterTestPlan version="1.2">
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.domain">jmeter-hostonly.acme.example</stringProp>
            <stringProp name="HTTPSampler.protocol">https</stringProp>
            <stringProp name="HTTPSampler.path">/api/v1</stringProp>
          </HTTPSamplerProxy>
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.path">https://jmeter-live.acme.example/status</stringProp>
          </HTTPSamplerProxy>
          <HTTPSamplerProxy>
            <stringProp name="HTTPSampler.domain">${tenant}.acme.example</stringProp>
            <stringProp name="HTTPSampler.protocol">https</stringProp>
            <stringProp name="HTTPSampler.path">/template</stringProp>
          </HTTPSamplerProxy>
        </jmeterTestPlan>
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_client_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="load-test.jmx",
    )

    assert observed_candidate_batches == [
        [
            "https://jmeter-hostonly.acme.example/api/v1",
            "https://jmeter-live.acme.example/status",
            "https://${tenant}.acme.example/template",
        ]
    ]
    assert result.splitlines() == [
        "https://jmeter-hostonly.acme.example/api/v1",
        "https://jmeter-live.acme.example/status",
    ]


def run_artillery_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        config:
          target: artillery-hostonly.acme.example/api
          environments:
            preview:
              target: https://${tenant}.acme.example/api
        scenarios:
          - name: status
            flow:
              - get:
                  url: /status
              - post:
                  url: https://artillery-live.acme.example/events
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_client_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="artillery.yml",
    )

    assert observed_candidate_batches == [
        [
            "artillery-hostonly.acme.example/api",
            "https://${tenant}.acme.example/api",
            "/status",
            "https://artillery-live.acme.example/events",
        ]
    ]
    assert result.splitlines() == [
        "https://artillery-hostonly.acme.example/api",
        "https://artillery-live.acme.example/events",
    ]


def run_gherkin_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        Feature: API
        Background:
          * url 'karate-hostonly.acme.example/api'
          * configure headers = { Accept: 'application/json' }
        Scenario: status
          Given path '/status'
          When method get
          And url 'https://karate-live.acme.example/events'
          * url 'https://${tenant}.acme.example/api'
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_client_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_client_text_structured_payload_text(
        payload,
        source_hint="api.feature",
    )

    assert observed_candidate_batches == [
        [
            "karate-hostonly.acme.example/api",
            "https://karate-live.acme.example/events",
            "https://${tenant}.acme.example/api",
        ]
    ]
    assert result.splitlines() == [
        "https://karate-hostonly.acme.example/api",
        "https://karate-live.acme.example/events",
    ]
