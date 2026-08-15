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


def run_selenium_side_structured_payload_resolves_navigation_targets(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = json.dumps(
        {
            "id": "acme-side",
            "version": "2.0",
            "name": "Acme Selenium",
            "url": "selenium-base.acme.example/app",
            "tests": [
                {
                    "name": "login",
                    "commands": [
                        {"command": "open", "target": "/login"},
                        {"command": "click", "target": "css=.submit"},
                        {"command": "openWindow", "target": "reports.acme.example/dashboard"},
                        {"command": "open", "target": "https://${tenant}.acme.example/template"},
                        {"command": "open", "target": "//cdn.acme.example/assets"},
                    ],
                }
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
        source_hint="login.side",
    )

    assert observed_candidate_batches == [
        [
            "selenium-base.acme.example/app",
            "https://selenium-base.acme.example/login",
            "reports.acme.example/dashboard",
            "https://${tenant}.acme.example/template",
            "https://cdn.acme.example/assets",
        ]
    ]
    assert result.splitlines() == [
        "https://selenium-base.acme.example/app",
        "https://selenium-base.acme.example/login",
        "https://reports.acme.example/dashboard",
        "https://cdn.acme.example/assets",
    ]


def run_tavern_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        test_name: Acme Tavern
        variables:
          base_url: tavern-env.acme.example/api
        stages:
          - name: host-only
            request:
              url: tavern-one.acme.example/v1/users
          - name: live
            request:
              url: https://tavern-two.acme.example/v2/session
          - name: templated
            request:
              url: https://${tenant}.acme.example/template
          - name: host-key
            request:
              host: tavern-host.acme.example
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
        source_hint="login.tavern.yaml",
    )

    assert observed_candidate_batches == [
        [
            "tavern-env.acme.example/api",
            "tavern-one.acme.example/v1/users",
            "https://tavern-two.acme.example/v2/session",
            "https://${tenant}.acme.example/template",
            "tavern-host.acme.example",
        ]
    ]
    assert result.splitlines() == [
        "https://tavern-env.acme.example/api",
        "https://tavern-one.acme.example/v1/users",
        "https://tavern-two.acme.example/v2/session",
        "https://tavern-host.acme.example",
    ]


def run_dredd_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        endpoint: dredd-hostonly.acme.example/api
        blueprint: https://dredd-docs.acme.example/openapi.yaml
        server: "python manage.py runserver"
        hookfiles:
          - hooks/*.js
        x_tenant_url: https://${tenant}.acme.example/template
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
        source_hint=".dredd.yml",
    )

    assert observed_candidate_batches == [
        [
            "dredd-hostonly.acme.example/api",
            "https://dredd-docs.acme.example/openapi.yaml",
            "https://${tenant}.acme.example/template",
        ]
    ]
    assert result.splitlines() == [
        "https://dredd-hostonly.acme.example/api",
        "https://dredd-docs.acme.example/openapi.yaml",
    ]


def run_schemathesis_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        schema = "https://schemathesis-schema.acme.example/openapi.json"
        base-url = "schemathesis-hostonly.acme.example/api"
        endpoint = "https://${tenant}.acme.example/template"
        headers = { Authorization = "Bearer ${TOKEN}" }
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
        source_hint=".schemathesis.toml",
    )

    assert observed_candidate_batches == [
        [
            "https://schemathesis-schema.acme.example/openapi.json",
            "schemathesis-hostonly.acme.example/api",
            "https://${tenant}.acme.example/template",
        ]
    ]
    assert result.splitlines() == [
        "https://schemathesis-schema.acme.example/openapi.json",
        "https://schemathesis-hostonly.acme.example/api",
    ]


def run_pactum_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        const pactum = require('pactum');

        pactum.request.setBaseUrl('pactum-base.acme.example/api');

        module.exports = {
          baseUrl: 'https://pactum-config.acme.example/v1',
          endpoint: 'https://${tenant}.acme.example/template',
          testGlob: './specs/**/*.spec.js',
        };
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
        source_hint="pactum.config.js",
    )

    assert observed_candidate_batches == [
        [
            "pactum-base.acme.example/api",
            "https://pactum-config.acme.example/v1",
            "https://${tenant}.acme.example/template",
        ]
    ]
    assert result.splitlines() == [
        "https://pactum-base.acme.example/api",
        "https://pactum-config.acme.example/v1",
    ]


def run_pact_contract_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = json.dumps(
        {
            "consumer": {"name": "acme-web"},
            "provider": {
                "name": "acme-api",
                "baseUrl": "pact-provider.acme.example/api",
            },
            "metadata": {
                "pactBrokerUrl": "https://pact-broker.acme.example/pacts",
            },
            "interactions": [
                {
                    "description": "relative request resolves through provider base",
                    "request": {"method": "GET", "path": "/v1/status"},
                    "providerStates": [
                        {
                            "name": "tenant callback",
                            "params": {
                                "callbackUrl": "pact-state.acme.example/callback",
                            },
                        }
                    ],
                },
                {
                    "description": "full URL request is preserved",
                    "request": {"method": "POST", "url": "https://pact-live.acme.example/events"},
                },
                {
                    "description": "templated request is filtered later",
                    "request": {"method": "GET", "url": "https://${tenant}.acme.example/template"},
                },
            ],
            "messages": [
                {
                    "description": "async callback",
                    "contents": {
                        "messageCallbackUrl": "pact-message.acme.example/callback",
                    },
                }
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
        source_hint="pacts/acme-web-acme-api.json",
    )

    assert observed_candidate_batches == [
        [
            "pact-provider.acme.example/api",
            "https://pact-broker.acme.example/pacts",
            "https://pact-provider.acme.example/v1/status",
            "pact-state.acme.example/callback",
            "https://pact-live.acme.example/events",
            "https://${tenant}.acme.example/template",
            "pact-message.acme.example/callback",
        ]
    ]
    assert result.splitlines() == [
        "https://pact-provider.acme.example/api",
        "https://pact-broker.acme.example/pacts",
        "https://pact-provider.acme.example/v1/status",
        "https://pact-state.acme.example/callback",
        "https://pact-live.acme.example/events",
        "https://pact-message.acme.example/callback",
    ]
