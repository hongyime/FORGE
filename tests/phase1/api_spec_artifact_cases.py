from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_api_spec_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        openapi: 3.1.0
        servers:
          - url: api-one.acme.example/v1
          - url: https://api-two.acme.example/v2
          - url: https://{tenant}.acme.example/v3
        externalDocs:
          url: docs.acme.example/openapi
        callbacks:
          status:
            https://callback.acme.example/status: {}
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_spec_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_spec_text_structured_payload_text(
        payload,
        source_hint="openapi.yaml",
    )

    assert observed_candidate_batches == [
        [
            "api-one.acme.example/v1",
            "https://api-two.acme.example/v2",
            "https://{tenant}.acme.example/v3",
            "docs.acme.example/openapi",
            "https://callback.acme.example/status",
        ]
    ]
    assert result.splitlines() == [
        "https://api-one.acme.example/v1",
        "https://api-two.acme.example/v2",
        "https://docs.acme.example/openapi",
        "https://callback.acme.example/status",
    ]


def run_api_blueprint_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        FORMAT: 1A
        HOST: apib-hostonly.acme.example/api

        # Acme API

        Support: apib-owner@acme.example

        # Group Users

        ## User [/users/{id}]

        + Response 200 (application/json)
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_spec_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_spec_text_structured_payload_text(
        payload,
        source_hint="apiary.apib",
    )

    assert observed_candidate_batches == [["apib-hostonly.acme.example/api"]]
    assert result.splitlines() == ["https://apib-hostonly.acme.example/api"]


def run_arazzo_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        arazzo: 1.0.1
        info:
          title: Acme workflows
          version: 1.0.0
        sourceDescriptions:
          - name: public
            type: openapi
            url: arazzo-source.acme.example/openapi.yaml
          - name: templated
            type: openapi
            url: https://${tenant}.acme.example/openapi.yaml
        workflows:
          - workflowId: login
            steps:
              - stepId: create-session
                operationId: createSession
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_spec_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_spec_text_structured_payload_text(
        payload,
        source_hint="workflow.arazzo",
    )

    assert observed_candidate_batches == [
        [
            "arazzo-source.acme.example/openapi.yaml",
            "https://${tenant}.acme.example/openapi.yaml",
        ]
    ]
    assert result.splitlines() == ["https://arazzo-source.acme.example/openapi.yaml"]


def run_openapi_overlay_text_structured_payload_extracts_extends_and_update_urls(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        overlay: 1.0.0
        info:
          title: Acme overlay
          version: 1.0.0
        extends: https://overlay-source.acme.example/openapi.yaml
        actions:
          - target: $.servers
            update:
              - url: overlay-hostonly.acme.example/api
          - target: $.x-tenant
            update:
              url: https://${tenant}.acme.example/template
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_api_spec_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._api_spec_text_structured_payload_text(
        payload,
        source_hint="petstore.openapi-overlay",
    )

    assert observed_candidate_batches == [
        [
            "https://overlay-source.acme.example/openapi.yaml",
            "overlay-hostonly.acme.example/api",
            "https://${tenant}.acme.example/template",
        ]
    ]
    assert result.splitlines() == [
        "https://overlay-source.acme.example/openapi.yaml",
        "https://overlay-hostonly.acme.example/api",
    ]
