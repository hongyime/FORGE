from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
)


def test_interface_definition_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        #%RAML 1.0
        baseUri: raml-one.acme.example/api
        <soap:address location="wsdl-one.acme.example/service" />
        <resources base="wadl-one.acme.example/api" />
        option (acme.endpoint) = "proto-one.acme.example/grpc";
        endpoint: https://interface-two.acme.example/rpc
        callbackUrl: https://{tenant}.acme.example/callback
        """
    ).strip()
    observed_pattern_batches: list[list[str]] = []
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_interface_definition_pattern_candidates":
            observed_pattern_batches.append([str(item[0]) for item in materialized])
        if getattr(worker, "__name__", "") == "_interface_definition_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._interface_definition_text_structured_payload_text(
        payload,
        source_hint="service.raml",
    )

    assert observed_pattern_batches == [["key_value", "xml_attr", "proto_option"]]
    assert observed_candidate_batches == [
        [
            "raml-one.acme.example/api",
            "wsdl-one.acme.example/service",
            "wadl-one.acme.example/api",
            "proto-one.acme.example/grpc",
            "https://interface-two.acme.example/rpc",
            "https://{tenant}.acme.example/callback",
        ]
    ]
    assert result.splitlines() == [
        "https://raml-one.acme.example/api",
        "https://wsdl-one.acme.example/service",
        "https://wadl-one.acme.example/api",
        "https://proto-one.acme.example/grpc",
        "https://interface-two.acme.example/rpc",
    ]


def test_buf_config_structured_payload_extracts_registry_modules_with_bounded_workers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        version: v2
        deps:
          - buf.build/acme/paymentapis
          - buf.internal.acme.example/platform/privateapis
          - acme.buf.dev/platform/proapis
        plugins:
          - remote: buf.build/protocolbuffers/go:v1.35.1
        breaking:
          against:
            - buf.build/acme/previous-api
        """
    ).strip()
    observed_pattern_batches: list[list[str]] = []
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_interface_definition_pattern_candidates":
            observed_pattern_batches.append([str(item[0]) for item in materialized])
        if getattr(worker, "__name__", "") == "_interface_definition_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._interface_definition_text_structured_payload_text(
        payload,
        source_hint="buf.gen.yaml",
    )

    assert observed_pattern_batches == [["key_value", "xml_attr", "proto_option", "buf_registry"]]
    assert observed_candidate_batches == [
        [
            "buf.build/acme/paymentapis",
            "buf.internal.acme.example/platform/privateapis",
            "acme.buf.dev/platform/proapis",
            "buf.build/protocolbuffers/go",
            "buf.build/acme/previous-api",
            "buf.build/acme/paymentapis",
            "buf.internal.acme.example/platform/privateapis",
            "acme.buf.dev/platform/proapis",
            "buf.build/protocolbuffers/go",
            "buf.build/acme/previous-api",
        ]
    ]
    assert result.splitlines() == [
        "https://buf.build/acme/paymentapis",
        "https://buf.internal.acme.example/platform/privateapis",
        "https://acme.buf.dev/platform/proapis",
        "https://buf.build/protocolbuffers/go",
        "https://buf.build/acme/previous-api",
    ]


def test_buf_config_artifacts_are_first_class_text_configs() -> None:
    expected = {
        "buf.yaml": "buf-config",
        "buf.yml": "buf-config",
        "proto/buf.gen.yaml": "buf-generation-config",
        "proto/buf.gen.yml": "buf-generation-config",
        "proto/buf.work.yaml": "buf-workspace",
        "proto/buf.work.yml": "buf-workspace",
        "proto/buf.lock": "buf-lock",
    }

    for name, label in expected.items():
        assert _classify_artifact_name(name) == "config"
        assert _artifact_format_label(name) == label
