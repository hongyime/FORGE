from __future__ import annotations

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_orchestration_routing_rules_use_bounded_workers_and_preserve_order(
    tmp_path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    document = {
        "metadata": {
            "labels": {
                "traefik.enable": "true",
                "traefik.http.routers.api.rule": (
                    "Host(`first.acme.example`) || Host(`second.acme.example`)"
                ),
                "traefik.http.routers.admin.rule": "Host(`first.acme.example`)",
            }
        }
    }
    observed_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_edge_proxy_line_url_candidates":
            observed_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    assert processor._orchestration_document_url_candidates(
        document,
        source_label="kubernetes-manifest",
    ) == [
        "http://first.acme.example",
        "http://second.acme.example",
    ]
    assert observed_batches[0] == [
        "true",
        "Host(`first.acme.example`) || Host(`second.acme.example`)",
        "Host(`first.acme.example`)",
    ]
    assert processor._orchestration_structured_payload_text(
        "metadata:\n  labels:\n    traefik.http.routers.api.rule: Host(`ignored.acme.example`)",
        source_hint="notes.yaml",
    ) == ""
