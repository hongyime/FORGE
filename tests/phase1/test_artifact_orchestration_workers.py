from __future__ import annotations

import threading
import time

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_orchestration_document_children_use_bounded_workers_and_preserve_order(
    tmp_path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "chart": {"repository": "charts.acme.example/stable"},
        "metadata": {
            "annotations": {
                "external-dns.alpha.kubernetes.io/hostname": "anno.acme.example",
            }
        },
        "route": {
            "rule": "Host(`rule-one.acme.example`) || Host(`rule-two.acme.example`)",
        },
        "service": {"endpoint": "svc.acme.example:8080/path"},
    }
    original_child = ArtifactQueueProcessor._orchestration_child_url_candidates
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object, object, str, str],
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
        "_orchestration_child_url_candidates",
        _tracking_child_values,
    )

    result = processor._orchestration_document_url_candidates(
        document,
        source_label="helm-chart",
    )

    assert peak == 4
    assert result == [
        "http://charts.acme.example/stable",
        "http://anno.acme.example",
        "http://rule-one.acme.example",
        "http://rule-two.acme.example",
        "http://svc.acme.example:8080/path",
    ]


def test_orchestration_routing_rules_use_bounded_workers_and_preserve_order(
    tmp_path,
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

    assert processor._orchestration_document_url_candidates(
        document,
        source_label="kubernetes-manifest",
    ) == [
        "http://first.acme.example",
        "http://second.acme.example",
    ]
    assert processor._orchestration_structured_payload_text(
        "metadata:\n  labels:\n    traefik.http.routers.api.rule: Host(`ignored.acme.example`)",
        source_hint="notes.yaml",
    ) == ""
