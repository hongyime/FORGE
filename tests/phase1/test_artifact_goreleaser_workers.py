from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_goreleaser_config_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    mapping = {
        "project_name": "forgecli",
        "dockers": [
            {
                "image_templates": [
                    "ghcr.io/acme/forgecli:{{ .Tag }}",
                    "registry.gitlab.com/acme/forgecli:v{{ .Version }}",
                ]
            }
        ],
        "docker_manifests": [{"name_template": "quay.io/acme/forgecli:{{ .Tag }}"}],
        "blobs": [
            {"provider": "s3", "bucket": "acme-goreleaser-bucket"},
            {"provider": "gs", "bucket": "acme-goreleaser-gcs"},
        ],
    }
    normalized = processor._yaml_normalized_mapping(mapping)
    original_child = ArtifactQueueProcessor._yaml_goreleaser_child_candidate_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object, object, tuple[str, ...]],
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
        "_yaml_goreleaser_child_candidate_values",
        _tracking_child_values,
    )

    result = processor._yaml_goreleaser_config_structured_candidates(
        mapping,
        normalized,
        ".goreleaser.yaml",
    )

    assert peak == 4
    assert result == [
        "https://ghcr.io/acme/forgecli",
        "https://registry.gitlab.com/acme/forgecli",
        "https://quay.io/repository/acme/forgecli",
        "s3://acme-goreleaser-bucket",
        "gs://acme-goreleaser-gcs",
    ]
