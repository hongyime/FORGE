from __future__ import annotations

import threading
import time
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_observability_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "jobOne": {
            "scheme": "https",
            "targets": [
                "api-one.acme.example:9443",
                "localhost:9090",
                "{{ template_target }}:9100",
            ],
        },
        "jobTwo": {"static_configs": [{"targets": ["worker.acme.example:9100/custom"]}]},
        "jobThree": {
            "scheme": "https",
            "nested": {"endpoint": "traces.acme.example:4317"},
        },
        "jobFour": {
            "urls": [
                "https://metrics.acme.example/api/v1/write?token=hidden&view=public",
                "https://metrics.acme.example/api/v1/write?token=hidden&view=public",
            ]
        },
    }
    original_child = ArtifactQueueProcessor._observability_child_candidate_values
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
        "_observability_child_candidate_values",
        _tracking_child_values,
    )

    result = processor._observability_structured_document_candidates(
        document,
        "prometheus-config",
    )

    assert peak == 4
    assert result == [
        "https://api-one.acme.example:9443",
        "http://worker.acme.example:9100/custom",
        "https://traces.acme.example:4317",
        "https://metrics.acme.example/api/v1/write?view=public",
    ]


def test_observability_payload_remains_source_gated(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        scrape_configs:
          - job_name: api
            targets:
              - api.acme.example:9443
        """
    ).strip()

    assert processor._observability_structured_payload_text(payload, source_hint="notes.yml") == ""
