from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_charles_session_json_child_candidates_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = json.dumps(
        [
            {
                "marker": "one",
                "targetUrl": "https://one.acme.example/a?token=hidden&ok=1",
            },
            {
                "marker": "two",
                "targetUrl": "https://two.acme.example/b?api_key=hidden&ok=1",
            },
            {
                "marker": "three",
                "targetUrl": "https://three.acme.example/c?signature=hidden&ok=1",
            },
            {
                "marker": "four",
                "originalUrl": "https://four.acme.example/d?session=hidden&ok=1",
            },
        ],
        sort_keys=True,
    )
    original_child = ArtifactQueueProcessor._charles_session_json_child_candidate_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_candidate_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object],
    ) -> list[str]:
        _index, child = child_job
        nonlocal active, peak
        if isinstance(child, dict) and "marker" in child:
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.05)
                return original_child(self, child_job)
            finally:
                with lock:
                    active -= 1
        return original_child(self, child_job)

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_charles_session_json_child_candidate_values",
        _tracking_child_candidate_values,
    )

    result = processor._charles_session_json_structured_payload_text(
        payload,
        source_hint="session.chlsj",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://one.acme.example/a?ok=1",
        "https://two.acme.example/b?ok=1",
        "https://three.acme.example/c?ok=1",
        "https://four.acme.example/d?ok=1",
    ]
