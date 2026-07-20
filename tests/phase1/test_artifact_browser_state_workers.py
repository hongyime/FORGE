from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_artifact_queue_processor_parallelizes_browser_state_child_candidates_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    sqlite3.connect(db_path).close()
    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=3)
    active = 0
    peak = 0
    entered = 0
    lock = threading.Lock()
    gate = threading.Event()
    delays = {
        "one": 0.05,
        "two": 0.01,
        "three": 0.03,
    }
    original_child_values = ArtifactQueueProcessor._browser_state_child_candidate_values

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[Any, tuple[str, ...], tuple[str, ...], dict[str, Any]],
    ) -> list[str]:
        label = child_job[2][-1]
        nonlocal active, peak, entered
        with lock:
            active += 1
            peak = max(peak, active)
            entered += 1
            current_entered = entered
            if entered >= 3:
                gate.set()
        try:
            if current_entered <= 3:
                assert gate.wait(timeout=1.0)
            time.sleep(delays[label])
            return original_child_values(self, child_job)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_browser_state_child_candidate_values",
        _tracking_child_values,
    )

    values = processor._browser_state_document_candidate_values(
        {
            "one": "https://one.acme.example",
            "two": "https://two.acme.example",
            "three": "browser-state-owner@acme.example",
        }
    )

    assert peak == 3
    assert values == [
        "https://one.acme.example",
        "https://two.acme.example",
        "browser-state-owner@acme.example",
    ]
