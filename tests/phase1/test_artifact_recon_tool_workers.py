from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_recon_tool_json_document_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "one": {"host": "one.acme.example"},
        "two": {"url": "two.acme.example/status?token=drop-me&view=public"},
        "three": {"results": [{"name": "three.acme.example"}]},
        "four": {"matched-url": "https://four.acme.example/path"},
    }
    original_child = (
        ArtifactQueueProcessor._recon_tool_output_structured_document_child_values
    )
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[object, object, set[str]],
    ) -> list[str]:
        nonlocal active, peak
        tracks_top_level = child_job[0] in {"one", "two", "three", "four"}
        if tracks_top_level:
            with lock:
                active += 1
                peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_child(self, child_job)
        finally:
            if tracks_top_level:
                with lock:
                    active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_recon_tool_output_structured_document_child_values",
        _tracking_child_values,
    )

    result = processor._recon_tool_output_structured_payload_text(
        json.dumps(document),
        source_hint="httpx-output.json",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://one.acme.example",
        "https://two.acme.example/status?view=public",
        "https://three.acme.example",
        "https://four.acme.example/path",
    ]
