from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_recon_tool_output_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = "\n".join(
        [
            json.dumps({"host": "one.acme.example"}),
            json.dumps({"url": "two.acme.example/status?token=drop-me&view=public"}),
            json.dumps({"name": "three.acme.example"}),
            json.dumps({"matched-url": "https://four.acme.example/path"}),
        ]
    )
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_recon_tool_output_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._recon_tool_output_structured_payload_text(
        payload,
        source_hint="subfinder.jsonl",
    )

    assert observed_candidate_batches == [
        [
            "one.acme.example",
            "two.acme.example/status?token=drop-me&view=public",
            "three.acme.example",
            "https://four.acme.example/path",
        ]
    ]
    assert result.splitlines() == [
        "https://one.acme.example",
        "https://two.acme.example/status?view=public",
        "https://three.acme.example",
        "https://four.acme.example/path",
    ]
