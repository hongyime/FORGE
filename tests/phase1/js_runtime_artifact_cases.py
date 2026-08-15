from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_js_runtime_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        {
          "imports": {
            "@std/assert": "jsr:@std/assert@1",
            "chalk": "npm:chalk@5"
          },
          "publish": {
            "registry": "jsr.acme.example/api"
          }
        }
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_js_runtime_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._js_runtime_text_structured_payload_text(
        payload,
        source_hint="deno.jsonc",
    )

    assert observed_candidate_batches == [
        [
            "jsr:@std/assert@1",
            "npm:chalk@5",
            "jsr.acme.example/api",
        ]
    ]
    assert result.splitlines() == [
        "https://jsr.io/@std/assert",
        "https://www.npmjs.com/package/chalk",
        "https://jsr.acme.example/api",
    ]
