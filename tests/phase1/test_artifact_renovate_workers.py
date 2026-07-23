from __future__ import annotations

import threading
import time
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_renovate_text_candidates_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        matchHost: "quay.io"
        registryUrl: "nuget.pkg.github.com"
        registryUrls: [
          "https://npm.pkg.github.com",
          "https://renovate.acme.example/registry?token=hidden&view=public"
        ]
        """
    ).strip()
    original_entry = ArtifactQueueProcessor._renovate_text_candidate_entry
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_candidate_entry(raw_value: object) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(raw_value)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_renovate_text_candidate_entry",
        staticmethod(_tracking_candidate_entry),
    )

    result = processor._renovate_text_structured_payload_text(
        payload,
        source_hint="renovate.json5",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://quay.io",
        "https://nuget.pkg.github.com",
        "https://npm.pkg.github.com",
        "https://renovate.acme.example/registry?view=public",
    ]
