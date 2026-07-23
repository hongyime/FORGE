from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_external_secret_remote_refs_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    spec = {
        "data": [
            {"remoteRef": {"key": "prod/db/password"}},
            {"remoteRef": {"remoteKey": "prod/db/password"}},
        ],
        "dataFrom": [
            {"extract": {"key": "prod/shared/config"}},
            {"find": {"path": "prod/team/*"}},
            {"find": {"name": "prod/named-secret"}},
        ],
    }
    original_entry = ArtifactQueueProcessor._yaml_external_secret_remote_ref_entry_keys
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_remote_ref_keys(
        self: ArtifactQueueProcessor,
        remote_ref_job: tuple[str, dict[str, object]],
    ) -> list[str]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(self, remote_ref_job)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_yaml_external_secret_remote_ref_entry_keys",
        _tracking_remote_ref_keys,
    )

    assert processor._yaml_external_secret_remote_ref_keys(spec) == [
        "prod/db/password",
        "prod/shared/config",
        "prod/team/*",
        "prod/named-secret",
    ]
    assert peak == 4
