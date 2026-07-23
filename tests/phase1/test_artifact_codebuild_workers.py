from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_codebuild_secret_refs_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "version": "0.2",
        "env": {
            "parameter-store": {
                "API": "/acme/api",
                "DUP": "/acme/api",
            },
            "secrets-manager": {
                "DB": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-pass-AbCdEf",
                "TOKEN": "shared/path:jsonKey",
            },
        },
    }
    normalized = processor._yaml_normalized_mapping(document)
    original_entry = ArtifactQueueProcessor._yaml_codebuild_secret_job_candidate
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_secret_candidate(
        self: ArtifactQueueProcessor,
        secret_job: tuple[str, object],
    ) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(self, secret_job)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_yaml_codebuild_secret_job_candidate",
        _tracking_secret_candidate,
    )

    assert processor._yaml_codebuild_buildspec_structured_candidates(document, normalized, ()) == [
        "aws-parameterstore://acme/api",
        "aws-secretsmanager://arn:aws:secretsmanager:us-east-1:123456789012:secret:db-pass-AbCdEf",
        "aws-secretsmanager://shared/path",
    ]
    assert peak == 4
