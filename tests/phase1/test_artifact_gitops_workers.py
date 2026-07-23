from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_gitops_repository_walk_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    mapping = {
        "branchOne": {"repoURL": "https://github.com/acme/one.git"},
        "branchTwo": {"name": "sourceRepository", "value": "git@github.com:acme/two.git"},
        "branchThree": [{"url": "ssh://git@github.com/acme/three.git"}],
        "branchFour": {"nested": {"repo_url": "https://gitlab.com/acme/four.git"}},
    }
    original_child = ArtifactQueueProcessor._yaml_gitops_repository_child_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object],
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
        "_yaml_gitops_repository_child_values",
        _tracking_child_values,
    )

    result = processor._yaml_gitops_repository_candidates_from_mapping(mapping)

    assert peak == 4
    assert result == [
        "https://github.com/acme/one",
        "https://github.com/acme/two",
        "https://github.com/acme/three",
        "https://gitlab.com/acme/four",
    ]


def test_gitops_repository_normalization_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    mapping = {
        "branchOne": {"repoURL": "https://github.com/acme/one.git"},
        "branchTwo": {"repoURL": "git@github.com:acme/two.git"},
        "branchThree": {"repoURL": "ssh://git@github.com/acme/three.git"},
        "branchFour": {"repoURL": "oci://ghcr.io/acme/four:latest"},
    }
    original_candidates = ArtifactQueueProcessor._yaml_gitops_repository_candidates
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_repository_candidates(
        self: ArtifactQueueProcessor,
        value: object,
    ) -> list[str]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_candidates(self, value)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_yaml_gitops_repository_candidates",
        _tracking_repository_candidates,
    )

    result = processor._yaml_gitops_repository_candidates_from_mapping(mapping)

    assert peak == 4
    assert result == [
        "https://github.com/acme/one",
        "https://github.com/acme/two",
        "https://github.com/acme/three",
        "https://ghcr.io/acme/four",
    ]
