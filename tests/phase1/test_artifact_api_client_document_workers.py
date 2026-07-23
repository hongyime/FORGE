from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_api_client_document_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "first": {"request": {"url": {"host": ["api-one", "acme", "example"], "path": ["v1"]}}},
        "second": {"request": {"url": "two.acme.example/status?token=hidden&view=public"}},
        "third": {"key": "baseUrl", "value": "three.acme.example/api"},
        "fourth": {"variables": {"serviceEndpoint": "https://four.acme.example/path"}},
    }
    original_child = ArtifactQueueProcessor._api_client_child_candidate_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object, object, tuple[str, ...], bool],
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
        "_api_client_child_candidate_values",
        _tracking_child_values,
    )

    raw_values = processor._api_client_document_candidate_values(document)
    result = [
        ArtifactQueueProcessor._api_client_url_candidate_entry(raw_value)
        for raw_value in raw_values
    ]

    assert peak == 4
    assert result == [
        "https://api-one.acme.example/v1",
        "https://two.acme.example/status?view=public",
        "https://three.acme.example/api",
        "https://four.acme.example/path",
    ]


def test_api_client_document_list_items_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = [
        {"request": {"url": "list-one.acme.example/api"}},
        {"request": {"url": {"host": "list-two.acme.example", "path": "v2"}}},
        {"name": "targetUrl", "currentValue": "https://list-three.acme.example/status"},
        {"baseUrl": "list-four.acme.example/base?api_key=hidden&view=public"},
    ]
    original_item = ArtifactQueueProcessor._api_client_list_item_candidate_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_item_values(
        self: ArtifactQueueProcessor,
        item_job: tuple[int, object, tuple[str, ...]],
    ) -> list[str]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_item(self, item_job)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_api_client_list_item_candidate_values",
        _tracking_item_values,
    )

    raw_values = processor._api_client_document_candidate_values(document)
    result = [
        ArtifactQueueProcessor._api_client_url_candidate_entry(raw_value)
        for raw_value in raw_values
    ]

    assert peak == 4
    assert result == [
        "https://list-one.acme.example/api",
        "https://list-two.acme.example/v2",
        "https://list-three.acme.example/status",
        "https://list-four.acme.example/base?view=public",
    ]
