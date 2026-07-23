from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_api_spec_mapping_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "openapi": "3.1.0",
        "servers": [
            {"url": "https://api-one.acme.example/v1?token=hidden&view=public"},
            {"host": "api-two.acme.example", "scheme": "https", "basePath": "/v2"},
        ],
        "externalDocs": {"url": "docs.acme.example/openapi"},
        "callbacks": {"https://callback.acme.example/hooks": {"post": {}}},
    }
    original_child = ArtifactQueueProcessor._api_spec_child_candidate_values
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
        "_api_spec_child_candidate_values",
        _tracking_child_values,
    )

    raw_values = processor._api_spec_document_candidate_values(document)
    result = [
        ArtifactQueueProcessor._api_spec_url_candidate_entry(raw_value)
        for raw_value in raw_values
    ]

    assert peak == 4
    assert result == [
        "https://api-one.acme.example/v1?view=public",
        "https://api-two.acme.example/v2",
        "https://docs.acme.example/openapi",
        "https://callback.acme.example/hooks",
    ]


def test_api_spec_list_items_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = [
        {"url": "https://list-one.acme.example"},
        {"url": "list-two.acme.example/path"},
        {"callbacks": {"https://list-callback.acme.example/hook": {}}},
        {"externalDocs": {"url": "https://list-docs.acme.example/openapi"}},
    ]
    original_item = ArtifactQueueProcessor._api_spec_list_item_candidate_values
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
        "_api_spec_list_item_candidate_values",
        _tracking_item_values,
    )

    raw_values = processor._api_spec_document_candidate_values(document)
    result = [
        ArtifactQueueProcessor._api_spec_url_candidate_entry(raw_value)
        for raw_value in raw_values
    ]

    assert peak == 4
    assert result == [
        "https://list-one.acme.example",
        "https://list-two.acme.example/path",
        "https://list-callback.acme.example/hook",
        "https://list-docs.acme.example/openapi",
    ]
