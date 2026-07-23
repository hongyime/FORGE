from __future__ import annotations

import threading
import time
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_graphql_config_document_children_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        schema: graphql-one.acme.example/graphql
        endpoint: https://graphql-two.acme.example/api?token=hidden&view=public
        ignored: local-schema.graphql
        extensions:
          endpoints:
            prod:
              url: graphql-three.acme.example/v1
            tenant:
              url: https://{tenant}.acme.example/graphql
        """
    ).strip()
    original_child = ArtifactQueueProcessor._graphql_config_child_candidate_values
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_child_values(
        self: ArtifactQueueProcessor,
        child_job: tuple[int, object, object, tuple[str, ...]],
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
        "_graphql_config_child_candidate_values",
        _tracking_child_values,
    )

    result = processor._graphql_config_text_structured_payload_text(
        payload,
        source_hint=".graphqlrc.yml",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://graphql-one.acme.example/graphql",
        "https://graphql-two.acme.example/api?view=public",
        "https://graphql-three.acme.example/v1",
    ]


def test_graphql_config_list_items_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = dedent(
        """
        - schema: graphql-list-one.acme.example/graphql
        - endpoint: https://graphql-list-two.acme.example/api?api_key=hidden&view=public
        - extensions:
            endpoints:
              prod:
                url: graphql-list-three.acme.example/v1
        - schema: https://{tenant}.acme.example/graphql
        """
    ).strip()
    original_item = ArtifactQueueProcessor._graphql_config_list_item_candidate_values
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
        "_graphql_config_list_item_candidate_values",
        _tracking_item_values,
    )

    result = processor._graphql_config_text_structured_payload_text(
        payload,
        source_hint=".graphqlrc.yml",
    )

    assert peak == 4
    assert result.splitlines() == [
        "https://graphql-list-one.acme.example/graphql",
        "https://graphql-list-two.acme.example/api?view=public",
        "https://graphql-list-three.acme.example/v1",
    ]
