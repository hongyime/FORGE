from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_graphql_config_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        schema: graphql-one.acme.example/graphql
        endpoint: https://graphql-two.acme.example/api
        extensions:
          endpoints:
            prod:
              url: graphql-three.acme.example/v1
            tenant:
              url: https://{tenant}.acme.example/graphql
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_graphql_config_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._graphql_config_text_structured_payload_text(
        payload,
        source_hint=".graphqlrc.yml",
    )

    assert observed_candidate_batches == [
        [
            "graphql-one.acme.example/graphql",
            "https://graphql-two.acme.example/api",
            "graphql-three.acme.example/v1",
            "https://{tenant}.acme.example/graphql",
        ]
    ]
    assert result.splitlines() == [
        "https://graphql-one.acme.example/graphql",
        "https://graphql-two.acme.example/api",
        "https://graphql-three.acme.example/v1",
    ]

    observed_candidate_batches.clear()
    js_result = processor._graphql_config_text_structured_payload_text(
        "module.exports = { client: { service: { url: 'apollo-js.acme.example/graphql' } } }",
        source_hint="apollo.config.js",
    )

    assert observed_candidate_batches == [["apollo-js.acme.example/graphql"]]
    assert js_result.splitlines() == ["https://apollo-js.acme.example/graphql"]
