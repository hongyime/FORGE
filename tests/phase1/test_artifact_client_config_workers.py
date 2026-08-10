from __future__ import annotations

from pathlib import Path

import forge.engagement_orchestrator as orchestrator
from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_client_config_structured_payloads_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    observed_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        observed_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)
    monkeypatch.setattr(
        orchestrator, "connection_client_config_artifact_label", lambda _: "winscp-config"
    )
    monkeypatch.setattr(
        orchestrator,
        "connection_client_host_candidates",
        lambda _: ["alpha.acme.example", "[beta.acme.example]", "alpha.acme.example"],
    )
    monkeypatch.setattr(orchestrator, "database_client_config_artifact_label", lambda _: "dbeaver")
    monkeypatch.setattr(
        orchestrator,
        "database_client_endpoint_candidates",
        lambda _: [
            "postgres://Db.Acme.Example/prod",
            "postgres://db.acme.example/prod",
            "mysql://mysql.acme.example/prod",
        ],
    )
    monkeypatch.setattr(orchestrator, "storage_client_config_artifact_label", lambda _: "s3cfg")
    monkeypatch.setattr(
        orchestrator,
        "storage_client_config_candidates",
        lambda _: ["s3://Acme-Bucket", "s3://acme-bucket", "https://storage.acme.example"],
    )
    monkeypatch.setattr(orchestrator, "amplify_client_config_artifact_label", lambda _: "amplify")
    monkeypatch.setattr(
        orchestrator,
        "amplify_client_config_text_candidates",
        lambda _: [
            "aws-cognito-user-pool://us-east-1_AbC",
            "AWS-COGNITO-USER-POOL://us-east-1_abc",
            "https://api.acme.example/graphql",
        ],
    )
    monkeypatch.setattr(orchestrator, "orm_config_artifact_label", lambda _: "prisma")
    monkeypatch.setattr(
        orchestrator,
        "orm_config_host_candidates",
        lambda _: ["[orm-one.acme.example]", "orm-two.acme.example", "orm-one.acme.example"],
    )
    monkeypatch.setattr(orchestrator, "framework_config_artifact_label", lambda _: "rails")
    monkeypatch.setattr(
        orchestrator,
        "framework_config_host_candidates",
        lambda _: ["[fw-one.acme.example]", "fw-two.acme.example", "fw-one.acme.example"],
    )
    monkeypatch.setattr(
        orchestrator,
        "framework_config_service_endpoint_candidates",
        lambda _: [
            "redis://cache.acme.example",
            "REDIS://cache.acme.example",
            "amqp://mq.acme.example",
        ],
    )

    assert processor._connection_client_structured_payload_text(
        "payload", source_hint="WinSCP.ini"
    ).splitlines() == [
        "ssh://alpha.acme.example",
        "ssh://beta.acme.example",
    ]
    assert processor._database_client_structured_payload_text(
        "payload", source_hint="data-sources.json"
    ).splitlines() == [
        "postgres://Db.Acme.Example/prod",
        "mysql://mysql.acme.example/prod",
    ]
    assert processor._storage_client_config_structured_payload_text(
        "payload", source_hint=".s3cfg"
    ).splitlines() == [
        "s3://Acme-Bucket",
        "https://storage.acme.example",
    ]
    assert processor._amplify_client_config_structured_payload_text(
        "payload", source_hint="aws-exports.js"
    ).splitlines() == [
        "aws-cognito-user-pool://us-east-1_AbC",
        "https://api.acme.example/graphql",
    ]
    assert processor._orm_config_structured_payload_text(
        "payload", source_hint="schema.prisma"
    ).splitlines() == [
        "postgres://orm-one.acme.example",
        "postgres://orm-two.acme.example",
    ]
    assert processor._framework_config_structured_payload_text(
        "payload", source_hint="database.yml"
    ).splitlines() == [
        "postgres://fw-one.acme.example",
        "postgres://fw-two.acme.example",
        "redis://cache.acme.example",
        "amqp://mq.acme.example",
    ]

    assert observed_batches == [
        ["alpha.acme.example", "[beta.acme.example]", "alpha.acme.example"],
        [
            "postgres://Db.Acme.Example/prod",
            "postgres://db.acme.example/prod",
            "mysql://mysql.acme.example/prod",
        ],
        ["s3://Acme-Bucket", "s3://acme-bucket", "https://storage.acme.example"],
        [
            "aws-cognito-user-pool://us-east-1_AbC",
            "AWS-COGNITO-USER-POOL://us-east-1_abc",
            "https://api.acme.example/graphql",
        ],
        ["[orm-one.acme.example]", "orm-two.acme.example", "orm-one.acme.example"],
        ["[fw-one.acme.example]", "fw-two.acme.example", "fw-one.acme.example"],
        ["redis://cache.acme.example", "REDIS://cache.acme.example", "amqp://mq.acme.example"],
    ]
