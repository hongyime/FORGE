from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from forge.utils.artifact_hashicorp_config import (
    hashicorp_config_artifact_label,
    hashicorp_config_candidates,
)


def test_hashicorp_vault_config_labels_are_source_gated() -> None:
    assert hashicorp_config_artifact_label("vault/config.hcl") == "hashicorp-vault-config"
    assert hashicorp_config_artifact_label(".vault.d/config.hcl") == "hashicorp-vault-config"
    assert hashicorp_config_artifact_label("vault.hcl") == "hashicorp-vault-config"
    assert hashicorp_config_artifact_label("vault-agent.hcl") == "hashicorp-vault-config"
    assert _artifact_format_label("vault/config.hcl") == "hashicorp-vault-config"

    assert hashicorp_config_artifact_label("config.hcl") == ""
    assert hashicorp_config_artifact_label("consul/config.hcl") == ""
    assert hashicorp_config_artifact_label("terraform/vault-policy.hcl") == ""


def test_hashicorp_vault_config_candidates_promote_public_hostonly_endpoints() -> None:
    payload = """
api_addr = "vault-api.acme.example:8200"
cluster_addr = "https://vault-cluster.acme.example:8201"
redirect_addr = ["vault-redirect.acme.example/ui", "http://localhost:8200"]
VAULT_ADDR = "${VAULT_ADDR}"
vault_addr = "https://user:pass@vault-secret.acme.example"
""".strip()

    assert hashicorp_config_candidates(payload, source_hint="notes/config.hcl") == []
    assert hashicorp_config_candidates(payload, source_hint="vault/config.hcl") == [
        "https://vault-api.acme.example:8200",
        "https://vault-cluster.acme.example:8201",
        "https://vault-redirect.acme.example/ui",
    ]


def test_artifact_vault_config_payload_uses_structured_worker_family(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = dedent(
        """
        api_addr = "vault-api.acme.example:8200"
        cluster_addr = ["vault-cluster.acme.example:8201", "http://127.0.0.1:8201"]
        vault_addr = "https://${tenant}.acme.example"
        """
    ).strip()
    observed_family_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if "hashicorp_config_text" in materialized:
            observed_family_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    assert _artifact_format_label("config.hcl") == "hcl"
    assert _artifact_format_label("vault/config.hcl") == "hashicorp-vault-config"
    assert processor._build_structured_discovery_payload_fragment(
        "hashicorp_config_text",
        text=payload,
        extract_path="notes/config.hcl",
    ) == ""

    jobs = processor._structured_discovery_jobs_for_payload(
        ("https://static.acme.example/vault/config.hcl", "vault/config.hcl", payload)
    )

    assert observed_family_batches
    assert [
        job_payload
        for _source_file, job_payload in jobs
        if job_payload.startswith("https://vault-")
    ] == [
        "https://vault-api.acme.example:8200\nhttps://vault-cluster.acme.example:8201"
    ]
