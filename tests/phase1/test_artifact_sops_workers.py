from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_sops_metadata_entries_use_bounded_workers_and_preserve_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    document = {
        "sops": {
            "kms": [
                {"arn": "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"},
                {"arn": "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"},
            ],
            "gcp_kms": [
                {"resource_id": "projects/acme-prod/locations/global/keyRings/main/cryptoKeys/app"}
            ],
            "azure_kv": [{"vault_url": "https://acmekv.vault.azure.net/keys/app/123"}],
            "hc_vault": [{"vault_address": "vault.acme.example"}],
        }
    }
    normalized = processor._yaml_normalized_mapping(document)
    original_entry = ArtifactQueueProcessor._yaml_sops_metadata_entry_candidate
    active = 0
    peak = 0
    lock = threading.Lock()

    def _tracking_entry_candidate(
        self: ArtifactQueueProcessor,
        sops_job: tuple[str, dict[str, object]],
    ) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return original_entry(self, sops_job)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_yaml_sops_metadata_entry_candidate",
        _tracking_entry_candidate,
    )

    assert processor._yaml_sops_metadata_structured_candidates(document, normalized, "") == [
        "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111",
        "projects/acme-prod/locations/global/keyRings/main/cryptoKeys/app",
        "https://acmekv.vault.azure.net/keys/app/123",
        "https://vault.acme.example",
    ]
    assert peak == 4
