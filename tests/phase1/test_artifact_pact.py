from __future__ import annotations

import json
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor


def test_pact_contract_protocol_relative_endpoints_normalize_to_https(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001, max_workers=4)
    payload = {
        "provider": {"baseUrl": "pact-provider.acme.example/api"},
        "interactions": [
            {
                "providerStates": [
                    {"params": {"callbackUrl": "//pact-callback.acme.example/hook"}}
                ],
                "request": {"method": "GET", "url": "//pact-cdn.acme.example/v1/status"},
            }
        ],
    }

    result = processor._api_client_text_structured_payload_text(
        json.dumps(payload),
        source_hint="pacts/acme-web-acme-api.json",
    )

    assert result.splitlines() == [
        "https://pact-provider.acme.example/api",
        "https://pact-cdn.acme.example/v1/status",
        "https://pact-callback.acme.example/hook",
    ]
