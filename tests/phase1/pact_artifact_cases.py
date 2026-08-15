from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Callable

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
    _suffix_from_content_type,
)


def run_queue_processor_extracts_pact_contract_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_pact_contracts"
    pacts_dir = artifact_root / "pacts"
    pacts_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    pact_path = pacts_dir / "acme-web-acme-api.json"
    pact_path.write_text(
        json.dumps(
            {
                "consumer": {"name": "acme-web"},
                "provider": {
                    "name": "acme-api",
                    "baseUrl": "pact-provider.acme.example/api",
                },
                "metadata": {
                    "owner": "pact-owner@acme.example",
                    "pactBrokerUrl": "https://pact-broker.acme.example/pacts",
                    "firebaseUrl": "https://pact-firebase.firebaseio.com",
                    "supabaseUrl": "https://pactworkspace.supabase.co/rest/v1",
                    "bucket": "s3://acme-pact-bucket/contracts/latest.json",
                },
                "interactions": [
                    {
                        "description": "relative request resolves through provider base",
                        "request": {"method": "GET", "path": "/v1/status"},
                        "providerStates": [
                            {
                                "name": "tenant callback",
                                "params": {
                                    "callbackUrl": "pact-state.acme.example/callback",
                                },
                            }
                        ],
                    },
                    {
                        "description": "full URL request is preserved",
                        "request": {
                            "method": "POST",
                            "url": "https://pact-live.acme.example/events",
                        },
                    },
                    {
                        "description": "templated request is filtered",
                        "request": {
                            "method": "GET",
                            "url": "https://${tenant}.acme.example/template",
                        },
                    },
                ],
                "messages": [
                    {
                        "description": "async callback",
                        "contents": {
                            "messageCallbackUrl": "pact-message.acme.example/callback",
                        },
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    archive_path = artifact_root / "pact-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "provider-pacts/mobile-api.pact.json",
            json.dumps(
                {
                    "consumer": {"name": "mobile"},
                    "provider": {"name": "mobile-api", "url": "pact-mobile-api.acme.example/v2"},
                    "metadata": {"owner": "pact-mobile-owner@acme.example"},
                    "interactions": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://pact-mobile-live.acme.example/status",
                            }
                        }
                    ],
                }
            ),
        )

    assert _classify_artifact_name(pact_path) == "config"
    assert _artifact_format_label(pact_path) == "pact-contract"
    assert _artifact_format_label("pacts/acme-web-acme-api.json") == "pact-contract"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/pacts/acme-web-acme-api")
        == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/pacts/acme-web-acme-api",
            "config",
            content_type="application/pact+json",
        )
        == "acme-web-acme-api.pact.json"
    )
    assert _suffix_from_content_type("application/pact+json") == ".pact.json"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 9

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "pact-owner@acme.example" in emails
        assert "pact-mobile-owner@acme.example" in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("https://pact-provider.acme.example/api", "url") in seeds
        assert ("https://pact-broker.acme.example/pacts", "url") in seeds
        assert ("https://pact-provider.acme.example/v1/status", "url") in seeds
        assert ("https://pact-state.acme.example/callback", "url") in seeds
        assert ("https://pact-live.acme.example/events", "url") in seeds
        assert ("https://pact-message.acme.example/callback", "url") in seeds
        assert ("https://pact-mobile-api.acme.example/v2", "url") in seeds
        assert ("https://pact-mobile-live.acme.example/status", "url") in seeds
        assert ("https://${tenant}.acme.example/template", "url") not in seeds
        assert ("pact-owner@acme.example", "email") in seeds
        assert ("pact-mobile-owner@acme.example", "email") in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws_s3", "acme-pact-bucket") in cloud_assets
        assert ("firebase", "pact-firebase") in cloud_assets
        assert ("supabase", "pactworkspace") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[pact_path.resolve().as_posix()]["format"] == "pact-contract"
        assert artifact_meta[pact_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


