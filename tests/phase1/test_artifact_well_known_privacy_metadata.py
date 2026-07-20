from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_url,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_well_known_privacy_metadata_routes_are_source_aware() -> None:
    expected = {
        ".well-known/gpc.json": "gpc.json",
        ".well-known/tdmrep.json": "tdmrep.json",
        ".well-known/pubvendors.json": "pubvendors.json",
        ".well-known/trust.txt": "trust.txt",
        ".well-known/dnt-policy.txt": "dnt-policy.txt",
        ".well-known/privacy-sandbox-attestations.json": "privacy-sandbox-attestations.json",
    }
    for route, label in expected.items():
        url = f"https://policy.acme.example/{route}"
        assert _classify_remote_artifact_url(url) == "config"
        assert _classify_artifact_name(route) == "config"
        assert _artifact_format_label(route) == label
        assert _artifact_format_label(label) == label
        assert _artifact_format_label(f"42-{label}") == label


def test_local_well_known_privacy_metadata_feeds_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "well_known_privacy_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Well Known Privacy Metadata Test")

    payloads = {
        "gpc.json": json.dumps(
            {
                "gpc": True,
                "policy": "https://privacy.acme.example/gpc",
                "contact": "gpc-owner@acme.example",
                "supabase": "https://gpcvault.supabase.co",
            }
        ),
        "tdmrep.json": json.dumps(
            {
                "tdm-reservation": 1,
                "policy": "https://privacy.acme.example/tdm",
                "contact": "tdm-owner@acme.example",
                "supabase": "https://tdmvault.supabase.co",
            }
        ),
        "pubvendors.json": json.dumps(
            {
                "publisher": "Acme",
                "vendors": [{"policyUrl": "https://vendors.acme.example/policy"}],
                "contact": "pubvendors-owner@acme.example",
                "supabase": "https://pubvendorsvault.supabase.co",
            }
        ),
        "trust.txt": "\n".join(
            [
                "Contact: trust-owner@acme.example",
                "Policy: https://trust.acme.example/policy",
                "Supabase: https://trustvault.supabase.co",
            ]
        ),
        "dnt-policy.txt": "\n".join(
            [
                "Contact: dnt-owner@acme.example",
                "Policy: https://privacy.acme.example/dnt",
                "Supabase: https://dntvault.supabase.co",
            ]
        ),
        "privacy-sandbox-attestations.json": json.dumps(
            {
                "attestations": ["https://privacy.acme.example/sandbox/attestation"],
                "contact": "privacy-sandbox-owner@acme.example",
                "supabase": "https://privacysandboxvault.supabase.co",
            }
        ),
    }
    for name, payload in payloads.items():
        (artifact_root / name).write_text(payload, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root.parent])
    summary = processor.process()

    assert queued == len(payloads)
    assert summary.processed == len(payloads)

    con = sqlite3.connect(db_path)
    try:
        artifact_formats = {
            Path(row[0]).name: json.loads(str(row[1] or "{}")).get("format")
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
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
    finally:
        con.close()

    assert artifact_formats == {
        "gpc.json": "gpc.json",
        "tdmrep.json": "tdmrep.json",
        "pubvendors.json": "pubvendors.json",
        "trust.txt": "trust.txt",
        "dnt-policy.txt": "dnt-policy.txt",
        "privacy-sandbox-attestations.json": "privacy-sandbox-attestations.json",
    }
    for email in (
        "gpc-owner@acme.example",
        "tdm-owner@acme.example",
        "pubvendors-owner@acme.example",
        "trust-owner@acme.example",
        "dnt-owner@acme.example",
        "privacy-sandbox-owner@acme.example",
    ):
        assert (email, "email") in seeds
    for url in (
        "https://privacy.acme.example/gpc",
        "https://privacy.acme.example/tdm",
        "https://vendors.acme.example/policy",
        "https://trust.acme.example/policy",
        "https://privacy.acme.example/dnt",
        "https://privacy.acme.example/sandbox/attestation",
    ):
        assert (url, "url") in seeds
    for identifier in (
        "gpcvault",
        "tdmvault",
        "pubvendorsvault",
        "trustvault",
        "dntvault",
        "privacysandboxvault",
    ):
        assert ("supabase", identifier) in cloud_assets
