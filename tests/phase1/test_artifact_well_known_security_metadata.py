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


def test_well_known_security_metadata_routes_are_source_aware() -> None:
    expected = {
        ".well-known/csaf": "csaf",
        ".well-known/csaf-aggregator": "csaf-aggregator",
        ".well-known/sbom": "sbom",
        ".well-known/passkey-endpoints": "passkey-endpoints",
        ".well-known/ssh-known-hosts": "ssh-known-hosts",
        ".well-known/sshfp": "sshfp",
        ".well-known/pki-validation": "pki-validation",
    }
    for route, label in expected.items():
        url = f"https://security.acme.example/{route}"
        assert _classify_remote_artifact_url(url) == "config"
        assert _classify_artifact_name(route) == "config"
        assert _artifact_format_label(route) == label
        assert _artifact_format_label(label) == label
        assert _artifact_format_label(f"42-{label}") == label


def test_local_well_known_security_metadata_feeds_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "well_known_security_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Well Known Security Metadata Test")

    payloads = {
        "csaf": json.dumps(
            {
                "provider_metadata": {
                    "url": "https://security.acme.example/csaf/provider-metadata.json",
                    "contact": "csaf-owner@acme.example",
                },
                "supabase": "https://csafvault.supabase.co",
            }
        ),
        "csaf-aggregator": json.dumps(
            {
                "aggregator": "https://security.acme.example/csaf/aggregate.json",
                "contact": "csaf-aggregator-owner@acme.example",
                "supabase": "https://csafaggregatorvault.supabase.co",
            }
        ),
        "sbom": json.dumps(
            {
                "spdx": "https://sbom.acme.example/spdx/app.spdx.json",
                "contact": "sbom-owner@acme.example",
                "supabase": "https://sbomvault.supabase.co",
            }
        ),
        "passkey-endpoints": json.dumps(
            {
                "enroll": "https://login.acme.example/passkeys/enroll",
                "manage": "https://login.acme.example/passkeys/manage",
                "support": "passkey-owner@acme.example",
                "supabase": "https://passkeyvault.supabase.co",
            }
        ),
        "ssh-known-hosts": "\n".join(
            [
                "ssh.acme.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample",
                "Contact: ssh-known-hosts-owner@acme.example",
                "Docs: https://ssh.acme.example/known-hosts",
                "Supabase: https://sshknownhostsvault.supabase.co",
            ]
        ),
        "sshfp": "\n".join(
            [
                "ssh.acme.example IN SSHFP 4 2 deadbeef",
                "Contact: sshfp-owner@acme.example",
                "Docs: https://ssh.acme.example/sshfp",
                "Supabase: https://sshfpvault.supabase.co",
            ]
        ),
        "pki-validation": "\n".join(
            [
                "CA validation placeholder for static review only",
                "Contact: pki-validation-owner@acme.example",
                "Docs: https://pki.acme.example/validation",
                "Supabase: https://pkivalidationvault.supabase.co",
            ]
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
        "csaf": "csaf",
        "csaf-aggregator": "csaf-aggregator",
        "sbom": "sbom",
        "passkey-endpoints": "passkey-endpoints",
        "ssh-known-hosts": "ssh-known-hosts",
        "sshfp": "sshfp",
        "pki-validation": "pki-validation",
    }
    for email in (
        "csaf-owner@acme.example",
        "csaf-aggregator-owner@acme.example",
        "sbom-owner@acme.example",
        "passkey-owner@acme.example",
        "ssh-known-hosts-owner@acme.example",
        "sshfp-owner@acme.example",
        "pki-validation-owner@acme.example",
    ):
        assert (email, "email") in seeds
    for url in (
        "https://security.acme.example/csaf/provider-metadata.json",
        "https://security.acme.example/csaf/aggregate.json",
        "https://sbom.acme.example/spdx/app.spdx.json",
        "https://login.acme.example/passkeys/enroll",
        "https://ssh.acme.example/known-hosts",
        "https://ssh.acme.example/sshfp",
        "https://pki.acme.example/validation",
    ):
        assert (url, "url") in seeds
    for identifier in (
        "csafvault",
        "csafaggregatorvault",
        "sbomvault",
        "passkeyvault",
        "sshknownhostsvault",
        "sshfpvault",
        "pkivalidationvault",
    ):
        assert ("supabase", identifier) in cloud_assets
