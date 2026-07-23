from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from forge.utils.artifact_terraform_dns import terraform_dns_record_hosts
from tests.phase1.artifact_test_support import bootstrap_engagement


TERRAFORM_DNS_PAYLOAD = dedent(
    """
    resource "aws_route53_record" "api" {
      zone_id = "Z123EXAMPLE"
      name    = "api.acme.example"
      type    = "A"
      records = ["203.0.113.10"]
    }

    resource "cloudflare_record" "portal" {
      zone_name = "acme.example"
      name      = "portal"
      type      = "CNAME"
      value     = "origin.acme.example"
    }

    resource "google_dns_record_set" "cdn" {
      managed_zone = "acme"
      name         = "cdn.acme.example."
      type         = "CNAME"
      rrdatas      = ["edge.acme.example."]
    }

    resource "azurerm_dns_cname_record" "docs" {
      zone_name           = "acme.example"
      name                = "docs"
      record              = "docs-origin.acme.example"
      resource_group_name = "rg"
    }
    """
).strip()


def test_terraform_dns_record_hosts_resolve_record_names_and_targets() -> None:
    assert terraform_dns_record_hosts(TERRAFORM_DNS_PAYLOAD) == [
        "api.acme.example",
        "portal.acme.example",
        "origin.acme.example",
        "cdn.acme.example",
        "edge.acme.example",
        "docs.acme.example",
        "docs-origin.acme.example",
    ]


def test_terraform_dns_record_hosts_reject_low_signal_values() -> None:
    payload = dedent(
        """
        resource "aws_route53_record" "ignored" {
          name    = "${var.host}"
          records = ["127.0.0.1", "internal.service.local", "relative-only"]
        }
        """
    ).strip()

    assert terraform_dns_record_hosts(payload) == []


def test_artifact_terraform_dns_records_recurse_to_host_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, scope_json='["acme.example"]')
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    terraform_path = artifact_root / "main.tf"
    terraform_path.write_text(TERRAFORM_DNS_PAYLOAD, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    assert summary.discovered_seeds >= 7
    assert _artifact_format_label("main.tf") == "terraform"

    con = sqlite3.connect(db_path)
    try:
        metadata = con.execute(
            """
            SELECT metadata_json
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (terraform_path.resolve().as_posix(),),
        ).fetchone()
        assert metadata is not None
        assert json.loads(str(metadata[0] or "{}"))["format"] == "terraform"

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
    finally:
        con.close()

    assert ("api.acme.example", "subdomain") in seeds
    assert ("portal.acme.example", "subdomain") in seeds
    assert ("origin.acme.example", "subdomain") in seeds
    assert ("cdn.acme.example", "subdomain") in seeds
    assert ("edge.acme.example", "subdomain") in seeds
    assert ("docs.acme.example", "subdomain") in seeds
    assert ("docs-origin.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds


def test_artifact_well_known_terraform_json_dns_records_recurse_to_host_seeds(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, scope_json='["acme.example"]')
    artifact_root = tmp_path / "artifacts" / ".well-known"
    artifact_root.mkdir(parents=True)
    terraform_path = artifact_root / "terraform.json"
    terraform_path.write_text(TERRAFORM_DNS_PAYLOAD, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root.parent])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    assert summary.discovered_seeds >= 7
    assert _artifact_format_label(".well-known/terraform.json") == "terraform.json"

    con = sqlite3.connect(db_path)
    try:
        metadata = con.execute(
            """
            SELECT metadata_json
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (terraform_path.resolve().as_posix(),),
        ).fetchone()
        assert metadata is not None
        assert json.loads(str(metadata[0] or "{}"))["format"] == "terraform.json"

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
    finally:
        con.close()

    assert ("api.acme.example", "subdomain") in seeds
    assert ("portal.acme.example", "subdomain") in seeds
    assert ("origin.acme.example", "subdomain") in seeds
    assert ("cdn.acme.example", "subdomain") in seeds
    assert ("edge.acme.example", "subdomain") in seeds
    assert ("docs.acme.example", "subdomain") in seeds
    assert ("docs-origin.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
