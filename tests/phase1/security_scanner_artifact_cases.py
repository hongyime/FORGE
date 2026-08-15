from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def _seed_pairs(db_path: Path) -> set[tuple[str, str]]:
    con = sqlite3.connect(db_path)
    try:
        return {
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


def _cloud_assets(db_path: Path) -> list[tuple[str, str]]:
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
    finally:
        con.close()


def _artifact_meta(db_path: Path) -> dict[str, dict[str, object]]:
    con = sqlite3.connect(db_path)
    try:
        return {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()


def _db_dump(db_path: Path) -> str:
    con = sqlite3.connect(db_path)
    try:
        return "\n".join(con.iterdump())
    finally:
        con.close()


def run_security_scanner_control_files(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_security_scanner_controls"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    snyk_path = artifact_root / ".snyk"
    snyk_path.write_text(
        dedent(
            """
            version: v1.25.0
            ignore:
              SNYK-JS-EXAMPLE-123:
                - '*':
                    reason: owner snyk-owner@acme.example https://snyk-api.acme.example/status?token=snyk-token-do-not-store
                    expires: 2027-01-01T00:00:00.000Z
            patch: {}
            """
        ).strip(),
        encoding="utf-8",
    )

    semgrepignore_path = artifact_root / ".semgrepignore"
    semgrepignore_path.write_text(
        dedent(
            """
            # semgrep-owner@acme.example
            # https://semgrep-control.acme.example/config
            # https://semgrep-firebase.firebaseio.com
            generated/
            """
        ).strip(),
        encoding="utf-8",
    )

    gitleaksignore_path = artifact_root / ".gitleaksignore"
    gitleaksignore_path.write_text(
        dedent(
            """
            # gitleaks-owner@acme.example
            # s3://acme-gitleaks-ignore-bucket/evidence.json
            scanner-secret-do-not-store
            """
        ).strip(),
        encoding="utf-8",
    )

    trufflehogignore_path = artifact_root / ".trufflehogignore"
    trufflehogignore_path.write_text(
        dedent(
            """
            # trufflehog-owner@acme.example
            # https://trufflehog-control.acme.example/findings
            """
        ).strip(),
        encoding="utf-8",
    )

    trivyignore_path = artifact_root / ".trivyignore"
    trivyignore_path.write_text(
        dedent(
            """
            # trivy-owner@acme.example
            # https://trivyvault.supabase.co/rest/v1
            CVE-2026-0001
            """
        ).strip(),
        encoding="utf-8",
    )

    secretlintrc_path = artifact_root / ".secretlintrc"
    secretlintrc_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "owner",
                        "message": (
                            "secretlint-owner@acme.example "
                            "https://secretlint-control.acme.example/report"
                        ),
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 6
    assert summary.processed >= 6
    assert summary.discovered_seeds >= 10

    seeds = _seed_pairs(db_path)
    for expected_seed in {
        ("snyk-owner@acme.example", "email"),
        ("semgrep-owner@acme.example", "email"),
        ("gitleaks-owner@acme.example", "email"),
        ("trufflehog-owner@acme.example", "email"),
        ("trivy-owner@acme.example", "email"),
        ("secretlint-owner@acme.example", "email"),
        ("https://snyk-api.acme.example/status", "url"),
        ("https://semgrep-control.acme.example/config", "url"),
        ("https://trufflehog-control.acme.example/findings", "url"),
        ("https://secretlint-control.acme.example/report", "url"),
        ("snyk-api.acme.example", "subdomain"),
        ("semgrep-control.acme.example", "subdomain"),
        ("trufflehog-control.acme.example", "subdomain"),
        ("secretlint-control.acme.example", "subdomain"),
    }:
        assert expected_seed in seeds

    cloud_assets = _cloud_assets(db_path)
    assert ("aws_s3", "acme-gitleaks-ignore-bucket") in cloud_assets
    assert ("firebase", "semgrep-firebase") in cloud_assets
    assert ("supabase", "trivyvault") in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[snyk_path.resolve().as_posix()]["format"] == "snyk"
    assert artifact_meta[semgrepignore_path.resolve().as_posix()]["format"] == "semgrepignore"
    assert artifact_meta[gitleaksignore_path.resolve().as_posix()]["format"] == "gitleaksignore"
    assert artifact_meta[trufflehogignore_path.resolve().as_posix()]["format"] == "trufflehogignore"
    assert artifact_meta[trivyignore_path.resolve().as_posix()]["format"] == "trivyignore"
    assert artifact_meta[secretlintrc_path.resolve().as_posix()]["format"] == "secretlintrc"

    db_dump = _db_dump(db_path)
    assert "scanner-secret-do-not-store" not in db_dump
    assert "snyk-token-do-not-store" not in db_dump


def run_security_scanner_policy_configs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_security_scanner_policy_configs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    codeql_path = artifact_root / ".github" / "codeql" / "codeql-config.yml"
    codeql_path.parent.mkdir(parents=True, exist_ok=True)
    codeql_path.write_text(
        dedent(
            """
            name: acme-codeql
            owner: codeql-owner@acme.example
            endpoint: codeql-results.acme.example/api
            paths-ignore:
              - generated/
            """
        ).strip(),
        encoding="utf-8",
    )

    sonar_path = artifact_root / "sonar-project.properties"
    sonar_path.write_text(
        dedent(
            """
            sonar.projectKey=acme-platform
            sonar.host.url=sonar.acme.example
            sonar.links.homepage=https://sonar-home.acme.example/project?token=sonar-token-do-not-store
            sonar.projectDescription=owner sonar-owner@acme.example
            supabase=https://sonarvault.supabase.co/rest/v1
            """
        ).strip(),
        encoding="utf-8",
    )

    precommit_path = artifact_root / ".pre-commit-config.yaml"
    precommit_path.write_text(
        dedent(
            """
            repos:
              - repo: github.com/acme/pre-commit-hooks
                rev: v1.0.0
                hooks:
                  - id: acme-lint
            contact: precommit-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    checkov_path = artifact_root / ".checkov.yml"
    checkov_path.write_text(
        dedent(
            """
            bc-api-url: bridgecrew.acme.example/api?token=checkov-token-do-not-store
            output: cli
            owner: checkov-owner@acme.example
            archive: s3://acme-checkov-bucket/reports/latest.json
            """
        ).strip(),
        encoding="utf-8",
    )

    trivy_path = artifact_root / "trivy.yaml"
    trivy_path.write_text(
        dedent(
            """
            dbRepository: ghcr.io/acme/trivy-db
            server: trivy-control.acme.example
            contact: trivy-config-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    grype_path = artifact_root / ".grype.yaml"
    grype_path.write_text(
        dedent(
            """
            db:
              cache-dir: .grype/db
              update-url: https://grype-user:grype-token-do-not-store@grype-db.acme.example/vulnerability-db/listing.json
            registry: grype-registry.acme.example
            owner: grype-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    syft_path = artifact_root / "syft.toml"
    syft_path.write_text(
        dedent(
            """
            source = "https://syft-source.acme.example/images/latest"
            registry = "syft-registry.acme.example"
            owner = "syft-owner@acme.example"
            """
        ).strip(),
        encoding="utf-8",
    )

    hadolint_config_path = artifact_root / ".hadolint.yaml"
    hadolint_config_path.write_text(
        dedent(
            """
            trustedRegistries: ["https://hadolint-user:hadolint-token-do-not-store@hadolint-registry.acme.example/base"]
            owner: hadolint-config-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    semgrep_path = artifact_root / ".semgrep" / "config.yml"
    semgrep_path.parent.mkdir(parents=True, exist_ok=True)
    semgrep_path.write_text(
        dedent(
            """
            url: semgrep-registry.acme.example/rules
            owner: semgrep-config-owner@acme.example
            firebase: https://scanner-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    gitleaks_path = artifact_root / ".gitleaks.toml"
    gitleaks_path.write_text(
        dedent(
            """
            endpoint = "gitleaks-control.acme.example/api"
            owner = "gitleaks-config-owner@acme.example"
            """
        ).strip(),
        encoding="utf-8",
    )

    kics_path = artifact_root / "kics.config"
    kics_path.write_text(
        dedent(
            """
            server = kics-control.acme.example
            owner = kics-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    osv_path = artifact_root / "osv-scanner.toml"
    osv_path.write_text(
        dedent(
            """
            endpoint = "osv-scanner.acme.example/api"
            owner = "osv-owner@acme.example"
            """
        ).strip(),
        encoding="utf-8",
    )

    trufflehog_config_path = artifact_root / ".trufflehog.yml"
    trufflehog_config_path.write_text(
        dedent(
            """
            endpoint: trufflehog-config.acme.example/api
            owner: trufflehog-config-owner@acme.example
            archive: gs://acme-trufflehog-config/reports/latest.json
            """
        ).strip(),
        encoding="utf-8",
    )

    detect_secrets_config_path = artifact_root / ".detect-secrets.toml"
    detect_secrets_config_path.write_text(
        dedent(
            """
            url = "detect-secrets.acme.example/baseline?token=detect-token-do-not-store"
            owner = "detect-secrets-owner@acme.example"
            """
        ).strip(),
        encoding="utf-8",
    )

    secretlint_config_path = artifact_root / "secretlint.config.json"
    secretlint_config_path.write_text(
        json.dumps(
            {
                "url": "secretlint-config.acme.example/rules",
                "owner": "secretlint-config-owner@acme.example",
            }
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 14
    assert summary.processed >= 14
    assert summary.discovered_seeds >= 32

    seeds = _seed_pairs(db_path)
    for expected_seed in {
        ("https://codeql-results.acme.example/api", "url"),
        ("https://sonar.acme.example", "url"),
        ("https://sonar-home.acme.example/project", "url"),
        ("https://github.com/acme/pre-commit-hooks", "url"),
        ("https://bridgecrew.acme.example/api", "url"),
        ("https://ghcr.io/acme/trivy-db", "url"),
        ("https://trivy-control.acme.example", "url"),
        ("https://grype-db.acme.example/vulnerability-db/listing.json", "url"),
        ("https://grype-registry.acme.example", "url"),
        ("https://syft-source.acme.example/images/latest", "url"),
        ("https://syft-registry.acme.example", "url"),
        ("https://hadolint-registry.acme.example/base", "url"),
        ("https://semgrep-registry.acme.example/rules", "url"),
        ("https://gitleaks-control.acme.example/api", "url"),
        ("https://kics-control.acme.example", "url"),
        ("https://osv-scanner.acme.example/api", "url"),
        ("https://trufflehog-config.acme.example/api", "url"),
        ("https://detect-secrets.acme.example/baseline", "url"),
        ("https://secretlint-config.acme.example/rules", "url"),
        ("codeql-owner@acme.example", "email"),
        ("sonar-owner@acme.example", "email"),
        ("precommit-owner@acme.example", "email"),
        ("checkov-owner@acme.example", "email"),
        ("trivy-config-owner@acme.example", "email"),
        ("grype-owner@acme.example", "email"),
        ("syft-owner@acme.example", "email"),
        ("hadolint-config-owner@acme.example", "email"),
        ("semgrep-config-owner@acme.example", "email"),
        ("gitleaks-config-owner@acme.example", "email"),
        ("kics-owner@acme.example", "email"),
        ("osv-owner@acme.example", "email"),
        ("trufflehog-config-owner@acme.example", "email"),
        ("detect-secrets-owner@acme.example", "email"),
        ("secretlint-config-owner@acme.example", "email"),
    }:
        assert expected_seed in seeds

    cloud_assets = _cloud_assets(db_path)
    assert ("aws_s3", "acme-checkov-bucket") in cloud_assets
    assert ("firebase", "scanner-firebase") in cloud_assets
    assert ("gcs", "acme-trufflehog-config") in cloud_assets
    assert ("supabase", "sonarvault") in cloud_assets

    artifact_meta = _artifact_meta(db_path)
    assert artifact_meta[codeql_path.resolve().as_posix()]["format"] == "codeql-config"
    assert artifact_meta[sonar_path.resolve().as_posix()]["format"] == "sonar-project"
    assert artifact_meta[precommit_path.resolve().as_posix()]["format"] == "pre-commit-config"
    assert artifact_meta[checkov_path.resolve().as_posix()]["format"] == "checkov-config"
    assert artifact_meta[trivy_path.resolve().as_posix()]["format"] == "trivy-config"
    assert artifact_meta[grype_path.resolve().as_posix()]["format"] == "grype-config"
    assert artifact_meta[syft_path.resolve().as_posix()]["format"] == "syft-config"
    assert artifact_meta[hadolint_config_path.resolve().as_posix()]["format"] == "hadolint-config"
    assert artifact_meta[semgrep_path.resolve().as_posix()]["format"] == "semgrep-config"
    assert artifact_meta[gitleaks_path.resolve().as_posix()]["format"] == "gitleaks-config"
    assert artifact_meta[kics_path.resolve().as_posix()]["format"] == "kics-config"
    assert artifact_meta[osv_path.resolve().as_posix()]["format"] == "osv-scanner-config"
    assert (
        artifact_meta[trufflehog_config_path.resolve().as_posix()]["format"] == "trufflehog-config"
    )
    assert (
        artifact_meta[detect_secrets_config_path.resolve().as_posix()]["format"]
        == "detect-secrets-config"
    )
    assert (
        artifact_meta[secretlint_config_path.resolve().as_posix()]["format"] == "secretlint-config"
    )

    db_dump = _db_dump(db_path)
    assert "sonar-token-do-not-store" not in db_dump
    assert "checkov-token-do-not-store" not in db_dump
    assert "grype-token-do-not-store" not in db_dump
    assert "hadolint-token-do-not-store" not in db_dump
    assert "detect-token-do-not-store" not in db_dump
