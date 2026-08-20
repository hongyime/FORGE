from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.db.direct_connect import direct_connect
from forge.db.migrations import TARGET_VERSION, run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.graph.attribution import import_asset_attribution_records
from forge.graph.assets import (
    list_asset_graph,
    ownership_claims_for_entity,
    ownership_conflicts_for_engagement,
    resolve_asset_owner,
    resolve_ownership_conflict,
    sync_engagement_asset_graph,
    upsert_asset_entity,
    upsert_ownership_claim,
)


def _build_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.execute(
        """
        INSERT INTO engagement_seeds
            (id, engagement_id, seed_value, seed_type, source, status, depth, confidence)
        VALUES
            (1, 1001, 'acme.example', 'domain', 'operator', 'completed', 0, 1.0),
            (2, 1001, 'app.acme.example', 'subdomain', 'discovered', 'completed', 1, 0.8)
        """
    )
    con.execute(
        """
        UPDATE engagement_seeds
        SET parent_seed_id=1
        WHERE id=2
        """
    )
    con.execute(
        """
        INSERT INTO seed_relations
            (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
        VALUES
            (1001, 1, 2, 'related_asset', 0.75, '{"source":"fixture"}')
        """
    )
    con.execute(
        """
        INSERT INTO hosts (id, engagement_id, ip, hostname, os_family, host_context)
        VALUES (10, 1001, '203.0.113.10', 'app.acme.example', 'linux',
                '{"provider_sources":["urlscan"],"workload":{"name":"payments-api","runtime_kind":"kubernetes","cluster":"prod-eks","namespace":"payments","environment":"prod"},"apiKey":"should-not-store"}')
        """
    )
    con.execute(
        """
        INSERT INTO cloud_assets
            (id, engagement_id, asset_type, identifier, provider_identifier, source, metadata_json)
        VALUES
            (20, 1001, 'aws_s3', 'acme-assets', 'arn:aws:s3:::acme-assets', 'fixture',
             '{
                "region":"us-east-1",
                "account_id":"123456789012",
                "organization_id":"o-acme",
                "data_classification":"restricted",
                "contains_pii":true,
                "public_access":true,
                "workload_context":{
                    "name":"payments-api",
                    "runtime_kind":"kubernetes",
                    "cluster":"prod-eks",
                    "namespace":"payments",
                    "environment":"prod"
                },
                "iam_context":{
                    "principal_arn":"arn:aws:iam::123456789012:role/payments-prod-admin",
                    "principal_type":"role",
                    "principal_name":"payments-prod-admin",
                    "privilege":"read_write_admin",
                    "managed_policies":["AdministratorAccess"],
                    "policy_document":{
                        "Statement":[{
                            "Effect":"Allow",
                            "Action":["s3:*","iam:PassRole","kms:Decrypt"],
                            "Resource":"*"
                        }]
                    },
                    "condition":{"api_key":"permission-secret-never-render"},
                    "token":"iam-token-never-render"
                },
                "apiKey":"should-not-store"
              }')
        """
    )
    con.execute(
        """
        INSERT INTO cloud_validation_results
            (id, engagement_id, asset_type, identifier, provider_identifier,
             validation_status, validation_method, http_status, evidence)
        VALUES
            (21, 1001, 'aws_s3', 'acme-assets', 'arn:aws:s3:::acme-assets',
             'VALIDATED', 's3_public_listing', 200, 'HTTP 200')
        """
    )
    con.execute(
        """
        INSERT INTO key_scanner_findings
            (id, engagement_id, domain, service, pattern_name, source_backend,
             source_url, repo_name, key_redacted, key_enc, validation_state)
        VALUES
            (30, 1001, 'acme.example', 'aws', 'AWS Access Key', 'github',
             'https://github.com/acme/app/blob/main/.env', 'acme/app',
             'AKIA...TEST', 'age1secret', 'ACTIVE')
        """
    )
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (id, engagement_id, vuln_type, target_url, parameter, severity,
             title, description, evidence, cve_id, cvss_score, cvss_version,
             cvss_vector, cwe_ids, cpe_matches, epss_score, epss_percentile,
             cisa_kev, cisa_kev_due_date, attack_techniques, standards_json)
        VALUES
            (40, 1001, 'cloud_exposure', 'https://app.acme.example', 'bucket',
             'HIGH', 'Public bucket exposure', 'Bucket is public',
             'proof Authorization: Bearer raw-secret-token CVE-2026-0001 CWE-200 T1530',
             'CVE-2026-0001', 8.1, '3.1',
             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
             '["CWE-200"]',
             '["cpe:2.3:a:acme:bucket:1.0:*:*:*:*:*:*:*"]',
             0.72, 0.93, 1, '2026-09-30', '["T1530"]',
             '{"reportable":true,"source":"fixture"}')
        """
    )
    con.execute(
        """
        INSERT INTO remediation_items
            (id, engagement_id, finding_table, finding_id, finding_ref, title,
             severity, owner, status, ticket_system, ticket_ref, ticket_url)
        VALUES
            (50, 1001, 'vulnerability_findings', 40, '40', 'Fix public bucket',
             'HIGH', 'cloud-team', 'assigned', 'jira', 'SEC-123',
             'https://user:pass@acme.atlassian.net/browse/SEC-123?token=never&view=ok')
        """
    )
    con.execute(
        """
        INSERT INTO active_validation_jobs
            (id, engagement_id, target_ref, target_kind, method, mode, status,
             approved, safe_profile, max_steps, metadata_json)
        VALUES
            (60, 1001, 'https://app.acme.example/health?token=active-secret&view=ok',
             'service', 'control_simulation', 'lab', 'completed', 1,
             'non_destructive', 1,
             '{"source":"graph-test","remediation_item_id":50,
               "remediation_finding_table":"vulnerability_findings",
               "remediation_finding_ref":"40",
               "detection_signal":"https://siem.acme.example/event?token=active-secret&ok=1"}')
        """
    )
    con.execute(
        """
        INSERT INTO active_validation_runs
            (id, engagement_id, job_id, status, result, operator, evidence_json)
        VALUES
            (61, 1001, 60, 'completed', 'control_passed', 'delta-one',
             '{"network_execution":false,"destructive_actions":false,
               "lateral_movement":false,"post_exploitation":false,
               "method":{"id":"control_simulation","proof_kind":"control_simulation"},
               "control_validation":{"expected_result":"detected",
                 "observed_result":"detected","matched":true,
                 "control_name":"EDR command execution alert",
                 "attack_step":"T1059 command execution","body_captured":false},
               "proof_summary":{"evidence":"control expected=detected observed=detected matched=yes control=EDR command execution alert attack=T1059 command execution body=no",
                 "live_proof":"-","fix_match":"-"}}')
        """
    )
    con.execute(
        """
        INSERT INTO validation_claims
            (engagement_id, claim_type, asset_type, identifier, owner, expires_at)
        VALUES
            (1001, 'asset', 'aws_s3', 'acme-assets', 'storage-team',
             '2026-09-01T00:00:00Z')
        """
    )
    con.execute(
        """
        INSERT INTO validation_claims
            (engagement_id, claim_type, key_id, owner, expires_at)
        VALUES
            (1001, 'key', 30, 'security-team', '2026-09-01T00:00:00Z')
        """
    )
    con.commit()
    return con


def _build_data_dir_db(data_dir: Path) -> Path:
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = direct_connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        validate_canonical_schema(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, source, metadata_json)
            VALUES (1001, 'firebase', 'acme-prod', 'fixture', '{}')
            """
        )
        con.commit()
    finally:
        con.close()
    return db_path


def test_sync_engagement_asset_graph_projects_existing_evidence_idempotently(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        first = sync_engagement_asset_graph(con, 1001)
        second = sync_engagement_asset_graph(con, 1001)
        keys = {
            row["entity_key"]
            for row in con.execute(
                "SELECT entity_key FROM asset_entities WHERE engagement_id=1001"
            ).fetchall()
        }
        relationships = {
            row["relationship_type"]
            for row in con.execute(
                "SELECT relationship_type FROM asset_relationships WHERE engagement_id=1001"
            ).fetchall()
        }
        entity_types = {
            row["entity_type"]
            for row in con.execute(
                "SELECT entity_type FROM asset_entities WHERE engagement_id=1001"
            ).fetchall()
        }
        claims = {
            row["owner_ref"]
            for row in con.execute(
                "SELECT owner_ref FROM asset_ownership_claims WHERE engagement_id=1001"
            ).fetchall()
        }
        cloud_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='cloud:aws_s3:acme-assets'
                """
            ).fetchone()["metadata_json"]
        )
        host_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='host:app.acme.example'
                """
            ).fetchone()["metadata_json"]
        )
        cloud_workload_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='workload:aws:123456789012:payments:payments-api'
                """
            ).fetchone()["metadata_json"]
        )
        secret_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_type='secret'
                """
            ).fetchone()["metadata_json"]
        )
        finding_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='finding:vulnerability:40'
                """
            ).fetchone()["metadata_json"]
        )
        active_validation_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='validation:active_validation:61'
                """
            ).fetchone()["metadata_json"]
        )
        active_validation_evidence_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='evidence:active_validation_runs:61:active_validation'
                """
            ).fetchone()["metadata_json"]
        )
        graph = list_asset_graph(con, 1001, limit=200)
        aws_identity_key = (
            "identity:cloud_principal:aws:role:"
            "arn:aws:iam::123456789012:role/payments-prod-admin"
        )
        cloud_identity_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key=?
                """,
                (aws_identity_key,),
            ).fetchone()["metadata_json"]
        )
    finally:
        con.close()

    assert first == second
    assert first["source_counts"]["active_validation"] == 1
    assert first["node_count"] >= 15
    assert first["edge_count"] >= 12
    assert graph["schema_version"] == "forge.asset_graph.list.v1"
    assert graph["execution_policy"] == "read_only_asset_graph_inventory_no_commands_executed"
    assert graph["total_count"] >= first["node_count"]
    assert graph["selected_count"] == len(graph["nodes"])
    assert graph["omitted_count"] == max(0, graph["total_count"] - len(graph["nodes"]))
    assert {
        "seed:domain:acme.example",
        "seed:subdomain:app.acme.example",
        "host:app.acme.example",
        "asset:internet:public",
        "cloud:aws_s3:acme-assets",
        "workload:aws:123456789012:payments:payments-api",
        "workload:kubernetes:prod-eks:payments:payments-api",
        aws_identity_key,
        "organization:cloud_account:aws:123456789012",
        "organization:cloud_org:aws:o-acme",
        "evidence:cloud_validation_results:21:validation",
        "evidence:key_scanner_findings:30:secret_observation",
        "evidence:vulnerability_findings:40:finding_evidence",
        "evidence:remediation_items:50:workflow_state",
        "evidence:active_validation_runs:61:active_validation",
        "validation:cloud:aws_s3:acme-assets",
        "validation:active_validation:61",
        "finding:vulnerability:40",
        "remediation:50",
        "ticket:jira:sec-123",
    } <= keys
    assert {
        "derived_from",
        "related_asset",
        "has_identity",
        "supported_by",
        "validated_by",
        "has_finding",
        "remediates",
        "tracked_by",
        "owned_by",
    } <= relationships
    assert "evidence" in entity_types
    assert {
        "aws:123456789012",
        "cloud-team",
        "storage-team",
        "security-team",
    } <= claims
    assert "apiKey" not in cloud_metadata
    assert "apiKey" not in host_metadata
    assert host_metadata["internet_exposure"]["public_observation_sources"] == ["urlscan"]
    assert host_metadata["internet_exposure"]["hostname"] == "app.acme.example"
    assert cloud_workload_metadata["asset_role"] == "workload"
    assert cloud_workload_metadata["workload_context"]["runtime_kind"] == "kubernetes"
    assert cloud_workload_metadata["workload_context"]["account_ref"] == "123456789012"
    assert cloud_workload_metadata["workload_context"]["internet_exposed"] is True
    cloud_context = cloud_metadata["cloud_context"]
    assert cloud_context["account_ref"] == "123456789012"
    assert cloud_context["org_ref"] == "o-acme"
    assert cloud_context["region"] == "us-east-1"
    assert cloud_context["data_sensitivity"]["tier"] == "high"
    assert "contains_pii=true" in cloud_context["data_sensitivity"]["signals"]
    assert cloud_context["internet_exposed"] is True
    identity_context = cloud_identity_metadata["identity_context"]
    assert identity_context["provider"] == "aws"
    assert identity_context["account_ref"] == "123456789012"
    assert identity_context["identity_kind"] == "role"
    assert identity_context["principal_name"] == "payments-prod-admin"
    assert identity_context["privilege"] == "read_write_admin"
    permission_summary = identity_context["permission_summary"]
    assert permission_summary["action_count"] == 3
    assert permission_summary["resource_count"] == 1
    assert permission_summary["policy_count"] == 1
    assert permission_summary["actions"] == ["s3:*", "iam:PassRole", "kms:Decrypt"]
    assert permission_summary["resources"] == ["*"]
    assert permission_summary["policies"] == ["AdministratorAccess"]
    assert permission_summary["effects"] == ["allow"]
    assert permission_summary["wildcard_action"] is True
    assert permission_summary["wildcard_resource"] is True
    assert permission_summary["write_action_count"] == 2
    assert permission_summary["sensitive_data_action_count"] == 2
    assert cloud_identity_metadata["cloud_context"]["resource_kind"] == "storage"
    assert secret_metadata["key_redacted"] == "AKIA...TEST"
    assert "key_enc" not in secret_metadata
    assert secret_metadata["lifecycle"]["owner"] == "security-team"
    assert secret_metadata["lifecycle"]["lifecycle_status"] == "owner_routed"
    assert secret_metadata["lifecycle"]["revocation_guidance"]["service"] == "aws"
    assert any(
        item["tool"] == "gitleaks"
        for item in secret_metadata["lifecycle"]["prevention_guidance"]
    )
    standards = finding_metadata["standards"]
    assert standards["primary_cve"] == "CVE-2026-0001"
    assert standards["cvss"]["version"] == "3.1"
    assert standards["cvss"]["score"] == 8.1
    assert standards["epss"] == {"score": 0.72, "percentile": 0.93}
    assert standards["cisa_kev"] is True
    assert standards["cisa_kev_due_date"] == "2026-09-30"
    assert standards["cwe_ids"] == ["CWE-200"]
    assert standards["attack_techniques"] == ["T1530"]
    assert standards["cpe_matches"] == ["cpe:2.3:a:acme:bucket:1.0:*:*:*:*:*:*:*"]
    assert {"source_name": "cve", "external_id": "CVE-2026-0001"} in standards["stix_external_refs"]
    assert {"source_name": "mitre-attack", "external_id": "T1530"} in standards["stix_external_refs"]
    assert active_validation_metadata["validation_method"] == "control_simulation"
    assert active_validation_metadata["validation_result"] == "control_passed"
    assert active_validation_metadata["proof_kind"] == "control_simulation"
    assert active_validation_metadata["network_execution"] is False
    assert active_validation_metadata["destructive_actions"] is False
    assert active_validation_metadata["proof_summary"]["evidence"].startswith(
        "control expected=detected observed=detected matched=yes"
    )
    assert "active-secret" not in json.dumps(active_validation_metadata, sort_keys=True)
    assert active_validation_evidence_metadata["validation_result"] == "control_passed"
    assert "active-secret" not in json.dumps(active_validation_evidence_metadata, sort_keys=True)
    summary = graph["attack_path_summary"]
    assert summary["scoring_model"] == "forge.asset_graph.v1"
    assert summary["critical_asset_count"] >= 2
    assert summary["path_count"] >= 2
    assert summary["choke_point_count"] >= 1
    critical_by_key = {item["entity_key"]: item for item in graph["critical_assets"]}
    graph_key_by_id = {int(node["id"]): node["entity_key"] for node in graph["nodes"]}
    graph_edges = {
        (
            graph_key_by_id.get(int(edge["source_entity_id"])),
            graph_key_by_id.get(int(edge["target_entity_id"])),
            edge["relationship_type"],
            edge["evidence"].get("match"),
        )
        for edge in graph["edges"]
    }
    assert critical_by_key["finding:vulnerability:40"]["owner_ref"] == "cloud-team"
    assert critical_by_key["secret:aws:aws access key:30"]["owner_ref"] == "security-team"
    assert {
        "cloud_account_mapped",
        "cloud_identity",
        "cloud_principal",
        "cloud_permission_context",
        "data_access_identity",
        "identity",
        "privileged_identity",
        "wildcard_action",
        "wildcard_resource",
        "write_capable_identity",
    } <= set(critical_by_key[aws_identity_key]["tags"])
    assert {
        "identity_privilege=read_write_admin",
        "permission_actions=3",
        "wildcard_action=true",
        "wildcard_resource=true",
        "write_actions=2",
        "sensitive_data_actions=2",
    } <= set(critical_by_key[aws_identity_key]["risk_factors"])
    assert {
        "cloud_account_mapped",
        "data_asset",
        "internet_exposed",
        "sensitive_data",
    } <= set(critical_by_key["cloud:aws_s3:acme-assets"]["tags"])
    assert (
        "asset:internet:public",
        "host:app.acme.example",
        "related_asset",
        None,
    ) in graph_edges
    assert (
        "asset:internet:public",
        "cloud:aws_s3:acme-assets",
        "related_asset",
        None,
    ) in graph_edges
    assert (
        "host:app.acme.example",
        "workload:kubernetes:prod-eks:payments:payments-api",
        "runs_service",
        "host_to_runtime_workload",
    ) in graph_edges
    assert (
        "cloud:aws_s3:acme-assets",
        "workload:aws:123456789012:payments:payments-api",
        "related_asset",
        "cloud_asset_to_runtime_workload",
    ) in graph_edges
    assert (
        "cloud:aws_s3:acme-assets",
        aws_identity_key,
        "has_identity",
        "cloud_resource_identity_context",
    ) in graph_edges
    assert (
        aws_identity_key,
        "cloud:aws_s3:acme-assets",
        "references_cloud",
        "cloud_identity_to_cloud_resource",
    ) in graph_edges
    assert (
        aws_identity_key,
        "organization:cloud_account:aws:123456789012",
        "references_cloud",
        "cloud_identity_to_cloud_account",
    ) in graph_edges
    assert (
        "secret:aws:aws access key:30",
        "organization:cloud_account:aws:123456789012",
        "references_cloud",
        "validated_secret_provider_to_cloud_account",
    ) in graph_edges
    assert (
        "secret:aws:aws access key:30",
        "cloud:aws_s3:acme-assets",
        "references_cloud",
        "validated_secret_to_cloud_resource",
    ) in graph_edges
    assert (
        "host:app.acme.example",
        "validation:active_validation:61",
        "validated_by",
        None,
    ) in graph_edges
    assert (
        "finding:vulnerability:40",
        "validation:active_validation:61",
        "validated_by",
        None,
    ) in graph_edges
    assert (
        "remediation:50",
        "validation:active_validation:61",
        "validated_by",
        None,
    ) in graph_edges
    assert "cisa_kev" in critical_by_key["finding:vulnerability:40"]["tags"]
    assert any(
        path["terminal_entity_key"] == "finding:vulnerability:40"
        for path in graph["attack_paths"]
    )
    finding_path = next(
        path
        for path in graph["attack_paths"]
        if path["terminal_entity_key"] == "finding:vulnerability:40"
    )
    exposure_summary = finding_path["exposure_summary"]
    assert exposure_summary["entry_entity_key"].startswith("asset:")
    assert exposure_summary["terminal_entity_key"] == "finding:vulnerability:40"
    assert " graph hop" in exposure_summary["summary"]
    assert exposure_summary["relationship_chain"]
    assert "cisa_kev" in exposure_summary["risk_tags"]
    assert "cloud-team" in exposure_summary["owner_refs"]
    assert exposure_summary["remediation_action_count"] >= 1
    assert exposure_summary["recommended_actions"] == [
        "assign_remediation_owner",
        "open_or_update_ticket",
        "request_retest",
    ]
    assert finding_path["recommended_actions"] == exposure_summary["recommended_actions"]
    identity_path = next(
        path
        for path in graph["attack_paths"]
        if path["terminal_entity_key"] == aws_identity_key
    )
    identity_exposure = identity_path["exposure_summary"]
    assert {
        "public_sensitive_data_exposure",
        "public_to_privileged_sensitive_data_path",
        "privileged_identity_to_sensitive_data",
    } <= set(identity_exposure["toxic_combinations"])
    assert identity_exposure["cloud_context"]["account_refs"] == ["123456789012"]
    assert identity_exposure["cloud_context"]["regions"] == ["us-east-1"]
    assert identity_exposure["cloud_context"]["data_sensitivity_tiers"] == ["high"]
    assert {
        "payments-api",
    } <= set(identity_exposure["cloud_context"]["workloads"])
    assert {
        "arn:aws:iam::123456789012:role/payments-prod-admin",
    } <= set(identity_exposure["cloud_context"]["identity_refs"])
    assert any(
        point["entity_key"] == "finding:vulnerability:40"
        for point in graph["choke_points"]
    )
    assert {
        "remediate_highest_risk_finding",
        "restrict_public_sensitive_data_asset",
        "reduce_cloud_identity_privilege",
        "revoke_or_rotate_secret",
    } <= {item["reason"] for item in graph["minimal_fix_set_candidates"]}
    cloud_fix = next(
        item
        for item in graph["minimal_fix_set_candidates"]
        if item["entity_key"] == "cloud:aws_s3:acme-assets"
    )
    assert cloud_fix["reason"] == "restrict_public_sensitive_data_asset"
    assert cloud_fix["recommended_actions"] == [
        "disable_public_access",
        "restrict_public_policy_or_acl",
        "confirm_data_classification",
        "add_data_loss_guardrails",
        "route_to_cloud_account_owner",
    ]
    assert "data_sensitivity=high" in cloud_fix["risk_factors"]
    assert "internet_exposed=true" in cloud_fix["risk_factors"]
    identity_fix = next(
        item
        for item in graph["minimal_fix_set_candidates"]
        if item["entity_key"] == aws_identity_key
    )
    assert identity_fix["reason"] == "reduce_cloud_identity_privilege"
    assert "wildcard_action=true" in identity_fix["risk_factors"]
    assert "wildcard_resource=true" in identity_fix["risk_factors"]
    assert "write_actions=2" in identity_fix["risk_factors"]
    finding_fix = next(
        item
        for item in graph["minimal_fix_set_candidates"]
        if item["entity_key"] == "finding:vulnerability:40"
    )
    assert finding_fix["remediation"] == {
        "item_count": 1,
        "open_count": 1,
        "ticketed_count": 1,
        "retest_pending_count": 0,
        "risk_acceptance_state": "none",
        "items": finding_fix["remediation_actions"],
    }
    assert finding_fix["remediation_action_count"] == 1
    remediation_action = finding_fix["remediation_actions"][0]
    assert remediation_action["id"] == 50
    assert remediation_action["entity_key"] == "remediation:50"
    assert remediation_action["status"] == "assigned"
    assert remediation_action["retest_status"] == "not_requested"
    assert remediation_action["ticket_system"] == "jira"
    assert remediation_action["ticket_ref"] == "SEC-123"
    assert remediation_action["ticket_url"] == "https://acme.atlassian.net/browse/SEC-123?view=ok"
    assert remediation_action["owner_ref"] == "cloud-team"
    finding_path_node = next(
        node
        for path in graph["attack_paths"]
        for node in path["nodes"]
        if node["entity_key"] == "finding:vulnerability:40"
    )
    assert finding_path_node["remediation"]["item_count"] == 1
    finding_choke_point = next(
        point
        for point in graph["choke_points"]
        if point["entity_key"] == "finding:vulnerability:40"
    )
    assert finding_choke_point["remediation"]["items"][0]["ticket_ref"] == "SEC-123"
    finding_blast_radius = finding_choke_point["blast_radius_summary"]
    assert finding_blast_radius["source_node_id"] == finding_choke_point["node_id"]
    assert finding_blast_radius["reachable_count"] == finding_choke_point["blast_radius_count"]
    assert finding_blast_radius["entity_type_counts"] == {
        "evidence": 2,
        "owner": 1,
        "validation": 1,
    }
    assert "cisa_kev" in finding_blast_radius["risk_tags"]
    assert "severity=HIGH" in finding_blast_radius["risk_factors"]
    assert finding_blast_radius["risk_tier_counts"]["critical"] == 1
    assert finding_blast_radius["risk_tier_counts"]["low"] >= 1
    assert finding_blast_radius["cloud_context"] == {
        "account_refs": [],
        "regions": [],
        "data_sensitivity_tiers": [],
        "workloads": [],
        "identity_refs": [],
    }
    cloud_choke_point = next(
        point
        for point in graph["choke_points"]
        if point["entity_key"] == "cloud:aws_s3:acme-assets"
    )
    cloud_blast_radius = cloud_choke_point["blast_radius_summary"]
    assert cloud_blast_radius["critical_asset_count"] >= 1
    assert aws_identity_key in cloud_blast_radius["critical_asset_refs"]
    assert {
        "public_sensitive_data_exposure",
        "public_to_privileged_sensitive_data_path",
        "privileged_identity_to_sensitive_data",
    } <= set(cloud_blast_radius["toxic_combinations"])
    assert cloud_blast_radius["cloud_context"]["account_refs"] == ["123456789012"]
    assert cloud_blast_radius["cloud_context"]["regions"] == ["us-east-1"]
    assert cloud_blast_radius["cloud_context"]["data_sensitivity_tiers"] == ["high"]
    assert {
        "payments-api",
    } <= set(cloud_blast_radius["cloud_context"]["workloads"])
    assert {
        "arn:aws:iam::123456789012:role/payments-prod-admin",
    } <= set(cloud_blast_radius["cloud_context"]["identity_refs"])
    graph_blob = json.dumps(graph, sort_keys=True)
    assert "iam-token-never-render" not in graph_blob
    assert "permission-secret-never-render" not in graph_blob
    assert "raw-secret-token" not in graph_blob
    assert "should-not-store" not in graph_blob
    assert "user:pass" not in graph_blob
    assert "token=never" not in graph_blob
    assert "[REDACTED]" in graph_blob


def test_asset_graph_list_reports_limited_node_counts(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        sync_engagement_asset_graph(con, 1001)
        graph = list_asset_graph(con, 1001, limit=2)
    finally:
        con.close()

    assert graph["schema_version"] == "forge.asset_graph.list.v1"
    assert graph["execution_policy"] == "read_only_asset_graph_inventory_no_commands_executed"
    assert graph["total_count"] > 2
    assert graph["selected_count"] == 2
    assert graph["omitted_count"] == graph["total_count"] - 2
    assert len(graph["nodes"]) == 2


def test_asset_graph_promotes_aws_sts_validation_to_account_context(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (id, engagement_id, asset_type, identifier, provider_identifier,
                 validation_status, validation_method, http_status, evidence)
            VALUES
                (22, 1001, 'aws', '742931608514', '742931608514',
                 'VALIDATED', 'aws_sts_get_caller_identity', NULL,
                 'AWS AccountId: 742931608514 UserId=AIDAEXAMPLE')
            """
        )
        con.commit()

        sync_engagement_asset_graph(con, 1001)
        graph = list_asset_graph(con, 1001, limit=250)
        cloud_metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM asset_entities
                WHERE entity_key='cloud:aws:742931608514'
                """
            ).fetchone()["metadata_json"]
        )
    finally:
        con.close()

    nodes = {node["entity_key"]: node for node in graph["nodes"]}
    graph_key_by_id = {int(node["id"]): node["entity_key"] for node in graph["nodes"]}
    graph_edges = {
        (
            graph_key_by_id.get(int(edge["source_entity_id"])),
            graph_key_by_id.get(int(edge["target_entity_id"])),
            edge["relationship_type"],
            edge["evidence"].get("match"),
        )
        for edge in graph["edges"]
    }
    account_key = "organization:cloud_account:aws:742931608514"
    cloud_key = "cloud:aws:742931608514"
    secret_key = "secret:aws:aws access key:30"

    assert account_key in nodes
    assert cloud_key in nodes
    assert cloud_metadata["cloud_context"]["provider"] == "aws"
    assert cloud_metadata["cloud_context"]["account_ref"] == "742931608514"
    assert cloud_metadata["cloud_context"]["resource_kind"] == "account"
    assert (
        account_key,
        cloud_key,
        "references_cloud",
        None,
    ) in graph_edges
    assert (
        secret_key,
        account_key,
        "references_cloud",
        "validated_secret_provider_to_cloud_account",
    ) in graph_edges
    assert (
        secret_key,
        cloud_key,
        "references_cloud",
        "validated_secret_to_cloud_resource",
    ) in graph_edges
    assert "aws:742931608514" in {
        claim["owner_ref"] for claim in graph["ownership_claims"]
    }


def test_asset_graph_promotes_cross_cloud_iam_bindings_to_identity_paths(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        con.execute(
            """
            INSERT INTO cloud_assets
                (id, engagement_id, asset_type, identifier, provider_identifier, source, metadata_json)
            VALUES
                (70, 1001, 'gcs', 'pii-archive', 'gs://pii-archive', 'fixture', ?),
                (71, 1001, 'azure_blob', 'reports', '/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/reports', 'fixture', ?)
            """,
            (
                json.dumps(
                    {
                        "project_id": "acme-prod",
                        "data_classification": "restricted",
                        "public_access": True,
                        "iam_bindings": [
                            {
                                "role": "roles/storage.admin",
                                "members": [
                                    "serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com"
                                ],
                                "condition": {"api_key": "binding-secret-never-render"},
                            }
                        ],
                        "apiKey": "gcp-secret-never-render",
                    }
                ),
                json.dumps(
                    {
                        "subscription_id": "sub-123",
                        "tenant_id": "tenant-456",
                        "data_sensitivity": "confidential",
                        "public_access": True,
                        "role_assignments": [
                            {
                                "principal_id": "11111111-2222-3333-4444-555555555555",
                                "principal_type": "ManagedIdentity",
                                "principal_name": "reports-api-mi",
                                "role_definition_name": "Storage Blob Data Contributor",
                                "scope": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/reports",
                                "client_secret": "azure-secret-never-render",
                            }
                        ],
                    }
                ),
            ),
        )
        con.commit()

        sync_engagement_asset_graph(con, 1001)
        graph = list_asset_graph(con, 1001, limit=500)
    finally:
        con.close()

    nodes = {node["entity_key"]: node for node in graph["nodes"]}
    graph_key_by_id = {int(node["id"]): node["entity_key"] for node in graph["nodes"]}
    graph_edges = {
        (
            graph_key_by_id.get(int(edge["source_entity_id"])),
            graph_key_by_id.get(int(edge["target_entity_id"])),
            edge["relationship_type"],
            edge["evidence"].get("match"),
        )
        for edge in graph["edges"]
    }
    gcp_identity_key = (
        "identity:cloud_principal:gcp:service_account:"
        "etl-runner@acme-prod.iam.gserviceaccount.com"
    )
    azure_identity_key = (
        "identity:cloud_principal:azure:managed_identity:"
        "11111111-2222-3333-4444-555555555555"
    )

    assert gcp_identity_key in nodes
    assert azure_identity_key in nodes
    assert "organization:cloud_account:gcp:acme-prod" in nodes
    assert "organization:cloud_account:azure:sub-123" in nodes
    assert {
        "apiKey",
        "client_secret",
        "binding-secret-never-render",
        "gcp-secret-never-render",
        "azure-secret-never-render",
    }.isdisjoint(json.dumps(nodes, sort_keys=True))

    gcp_identity_context = nodes[gcp_identity_key]["metadata"]["identity_context"]
    assert gcp_identity_context["identity_kind"] == "service_account"
    assert gcp_identity_context["account_ref"] == "acme-prod"
    assert gcp_identity_context["privilege"] == "admin"
    assert gcp_identity_context["permission_summary"]["policies"] == ["roles/storage.admin"]
    assert gcp_identity_context["permission_summary"]["write_action_count"] == 0

    azure_identity_context = nodes[azure_identity_key]["metadata"]["identity_context"]
    assert azure_identity_context["identity_kind"] == "managed_identity"
    assert azure_identity_context["account_ref"] == "sub-123"
    assert azure_identity_context["org_ref"] == "tenant-456"
    assert azure_identity_context["privilege"] == "admin"
    assert azure_identity_context["permission_summary"]["policies"] == [
        "Storage Blob Data Contributor"
    ]

    assert (
        gcp_identity_key,
        "cloud:gcs:pii-archive",
        "references_cloud",
        "cloud_identity_to_cloud_resource",
    ) in graph_edges
    assert (
        gcp_identity_key,
        "organization:cloud_account:gcp:acme-prod",
        "references_cloud",
        "cloud_identity_to_cloud_account",
    ) in graph_edges
    assert (
        azure_identity_key,
        "cloud:azure_blob:reports",
        "references_cloud",
        "cloud_identity_to_cloud_resource",
    ) in graph_edges
    assert (
        azure_identity_key,
        "organization:cloud_account:azure:sub-123",
        "references_cloud",
        "cloud_identity_to_cloud_account",
    ) in graph_edges

    critical_by_key = {item["entity_key"]: item for item in graph["critical_assets"]}
    assert "privileged_identity" in critical_by_key[gcp_identity_key]["tags"]
    assert "identity_privilege=admin" in critical_by_key[gcp_identity_key]["risk_factors"]
    assert "privileged_identity" in critical_by_key[azure_identity_key]["tags"]
    assert "identity_privilege=admin" in critical_by_key[azure_identity_key]["risk_factors"]
    assert any(
        item["entity_key"] == gcp_identity_key
        and item["reason"] == "reduce_cloud_identity_privilege"
        for item in graph["minimal_fix_set_candidates"]
    )
    assert any(
        item["entity_key"] == azure_identity_key
        and item["reason"] == "reduce_cloud_identity_privilege"
        for item in graph["minimal_fix_set_candidates"]
    )


def test_asset_graph_evidence_migration_expands_existing_enum_constraints(tmp_path: Path) -> None:
    con = sqlite3.connect(tmp_path / "engagement.db")
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES (39);

            CREATE TABLE engagements (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT    NOT NULL UNIQUE,
                scope_json   TEXT    NOT NULL DEFAULT '[]',
                status       TEXT    NOT NULL DEFAULT 'PREP',
                operator     TEXT    NOT NULL,
                created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one');

            CREATE TABLE asset_entities (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
                entity_key     TEXT    NOT NULL,
                entity_type    TEXT    NOT NULL
                               CHECK (entity_type IN (
                                   'asset',
                                   'seed',
                                   'host',
                                   'service',
                                   'identity',
                                   'cloud',
                                   'secret',
                                   'finding',
                                   'validation',
                                   'remediation',
                                   'ticket',
                                   'owner',
                                   'organization',
                                   'other'
                               )),
                label          TEXT    NOT NULL,
                source_table   TEXT,
                source_id      INTEGER,
                confidence     REAL    NOT NULL DEFAULT 0.5,
                metadata_json  TEXT    NOT NULL DEFAULT '{}',
                first_seen_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, entity_key)
            );
            INSERT INTO asset_entities
                (id, engagement_id, entity_key, entity_type, label)
            VALUES (1, 1001, 'asset:domain:acme.example', 'asset', 'acme.example');

            CREATE TABLE asset_relationships (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
                source_entity_id    INTEGER NOT NULL REFERENCES asset_entities(id),
                target_entity_id    INTEGER NOT NULL REFERENCES asset_entities(id),
                relationship_type   TEXT    NOT NULL
                                    CHECK (relationship_type IN (
                                        'derived_from',
                                        'corroborates',
                                        'conflicts_with',
                                        'same_entity',
                                        'related_asset',
                                        'runs_service',
                                        'has_identity',
                                        'references_cloud',
                                        'validated_by',
                                        'has_finding',
                                        'remediates',
                                        'tracked_by',
                                        'owned_by',
                                        'routed_to',
                                        'observed_in',
                                        'other'
                                    )),
                confidence          REAL    NOT NULL DEFAULT 0.5,
                source_table        TEXT    NOT NULL DEFAULT 'system',
                source_id           INTEGER NOT NULL DEFAULT 0,
                evidence_json       TEXT    NOT NULL DEFAULT '{}',
                created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (
                    engagement_id,
                    source_entity_id,
                    target_entity_id,
                    relationship_type,
                    source_table,
                    source_id
                )
            );
            """
        )

        run_migrations(con)

        con.execute(
            """
            INSERT INTO asset_entities
                (engagement_id, entity_key, entity_type, label, source_table, source_id)
            VALUES
                (1001, 'evidence:vulnerability_findings:40:finding_evidence',
                 'evidence', 'Finding evidence', 'vulnerability_findings', 40)
            """
        )
        con.execute(
            """
            INSERT INTO asset_relationships
                (engagement_id, source_entity_id, target_entity_id,
                 relationship_type, source_table, source_id)
            VALUES (1001, 1, 2, 'supported_by', 'vulnerability_findings', 40)
            """
        )
        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
    finally:
        con.close()

    assert int(version) == TARGET_VERSION


def test_ownership_claim_upsert_creates_owner_entity_and_edge(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="asset:domain:acme.example",
            entity_type="asset",
            label="acme.example",
            confidence=0.9,
            metadata={"source": "operator", "token": "do-not-store"},
        )
        first = upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="appsec@example.com",
            owner_kind="email",
            owner_display="AppSec",
            claim_type="explicit",
            confidence=0.8,
            source="operator",
            evidence={"reason": "scope owner", "secret": "do-not-store"},
            created_by="delta-one",
        )
        second = upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="appsec@example.com",
            owner_kind="email",
            owner_display="Application Security",
            claim_type="explicit",
            confidence=0.9,
            source="operator",
            evidence={"reason": "scope owner"},
            created_by="delta-one",
        )
        graph = list_asset_graph(con, 1001, entity_key="asset:domain:acme.example")
        metadata = json.loads(
            con.execute(
                "SELECT metadata_json FROM asset_entities WHERE id=?",
                (entity_id,),
            ).fetchone()["metadata_json"]
        )
        evidence = json.loads(
            con.execute(
                "SELECT evidence_json FROM asset_ownership_claims WHERE id=?",
                (first,),
            ).fetchone()["evidence_json"]
        )
    finally:
        con.close()

    assert first == second
    assert graph["ownership_claims"][0]["owner_display"] == "Application Security"
    assert graph["ownership_claims"][0]["confidence"] == 0.9
    assert graph["edges"][0]["relationship_type"] == "owned_by"
    assert "token" not in metadata
    assert "secret" not in evidence


def test_resolve_asset_owner_surfaces_conflicts_and_source_fallback(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="host:vpn.acme.example",
            entity_type="host",
            label="vpn.acme.example",
            source_table="hosts",
            source_id=200,
            confidence=0.8,
            metadata={"source": "fixture"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="network-team",
            owner_kind="team",
            owner_display="Network Team",
            claim_type="manual",
            confidence=0.7,
            source="operator",
            evidence={"reason": "primary owner"},
        )
        upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="cloud-team",
            owner_kind="team",
            owner_display="Cloud Team",
            claim_type="inferred",
            confidence=0.9,
            source="cloud_account",
            evidence={"reason": "shared account", "token": "do-not-store"},
        )
        resolved = resolve_asset_owner(
            con,
            engagement_id=1001,
            source_table="hosts",
            source_id=200,
        )
        claims = ownership_claims_for_entity(
            con,
            engagement_id=1001,
            entity_key="host:vpn.acme.example",
        )
        conflicts = ownership_conflicts_for_engagement(con, 1001)
        graph = list_asset_graph(con, 1001, entity_key="host:vpn.acme.example")
    finally:
        con.close()

    assert resolved["owner_ref"] == "cloud-team"
    assert resolved["owner_display"] == "Cloud Team"
    assert resolved["conflict"] is True
    assert [claim["owner_ref"] for claim in claims] == ["cloud-team", "network-team"]
    assert conflicts[0]["entity_key"] == "host:vpn.acme.example"
    assert {owner["owner_ref"] for owner in conflicts[0]["owners"]} == {
        "cloud-team",
        "network-team",
    }
    assert graph["ownership_conflicts"][0]["owner_count"] == 2
    assert "do-not-store" not in json.dumps(graph, sort_keys=True)


def test_resolve_ownership_conflict_selects_owner_and_supersedes_edges(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        entity_id = upsert_asset_entity(
            con,
            engagement_id=1001,
            entity_key="host:vpn.acme.example",
            entity_type="host",
            label="vpn.acme.example",
            source_table="hosts",
            source_id=200,
            confidence=0.8,
            metadata={"source": "fixture"},
        )
        network_claim_id = upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="network-team",
            owner_kind="team",
            claim_type="manual",
            confidence=0.7,
            source="operator",
            evidence={"reason": "primary owner"},
        )
        cloud_claim_id = upsert_ownership_claim(
            con,
            engagement_id=1001,
            entity_id=entity_id,
            owner_ref="cloud-team",
            owner_kind="team",
            claim_type="inferred",
            confidence=0.9,
            source="cloud_account",
            evidence={"reason": "shared account", "token": "do-not-store"},
        )
        before = resolve_asset_owner(con, engagement_id=1001, entity_key="host:vpn.acme.example")
        result = resolve_ownership_conflict(
            con,
            engagement_id=1001,
            entity_key="host:vpn.acme.example",
            claim_id=network_claim_id,
            reason="network team owns the VPN service",
            resolved_by="delta-one",
        )
        after = resolve_asset_owner(con, engagement_id=1001, entity_key="host:vpn.acme.example")
        claim_statuses = {
            row["owner_ref"]: row["status"]
            for row in con.execute(
                """
                SELECT owner_ref, status
                FROM asset_ownership_claims
                WHERE engagement_id=1001 AND entity_id=?
                """,
                (entity_id,),
            ).fetchall()
        }
        remaining_claim_edges = {
            int(row["source_id"])
            for row in con.execute(
                """
                SELECT source_id
                FROM asset_relationships
                WHERE engagement_id=1001
                  AND relationship_type='owned_by'
                  AND source_table='asset_ownership_claims'
                """
            ).fetchall()
        }
        graph = list_asset_graph(con, 1001, entity_key="host:vpn.acme.example")
    finally:
        con.close()

    assert before["owner_ref"] == "cloud-team"
    assert before["conflict"] is True
    assert result["selected_owner"] == "network-team"
    assert result["selected_claim_ids"] == [network_claim_id]
    assert result["superseded_claim_ids"] == [cloud_claim_id]
    assert result["conflicts"] == []
    assert after["owner_ref"] == "network-team"
    assert after["conflict"] is False
    assert claim_statuses == {"network-team": "active", "cloud-team": "superseded"}
    assert network_claim_id in remaining_claim_edges
    assert cloud_claim_id not in remaining_claim_edges
    assert graph["ownership_conflicts"] == []
    assert "do-not-store" not in json.dumps(result, sort_keys=True)
    assert "do-not-store" not in json.dumps(graph, sort_keys=True)


def test_asset_attribution_import_maps_subsidiary_third_party_and_cloud_org(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        sync_engagement_asset_graph(con, 1001)
        result = import_asset_attribution_records(
            con,
            engagement_id=1001,
            source="unit-attribution",
            created_by="delta-one",
            records=[
                {
                    "entity_key": "host:app.acme.example",
                    "entity_type": "host",
                    "label": "App host",
                    "attribution_kind": "subsidiary",
                    "organization_ref": "Acme Payments Pte Ltd",
                    "parent_organization_ref": "Acme Group",
                    "owner_ref": "payments-sec",
                    "owner_kind": "team",
                    "confidence": 0.82,
                    "evidence": {"source_url": "fixture", "token": "do-not-store"},
                },
                {
                    "entity_key": "cloud:aws_s3:acme-assets",
                    "attribution_kind": "cloud_account",
                    "cloud_provider": "aws",
                    "cloud_account_id": "999999999999",
                    "cloud_org_id": "o-acme-root",
                    "confidence": 0.91,
                },
                {
                    "entity_key": "service:cdn.vendor.example",
                    "entity_type": "service",
                    "attribution_kind": "third_party",
                    "third_party_ref": "cdn-vendor",
                    "third_party_display": "CDN Vendor",
                    "confidence": 0.64,
                },
            ],
        )
        con.commit()
        graph = list_asset_graph(con, 1001, limit=500)
    finally:
        con.close()

    nodes = {node["entity_key"]: node for node in graph["nodes"]}
    owner_refs = {claim["owner_ref"] for claim in graph["ownership_claims"]}
    key_by_id = {int(node["id"]): node["entity_key"] for node in graph["nodes"]}
    relationships = {
        (
            key_by_id.get(int(edge["source_entity_id"])),
            key_by_id.get(int(edge["target_entity_id"])),
            edge["relationship_type"],
            edge["evidence"].get("relationship_kind"),
        )
        for edge in graph["edges"]
    }

    assert result["processed_count"] == 3
    assert result["imported_count"] == 3
    assert result["error_count"] == 0
    assert result["ownership_claim_count"] >= 4
    assert "organization:subsidiary:acme-payments-pte-ltd" in nodes
    assert "organization:organization:acme-group" in nodes
    assert "organization:cloud_account:aws:999999999999" in nodes
    assert "organization:cloud_org:aws:org:o-acme-root" in nodes
    assert "organization:third_party:cdn-vendor" in nodes
    assert nodes["host:app.acme.example"]["confidence"] >= 0.82
    assert {"payments-sec", "Acme Payments Pte Ltd", "aws:999999999999", "cdn-vendor"} <= owner_refs
    assert (
        "organization:subsidiary:acme-payments-pte-ltd",
        "organization:organization:acme-group",
        "related_asset",
        "subsidiary_of",
    ) in relationships
    assert (
        "cloud:aws_s3:acme-assets",
        "organization:cloud_account:aws:999999999999",
        "owned_by",
        "cloud_account_mapping",
    ) in relationships
    assert (
        "organization:cloud_account:aws:999999999999",
        "organization:cloud_org:aws:org:o-acme-root",
        "related_asset",
        "cloud_org_member",
    ) in relationships
    assert (
        "service:cdn.vendor.example",
        "organization:third_party:cdn-vendor",
        "owned_by",
        "third_party_provider",
    ) in relationships
    assert "do-not-store" not in json.dumps(graph, sort_keys=True)


def test_graph_sync_assets_cli_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "data"
    _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    from forge.cli import app as forge_app

    result = CliRunner().invoke(
        forge_app,
        ["graph", "sync-assets", "--engagement", "1001", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["node_count"] == 1
    assert payload["source_counts"]["cloud"] == 1
    assert payload["source_counts"]["active_validation"] == 0


def test_graph_attribution_import_cli_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "data"
    _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    attribution_file = tmp_path / "attribution.json"
    attribution_file.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "entity_key": "cloud:firebase:acme-prod",
                        "entity_type": "cloud",
                        "attribution_kind": "cloud_account",
                        "cloud_provider": "gcp",
                        "cloud_account_id": "acme-prod",
                        "organization_id": "folders/123",
                        "confidence": 0.88,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    from forge.cli import app as forge_app

    result = CliRunner().invoke(
        forge_app,
        [
            "graph",
            "attribution",
            "import",
            "--engagement",
            "1001",
            "--file",
            str(attribution_file),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["processed_count"] == 1
    assert payload["imported_count"] == 1
    assert payload["ownership_claim_count"] == 1


def test_graph_ownership_resolve_cli_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "data"
    _build_data_dir_db(data_dir)
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    from forge.cli import app as forge_app

    first = CliRunner().invoke(
        forge_app,
        [
            "graph",
            "ownership",
            "set",
            "--engagement",
            "1001",
            "--entity-key",
            "cloud:firebase:acme-prod",
            "--entity-type",
            "cloud",
            "--owner",
            "app-team",
            "--confidence",
            "0.6",
            "--json",
        ],
    )
    second = CliRunner().invoke(
        forge_app,
        [
            "graph",
            "ownership",
            "set",
            "--engagement",
            "1001",
            "--entity-key",
            "cloud:firebase:acme-prod",
            "--owner",
            "cloud-team",
            "--confidence",
            "0.9",
            "--json",
        ],
    )
    resolved = CliRunner().invoke(
        forge_app,
        [
            "graph",
            "ownership",
            "resolve",
            "--engagement",
            "1001",
            "--entity-key",
            "cloud:firebase:acme-prod",
            "--owner",
            "app-team",
            "--reason",
            "application team owns the Firebase project",
            "--json",
        ],
    )

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert resolved.exit_code == 0, resolved.output
    payload = json.loads(resolved.output)
    assert payload["selected_owner"] == "app-team"
    assert payload["owner"]["owner_ref"] == "app-team"
    assert payload["owner"]["conflict"] is False
    assert payload["conflicts"] == []
    statuses = {claim["owner_ref"]: claim["status"] for claim in payload["claims"]}
    assert statuses == {"cloud-team": "superseded", "app-team": "active"}
