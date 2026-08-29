from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.webui.app import create_app
from forge.webui.auth import mint_token


def _build_engagement_db(data_dir: Path) -> Path:
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
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
            INSERT INTO engagement_seeds
                (id, engagement_id, seed_value, seed_type, source, status, depth, confidence)
            VALUES (1, 1001, 'acme.example', 'domain', 'operator', 'completed', 0, 1.0)
            """
        )
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, provider_identifier, source, metadata_json)
            VALUES
                (1001, 'aws_s3', 'acme-assets', 'arn:aws:s3:::acme-assets',
                 'fixture',
                 '{
                    "region":"us-east-1",
                    "iam_context":{
                        "principal_arn":"arn:aws:iam::123456789012:role/api-admin",
                        "principal_type":"role",
                        "principal_name":"api-admin",
                        "policy_document":{
                            "Statement":[{
                                "Effect":"Allow",
                                "Action":["s3:*","kms:Decrypt"],
                                "Resource":"*"
                            }]
                        },
                        "token":"do-not-store-identity"
                    },
                    "apiKey":"do-not-store"
                  }')
            """
        )
        con.commit()
    finally:
        con.close()
    return db_path


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_asset_graph_api_rebuild_read_and_claim_routes(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / ".forge_data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    _build_engagement_db(data_dir)

    app = create_app()
    read_token = mint_token(
        "delta-one",
        permissions=("assets:read", "workspaces:legacy"),
    )
    write_token = mint_token(
        "delta-one",
        permissions=("assets:read", "assets:write", "workspaces:legacy"),
    )
    denied_token = mint_token(
        "delta-one",
        permissions=("engagements:read", "workspaces:legacy"),
    )
    with TestClient(app) as client:
        denied_read = client.get(
            "/api/engagements/1001/asset-graph",
            headers=_headers(denied_token),
        )
        rebuild = client.post(
            "/api/engagements/1001/asset-graph/rebuild",
            headers=_headers(write_token),
        )
        graph = client.get(
            "/api/engagements/1001/asset-graph",
            headers=_headers(read_token),
        )
        denied_claim = client.post(
            "/api/engagements/1001/asset-graph/ownership-claims",
            headers=_headers(read_token),
            json={"entity_key": "cloud:aws_s3:acme-assets", "owner_ref": "cloud-team"},
        )
        denied_attribution = client.post(
            "/api/engagements/1001/asset-graph/attribution",
            headers=_headers(read_token),
            json={"records": [{"entity_key": "cloud:aws_s3:acme-assets"}]},
        )
        denied_resolve = client.post(
            "/api/engagements/1001/asset-graph/ownership-conflicts/resolve",
            headers=_headers(read_token),
            json={
                "entity_key": "cloud:aws_s3:acme-assets",
                "owner_ref": "cloud-team",
            },
        )
        claim = client.post(
            "/api/engagements/1001/asset-graph/ownership-claims",
            headers=_headers(write_token),
            json={
                "entity_key": "cloud:aws_s3:acme-assets",
                "owner_ref": "cloud-team",
                "owner_kind": "team",
                "confidence": 0.9,
                "evidence": {"source": "test", "token": "do-not-store"},
            },
        )
        conflicting_claim = client.post(
            "/api/engagements/1001/asset-graph/ownership-claims",
            headers=_headers(write_token),
            json={
                "entity_key": "cloud:aws_s3:acme-assets",
                "owner_ref": "legacy-cloud",
                "owner_kind": "team",
                "confidence": 0.5,
                "evidence": {"source": "test", "secret": "do-not-store-conflict"},
            },
        )
        resolved_conflict = client.post(
            "/api/engagements/1001/asset-graph/ownership-conflicts/resolve",
            headers=_headers(write_token),
            json={
                "entity_key": "cloud:aws_s3:acme-assets",
                "owner_ref": "cloud-team",
                "reason": "cloud team is current owner",
            },
        )
        attribution = client.post(
            "/api/engagements/1001/asset-graph/attribution",
            headers=_headers(write_token),
            json={
                "source": "api-test",
                "records": [
                    {
                        "entity_key": "cloud:aws_s3:acme-assets",
                        "attribution_kind": "cloud_account",
                        "cloud_provider": "aws",
                        "cloud_account_id": "999999999999",
                        "cloud_org_id": "o-acme-root",
                        "confidence": 0.92,
                    },
                    {
                        "entity_key": "service:cdn.vendor.example",
                        "entity_type": "service",
                        "attribution_kind": "third_party",
                        "third_party_ref": "cdn-vendor",
                        "third_party_display": "CDN Vendor",
                        "confidence": 0.7,
                        "evidence": {"api_key": "do-not-store"},
                    },
                ],
            },
        )
        filtered = client.get(
            "/api/engagements/1001/asset-graph",
            headers=_headers(read_token),
            params={"entity_key": "cloud:aws_s3:acme-assets"},
        )

    assert denied_read.status_code == 403
    assert denied_read.json()["detail"] == "Missing required permission: assets:read"
    assert rebuild.status_code == 200, rebuild.text
    assert rebuild.json()["status"] == "rebuilt"
    assert rebuild.json()["node_count"] >= 2
    assert graph.status_code == 200, graph.text
    assert graph.json()["schema_version"] == "forge.asset_graph.list.v1"
    assert graph.json()["execution_policy"] == "read_only_asset_graph_inventory_no_commands_executed"
    assert graph.json()["selected_count"] == len(graph.json()["nodes"])
    assert graph.json()["omitted_count"] == max(
        0,
        graph.json()["total_count"] - len(graph.json()["nodes"]),
    )
    assert graph.json()["attack_path_summary"]["scoring_model"] == "forge.asset_graph.v1"
    assert "critical_assets" in graph.json()
    assert "minimal_fix_set_candidates" in graph.json()
    nodes = {node["entity_key"]: node for node in graph.json()["nodes"]}
    identity_key = (
        "identity:cloud_principal:aws:role:"
        "arn:aws:iam::123456789012:role/api-admin"
    )
    assert "cloud:aws_s3:acme-assets" in nodes
    assert identity_key in nodes
    assert "apiKey" not in nodes["cloud:aws_s3:acme-assets"]["metadata"]
    permission_summary = nodes[identity_key]["metadata"]["identity_context"]["permission_summary"]
    assert permission_summary["actions"] == ["s3:*", "kms:Decrypt"]
    assert permission_summary["wildcard_action"] is True
    assert permission_summary["wildcard_resource"] is True
    assert "do-not-store-identity" not in str(graph.json())
    assert denied_claim.status_code == 403
    assert denied_claim.json()["detail"] == "Missing required permission: assets:write"
    assert denied_attribution.status_code == 403
    assert denied_attribution.json()["detail"] == "Missing required permission: assets:write"
    assert denied_resolve.status_code == 403
    assert denied_resolve.json()["detail"] == "Missing required permission: assets:write"
    assert claim.status_code == 200, claim.text
    assert claim.json()["status"] == "upserted"
    assert claim.json()["asset_graph"]["ownership_claims"][0]["owner_ref"] == "cloud-team"
    assert conflicting_claim.status_code == 200, conflicting_claim.text
    assert conflicting_claim.json()["asset_graph"]["ownership_conflicts"][0]["owner_count"] == 2
    assert resolved_conflict.status_code == 200, resolved_conflict.text
    assert resolved_conflict.json()["status"] == "resolved"
    assert resolved_conflict.json()["owner"]["owner_ref"] == "cloud-team"
    assert resolved_conflict.json()["owner"]["conflict"] is False
    assert resolved_conflict.json()["conflicts"] == []
    resolved_statuses = {
        item["owner_ref"]: item["status"] for item in resolved_conflict.json()["claims"]
    }
    assert resolved_statuses == {"cloud-team": "active", "legacy-cloud": "superseded"}
    assert resolved_conflict.json()["asset_graph"]["ownership_conflicts"] == []
    assert attribution.status_code == 200, attribution.text
    assert attribution.json()["status"] == "imported"
    assert attribution.json()["imported_count"] == 2
    assert attribution.json()["ownership_claim_count"] == 2
    attribution_nodes = {node["entity_key"] for node in attribution.json()["asset_graph"]["nodes"]}
    attribution_owners = {
        claim["owner_ref"] for claim in attribution.json()["asset_graph"]["ownership_claims"]
    }
    assert "organization:cloud_account:aws:999999999999" in attribution_nodes
    assert "organization:third_party:cdn-vendor" in attribution_nodes
    assert {"aws:999999999999", "cdn-vendor"} <= attribution_owners
    assert filtered.status_code == 200, filtered.text
    assert "cloud-team" in {claim["owner_ref"] for claim in filtered.json()["ownership_claims"]}
    assert filtered.json()["ownership_conflicts"][0]["entity_key"] == "cloud:aws_s3:acme-assets"
    assert "do-not-store" not in str(filtered.json())
    assert "do-not-store-conflict" not in str(filtered.json())
    assert "do-not-store" not in str(attribution.json())
