"""Integration test — AzureHound JSON parser.

Contract (per task U1.3):

* Parse an AzureHound JSON fixture with 1,000+ objects.
* Complete in under 15 seconds.
* Azure-specific fields (tenant_id, object_id, app_id) preserved.
* All Azure AD object types in the sample are handled.
* ServicePrincipal objects include app_id and object_id.
* Role assignments link principals to roles correctly.
* Tenant IDs are not hardcoded — every value flows from the fixture.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import pytest

from forge.ingestion.parsers.azurehound_parser import (
    AzureEntityType,
    GraphEntity,
    parse_azurehound_json,
)


# ---------------------------------------------------------------------------
# Fixture builder — 1,000+ record synthetic AzureHound export
# ---------------------------------------------------------------------------


_TENANT_A = str(uuid.uuid4())
_TENANT_B = str(uuid.uuid4())


def _guid() -> str:
    return str(uuid.uuid4())


def _build_azurehound_payload() -> dict:
    """Build a realistic AzureHound v2 export with 1,000+ heterogeneous records.

    Distribution (mirrors real Entra tenant proportions):

    * 400 AZUser
    * 150 AZGroup
    * 150 AZServicePrincipal (each with a distinct app_id)
    *  80 AZApp
    *  50 AZRole (role definitions)
    * 200 AZRoleAssignment (links user/sp → role → scope)
    *  30 AZSubscription / ResourceGroup / KeyVault / VM (mixed)
    * Two tenants exercised so multi-tenant handling is verified.
    """
    data: list[dict] = []

    # Pre-generate role definition ids so role assignments can point at real roles
    role_ids: list[str] = [_guid() for _ in range(50)]
    for role_id in role_ids:
        data.append(
            {
                "kind": "AZRole",
                "data": {
                    "id": role_id,
                    "displayName": f"CustomRole-{role_id[:8]}",
                    "tenantId": _TENANT_A,
                    "description": "Synthetic role for parser test",
                },
            }
        )

    # 400 users
    user_ids: list[str] = []
    for i in range(400):
        oid = _guid()
        user_ids.append(oid)
        tenant = _TENANT_A if i % 3 else _TENANT_B
        data.append(
            {
                "kind": "AZUser",
                "data": {
                    "id": oid,
                    "displayName": f"user{i:04d}",
                    "userPrincipalName": f"user{i:04d}@example.onmicrosoft.com",
                    "tenantId": tenant,
                    "accountEnabled": True,
                },
            }
        )

    # 150 groups
    for i in range(150):
        data.append(
            {
                "kind": "AZGroup",
                "data": {
                    "id": _guid(),
                    "displayName": f"group-{i:03d}",
                    "tenantId": _TENANT_A,
                    "securityEnabled": True,
                },
            }
        )

    # 150 service principals — MUST have app_id
    sp_ids: list[str] = []
    for i in range(150):
        oid = _guid()
        sp_ids.append(oid)
        data.append(
            {
                "kind": "AZServicePrincipal",
                "data": {
                    "id": oid,
                    "appId": _guid(),
                    "displayName": f"sp-{i:03d}",
                    "tenantId": _TENANT_A,
                    "servicePrincipalType": "Application",
                },
            }
        )

    # 80 applications
    for i in range(80):
        data.append(
            {
                "kind": "AZApp",
                "data": {
                    "id": _guid(),
                    "appId": _guid(),
                    "displayName": f"app-{i:03d}",
                    "tenantId": _TENANT_A,
                },
            }
        )

    # 30 mixed resource-scope entities
    for i in range(30):
        kind = ("AZSubscription", "AZResourceGroup", "AZKeyVault", "AZVM")[i % 4]
        data.append(
            {
                "kind": kind,
                "data": {
                    "id": _guid(),
                    "displayName": f"{kind.lower()}-{i:02d}",
                    "tenantId": _TENANT_A,
                },
            }
        )

    # 200 role assignments — link real user/sp ids to real role ids
    principals = user_ids[:100] + sp_ids[:100]
    for i in range(200):
        principal_id = principals[i % len(principals)]
        role_id = role_ids[i % len(role_ids)]
        scope = (
            f"/subscriptions/{_guid()}/resourceGroups/rg-{i:03d}"
            if i % 2
            else f"/subscriptions/{_guid()}"
        )
        data.append(
            {
                "kind": "AZRoleAssignment",
                "data": {
                    "id": _guid(),
                    "principalId": principal_id,
                    "roleDefinitionId": role_id,
                    "scope": scope,
                    "principalType": "User" if i < 100 else "ServicePrincipal",
                    "tenantId": _TENANT_A,
                },
            }
        )

    return {
        "meta": {"type": "azurehound", "count": len(data), "version": "2.0.0-test"},
        "data": data,
    }


@pytest.fixture(scope="module")
def azurehound_fixture_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Write the synthetic AzureHound JSON to a temp file once per module."""
    payload = _build_azurehound_payload()
    path = tmp_path_factory.mktemp("azurehound") / "azurehound_sample.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    # Sanity: fixture must exceed 1,000 records so the test is meaningful.
    assert len(payload["data"]) >= 1000, "fixture must have 1,000+ records"
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_parse_azurehound_json_completes_under_budget(
    azurehound_fixture_path: Path,
) -> None:
    """Given a 1,000+ record AzureHound export,
    When parse_azurehound_json runs,
    Then it completes in under 15 seconds and returns one entity per record."""
    started = time.perf_counter()
    entities = parse_azurehound_json(azurehound_fixture_path)
    elapsed = time.perf_counter() - started

    assert elapsed < 15.0, f"parser took {elapsed:.2f}s (budget 15s)"
    assert len(entities) >= 1000
    assert all(isinstance(e, GraphEntity) for e in entities)


def test_all_azure_object_types_are_recognized(
    azurehound_fixture_path: Path,
) -> None:
    """Given every AzureHound kind emitted by the fixture,
    When parsed,
    Then none maps to AzureEntityType.UNKNOWN."""
    entities = parse_azurehound_json(azurehound_fixture_path)

    unknown = [e for e in entities if e.entity_type is AzureEntityType.UNKNOWN]
    assert not unknown, (
        f"parser failed to classify {len(unknown)} records; "
        f"first raw_kind={unknown[0].metadata.get('raw_kind')!r}"
    )

    kinds = {e.entity_type for e in entities}
    expected = {
        AzureEntityType.USER,
        AzureEntityType.GROUP,
        AzureEntityType.SERVICE_PRINCIPAL,
        AzureEntityType.APPLICATION,
        AzureEntityType.ROLE,
        AzureEntityType.ROLE_ASSIGNMENT,
    }
    missing = expected - kinds
    assert not missing, f"missing entity types: {missing}"


def test_service_principals_expose_app_id_and_object_id(
    azurehound_fixture_path: Path,
) -> None:
    """Given a ServicePrincipal record,
    When parsed,
    Then both app_id and object_id are populated (non-empty, lowercased)."""
    entities = parse_azurehound_json(azurehound_fixture_path)
    sps = [e for e in entities if e.entity_type is AzureEntityType.SERVICE_PRINCIPAL]

    assert sps, "fixture must contain ServicePrincipal records"
    for sp in sps:
        assert sp.app_id, f"SP {sp.entity_id} missing app_id"
        assert sp.object_id, f"SP {sp.entity_id} missing object_id"
        assert sp.app_id == sp.app_id.lower()
        assert sp.object_id == sp.object_id.lower()
        # app_id and object_id must be distinct GUIDs
        assert sp.app_id != sp.object_id


def test_tenant_id_preserved_and_multi_tenant_distinct(
    azurehound_fixture_path: Path,
) -> None:
    """Given records from two distinct tenants,
    When parsed,
    Then tenant_id is preserved and entity_ids do not collide across tenants."""
    entities = parse_azurehound_json(azurehound_fixture_path)

    tenants = {e.tenant_id for e in entities if e.tenant_id is not None}
    assert len(tenants) >= 2, f"expected multi-tenant fixture, got {tenants}"

    users = [e for e in entities if e.entity_type is AzureEntityType.USER]
    assert users
    # entity_id must be tenant-qualified so two tenants can't collide by object_id alone
    assert all(":" in u.entity_id for u in users)
    assert all(u.entity_id.startswith(u.tenant_id + ":") for u in users if u.tenant_id)


def test_role_assignments_link_principal_to_role(
    azurehound_fixture_path: Path,
) -> None:
    """Given AZRoleAssignment records,
    When parsed,
    Then each assignment emits HAS_ROLE and SCOPED_TO relationships
    that reference real principal, role, and scope ids."""
    entities = parse_azurehound_json(azurehound_fixture_path)
    assignments = [
        e for e in entities if e.entity_type is AzureEntityType.ROLE_ASSIGNMENT
    ]
    assert assignments, "fixture must contain role assignments"

    principal_ids = {
        e.object_id
        for e in entities
        if e.entity_type
        in (AzureEntityType.USER, AzureEntityType.SERVICE_PRINCIPAL)
    }
    role_ids = {e.object_id for e in entities if e.entity_type is AzureEntityType.ROLE}

    for assignment in assignments:
        rels_by_type = {r.relationship_type for r in assignment.relationships}
        assert "HAS_ROLE" in rels_by_type, f"{assignment.entity_id} missing HAS_ROLE"
        assert "SCOPED_TO" in rels_by_type, f"{assignment.entity_id} missing SCOPED_TO"

        has_role = next(
            r for r in assignment.relationships if r.relationship_type == "HAS_ROLE"
        )
        # Principal must be one we actually parsed
        assert has_role.source_id in principal_ids, (
            f"HAS_ROLE source {has_role.source_id} not in known principals"
        )
        assert has_role.target_id in role_ids, (
            f"HAS_ROLE target {has_role.target_id} not in known roles"
        )

        scoped = next(
            r for r in assignment.relationships if r.relationship_type == "SCOPED_TO"
        )
        assert scoped.source_id == assignment.object_id
        assert scoped.target_id.startswith("/subscriptions/")


def test_properties_are_lossless(azurehound_fixture_path: Path) -> None:
    """Given raw AzureHound records,
    When parsed,
    Then every non-lifted field is preserved verbatim under `properties`."""
    entities = parse_azurehound_json(azurehound_fixture_path)
    users = [e for e in entities if e.entity_type is AzureEntityType.USER]
    assert users

    sample = users[0]
    # `userPrincipalName` is not lifted to a first-class field, so it must
    # survive into `properties` verbatim.
    assert "userPrincipalName" in sample.properties
    assert sample.properties["userPrincipalName"].startswith("user")
    assert sample.properties.get("accountEnabled") is True


def test_missing_file_raises(tmp_path: Path) -> None:
    """Given a non-existent path, When parsed, Then FileNotFoundError is raised."""
    with pytest.raises(FileNotFoundError):
        parse_azurehound_json(tmp_path / "nope.json")


def test_invalid_json_raises(tmp_path: Path) -> None:
    """Given a non-JSON file, When parsed, Then ValueError is raised."""
    path = tmp_path / "bad.json"
    path.write_text("not valid json {", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_azurehound_json(path)


def test_bare_list_shape_accepted(tmp_path: Path) -> None:
    """Given a bare-list AzureHound payload (no `meta`/`data` wrapper),
    When parsed,
    Then records are still recognized."""
    payload = [
        {
            "kind": "AZUser",
            "data": {"id": _guid(), "displayName": "bare-user", "tenantId": _TENANT_A},
        }
    ]
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    entities = parse_azurehound_json(path)
    assert len(entities) == 1
    assert entities[0].entity_type is AzureEntityType.USER
    assert entities[0].label == "bare-user"
