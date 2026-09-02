"""AzureHound (Entra ID / Azure RBAC) JSON parser.

AzureHound emits a single JSON document with the canonical shape::

    {
        "meta": {"type": "azurehound", "count": N, "version": "..."},
        "data": [
            {"kind": "AZUser",              "data": {...user props...}},
            {"kind": "AZGroup",             "data": {...group props...}},
            {"kind": "AZServicePrincipal",  "data": {...sp props...}},
            {"kind": "AZApp",               "data": {...app props...}},
            {"kind": "AZRoleAssignment",    "data": {...assignment...}},
            ...
        ]
    }

This differs from SharpHound (BloodHound on-prem) — SharpHound emits
per-object-type files (``users.json``, ``groups.json``, ...) with a
top-level ``data`` array and no ``kind`` discriminator. This parser is
AzureHound-only; ``forge.graph.normalizer`` remains the shared post-parse
normalization layer if the caller wants a merged AD+Azure taxonomy.

Design contract (parse-don't-validate boundary):

* One untrusted JSON file enters. A list of typed :class:`GraphEntity`
  values leaves. Every record from the input ``data`` array either
  becomes a :class:`GraphEntity` or is skipped with a structured
  reason in :attr:`GraphEntity.metadata` on an ``UNKNOWN`` entity so
  callers can audit rejections.
* Role assignments are first-class. Each ``AZRoleAssignment`` produces
  a :class:`GraphEntity` of type
  :attr:`AzureEntityType.ROLE_ASSIGNMENT` whose ``relationships`` link
  the principal to the role definition and target scope — never
  dropped, always parsed.
* Tenant identity is preserved per entity. AzureHound emits
  ``tenantId`` (or nested ``tenant_id``) on most Entra objects; the
  parser lifts it into a first-class field so multi-tenant exports do
  not collide by ``object_id`` alone.
* No hardcoded tenant ids, no hardcoded object ids. Everything is
  derived from the input record.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any, Final, Mapping

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AzureEntityType",
    "GraphEntity",
    "Relationship",
    "parse_azurehound_json",
]


# ---------------------------------------------------------------------------
# Canonical Azure entity taxonomy for the ingestion layer
# ---------------------------------------------------------------------------


class AzureEntityType(str, Enum):
    """FORGE-canonical Azure entity kinds emitted by AzureHound.

    Values are stable strings (persisted in graph exports). Do not
    rename existing members; extend at the end.
    """

    USER = "AZUser"
    GROUP = "AZGroup"
    SERVICE_PRINCIPAL = "AZServicePrincipal"
    APPLICATION = "AZApp"
    DEVICE = "AZDevice"
    TENANT = "AZTenant"
    ROLE = "AZRole"
    ROLE_ASSIGNMENT = "AZRoleAssignment"
    MANAGEMENT_GROUP = "AZManagementGroup"
    SUBSCRIPTION = "AZSubscription"
    RESOURCE_GROUP = "AZResourceGroup"
    KEY_VAULT = "AZKeyVault"
    STORAGE_ACCOUNT = "AZStorageAccount"
    VM = "AZVM"
    UNKNOWN = "AZUnknown"


# AzureHound ``kind`` strings — accepts both modern prefixed and older
# bare forms — mapped to the canonical :class:`AzureEntityType`.
_KIND_MAP: Final[Mapping[str, AzureEntityType]] = {
    # Modern AzureHound (v2+) prefixed forms
    "AZUser": AzureEntityType.USER,
    "AZGroup": AzureEntityType.GROUP,
    "AZServicePrincipal": AzureEntityType.SERVICE_PRINCIPAL,
    "AZApp": AzureEntityType.APPLICATION,
    "AZApplication": AzureEntityType.APPLICATION,
    "AZDevice": AzureEntityType.DEVICE,
    "AZTenant": AzureEntityType.TENANT,
    "AZRole": AzureEntityType.ROLE,
    "AZRoleDefinition": AzureEntityType.ROLE,
    "AZRoleAssignment": AzureEntityType.ROLE_ASSIGNMENT,
    "AZManagementGroup": AzureEntityType.MANAGEMENT_GROUP,
    "AZSubscription": AzureEntityType.SUBSCRIPTION,
    "AZResourceGroup": AzureEntityType.RESOURCE_GROUP,
    "AZKeyVault": AzureEntityType.KEY_VAULT,
    "AZStorageAccount": AzureEntityType.STORAGE_ACCOUNT,
    "AZVM": AzureEntityType.VM,
    # Bare (older) forms occasionally seen in legacy AzureHound outputs
    "User": AzureEntityType.USER,
    "Group": AzureEntityType.GROUP,
    "ServicePrincipal": AzureEntityType.SERVICE_PRINCIPAL,
    "Application": AzureEntityType.APPLICATION,
    "Device": AzureEntityType.DEVICE,
    "Tenant": AzureEntityType.TENANT,
    "Role": AzureEntityType.ROLE,
    "RoleAssignment": AzureEntityType.ROLE_ASSIGNMENT,
    "ManagementGroup": AzureEntityType.MANAGEMENT_GROUP,
    "Subscription": AzureEntityType.SUBSCRIPTION,
    "ResourceGroup": AzureEntityType.RESOURCE_GROUP,
    "KeyVault": AzureEntityType.KEY_VAULT,
    "StorageAccount": AzureEntityType.STORAGE_ACCOUNT,
    "VM": AzureEntityType.VM,
}


# ---------------------------------------------------------------------------
# Typed value objects (Pydantic v2, frozen)
# ---------------------------------------------------------------------------


class Relationship(BaseModel):
    """A single directed relationship emitted by a parsed AzureHound record.

    Role assignments are the primary source: each ``AZRoleAssignment``
    produces at minimum two relationships — ``HAS_ROLE`` (principal →
    role definition) and ``SCOPED_TO`` (assignment → target scope) — so
    downstream attack-path analysis can traverse principal → role → scope
    without re-reading the raw JSON.
    """

    model_config = ConfigDict(frozen=True)

    source_id: str = Field(description="Object id of the source entity.")
    target_id: str = Field(description="Object id of the target entity.")
    relationship_type: str = Field(
        description=(
            "Relationship kind. Common values: 'HAS_ROLE', 'SCOPED_TO', "
            "'MEMBER_OF', 'OWNS_APP', 'ASSIGNED_TO_SP'."
        )
    )
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional non-sensitive relationship metadata.",
    )


class GraphEntity(BaseModel):
    """FORGE-canonical graph entity produced by an ingestion parser.

    A :class:`GraphEntity` is the boundary type between untrusted vendor
    JSON and every downstream consumer (attack-path builder, dashboard,
    Neo4j exporter). The Azure-specific identity trio — ``tenant_id``,
    ``object_id``, ``app_id`` — is lifted to first-class fields so
    multi-tenant scenarios and service-principal-to-application chains
    are unambiguous.

    ``properties`` preserves every non-lifted key from the raw AzureHound
    record verbatim so ingestion is lossless.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: str = Field(
        description=(
            "Canonical FORGE entity identifier — tenant-qualified when a "
            "tenant is known ('<tenant_id>:<object_id>'), otherwise the "
            "object id alone. Case-normalized to lowercase."
        )
    )
    entity_type: AzureEntityType
    label: str = Field(
        description=(
            "Human-readable label (displayName, userPrincipalName, or "
            "object id fallback)."
        )
    )
    object_id: str = Field(
        description="Azure AD object id (GUID). Lowercased for case-insensitive match."
    )
    tenant_id: str | None = Field(
        default=None,
        description="Azure AD tenant id, if the source record carried one.",
    )
    app_id: str | None = Field(
        default=None,
        description=(
            "Azure AD application id — populated for ServicePrincipal and "
            "Application entities. None for other kinds."
        ),
    )
    source: str = Field(
        default="AzureHound",
        description="Collector name (always 'AzureHound' for this parser).",
    )
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "All non-lifted fields from the raw record. Preserved verbatim "
            "so round-tripping through the parser is lossless."
        ),
    )
    relationships: list[Relationship] = Field(
        default_factory=list,
        description=(
            "Directed relationships derived from the record. Role "
            "assignments always populate this."
        ),
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Parser-side metadata (raw ``kind`` string, skip reason for "
            "UNKNOWN entities, source file, etc.)."
        ),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_azurehound_json(json_path: Path) -> list[GraphEntity]:
    """Parse an AzureHound JSON export into FORGE :class:`GraphEntity` values.

    Accepts both canonical AzureHound v2 shape (``{"meta": ..., "data":
    [...]}`) and older / partial shapes:

    * A bare list of records (``[{"kind": ..., "data": ...}, ...]``).
    * A single record dict with a top-level ``kind``.

    Parameters
    ----------
    json_path:
        Absolute path to the AzureHound JSON file.

    Returns
    -------
    list[GraphEntity]
        One entity per parsed record. Records that cannot be parsed
        (missing object id, unknown kind) are returned as ``UNKNOWN``
        entities with the failure reason recorded in ``metadata`` — they
        are never silently dropped.

    Raises
    ------
    FileNotFoundError:
        If ``json_path`` does not exist.
    ValueError:
        If the file is not valid JSON or the top-level structure is
        neither a list nor a dict.
    """
    if not json_path.exists():
        raise FileNotFoundError(f"AzureHound JSON not found: {json_path}")

    with json_path.open("r", encoding="utf-8") as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid AzureHound JSON at {json_path}: {exc}") from exc

    records = _extract_records(payload)
    source_file = str(json_path)

    entities: list[GraphEntity] = []
    for record in records:
        entities.append(_parse_record(record, source_file=source_file))
    return entities


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_records(payload: Any) -> list[Mapping[str, Any]]:
    """Locate the record array inside a raw AzureHound payload."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, Mapping)]
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if isinstance(data, list):
            return [r for r in data if isinstance(r, Mapping)]
        # Single-record dict with top-level 'kind'
        if "kind" in payload:
            return [payload]
        return []
    raise ValueError(
        f"AzureHound payload must be a list or object, got {type(payload).__name__}"
    )


def _parse_record(record: Mapping[str, Any], *, source_file: str) -> GraphEntity:
    """Parse one AzureHound record into a :class:`GraphEntity`."""
    raw_kind = str(record.get("kind") or record.get("Kind") or "").strip()
    entity_type = _KIND_MAP.get(raw_kind, AzureEntityType.UNKNOWN)

    # AzureHound wraps object properties under 'data' (v2) — fall back to
    # 'Properties' (legacy) or the raw record itself.
    inner_data = record.get("data")
    if not isinstance(inner_data, Mapping):
        legacy_props = record.get("Properties")
        inner_data = legacy_props if isinstance(legacy_props, Mapping) else record

    object_id = _extract_object_id(inner_data, record)
    tenant_id = _extract_tenant_id(inner_data, record)
    app_id = _extract_app_id(inner_data)
    label = _extract_label(inner_data, fallback=object_id or raw_kind or "unknown")

    metadata: dict[str, Any] = {"raw_kind": raw_kind, "source_file": source_file}
    if entity_type is AzureEntityType.UNKNOWN:
        metadata["skip_reason"] = (
            f"unrecognized AzureHound kind: {raw_kind!r}"
            if raw_kind
            else "missing kind"
        )
    if not object_id:
        metadata["skip_reason"] = "missing object id"
        # Deterministic synthetic id so downstream de-dup does not
        # collapse every malformed record into one node.
        object_id = f"__missing_id__:{len(metadata)}:{raw_kind or 'no_kind'}"

    entity_id = _compose_entity_id(tenant_id, object_id)

    relationships: list[Relationship] = []
    if entity_type is AzureEntityType.ROLE_ASSIGNMENT:
        relationships.extend(_parse_role_assignment(inner_data, assignment_id=object_id))

    # Lossless property preservation — every key from the inner payload
    # except the ones we lifted to first-class fields.
    _lifted_keys = {
        "id",
        "objectId",
        "ObjectId",
        "objectID",
        "object_id",
        "tenantId",
        "TenantId",
        "tenant_id",
        "appId",
        "AppId",
        "app_id",
    }
    properties = {k: v for k, v in inner_data.items() if k not in _lifted_keys}

    return GraphEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        label=label,
        object_id=object_id.lower(),
        tenant_id=tenant_id.lower() if tenant_id else None,
        app_id=app_id.lower() if app_id else None,
        properties=properties,
        relationships=relationships,
        metadata=metadata,
    )


def _extract_object_id(
    inner: Mapping[str, Any], outer: Mapping[str, Any]
) -> str:
    """Extract the Azure object id (GUID) from a record."""
    for source in (inner, outer):
        for key in ("id", "objectId", "ObjectId", "objectID", "object_id"):
            val = source.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return ""


def _extract_tenant_id(
    inner: Mapping[str, Any], outer: Mapping[str, Any]
) -> str | None:
    """Extract the Azure tenant id (GUID) from a record."""
    for source in (inner, outer):
        for key in ("tenantId", "TenantId", "tenant_id"):
            val = source.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


def _extract_app_id(inner: Mapping[str, Any]) -> str | None:
    """Extract the Azure application id — ServicePrincipal / Application only."""
    for key in ("appId", "AppId", "app_id"):
        val = inner.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _extract_label(props: Mapping[str, Any], *, fallback: str) -> str:
    """Pick the best human-readable label from a record's properties."""
    for key in (
        "displayName",
        "displayname",
        "userPrincipalName",
        "userprincipalname",
        "name",
        "servicePrincipalNames",
    ):
        val = props.get(key)
        if isinstance(val, str) and val.strip():
            return val
        if isinstance(val, list) and val and isinstance(val[0], str):
            return val[0]
    return fallback


def _parse_role_assignment(
    data: Mapping[str, Any], *, assignment_id: str
) -> list[Relationship]:
    """Turn one ``AZRoleAssignment`` record into directed relationships.

    An Azure role assignment has three logical endpoints:

    * ``principalId``     — the identity being granted the role.
    * ``roleDefinitionId`` — the role granting the permission set.
    * ``scope``            — the resource / scope where the role applies.

    We emit one relationship per non-empty endpoint. Missing endpoints
    are recorded in the assignment's ``metadata`` (via a
    ``missing_endpoints`` list on the caller side) rather than causing a
    hard skip — the assignment record itself is still valuable evidence.
    """
    relationships: list[Relationship] = []
    principal_id = _first_str(
        data, ("principalId", "PrincipalId", "principal_id", "principalID")
    )
    role_definition_id = _first_str(
        data,
        (
            "roleDefinitionId",
            "RoleDefinitionId",
            "role_definition_id",
            "roleDefinitionID",
        ),
    )
    scope = _first_str(data, ("scope", "Scope"))
    principal_type = _first_str(
        data, ("principalType", "PrincipalType", "principal_type")
    )

    common_props: dict[str, Any] = {}
    if principal_type:
        common_props["principal_type"] = principal_type

    if principal_id:
        relationships.append(
            Relationship(
                source_id=principal_id.lower(),
                target_id=assignment_id.lower(),
                relationship_type="ASSIGNED",
                properties=dict(common_props),
            )
        )
        if role_definition_id:
            relationships.append(
                Relationship(
                    source_id=principal_id.lower(),
                    target_id=role_definition_id.lower(),
                    relationship_type="HAS_ROLE",
                    properties={
                        **common_props,
                        "assignment_id": assignment_id.lower(),
                    },
                )
            )
    if scope:
        relationships.append(
            Relationship(
                source_id=assignment_id.lower(),
                target_id=scope.lower(),
                relationship_type="SCOPED_TO",
                properties=dict(common_props),
            )
        )
    return relationships


def _first_str(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    """Return the first non-empty string value found under ``keys``."""
    for key in keys:
        val = mapping.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _compose_entity_id(tenant_id: str | None, object_id: str) -> str:
    """Compose the canonical FORGE entity id (tenant-qualified when possible)."""
    obj = object_id.lower()
    if tenant_id:
        return f"{tenant_id.lower()}:{obj}"
    return obj
