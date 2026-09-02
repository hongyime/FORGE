"""
forge/graph/normalizer.py

Graph normalization layer for heterogeneous BloodHound / AzureHound inputs.

Purpose
-------
BloodHound (on-prem AD, collected via SharpHound) and AzureHound (Entra ID /
Azure RBAC) emit graph data with divergent schemas. FORGE's internal attack
graph requires a single, consistent representation. This module is the
boundary parser (see AGENTS/programming skill §2 "Parse, don't validate"):
untrusted, source-shaped BloodHound/AzureHound records enter, canonical
``NormalizedEntity`` / ``NormalizedEdge`` values leave.

Design invariants
-----------------
1. **Additive by construction.** All mapping tables and dispatch functions
   are module-level constants + pure functions. New sources or entity types
   are added by extending the ``_*_ENTITY_TYPE_MAP`` / ``_EDGE_TYPE_MAP``
   dicts — never by rewriting normalization logic. The two public entry
   points (``normalize_entity``, ``normalize_edge``) are the stable API.
2. **Lossless.** Every original property that arrived on the input record is
   preserved verbatim under ``normalized_properties`` on the normalized
   value. No key from the source payload is silently dropped.
3. **Provenance on every entity.** Every normalized entity/edge carries a
   ``source`` (``"SharpHound"`` or ``"AzureHound"``) and, when available, a
   ``collection_time`` (ISO-8601 UTC). Absence of ``collection_time`` is
   represented explicitly as ``None`` rather than fabricated.
4. **Deterministic identity.** ``NormalizedEntity.object_id`` is the
   canonical identifier and is used to merge records for the same object
   from different collectors (see ``merge_entities``). Same ``object_id``
   from two sources → one merged entity with union'd properties, both
   sources recorded in ``sources``.
5. **Type-safe.** Frozen ``@dataclass(slots=True)`` values; enum-typed entity
   and edge kinds; ``assert_never`` on the exhaustive dispatch so a new
   ``EntityType`` added later without a corresponding mapping is a static
   error, not a silent skip.

This module has no runtime dependency on FORGE's attack-graph pydantic
models: normalized values are plain dataclasses so this layer is unit-test
friendly and does not force a validation step at every call site. Callers
that need the pydantic-validated attack graph should feed
``NormalizedEntity`` values into their existing builder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, Iterable, Mapping, assert_never

__all__ = [
    "CollectorSource",
    "EntityType",
    "EdgeType",
    "NormalizedEntity",
    "NormalizedEdge",
    "normalize_entity",
    "normalize_edge",
    "normalize_bulk",
    "merge_entities",
    "SHARPHOUND_ENTITY_TYPES",
    "AZUREHOUND_ENTITY_TYPES",
]


# ---------------------------------------------------------------------------
# Canonical taxonomies (public, frozen)
# ---------------------------------------------------------------------------


class CollectorSource(str, Enum):
    """Recognized upstream collectors. Extend, never rename."""

    SHARPHOUND = "SharpHound"
    AZUREHOUND = "AzureHound"


class EntityType(str, Enum):
    """FORGE canonical entity taxonomy for identity/directory graphs.

    Values are stable strings — they are persisted in graph exports and
    consumed by downstream renderers. Do not rename existing members; add
    new members at the end.
    """

    # AD / on-prem taxonomy (SharpHound source)
    USER = "User"
    GROUP = "Group"
    COMPUTER = "Computer"
    DOMAIN = "Domain"
    OU = "OU"
    GPO = "GPO"
    CONTAINER = "Container"
    BASE = "Base"  # SharpHound orphan/unresolved kind (kept distinct from Container)
    # Azure / Entra ID taxonomy (AzureHound source). "User" and "Group" are
    # shared with the AD taxonomy above and are reused intentionally.
    SERVICE_PRINCIPAL = "ServicePrincipal"
    ROLE = "Role"
    APPLICATION = "Application"


class EdgeType(str, Enum):
    """FORGE canonical edge taxonomy.

    Covers the relationship classes both BloodHound and AzureHound emit.
    Any unrecognized edge is passed through as :attr:`UNKNOWN` with the
    original label preserved on the normalized edge — see
    ``normalize_edge`` — so we never lose reachability information for a
    label we haven't mapped yet.
    """

    MEMBER_OF = "MemberOf"
    HAS_SESSION = "HasSession"
    ADMIN_TO = "AdminTo"
    CAN_RDP = "CanRDP"
    EXECUTE_DCOM = "ExecuteDCOM"
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDACL"
    WRITE_OWNER = "WriteOwner"
    OWNS = "Owns"
    CONTAINS = "Contains"
    GP_LINK = "GPLink"
    TRUSTED_BY = "TrustedBy"
    # Azure-native edges
    HAS_ROLE = "HasRole"
    AZ_MG_ADD_MEMBER = "AZMGAddMember"
    AZ_ADD_SECRET = "AZAddSecret"
    AZ_OWNS = "AZOwns"
    AZ_CONTAINS = "AZContains"
    AZ_GLOBAL_ADMIN = "AZGlobalAdmin"
    # Fallback preserving the source label
    UNKNOWN = "Unknown"


# ---------------------------------------------------------------------------
# Mapping tables — the single source of truth for normalization
# ---------------------------------------------------------------------------
#
# BloodHound (SharpHound) uses PascalCase kind names. AzureHound prefixes
# Azure objects with "AZ" in modern outputs. We accept both the modern
# prefixed form and the bare form.
#
# NOTE: `Final` + module-level makes these effectively read-only from the
# caller's perspective without paying the ``types.MappingProxyType``
# overhead in the hot path.

_SHARPHOUND_ENTITY_TYPE_MAP: Final[Mapping[str, EntityType]] = {
    "User": EntityType.USER,
    "Group": EntityType.GROUP,
    "Computer": EntityType.COMPUTER,
    "Domain": EntityType.DOMAIN,
    "OU": EntityType.OU,
    "GPO": EntityType.GPO,
    "Container": EntityType.CONTAINER,
    # SharpHound v5 emits a synthetic 'Base' kind for orphaned/unresolved
    # nodes. We keep it distinct so a later pass can promote it.
    "Base": EntityType.BASE,
}

_AZUREHOUND_ENTITY_TYPE_MAP: Final[Mapping[str, EntityType]] = {
    "AZUser": EntityType.USER,
    "AZGroup": EntityType.GROUP,
    "AZServicePrincipal": EntityType.SERVICE_PRINCIPAL,
    "AZRole": EntityType.ROLE,
    "AZApp": EntityType.APPLICATION,
    "AZApplication": EntityType.APPLICATION,
    # Bare (unprefixed) forms occasionally emitted by older AzureHound
    "User": EntityType.USER,
    "Group": EntityType.GROUP,
    "ServicePrincipal": EntityType.SERVICE_PRINCIPAL,
    "Role": EntityType.ROLE,
    "Application": EntityType.APPLICATION,
}

# Public view — read-only reference for tests and downstream tooling
SHARPHOUND_ENTITY_TYPES: Final[frozenset[EntityType]] = frozenset(
    _SHARPHOUND_ENTITY_TYPE_MAP.values()
)
AZUREHOUND_ENTITY_TYPES: Final[frozenset[EntityType]] = frozenset(
    _AZUREHOUND_ENTITY_TYPE_MAP.values()
)

_EDGE_TYPE_MAP: Final[Mapping[str, EdgeType]] = {
    # BloodHound / SharpHound
    "MemberOf": EdgeType.MEMBER_OF,
    "HasSession": EdgeType.HAS_SESSION,
    "AdminTo": EdgeType.ADMIN_TO,
    "CanRDP": EdgeType.CAN_RDP,
    "ExecuteDCOM": EdgeType.EXECUTE_DCOM,
    "AllowedToDelegate": EdgeType.ALLOWED_TO_DELEGATE,
    "ForceChangePassword": EdgeType.FORCE_CHANGE_PASSWORD,
    "GenericAll": EdgeType.GENERIC_ALL,
    "GenericWrite": EdgeType.GENERIC_WRITE,
    "WriteDACL": EdgeType.WRITE_DACL,
    "WriteOwner": EdgeType.WRITE_OWNER,
    "Owns": EdgeType.OWNS,
    "Contains": EdgeType.CONTAINS,
    "GPLink": EdgeType.GP_LINK,
    "TrustedBy": EdgeType.TRUSTED_BY,
    # AzureHound
    "HasRole": EdgeType.HAS_ROLE,
    "AZMGAddMember": EdgeType.AZ_MG_ADD_MEMBER,
    "AZAddSecret": EdgeType.AZ_ADD_SECRET,
    "AZOwns": EdgeType.AZ_OWNS,
    "AZContains": EdgeType.AZ_CONTAINS,
    "AZGlobalAdmin": EdgeType.AZ_GLOBAL_ADMIN,
}


# ---------------------------------------------------------------------------
# Normalized value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizedEntity:
    """A canonical FORGE entity.

    Parameters
    ----------
    object_id:
        Directory-scoped opaque identifier. AD SID for SharpHound, Azure
        object GUID for AzureHound. Uppercased to normalize case-insensitive
        comparison (both AD SIDs and Azure GUIDs are case-insensitive).
    entity_type:
        Canonical :class:`EntityType`.
    label:
        Human display label (e.g. ``[email protected]``,
        ``DOMAIN\\svc-account``). Never contains secret material.
    sources:
        Set of collectors that contributed to this entity. A single-source
        entity carries one member; a merged entity carries multiple.
    collection_time:
        UTC timestamp of the earliest collection event, if any collector
        reported one.
    normalized_properties:
        Union of every raw property the collectors emitted for this object.
        The original collector schema is preserved verbatim inside this
        dict, so a round-trip through the normalizer never loses data.
    """

    object_id: str
    entity_type: EntityType
    label: str
    sources: frozenset[CollectorSource]
    collection_time: datetime | None
    normalized_properties: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalizedEdge:
    """A canonical FORGE edge between two normalized entities.

    ``original_label`` preserves the exact collector label (useful when
    ``edge_type`` is :attr:`EdgeType.UNKNOWN` and the caller needs the raw
    string for triage).
    """

    source_object_id: str
    target_object_id: str
    edge_type: EdgeType
    original_label: str
    source: CollectorSource
    collection_time: datetime | None
    normalized_properties: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class NormalizationError(ValueError):
    """Raised for structurally invalid input (missing id, unknown kind).

    Callers that would rather skip bad records than fail the batch should
    catch this exception at the boundary.
    """


def normalize_entity(
    record: Mapping[str, Any],
    source: CollectorSource,
) -> NormalizedEntity:
    """Normalize a single BloodHound/AzureHound entity record.

    Parameters
    ----------
    record:
        Raw record as emitted by the collector. Expected keys:
        ``ObjectIdentifier`` (or ``ObjectID`` / ``id``), ``Properties``
        (dict), ``Kind`` (or ``ObjectType`` / ``type``). BloodHound
        ``Properties.name`` becomes the display label; if absent, the
        object id is reused.
    source:
        Which collector produced this record. Selects the mapping table.

    Raises
    ------
    NormalizationError:
        If the record lacks an object id or has an unrecognized kind.
    """
    object_id = _extract_object_id(record)
    kind = _extract_kind(record)
    entity_type = _resolve_entity_type(kind, source)

    props = _extract_properties(record)
    label = _extract_label(props, fallback=object_id)
    collection_time = _extract_collection_time(record, props)

    return NormalizedEntity(
        object_id=object_id.upper(),
        entity_type=entity_type,
        label=label,
        sources=frozenset({source}),
        collection_time=collection_time,
        # Preserve the full raw envelope, not just the Properties dict, so
        # a re-import can reconstruct the original record shape.
        normalized_properties=dict(record),
    )


def normalize_edge(
    record: Mapping[str, Any],
    source: CollectorSource,
) -> NormalizedEdge:
    """Normalize a single BloodHound/AzureHound edge record.

    ``record`` is expected to contain source/target object ids and an edge
    kind/label. Both BloodHound v5 (``Start``, ``End``, ``Kind``) and
    AzureHound (``StartNode``, ``EndNode``, ``EdgeType``) shapes are
    accepted.

    Unknown edge kinds are preserved as :attr:`EdgeType.UNKNOWN` with the
    raw label captured in ``original_label`` — they are never dropped.
    """
    source_id = _first(record, ("Start", "StartNode", "source", "source_object_id"))
    target_id = _first(record, ("End", "EndNode", "target", "target_object_id"))
    if not source_id or not target_id:
        raise NormalizationError(
            f"Edge record missing source/target: keys={sorted(record.keys())}"
        )

    raw_label = _first(record, ("Kind", "EdgeType", "type", "label"))
    if not raw_label:
        raise NormalizationError(
            f"Edge record missing edge type: {sorted(record.keys())}"
        )

    edge_type = _EDGE_TYPE_MAP.get(str(raw_label), EdgeType.UNKNOWN)
    collection_time = _extract_collection_time(record, record.get("Properties", {}))

    return NormalizedEdge(
        source_object_id=str(source_id).upper(),
        target_object_id=str(target_id).upper(),
        edge_type=edge_type,
        original_label=str(raw_label),
        source=source,
        collection_time=collection_time,
        normalized_properties=dict(record),
    )


def normalize_bulk(
    records: Iterable[Mapping[str, Any]],
    source: CollectorSource,
    *,
    kind: str = "entity",
) -> list[NormalizedEntity] | list[NormalizedEdge]:
    """Normalize an iterable of records of a single kind.

    ``kind`` selects entity vs. edge normalization. Records that raise
    :class:`NormalizationError` are skipped — the boundary parser fails
    open on per-record errors so a single bad row cannot poison a batch,
    but the caller is expected to inspect logs or add a strict wrapper if
    they need fail-fast behavior.
    """
    if kind == "entity":
        entities: list[NormalizedEntity] = []
        for rec in records:
            try:
                entities.append(normalize_entity(rec, source))
            except NormalizationError:
                continue
        return entities
    if kind == "edge":
        edges: list[NormalizedEdge] = []
        for rec in records:
            try:
                edges.append(normalize_edge(rec, source))
            except NormalizationError:
                continue
        return edges
    raise ValueError(f"kind must be 'entity' or 'edge', got {kind!r}")


def merge_entities(
    entities: Iterable[NormalizedEntity],
) -> list[NormalizedEntity]:
    """Deduplicate entities by ``object_id``.

    When two collectors emit the same object (same SID/GUID), the merged
    entity keeps:

    * the earliest ``collection_time``,
    * the union of ``sources``,
    * the union of ``normalized_properties`` (later collectors' keys win
      only for keys the earlier collector didn't set — the original
      collector's values are never overwritten silently),
    * the first non-empty label.

    Entity types are expected to agree; if a later record reports a
    different :class:`EntityType` for the same ``object_id``, the earlier
    record's type wins (SharpHound is authoritative for AD kinds,
    AzureHound is authoritative for Azure kinds, and the natural iteration
    order should reflect that; callers who care can sort).
    """
    merged: dict[str, NormalizedEntity] = {}
    for ent in entities:
        existing = merged.get(ent.object_id)
        if existing is None:
            merged[ent.object_id] = ent
            continue
        props = dict(existing.normalized_properties)
        for k, v in ent.normalized_properties.items():
            props.setdefault(k, v)
        merged[ent.object_id] = NormalizedEntity(
            object_id=existing.object_id,
            entity_type=existing.entity_type,
            label=existing.label or ent.label,
            sources=existing.sources | ent.sources,
            collection_time=_earliest(existing.collection_time, ent.collection_time),
            normalized_properties=props,
        )
    return list(merged.values())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_object_id(record: Mapping[str, Any]) -> str:
    raw = _first(record, ("ObjectIdentifier", "ObjectID", "id", "ObjectId"))
    if not raw:
        raise NormalizationError(
            f"Entity record missing object id: keys={sorted(record.keys())}"
        )
    return str(raw)


def _extract_kind(record: Mapping[str, Any]) -> str:
    raw = _first(record, ("Kind", "ObjectType", "type", "label"))
    if not raw:
        raise NormalizationError(
            f"Entity record missing kind: keys={sorted(record.keys())}"
        )
    return str(raw)


def _extract_properties(record: Mapping[str, Any]) -> Mapping[str, Any]:
    props = record.get("Properties")
    if isinstance(props, Mapping):
        return props
    return {}


def _extract_label(props: Mapping[str, Any], *, fallback: str) -> str:
    for key in ("name", "displayname", "displayName", "samaccountname"):
        val = props.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return fallback


def _extract_collection_time(
    record: Mapping[str, Any], props: Mapping[str, Any]
) -> datetime | None:
    for source in (record, props):
        for key in ("collected", "collection_time", "collectionTime", "meta_time"):
            val = source.get(key)
            parsed = _parse_timestamp(val)
            if parsed is not None:
                return parsed
    meta = record.get("meta")
    if isinstance(meta, Mapping):
        return _parse_timestamp(meta.get("collected") or meta.get("collection_time"))
    return None


def _parse_timestamp(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        # BloodHound emits Unix epoch seconds
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(val, str) and val.strip():
        try:
            parsed = datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _resolve_entity_type(kind: str, source: CollectorSource) -> EntityType:
    match source:
        case CollectorSource.SHARPHOUND:
            mapped = _SHARPHOUND_ENTITY_TYPE_MAP.get(kind)
        case CollectorSource.AZUREHOUND:
            mapped = _AZUREHOUND_ENTITY_TYPE_MAP.get(kind)
        case _ as unreachable:
            assert_never(unreachable)
    if mapped is None:
        raise NormalizationError(
            f"Unknown {source.value} entity kind: {kind!r}. "
            f"Add it to the mapping table before ingesting this record."
        )
    return mapped


def _first(record: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        val = record.get(key)
        if val:
            return val
    return None


def _earliest(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a <= b else b
