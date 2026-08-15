from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from forge.graph.assets import (
    entity_id_for_key,
    upsert_asset_entity,
    upsert_asset_relationship,
    upsert_ownership_claim,
)

_ATTRIBUTION_KINDS = {
    "internal",
    "subsidiary",
    "acquisition",
    "third_party",
    "cloud_account",
    "cloud_org",
    "unknown",
}


def _text(value: object) -> str:
    return str(value or "").strip()


def _safe_slug(value: object) -> str:
    text = _text(value).lower()
    out = []
    for char in text:
        out.append(char if char.isalnum() or char in {"-", "_", ".", ":"} else "-")
    return "-".join(part for part in "".join(out).split("-") if part)[:240]


def _confidence(value: object, default: float = 0.7) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = default
    return max(0.0, min(1.0, score))


def _first(record: Mapping[str, Any], *keys: str) -> Any:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for key in keys:
        if key.lower() in lowered and lowered[key.lower()] not in (None, ""):
            return lowered[key.lower()]
    return ""


def _jsonish(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if not _text(value):
        return {}
    text = _text(value)
    if text.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"note": text}
        if isinstance(parsed, Mapping):
            return dict(parsed)
        return {"items": parsed}
    return {"note": text}


def _attribution_kind(value: object) -> str:
    normalized = _safe_slug(value).replace("-", "_") or "unknown"
    aliases = {
        "acquired": "acquisition",
        "acquired_company": "acquisition",
        "cloud": "cloud_account",
        "cloud_account_mapping": "cloud_account",
        "cloud_organization": "cloud_org",
        "supplier": "third_party",
        "vendor": "third_party",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in _ATTRIBUTION_KINDS else "unknown"


def _owner_kind(record: Mapping[str, Any], owner_ref: str, attribution_kind: str) -> str:
    explicit = _text(_first(record, "owner_kind", "kind"))
    if explicit:
        return explicit
    if "@" in owner_ref:
        return "email"
    if attribution_kind == "third_party":
        return "third_party"
    if attribution_kind in {"cloud_account", "cloud_org"}:
        return "cloud_account"
    if _text(_first(record, "organization_ref", "organization", "subsidiary_ref")):
        return "organization"
    return "team"


def _organization_key(kind: str, ref: object) -> str:
    return f"organization:{_safe_slug(kind) or 'organization'}:{_safe_slug(ref)}"


def _cloud_account_ref(provider: str, account_id: str) -> str:
    return f"{_safe_slug(provider) or 'cloud'}:{account_id}"


def _cloud_account_key(provider: str, account_id: str) -> str:
    return _organization_key("cloud_account", _cloud_account_ref(provider, account_id))


def _cloud_org_ref(provider: str, org_id: str) -> str:
    return f"{_safe_slug(provider) or 'cloud'}:org:{org_id}"


def _cloud_org_key(provider: str, org_id: str) -> str:
    return _organization_key("cloud_org", _cloud_org_ref(provider, org_id))


def _record_payload(record: Mapping[str, Any], *, default_source: str, created_by: str) -> dict[str, Any]:
    attribution_kind = _attribution_kind(
        _first(record, "attribution_kind", "attribution_type", "relationship", "relationship_type")
    )
    source = _text(_first(record, "source", "attribution_source")) or default_source
    confidence = _confidence(_first(record, "confidence", "confidence_score"), 0.7)
    evidence = {
        "source": source,
        "attribution_kind": attribution_kind,
        "created_by": created_by,
        **_jsonish(_first(record, "evidence", "evidence_json", "reason", "note")),
    }
    metadata = {
        "source": source,
        "attribution_kind": attribution_kind,
        "created_by": created_by,
        **_jsonish(_first(record, "metadata", "metadata_json")),
    }
    provider = _text(_first(record, "cloud_provider", "provider")).lower()
    account_id = _text(
        _first(
            record,
            "cloud_account_id",
            "account_id",
            "subscription_id",
            "project_id",
            "tenant_account_id",
        )
    )
    cloud_org_id = _text(
        _first(
            record,
            "cloud_org_id",
            "organization_id",
            "org_id",
            "tenant_id",
            "management_group_id",
        )
    )
    entity_key = _text(_first(record, "entity_key", "asset_key", "key"))
    entity_type = _text(_first(record, "entity_type", "asset_type")) or "asset"
    label = _text(_first(record, "label", "asset_label", "name")) or entity_key
    if not entity_key and account_id:
        entity_key = _cloud_account_key(provider, account_id)
        entity_type = "organization"
        label = label or _cloud_account_ref(provider, account_id)
    if not entity_key:
        org_ref = _text(_first(record, "organization_ref", "organization", "subsidiary_ref"))
        if org_ref:
            entity_key = _organization_key(attribution_kind or "organization", org_ref)
            entity_type = "organization"
            label = label or org_ref
    return {
        "entity_key": entity_key,
        "entity_type": entity_type,
        "label": label or entity_key,
        "confidence": confidence,
        "source": source,
        "attribution_kind": attribution_kind,
        "metadata": metadata,
        "evidence": evidence,
        "provider": provider,
        "account_id": account_id,
        "cloud_org_id": cloud_org_id,
    }


def _upsert_org(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    kind: str,
    ref: str,
    label: str,
    confidence: float,
    source: str,
    source_id: int,
    metadata: Mapping[str, Any],
) -> int:
    return upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=_organization_key(kind, ref),
        entity_type="organization",
        label=label or ref,
        source_table="asset_attribution_import",
        source_id=source_id,
        confidence=confidence,
        metadata={"organization_kind": kind, "organization_ref": ref, "source": source, **dict(metadata)},
    )


def _upsert_claim(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    entity_id: int,
    owner_ref: str,
    owner_kind: str,
    owner_display: str,
    claim_type: str,
    confidence: float,
    source: str,
    evidence: Mapping[str, Any],
    created_by: str,
) -> int:
    return upsert_ownership_claim(
        con,
        engagement_id=engagement_id,
        entity_id=entity_id,
        owner_ref=owner_ref,
        owner_kind=owner_kind,
        owner_display=owner_display or owner_ref,
        claim_type=claim_type,
        confidence=confidence,
        source=source,
        status="active",
        evidence=evidence,
        created_by=created_by,
    )


def load_asset_attribution_records(path: str | Path) -> list[dict[str, Any]]:
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(str(source_path))
    if source_path.suffix.lower() == ".csv":
        with source_path.open("r", encoding="utf-8-sig", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    with source_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, Mapping):
        records = (
            payload.get("records")
            or payload.get("items")
            or payload.get("attributions")
            or payload.get("asset_attributions")
            or []
        )
    else:
        records = []
    if not isinstance(records, list):
        raise ValueError("asset attribution file must contain a list of records")
    if not all(isinstance(item, Mapping) for item in records):
        raise ValueError("asset attribution records must be JSON objects")
    return [dict(item) for item in records]


def import_asset_attribution_records(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    records: Iterable[Mapping[str, Any]],
    source: str = "operator_attribution",
    created_by: str = "operator",
) -> dict[str, Any]:
    entity_ids: set[int] = set()
    relationship_ids: set[int] = set()
    claim_ids: set[int] = set()
    imported: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for index, record in enumerate(records, start=1):
        try:
            payload = _record_payload(record, default_source=source, created_by=created_by)
            entity_key = _text(payload["entity_key"])
            if not entity_key:
                raise ValueError("entity_key is required unless a cloud account or organization ref is supplied")
            confidence = float(payload["confidence"])
            metadata = dict(payload["metadata"])
            entity_id = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=entity_key,
                entity_type=_text(payload["entity_type"]) or "asset",
                label=_text(payload["label"]) or entity_key,
                source_table="asset_attribution_import",
                source_id=index,
                confidence=confidence,
                metadata=metadata,
            )
            entity_ids.add(entity_id)
            source_label = _text(payload["source"]) or source
            evidence = dict(payload["evidence"])
            attribution_kind = _text(payload["attribution_kind"]) or "unknown"

            owner_ref = _text(_first(record, "owner_ref", "owner", "owner_slug", "team"))
            if owner_ref:
                claim_ids.add(
                    _upsert_claim(
                        con,
                        engagement_id=engagement_id,
                        entity_id=entity_id,
                        owner_ref=owner_ref,
                        owner_kind=_owner_kind(record, owner_ref, attribution_kind),
                        owner_display=_text(_first(record, "owner_display", "owner_name")) or owner_ref,
                        claim_type=_text(_first(record, "claim_type")) or "explicit",
                        confidence=confidence,
                        source=source_label,
                        evidence=evidence,
                        created_by=created_by,
                    )
                )

            org_ref = _text(_first(record, "organization_ref", "organization", "subsidiary_ref"))
            if org_ref:
                org_kind = "subsidiary" if attribution_kind == "subsidiary" else "organization"
                org_id = _upsert_org(
                    con,
                    engagement_id=engagement_id,
                    kind=org_kind,
                    ref=org_ref,
                    label=_text(_first(record, "organization_display", "organization_name")) or org_ref,
                    confidence=confidence,
                    source=source_label,
                    source_id=index,
                    metadata={"attribution_kind": attribution_kind},
                )
                entity_ids.add(org_id)
                relationship_ids.add(
                    upsert_asset_relationship(
                        con,
                        engagement_id=engagement_id,
                        source_entity_id=entity_id,
                        target_entity_id=org_id,
                        relationship_type="owned_by",
                        confidence=confidence,
                        source_table="asset_attribution_import",
                        source_id=index,
                        evidence={**evidence, "relationship_kind": f"{attribution_kind}_organization"},
                    )
                )
                claim_ids.add(
                    _upsert_claim(
                        con,
                        engagement_id=engagement_id,
                        entity_id=entity_id,
                        owner_ref=org_ref,
                        owner_kind="organization",
                        owner_display=_text(_first(record, "organization_display", "organization_name")) or org_ref,
                        claim_type="explicit",
                        confidence=confidence,
                        source=source_label,
                        evidence=evidence,
                        created_by=created_by,
                    )
                )
                parent_ref = _text(_first(record, "parent_organization_ref", "parent_ref", "acquirer_ref"))
                if parent_ref:
                    parent_id = _upsert_org(
                        con,
                        engagement_id=engagement_id,
                        kind="organization",
                        ref=parent_ref,
                        label=_text(_first(record, "parent_organization_display", "acquirer_display")) or parent_ref,
                        confidence=confidence,
                        source=source_label,
                        source_id=index,
                        metadata={"attribution_kind": "parent"},
                    )
                    entity_ids.add(parent_id)
                    relationship_ids.add(
                        upsert_asset_relationship(
                            con,
                            engagement_id=engagement_id,
                            source_entity_id=org_id,
                            target_entity_id=parent_id,
                            relationship_type="related_asset",
                            confidence=confidence,
                            source_table="asset_attribution_import",
                            source_id=index,
                            evidence={
                                **evidence,
                                "relationship_kind": "acquired_by"
                                if attribution_kind == "acquisition"
                                else "subsidiary_of",
                            },
                        )
                    )

            third_party_ref = _text(_first(record, "third_party_ref", "vendor_ref", "supplier_ref"))
            if third_party_ref:
                third_party_id = _upsert_org(
                    con,
                    engagement_id=engagement_id,
                    kind="third_party",
                    ref=third_party_ref,
                    label=_text(_first(record, "third_party_display", "vendor_display")) or third_party_ref,
                    confidence=confidence,
                    source=source_label,
                    source_id=index,
                    metadata={"attribution_kind": "third_party"},
                )
                entity_ids.add(third_party_id)
                relationship_ids.add(
                    upsert_asset_relationship(
                        con,
                        engagement_id=engagement_id,
                        source_entity_id=entity_id,
                        target_entity_id=third_party_id,
                        relationship_type="owned_by",
                        confidence=confidence,
                        source_table="asset_attribution_import",
                        source_id=index,
                        evidence={**evidence, "relationship_kind": "third_party_provider"},
                    )
                )
                claim_ids.add(
                    _upsert_claim(
                        con,
                        engagement_id=engagement_id,
                        entity_id=entity_id,
                        owner_ref=third_party_ref,
                        owner_kind="third_party",
                        owner_display=_text(_first(record, "third_party_display", "vendor_display")) or third_party_ref,
                        claim_type="explicit",
                        confidence=confidence,
                        source=source_label,
                        evidence=evidence,
                        created_by=created_by,
                    )
                )

            provider = _text(payload["provider"]) or "cloud"
            account_id = _text(payload["account_id"])
            cloud_org_id = _text(payload["cloud_org_id"])
            account_entity_id = 0
            if account_id:
                account_ref = _cloud_account_ref(provider, account_id)
                account_entity_id = upsert_asset_entity(
                    con,
                    engagement_id=engagement_id,
                    entity_key=_cloud_account_key(provider, account_id),
                    entity_type="organization",
                    label=account_ref,
                    source_table="asset_attribution_import",
                    source_id=index,
                    confidence=confidence,
                    metadata={
                        "organization_kind": "cloud_account",
                        "provider": provider,
                        "account_ref": account_id,
                        "cloud_org_ref": cloud_org_id,
                        "source": source_label,
                    },
                )
                entity_ids.add(account_entity_id)
                if account_entity_id != entity_id:
                    relationship_ids.add(
                        upsert_asset_relationship(
                            con,
                            engagement_id=engagement_id,
                            source_entity_id=entity_id,
                            target_entity_id=account_entity_id,
                            relationship_type="owned_by",
                            confidence=confidence,
                            source_table="asset_attribution_import",
                            source_id=index,
                            evidence={**evidence, "relationship_kind": "cloud_account_mapping"},
                        )
                    )
                    claim_ids.add(
                        _upsert_claim(
                            con,
                            engagement_id=engagement_id,
                            entity_id=entity_id,
                            owner_ref=account_ref,
                            owner_kind="cloud_account",
                            owner_display=account_ref,
                            claim_type="cloud_account",
                            confidence=confidence,
                            source=source_label,
                            evidence=evidence,
                            created_by=created_by,
                        )
                    )
            if cloud_org_id:
                org_ref = _cloud_org_ref(provider, cloud_org_id)
                cloud_org_entity_id = upsert_asset_entity(
                    con,
                    engagement_id=engagement_id,
                    entity_key=_cloud_org_key(provider, cloud_org_id),
                    entity_type="organization",
                    label=org_ref,
                    source_table="asset_attribution_import",
                    source_id=index,
                    confidence=confidence,
                    metadata={
                        "organization_kind": "cloud_org",
                        "provider": provider,
                        "org_ref": cloud_org_id,
                        "source": source_label,
                    },
                )
                entity_ids.add(cloud_org_entity_id)
                relationship_ids.add(
                    upsert_asset_relationship(
                        con,
                        engagement_id=engagement_id,
                        source_entity_id=account_entity_id or entity_id,
                        target_entity_id=cloud_org_entity_id,
                        relationship_type="related_asset",
                        confidence=confidence,
                        source_table="asset_attribution_import",
                        source_id=index,
                        evidence={**evidence, "relationship_kind": "cloud_org_member"},
                    )
                )

            imported.append(
                {
                    "index": index,
                    "entity_id": entity_id,
                    "entity_key": entity_key,
                    "attribution_kind": attribution_kind,
                    "confidence": confidence,
                }
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"index": index, "error": str(exc)})

    return {
        "engagement_id": int(engagement_id),
        "processed_count": len(imported) + len(errors),
        "imported_count": len(imported),
        "error_count": len(errors),
        "entity_count": len(entity_ids),
        "relationship_count": len(relationship_ids),
        "ownership_claim_count": len(claim_ids),
        "records": imported,
        "errors": errors,
    }


def import_asset_attribution_file(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    path: str | Path,
    source: str = "operator_attribution",
    created_by: str = "operator",
) -> dict[str, Any]:
    return import_asset_attribution_records(
        con,
        engagement_id=engagement_id,
        records=load_asset_attribution_records(path),
        source=source,
        created_by=created_by,
    )
