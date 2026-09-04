"""forge.ingestion.bloodhound_persist -- Normalized entity persistence.

Single write path for BloodHound/AzureHound entities imported through
:class:`forge.ingestion.bloodhound_importer.BloodHoundImporter`. Every row
that lands in ``bloodhound_entities`` is first normalized through
:mod:`forge.graph.normalizer` so downstream graph consumers see a canonical
schema regardless of collector version.

The CLI is **not** allowed to write to this table directly. All persistence
runs through :func:`persist_normalized_entities` which is only invoked from
inside the ROE-gated importer.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from forge.graph.normalizer import (
    CollectorSource,
    NormalizedEntity,
    normalize_entity,
)

__all__ = [
    "ParsedEntityBatch",
    "persist_normalized_entities",
    "ensure_bloodhound_schema",
    "detect_collector_source",
    "SHARPHOUND_ENTITY_TYPES",
]

_LOG = logging.getLogger(__name__)

# Canonical SharpHound (on-prem AD) BloodHound meta.type values. AzureHound
# emits its own set with an ``az``/``AZ`` prefix; anything else routes to
# SHARPHOUND by default.
SHARPHOUND_ENTITY_TYPES: frozenset[str] = frozenset({
    "users",
    "computers",
    "groups",
    "domains",
    "gpos",
    "ous",
    "containers",
    "aiacas",
    "rootcas",
    "enterprisecas",
    "ntauthstores",
    "certtemplates",
    "issuancepolicies",
})


@dataclass(frozen=True, slots=True)
class ParsedEntityBatch:
    """One BloodHound JSON payload prepared for normalization."""

    source_path: str
    collection_type: str
    source: CollectorSource
    raw_entities: tuple[dict, ...]


def detect_collector_source(collection_type: str) -> CollectorSource:
    """Return the collector that produced this meta.type value.

    BloodHound exports use lowercase pluralized ``meta.type`` values such as
    ``users`` (SharpHound) or ``azusers`` (AzureHound). Anything starting
    with ``az`` is AzureHound; the SharpHound whitelist covers the rest.
    """
    lowered = collection_type.lower().strip()
    if lowered.startswith("az"):
        return CollectorSource.AZUREHOUND
    return CollectorSource.SHARPHOUND


def ensure_bloodhound_schema(conn: sqlite3.Connection) -> None:
    """Create the normalized ``bloodhound_entities`` table if missing.

    Schema is additive: existing tables from earlier revisions gain the
    new provenance columns via ``ALTER TABLE`` no-ops guarded by
    ``PRAGMA table_info`` inspection.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS bloodhound_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            source_path TEXT NOT NULL,
            object_id TEXT,
            payload_json TEXT NOT NULL,
            collector_source TEXT NOT NULL DEFAULT 'SharpHound',
            raw_kind TEXT,
            collection_time TEXT,
            imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_bh_type ON bloodhound_entities(entity_type)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_bh_object ON bloodhound_entities(object_id)"
    )
    # Additive migration for previously-existing DBs that predate the
    # provenance columns.
    existing = {
        row[1]
        for row in conn.execute("PRAGMA table_info(bloodhound_entities)").fetchall()
    }
    for column, ddl in (
        ("collector_source", "TEXT NOT NULL DEFAULT 'SharpHound'"),
        ("raw_kind", "TEXT"),
        ("collection_time", "TEXT"),
    ):
        if column not in existing:
            conn.execute(
                f"ALTER TABLE bloodhound_entities ADD COLUMN {column} {ddl}"
            )


def _raw_kind_from_entity(entity: dict, fallback: str) -> str:
    for key in ("Kind", "ObjectType", "type"):
        val = entity.get(key)
        if isinstance(val, str) and val.strip():
            return val
    # BloodHound v4 payloads sometimes lack a per-entity kind and only
    # carry the collection type via ``meta.type``; use the pluralized
    # collection type as the fallback so the normalizer sees something
    # concrete.
    return _kind_from_collection_type(fallback)


_COLLECTION_KIND_MAP: dict[str, str] = {
    "users": "User",
    "computers": "Computer",
    "groups": "Group",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "azusers": "AZUser",
    "azgroups": "AZGroup",
    "azserviceprincipals": "AZServicePrincipal",
    "azroles": "AZRole",
    "azapps": "AZApp",
    "azapplications": "AZApplication",
}


def _kind_from_collection_type(collection_type: str) -> str:
    return _COLLECTION_KIND_MAP.get(collection_type.lower().strip(), "Base")


def _prepare_row(
    entity: NormalizedEntity,
    source_path: str,
    raw_kind: str,
) -> tuple[str, str, str | None, str, str, str, str | None]:
    """Return the SQL row tuple for one normalized entity."""
    payload = {
        "object_id": entity.object_id,
        "entity_type": entity.entity_type.value,
        "label": entity.label,
        "sources": sorted(s.value for s in entity.sources),
        "collection_time": (
            entity.collection_time.isoformat()
            if entity.collection_time is not None
            else None
        ),
        "properties": dict(entity.normalized_properties),
    }
    collector_source = next(iter(entity.sources)).value
    return (
        entity.entity_type.value,
        source_path,
        entity.object_id,
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        collector_source,
        raw_kind,
        entity.collection_time.isoformat() if entity.collection_time else None,
    )


def persist_normalized_entities(
    db_path: Path,
    batches: Iterable[ParsedEntityBatch],
    *,
    progress_cb=None,
) -> int:
    """Normalize every raw entity in ``batches`` and write to the DB.

    Returns the total number of persisted entity rows. Every row is
    produced by :func:`forge.graph.normalizer.normalize_entity`; a batch
    whose entity fails normalization is skipped and logged rather than
    aborting the whole import (parity with ``normalize_bulk``'s fail-open
    contract).
    """
    total = 0
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as conn:
        ensure_bloodhound_schema(conn)
        for batch in batches:
            rows: list[tuple[str, str, str | None, str, str, str, str | None]] = []
            for raw in batch.raw_entities:
                raw_kind = _raw_kind_from_entity(raw, batch.collection_type)
                # Ensure the normalizer has a ``Kind`` for records that
                # only carried it at the meta level.
                if "Kind" not in raw and "ObjectType" not in raw and "type" not in raw:
                    raw = {**raw, "Kind": raw_kind}
                try:
                    normalized = normalize_entity(raw, batch.source)
                except Exception as exc:  # noqa: BLE001 -- boundary parser
                    _LOG.warning(
                        "bloodhound_persist: skipping unnormalizable "
                        "entity source=%s type=%s error=%s",
                        batch.source_path,
                        batch.collection_type,
                        exc,
                    )
                    continue
                rows.append(_prepare_row(normalized, batch.source_path, raw_kind))
            if rows:
                conn.executemany(
                    "INSERT INTO bloodhound_entities "
                    "(entity_type, source_path, object_id, payload_json, "
                    " collector_source, raw_kind, collection_time) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                total += len(rows)
                if progress_cb is not None:
                    progress_cb(len(rows))
        conn.commit()
    return total
