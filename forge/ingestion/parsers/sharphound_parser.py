"""SharpHound zip parser.

Converts a SharpHound v2 collection zip (``sessions.json``, ``grouped.json``,
``containers.json`` plus any other JSON blobs it ships with) into FORGE
``GraphEntity`` records.

Design contract
---------------
* Read-only, offline. Never mutates the source zip.
* Streams zip entries one-at-a-time via ``zipfile.ZipFile.open`` — never
  extracts the whole archive to disk and never buffers every entry
  simultaneously in memory.
* Preserves BloodHound's original per-object payload verbatim in
  ``GraphEntity.properties`` so downstream stages can reason about SIDs,
  ACEs, session lists, ObjectType hints, and any other metadata SharpHound
  chose to emit.
* Missing expected files are logged and skipped — SharpHound legitimately
  omits sections it wasn't asked to collect. Unrecognized ``*.json``
  entries are also logged (warning) and still processed with a best-effort
  entity type.
* Corrupt zip / corrupt JSON raises :class:`SharpHoundParseError` with the
  offending entry name attached so operators can triage the export.

The public surface is intentionally tiny: one Pydantic model, one function,
one error type.

Note
----
This module defines its own :class:`GraphEntity` model tailored to
BloodHound-on-prem semantics (SID + BloodHound object-type taxonomy).
:mod:`forge.ingestion.parsers.azurehound_parser` defines a differently
shaped Azure-specific ``GraphEntity``; the two are intentionally
independent boundary types that ``forge.graph.normalizer`` can merge.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from pathlib import Path
from typing import Any, Final, Iterator, Mapping

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

__all__ = [
    "PARSER_VERSION",
    "GraphEntity",
    "SharpHoundParseError",
    "parse_sharphound_zip",
]


# ── Public error type ────────────────────────────────────────────────────────
class SharpHoundParseError(RuntimeError):
    """Raised when the SharpHound zip is unreadable or a JSON entry is
    corrupt.

    ``entry`` is the offending zip member name (``""`` when the failure is
    the zip container itself).
    """

    def __init__(self, message: str, *, entry: str = "") -> None:
        super().__init__(message)
        self.entry: str = entry


# ── GraphEntity ──────────────────────────────────────────────────────────────
class GraphEntity(BaseModel):
    """A single normalized graph node emitted by the SharpHound parser.

    Attributes
    ----------
    id:
        Stable identifier. For BloodHound objects this is the
        ``ObjectIdentifier`` (SID or Azure GUID). For containers/OUs this
        is their DN when no SID is present. For session rows this is a
        synthetic ``session:{user_sid}:{computer_sid}`` key. For grouped
        membership edges it is ``group_membership:{group}:{member}``.
    type:
        FORGE entity type. Common values: ``user``, ``computer``,
        ``group``, ``domain``, ``ou``, ``container``, ``gpo``, ``session``,
        ``group_membership``, ``unknown``.
    properties:
        Verbatim BloodHound payload for the object (``ObjectIdentifier``,
        ``Properties``, ``Aces``, ``Members``, ``SPNTargets`` and any
        tool-specific fields). Nothing is stripped.
    source_metadata:
        Provenance for this record: zip path, JSON member inside the zip,
        BloodHound ``meta`` block (if any), and the parser version.
        Enables idempotent re-ingestion and audit-friendly attribution.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Stable canonical identifier for this entity.")
    type: str = Field(description="FORGE entity type; see class docstring.")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Verbatim BloodHound payload for the record. Preserved so "
            "downstream analysis is lossless."
        ),
    )
    source_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Provenance metadata: zip path, JSON member, BloodHound meta "
            "block, parser version."
        ),
    )


# ── Type mapping ─────────────────────────────────────────────────────────────
# SharpHound / BloodHound object-type strings → FORGE canonical types.
# Keys are lower-cased before lookup so any case variant matches.
_BLOODHOUND_TO_FORGE: Final[Mapping[str, str]] = {
    "user": "user",
    "computer": "computer",
    "group": "group",
    "domain": "domain",
    "ou": "ou",
    "container": "container",
    "gpo": "gpo",
    "aiaca": "certificate_authority",
    "rootca": "certificate_authority",
    "enterpriseca": "certificate_authority",
    "ntauthstore": "certificate_authority",
    "certtemplate": "cert_template",
    "issuancepolicy": "issuance_policy",
    # AzureHound-adjacent kinds sometimes co-shipped in SharpHound bundles.
    "aztenant": "tenant",
    "azuser": "user",
    "azgroup": "group",
    "azdevice": "computer",
    "azserviceprincipal": "service_principal",
    "azapp": "app_registration",
    "azroleassignment": "role_assignment",
}

# Filename stem → default entity type when a JSON file lists objects
# without per-record type hints. ``grouped.json`` and ``containers.json``
# are the canonical BloodHound container/collection files called out by
# the task; the additional stems cover typical SharpHound bundles the
# parser may encounter in the same archive.
_FILENAME_DEFAULT_TYPE: Final[Mapping[str, str]] = {
    "sessions": "session",
    "grouped": "group_membership",
    "containers": "container",
    "users": "user",
    "computers": "computer",
    "groups": "group",
    "domains": "domain",
    "ous": "ou",
    "gpos": "gpo",
}

PARSER_VERSION: Final[str] = "sharphound_parser/1.0.0"


# ── Public entry point ───────────────────────────────────────────────────────
def parse_sharphound_zip(zip_path: Path) -> list[GraphEntity]:
    """Parse a SharpHound export zip into a list of :class:`GraphEntity`.

    Parameters
    ----------
    zip_path:
        Path to a SharpHound-produced ``.zip``. The file is opened
        read-only; the original archive is never written to.

    Returns
    -------
    list[GraphEntity]
        One entity per BloodHound object (users, computers, groups,
        domains, OUs, containers) plus one per session row and per
        group-membership row. Order follows zip entry order for
        deterministic re-ingestion.

    Raises
    ------
    FileNotFoundError
        The zip does not exist.
    SharpHoundParseError
        The zip is corrupt, or a member's JSON payload is malformed.
    """

    zip_path = Path(zip_path)
    if not zip_path.is_file():
        msg = f"SharpHound zip not found: {zip_path}"
        raise FileNotFoundError(msg)

    entities: list[GraphEntity] = []
    try:
        with zipfile.ZipFile(zip_path, mode="r") as archive:
            bad_member = archive.testzip()
            if bad_member is not None:
                msg = f"Corrupt zip entry: {bad_member}"
                raise SharpHoundParseError(msg, entry=bad_member)

            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if not name.lower().endswith(".json"):
                    logger.warning(
                        "sharphound_parser: skipping non-JSON entry %r",
                        name,
                    )
                    continue
                stem = _stem_of(name)
                if stem not in _FILENAME_DEFAULT_TYPE:
                    logger.warning(
                        "sharphound_parser: unrecognized JSON entry %r "
                        "(parsing with best-effort type)",
                        name,
                    )
                entities.extend(
                    _parse_zip_member(archive, info, zip_path=zip_path)
                )
    except zipfile.BadZipFile as exc:
        msg = f"Not a valid zip: {zip_path}"
        raise SharpHoundParseError(msg, entry="") from exc

    return entities


# ── Internals ────────────────────────────────────────────────────────────────
def _stem_of(name: str) -> str:
    """Return the lower-cased filename stem for zip entry ``name``.

    ``foo/bar/Users.json`` → ``users``. Uses forward-slash split so
    behavior is identical on Windows and POSIX regardless of what
    SharpHound wrote into the archive.
    """
    tail = name.rsplit("/", 1)[-1]
    if tail.lower().endswith(".json"):
        tail = tail[: -len(".json")]
    return tail.lower()


def _parse_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    zip_path: Path,
) -> Iterator[GraphEntity]:
    """Yield entities for one JSON entry inside the zip.

    Streams the zip entry through :func:`json.load` — the raw bytes are
    decompressed on demand by ``zipfile`` and never materialised as a
    monolithic in-memory buffer of the whole archive. The parsed JSON
    document for a single member is held in memory (SharpHound emits one
    document per file, so this is bounded by the largest section).
    """

    stem = _stem_of(info.filename)
    default_type = _FILENAME_DEFAULT_TYPE.get(stem, "unknown")

    try:
        with archive.open(info, mode="r") as raw:
            # UTF-8 with BOM tolerance — SharpHound sometimes ships BOMs
            # on Windows-produced exports; decoding here also proves that
            # Unicode object names survive the round-trip.
            document = json.load(
                io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")
            )
    except json.JSONDecodeError as exc:
        msg = f"Malformed JSON in zip entry {info.filename!r}: {exc.msg}"
        raise SharpHoundParseError(msg, entry=info.filename) from exc
    except UnicodeDecodeError as exc:
        msg = f"Non-UTF-8 payload in zip entry {info.filename!r}: {exc}"
        raise SharpHoundParseError(msg, entry=info.filename) from exc

    records, meta = _split_records_and_meta(document)
    base_source: dict[str, Any] = {
        "parser": PARSER_VERSION,
        "source_type": "sharphound",
        "zip_path": str(zip_path),
        "zip_member": info.filename,
    }
    if meta:
        base_source["bloodhound_meta"] = meta

    for record in records:
        entity = _record_to_entity(
            record,
            default_type=default_type,
            member_stem=stem,
            base_source=base_source,
        )
        if entity is not None:
            yield entity


def _split_records_and_meta(
    document: Any,
) -> tuple[list[Any], dict[str, Any] | None]:
    """Return ``(records, meta)`` for any recognized SharpHound shape.

    SharpHound v2 uses ``{"data": [...], "meta": {...}}``. Legacy /
    third-party variants sometimes emit a bare list. AzureHound-style
    single-object JSONL blobs occasionally sneak into bundles too and
    appear here as a dict with a ``kind`` field; treat that as one
    record.
    """
    if isinstance(document, dict):
        if "data" in document and isinstance(document["data"], list):
            meta = document.get("meta")
            if isinstance(meta, dict):
                return list(document["data"]), meta
            return list(document["data"]), None
        # Single-record document (rare but observed for standalone objects).
        return [document], None
    if isinstance(document, list):
        return list(document), None
    logger.warning(
        "sharphound_parser: unexpected top-level JSON type %s — skipping",
        type(document).__name__,
    )
    return [], None


def _record_to_entity(
    record: Any,
    *,
    default_type: str,
    member_stem: str,
    base_source: dict[str, Any],
) -> GraphEntity | None:
    """Normalize a single BloodHound-shaped record into a ``GraphEntity``."""

    if not isinstance(record, dict):
        logger.warning(
            "sharphound_parser: skipping non-object record in %s: %s",
            base_source.get("zip_member"),
            type(record).__name__,
        )
        return None

    entity_type = _resolve_entity_type(record, default_type=default_type)
    entity_id = _resolve_entity_id(record, member_stem=member_stem)
    if entity_id is None:
        logger.warning(
            "sharphound_parser: record without stable id in %s — skipping",
            base_source.get("zip_member"),
        )
        return None

    # Shallow copy so downstream mutation of ``properties`` cannot corrupt
    # callers sharing the same frozen entity — but preserve original
    # nested structures (BloodHound metadata is nested deep and must
    # survive verbatim).
    properties = dict(record)

    source_metadata = dict(base_source)
    source_metadata["record_kind"] = member_stem

    return GraphEntity(
        id=entity_id,
        type=entity_type,
        properties=properties,
        source_metadata=source_metadata,
    )


def _resolve_entity_type(
    record: Mapping[str, Any], *, default_type: str
) -> str:
    """Map a BloodHound object's declared type to a FORGE type.

    Precedence: explicit ``ObjectType`` (BloodHound edge/member records) →
    top-level ``kind`` (AzureHound style) → ``Properties.type`` →
    filename default.
    """
    for candidate_key in ("ObjectType", "kind", "Kind", "Type"):
        raw = record.get(candidate_key)
        if isinstance(raw, str) and raw:
            mapped = _BLOODHOUND_TO_FORGE.get(raw.lower())
            if mapped is not None:
                return mapped
            return raw.lower()

    props = record.get("Properties")
    if isinstance(props, dict):
        prop_type = props.get("type")
        if isinstance(prop_type, str) and prop_type:
            mapped = _BLOODHOUND_TO_FORGE.get(prop_type.lower())
            if mapped is not None:
                return mapped

    return default_type


def _resolve_entity_id(
    record: Mapping[str, Any], *, member_stem: str
) -> str | None:
    """Return a stable id for a BloodHound-shaped record.

    Order:
      1. ``ObjectIdentifier`` (users/computers/groups/domains/OUs/
         containers).
      2. ``data.id`` (AzureHound-style envelopes co-shipped in the
         bundle).
      3. Synthetic key for session rows keyed by user+computer SID.
      4. Synthetic key for grouped membership rows keyed by group+member.
      5. ``distinguishedname`` from ``Properties`` (containers/OUs
         sometimes lack SIDs).
    """
    raw_oid = record.get("ObjectIdentifier")
    if isinstance(raw_oid, str) and raw_oid:
        return raw_oid

    data = record.get("data")
    if isinstance(data, dict):
        oid = data.get("id") or data.get("ObjectIdentifier")
        if isinstance(oid, str) and oid:
            return oid

    if member_stem == "sessions":
        user_sid = record.get("UserSID") or record.get("UserId")
        computer_sid = record.get("ComputerSID") or record.get("ComputerId")
        if isinstance(user_sid, str) and isinstance(computer_sid, str):
            return f"session:{user_sid}:{computer_sid}"

    if member_stem == "grouped":
        group_id = record.get("GroupSID") or record.get("GroupId")
        member_id = record.get("MemberSID") or record.get("MemberId")
        if isinstance(group_id, str) and isinstance(member_id, str):
            return f"group_membership:{group_id}:{member_id}"

    props = record.get("Properties")
    if isinstance(props, dict):
        dn = props.get("distinguishedname") or props.get("objectid")
        if isinstance(dn, str) and dn:
            return dn

    return None
