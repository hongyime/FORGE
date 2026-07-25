from __future__ import annotations

from collections.abc import Iterable, Mapping
import sqlite3

from forge.utils.validation_proof import parse_validated_detail

CANONICAL_CLOUD_ASSET_TYPES = frozenset(
    {
        "aws_s3",
        "azure_blob",
        "do_spaces",
        "firebase",
        "gcs",
        "supabase",
    }
)
STORAGE_CLOUD_ASSET_TYPES = frozenset({"aws_s3", "azure_blob", "do_spaces", "gcs"})
STORAGE_LISTING_VALIDATION_METHODS = frozenset(
    {
        "azure_blob_list_container",
        "do_spaces_list_bucket",
        "gcs_list_bucket",
        "s3_list_bucket",
    }
)
STORAGE_METADATA_VALIDATION_METHODS = frozenset(
    {
        "azure_blob_http_probe",
        "do_spaces_head_probe",
        "gcs_http_probe",
        "s3_head_probe",
    }
)
CLOUD_DATA_VALIDATION_METHODS = {
    "firebase": frozenset({"firebase_database_node_read", "firebase_database_shallow_read"}),
    "supabase": frozenset({"supabase_rest_root"}),
}
PROVIDER_KEY_VALIDATION_METHODS = {
    "discord": frozenset({"discord_current_user"}),
    "slack": frozenset({"slack_auth_test"}),
    "telegram": frozenset({"telegram_get_me"}),
}

_ASSET_TYPE_ALIASES = {
    "azure_blob_storage": "azure_blob",
    "digitalocean_spaces": "do_spaces",
    "google_cloud_storage": "gcs",
    "s3": "aws_s3",
}
_TITLE_PREFIXES = (
    "validated firebase data exposure",
    "validated supabase data exposure",
    "validated public ",
    "externally reachable ",
    "public ",
)
_TITLE_SUFFIXES = (
    " listing exposure",
    " metadata observed",
    " detected",
)
_LOW_SIGNAL_STORAGE_METADATA_MARKERS = (
    "demo",
    "dummy",
    "fake",
    "honeypot",
    "low signal",
    "low-signal",
    "mock",
    "placeholder",
    "sample",
    "synthetic",
    "test data",
)
_INVENTORY_ONLY_VULNERABILITY_TYPES = frozenset(
    {
        "VALIDATION_INVENTORY",
        "VALIDATION_REVIEW",
        "VALIDATION_NOTE",
    }
)


def normalize_cloud_exposure_asset_type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return _ASSET_TYPE_ALIASES.get(normalized, normalized)


def is_deterministic_cloud_exposure(
    vuln_type: str,
    title: str,
    asset_hints: Iterable[str] = (),
) -> bool:
    """Identify cloud exposure rows whose reportability depends on validation."""
    if str(vuln_type or "").strip().upper() == "DETERMINISTIC_CLOUD_EXPOSURE":
        return True
    if not any(
        normalize_cloud_exposure_asset_type(hint) in CANONICAL_CLOUD_ASSET_TYPES
        for hint in asset_hints
    ):
        return False

    normalized_title = str(title or "").strip().lower()
    return normalized_title.startswith(_TITLE_PREFIXES) and (
        normalized_title.endswith(_TITLE_SUFFIXES)
        or " data exposure" in normalized_title
    )


def vulnerability_finding_evidence_is_reportable(
    vuln_type: str,
    title: str,
    evidence: object,
    asset_hints: Iterable[str] = (),
) -> bool:
    """Gate legacy finding rows that embed validation inventory in evidence."""

    normalized_type = str(vuln_type or "").strip().upper()
    if normalized_type in _INVENTORY_ONLY_VULNERABILITY_TYPES:
        return False
    normalized_title = str(title or "").strip().lower()
    if normalized_type == "DETERMINISTIC_KEY_EXPOSURE" or normalized_title.startswith(
        "active exposed "
    ):
        return True
    if is_deterministic_cloud_exposure(normalized_type, title, asset_hints):
        return True
    proof = parse_validated_detail(evidence)
    status = str(proof["validation_status"] or "").strip().upper()
    return not status or status == "VALIDATED"


def is_reportable_cloud_validation_method(asset_type: str, validation_method: str) -> bool:
    asset = normalize_cloud_exposure_asset_type(asset_type)
    method = str(validation_method or "").strip().lower()
    if method in PROVIDER_KEY_VALIDATION_METHODS.get(asset, frozenset()):
        return True
    if method in CLOUD_DATA_VALIDATION_METHODS.get(asset, frozenset()):
        return True
    if asset in STORAGE_CLOUD_ASSET_TYPES and method in STORAGE_LISTING_VALIDATION_METHODS:
        return True
    return asset in STORAGE_CLOUD_ASSET_TYPES and method in STORAGE_METADATA_VALIDATION_METHODS


def cloud_validation_requires_stable_proof(asset_type: str, validation_method: str) -> bool:
    asset = normalize_cloud_exposure_asset_type(asset_type)
    method = str(validation_method or "").strip().lower()
    return (
        method in PROVIDER_KEY_VALIDATION_METHODS.get(asset, frozenset())
        or method in CLOUD_DATA_VALIDATION_METHODS.get(asset, frozenset())
    ) or (
        asset in STORAGE_CLOUD_ASSET_TYPES
        and method in STORAGE_LISTING_VALIDATION_METHODS
    )


def _has_stable_validation_proof(validation_method: str, *proof_values: object) -> bool:
    method = str(validation_method or "").strip()
    if not method:
        return False
    for proof_value in proof_values:
        proof = str(proof_value or "").strip()
        if not proof:
            continue
        parsed = parse_validated_detail(f"VALIDATED:{method}:{proof}")
        if str(parsed["validation_status"] or "").strip().upper() == "VALIDATED":
            return True
    return False


def _has_concrete_storage_metadata_probe_evidence(*proof_values: object) -> bool:
    text = " ".join(str(value or "").strip() for value in proof_values if str(value or "").strip())
    if not text:
        return False
    lowered = text.lower()
    return not any(marker in lowered for marker in _LOW_SIGNAL_STORAGE_METADATA_MARKERS)


def is_reportable_cloud_validation(
    asset_type: str,
    validation_status: str,
    validation_method: str,
    *,
    evidence: object = None,
    notes: object = None,
    require_stable_proof: bool = False,
) -> bool:
    reportable = (
        str(validation_status or "").strip().upper() == "VALIDATED"
        and is_reportable_cloud_validation_method(asset_type, validation_method)
    )
    if not reportable:
        return False
    asset = normalize_cloud_exposure_asset_type(asset_type)
    method = str(validation_method or "").strip().lower()
    if (
        require_stable_proof
        and asset in STORAGE_CLOUD_ASSET_TYPES
        and method in STORAGE_METADATA_VALIDATION_METHODS
    ):
        return _has_concrete_storage_metadata_probe_evidence(evidence, notes)
    if require_stable_proof and cloud_validation_requires_stable_proof(
        asset_type,
        validation_method,
    ):
        return _has_stable_validation_proof(validation_method, evidence, notes)
    return True


def effective_cloud_validation_status(
    asset_type: str,
    validation_status: str,
    validation_method: str,
    *,
    evidence: object = None,
    notes: object = None,
    require_stable_proof: bool = True,
) -> str:
    """Return report-facing status without losing raw validation inventory."""

    stored_status = str(validation_status or "").strip().upper()
    if stored_status != "VALIDATED":
        return stored_status
    if is_reportable_cloud_validation(
        asset_type,
        stored_status,
        validation_method,
        evidence=evidence,
        notes=notes,
        require_stable_proof=require_stable_proof,
    ):
        return "VALIDATED"
    return "UNVERIFIED"


def effective_validation_status(
    asset_type: str,
    validation_status: str,
    validation_method: str,
    *,
    evidence: object = None,
    notes: object = None,
    require_stable_proof: bool = True,
) -> str:
    """Return display-facing validation status without changing report gates."""

    stored_status = str(validation_status or "").strip().upper()
    if stored_status != "VALIDATED":
        return stored_status
    if effective_cloud_validation_status(
        asset_type,
        stored_status,
        validation_method,
        evidence=evidence,
        notes=notes,
        require_stable_proof=require_stable_proof,
    ) == "VALIDATED":
        return "VALIDATED"
    if require_stable_proof and _has_stable_validation_proof(validation_method, evidence, notes):
        return "VALIDATED"
    return "UNVERIFIED"


def _cloud_validation_columns(con: sqlite3.Connection) -> set[str]:
    try:
        return {
            str(row[1])
            for row in con.execute("PRAGMA table_info(cloud_validation_results)").fetchall()
        }
    except sqlite3.Error:
        return set()


def latest_cloud_validation_reportability_index(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    require_stable_proof: bool = False,
) -> dict[tuple[str, str], bool]:
    """Return reportability for the latest validation row per cloud resource."""

    columns = _cloud_validation_columns(con)
    if not {"asset_type", "identifier", "validation_status"}.issubset(columns):
        return {}
    method_expr = "validation_method" if "validation_method" in columns else "NULL"
    evidence_expr = "evidence" if "evidence" in columns else "NULL"
    notes_expr = "notes" if "notes" in columns else "NULL"
    checked_expr = "COALESCE(checked_at, '')" if "checked_at" in columns else "''"
    id_expr = "id" if "id" in columns else "0"
    try:
        rows = con.execute(
            f"""
            SELECT asset_type, identifier, validation_status, {method_expr},
                   {evidence_expr}, {notes_expr}, {checked_expr}, {id_expr}
            FROM cloud_validation_results
            WHERE engagement_id=?
            """,
            (engagement_id,),
        ).fetchall()
    except sqlite3.Error:
        return {}

    index: dict[tuple[str, str], bool] = {}
    ordered_rows = sorted(
        rows,
        key=lambda row: (
            normalize_cloud_exposure_asset_type(str(row[0] or "")),
            str(row[1] or "").strip().lower(),
            str(row[6] or ""),
            int(row[7] or 0),
        ),
    )
    for (
        asset_raw,
        identifier_raw,
        status_raw,
        method_raw,
        evidence_raw,
        notes_raw,
        _checked_at,
        _row_id,
    ) in ordered_rows:
        asset_type = normalize_cloud_exposure_asset_type(str(asset_raw or ""))
        identifier = str(identifier_raw or "").strip().lower()
        if not asset_type or not identifier:
            continue
        method = str(method_raw or "").strip()
        reportable = is_reportable_cloud_validation(
            asset_type,
            str(status_raw or ""),
            method,
            evidence=evidence_raw,
            notes=notes_raw,
            require_stable_proof=require_stable_proof,
        )
        index[(asset_type, identifier)] = reportable
    return index


def linked_cloud_validation_reportability(
    validation_index: Mapping[tuple[str, str], bool],
    asset_types: Iterable[str],
    identifier: str,
) -> bool | None:
    """Return latest linked reportability when a cloud validation row exists."""

    normalized_identifier = str(identifier or "").strip().lower()
    if not normalized_identifier:
        return None
    matches: list[bool] = []
    for raw_asset_type in asset_types:
        asset_type = normalize_cloud_exposure_asset_type(str(raw_asset_type or ""))
        if not asset_type:
            continue
        key = (asset_type, normalized_identifier)
        if key in validation_index:
            matches.append(validation_index[key] is True)
    if not matches:
        return None
    return any(matches)
