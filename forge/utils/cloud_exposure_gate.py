from __future__ import annotations

from collections.abc import Iterable
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


def is_reportable_cloud_validation_method(asset_type: str, validation_method: str) -> bool:
    asset = normalize_cloud_exposure_asset_type(asset_type)
    method = str(validation_method or "").strip().lower()
    if method in CLOUD_DATA_VALIDATION_METHODS.get(asset, frozenset()):
        return True
    if asset in STORAGE_CLOUD_ASSET_TYPES and method in STORAGE_LISTING_VALIDATION_METHODS:
        return True
    return asset in STORAGE_CLOUD_ASSET_TYPES and method in STORAGE_METADATA_VALIDATION_METHODS


def cloud_validation_requires_stable_proof(asset_type: str, validation_method: str) -> bool:
    asset = normalize_cloud_exposure_asset_type(asset_type)
    method = str(validation_method or "").strip().lower()
    return method in CLOUD_DATA_VALIDATION_METHODS.get(asset, frozenset()) or (
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
    if require_stable_proof and cloud_validation_requires_stable_proof(
        asset_type,
        validation_method,
    ):
        return _has_stable_validation_proof(validation_method, evidence, notes)
    return True


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
                   {evidence_expr}, {notes_expr}
            FROM cloud_validation_results
            WHERE engagement_id=?
            ORDER BY asset_type ASC, identifier ASC, {checked_expr} ASC, {id_expr} ASC
            """,
            (engagement_id,),
        ).fetchall()
    except sqlite3.Error:
        return {}

    index: dict[tuple[str, str], bool] = {}
    for asset_raw, identifier_raw, status_raw, method_raw, evidence_raw, notes_raw in rows:
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
