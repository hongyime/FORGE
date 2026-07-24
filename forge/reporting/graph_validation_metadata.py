from __future__ import annotations

import sqlite3
from typing import Any

from forge.utils.cloud_exposure_gate import (
    effective_validation_status,
    is_reportable_cloud_validation,
    normalize_cloud_exposure_asset_type,
)
from forge.utils.validation_summary import safe_validation_summary


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})").fetchall()}
    except sqlite3.Error:
        return set()


def latest_cloud_validation_metadata_index(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[tuple[str, str], dict[str, Any]]:
    columns = _table_columns(con, "cloud_validation_results")
    if not {"asset_type", "identifier", "validation_status"}.issubset(columns):
        return {}

    provider_expr = (
        "COALESCE(NULLIF(provider_identifier, ''), identifier) AS provider_identifier"
        if "provider_identifier" in columns
        else "identifier AS provider_identifier"
    )
    method_expr = "validation_method" if "validation_method" in columns else "NULL AS validation_method"
    http_expr = "http_status" if "http_status" in columns else "NULL AS http_status"
    evidence_expr = "evidence" if "evidence" in columns else "NULL AS evidence"
    notes_expr = "notes" if "notes" in columns else "NULL AS notes"
    checked_expr = "checked_at" if "checked_at" in columns else "NULL AS checked_at"
    order_checked_expr = "COALESCE(checked_at, '')" if "checked_at" in columns else "''"
    order_id_expr = "id" if "id" in columns else "0"

    rows = con.execute(
        f"""
        SELECT asset_type,
               identifier,
               {provider_expr},
               validation_status,
               {method_expr},
               {http_expr},
               {evidence_expr},
               {notes_expr},
               {checked_expr}
        FROM cloud_validation_results
        WHERE engagement_id=?
        ORDER BY asset_type ASC,
                 identifier ASC,
                 {order_checked_expr} ASC,
                 {order_id_expr} ASC
        """,
        (engagement_id,),
    ).fetchall()

    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        asset_type = normalize_cloud_exposure_asset_type(str(row["asset_type"] or ""))
        identifier = str(row["identifier"] or "").strip().lower()
        if not asset_type or not identifier:
            continue
        index[(asset_type, identifier)] = _metadata_for_validation_row(asset_type, row)
    return index


def _metadata_for_validation_row(asset_type: str, row: sqlite3.Row) -> dict[str, Any]:
    stored_status = str(row["validation_status"] or "").strip().upper()
    method = str(row["validation_method"] or "").strip()
    evidence = row["evidence"]
    notes = row["notes"]
    metadata: dict[str, Any] = {
        "provider_identifier": str(row["provider_identifier"] or row["identifier"] or ""),
        "validation_asset_type": asset_type,
        "validation_status": effective_validation_status(
            asset_type,
            stored_status or "UNVALIDATED",
            method,
            evidence=evidence,
            notes=notes,
            require_stable_proof=True,
        ),
        "stored_validation_status": stored_status,
        "validation_method": method,
        "validation_reportable": is_reportable_cloud_validation(
            asset_type,
            stored_status,
            method,
            evidence=evidence,
            notes=notes,
            require_stable_proof=True,
        ),
        "validation_checked_at": str(row["checked_at"] or ""),
    }
    if row["http_status"] is not None:
        try:
            metadata["validation_http_status"] = int(row["http_status"])
        except (TypeError, ValueError):
            metadata["validation_http_status"] = str(row["http_status"])
    _add_safe_summary(metadata, "validation_evidence_summary", evidence)
    _add_safe_summary(metadata, "validation_notes", notes)
    return metadata


def _add_safe_summary(metadata: dict[str, Any], key: str, value: object) -> None:
    safe_value = safe_validation_summary(value)
    if safe_value:
        metadata[key] = safe_value
