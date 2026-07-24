from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from forge.reporting.dashboard import (
    _normalized_cloud_asset_type_sql,
    _relation_evidence_preview,
    _table_columns,
    _table_exists,
)
from forge.utils.cloud_exposure_gate import (
    effective_validation_status,
    is_reportable_cloud_validation,
    normalize_cloud_exposure_asset_type,
)

_FORBIDDEN_METADATA_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "client_secret",
    "credential",
    "credentials",
    "key",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}


def _safe_json_loads(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key or "").lower()).strip("_")
    return bool(
        normalized
        and (
            normalized in _FORBIDDEN_METADATA_KEYS
            or normalized.endswith(("_token", "_secret", "_password", "_api_key", "_apikey", "_key"))
            or "client_secret" in normalized
            or "raw_secret" in normalized
            or "raw_token" in normalized
        )
    )


def _scrub_metadata(value: Any) -> dict[str, Any]:
    def scrub(current: Any) -> Any:
        if isinstance(current, dict):
            return {
                str(key): scrub(raw_value)
                for key, raw_value in current.items()
                if not _is_sensitive_key(str(key))
            }
        if isinstance(current, list):
            return [scrub(item) for item in current]
        if current is None or isinstance(current, (str, int, float, bool)):
            return current
        return str(current)

    scrubbed = scrub(value)
    return scrubbed if isinstance(scrubbed, dict) else {}


def _cloud_asset_row(row: sqlite3.Row) -> dict[str, Any]:
    stored_type = str(row["asset_type"] or "").strip().lower()
    asset_type = normalize_cloud_exposure_asset_type(stored_type)
    stored_status = str(row["validation_status"] or "").strip().upper()
    method = str(row["validation_method"] or "").strip()
    raw_metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    metadata = _scrub_metadata(raw_metadata)
    reportable = bool(
        stored_status
        and is_reportable_cloud_validation(
            asset_type,
            stored_status,
            method,
            evidence=row["evidence"],
            notes=row["notes"],
            require_stable_proof=True,
        )
    )
    return {
        "asset_type": asset_type,
        "stored_asset_type": stored_type,
        "identifier": str(row["identifier"] or ""),
        "provider_identifier": str(row["display_identifier"] or row["identifier"] or ""),
        "source": str(row["source"] or ""),
        "metadata": metadata,
        "provenance": _relation_evidence_preview(metadata),
        "artifact_provenance": metadata.get("artifact_provenance") is True,
        "artifact_source_seed_id": metadata.get("artifact_source_seed_id"),
        "artifact_source_url": str(metadata.get("source_url") or ""),
        "artifact_source_file": str(metadata.get("source_file") or ""),
        "artifact_extract_rule": str(metadata.get("extract_rule") or ""),
        "artifact_format": str(metadata.get("format") or ""),
        "validation_status": effective_validation_status(
            asset_type,
            stored_status or "UNVALIDATED",
            method,
            evidence=row["evidence"],
            notes=row["notes"],
            require_stable_proof=True,
        ),
        "stored_validation_status": stored_status or "UNVALIDATED",
        "validation_reportable": reportable,
        "validation_method": method,
        "http_status": int(row["http_status"]) if row["http_status"] is not None else None,
        "discovered_at": str(row["discovered_at"] or ""),
        "checked_at": str(row["checked_at"] or ""),
    }


def cloud_assets_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 200,
) -> list[dict[str, Any]]:
    if not _table_exists(con, "cloud_assets"):
        return []
    cloud_columns = _table_columns(con, "cloud_assets")
    provider_expr = (
        "COALESCE(NULLIF(ca.provider_identifier, ''), ca.identifier) AS display_identifier"
        if "provider_identifier" in cloud_columns
        else "ca.identifier AS display_identifier"
    )
    source_expr = "ca.source" if "source" in cloud_columns else "NULL AS source"
    metadata_expr = "ca.metadata_json" if "metadata_json" in cloud_columns else "'{}' AS metadata_json"
    discovered_expr = (
        "CAST(ca.discovered_at AS TEXT) AS discovered_at"
        if "discovered_at" in cloud_columns
        else "NULL AS discovered_at"
    )
    order_expr = (
        "COALESCE(ca.discovered_at, '') DESC, ca.id DESC"
        if "discovered_at" in cloud_columns
        else "ca.id DESC"
    )
    validation_select = """
           NULL AS validation_status,
           NULL AS validation_method,
           NULL AS http_status,
           NULL AS evidence,
           NULL AS notes,
           NULL AS checked_at
    """
    validation_join = ""
    if _table_exists(con, "cloud_validation_results"):
        ca_key = _normalized_cloud_asset_type_sql("ca.asset_type")
        cvr_key = _normalized_cloud_asset_type_sql("cvr_latest.asset_type")
        validation_select = """
               cvr.validation_status,
               cvr.validation_method,
               cvr.http_status,
               cvr.evidence,
               cvr.notes,
               CAST(cvr.checked_at AS TEXT) AS checked_at
        """
        validation_join = f"""
        LEFT JOIN cloud_validation_results cvr
          ON cvr.id = (
              SELECT cvr_latest.id
              FROM cloud_validation_results cvr_latest
              WHERE cvr_latest.engagement_id=ca.engagement_id
                AND {cvr_key}={ca_key}
                AND cvr_latest.identifier=ca.identifier
              ORDER BY COALESCE(cvr_latest.checked_at, '') DESC, cvr_latest.id DESC
              LIMIT 1
          )
        """
    rows = con.execute(
        f"""
        SELECT ca.asset_type,
               ca.identifier,
               {provider_expr},
               {source_expr},
               {metadata_expr},
               {discovered_expr},
               {validation_select}
        FROM cloud_assets ca
        {validation_join}
        WHERE ca.engagement_id=?
        ORDER BY {order_expr}
        LIMIT ?
        """,
        (engagement_id, limit),
    ).fetchall()
    return [_cloud_asset_row(row) for row in rows]
