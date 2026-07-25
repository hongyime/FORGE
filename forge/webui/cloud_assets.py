from __future__ import annotations

import sqlite3
from typing import Any

from forge.reporting.dashboard import (
    _normalized_cloud_asset_type_sql,
    _relation_evidence_preview,
    _table_columns,
    _table_exists,
)
from forge.utils.cloud_asset_graph_metadata import stored_cloud_asset_graph_metadata
from forge.utils.cloud_exposure_gate import (
    effective_validation_status,
    is_reportable_cloud_validation,
    normalize_cloud_exposure_asset_type,
)

def _cloud_asset_row(row: sqlite3.Row) -> dict[str, Any]:
    stored_type = str(row["asset_type"] or "").strip().lower()
    asset_type = normalize_cloud_exposure_asset_type(stored_type)
    stored_status = str(row["validation_status"] or "").strip().upper()
    method = str(row["validation_method"] or "").strip()
    metadata = stored_cloud_asset_graph_metadata(row["metadata_json"])
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
