"""Short-lived SQLite claims for cloud validation sweep workers."""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema

_ASSET_TYPE_ALIASES = {
    "azure_blob_storage": "azure_blob",
    "digitalocean_spaces": "do_spaces",
    "google_cloud_storage": "gcs",
    "s3": "aws_s3",
}


def _normalize_cloud_asset_type(value: object) -> str:
    normalized = str(value or "").strip().lower()
    return _ASSET_TYPE_ALIASES.get(normalized, normalized)


def _normalized_cloud_asset_type_sql(column: str) -> str:
    return (
        f"CASE LOWER({column}) "
        "WHEN 'azure_blob_storage' THEN 'azure_blob' "
        "WHEN 'digitalocean_spaces' THEN 'do_spaces' "
        "WHEN 'google_cloud_storage' THEN 'gcs' "
        "WHEN 's3' THEN 'aws_s3' "
        f"ELSE LOWER({column}) END"
    )


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _lease_seconds() -> int:
    return _int_env("FORGE_VALIDATION_CLAIM_LEASE_SECONDS", 900, minimum=60, maximum=86400)


def _claim_owner() -> str:
    return f"{os.getpid()}:{time.time_ns()}"


def _purge_stale(con: sqlite3.Connection, claim_type: str) -> None:
    con.execute(
        """
        DELETE FROM validation_claims
        WHERE claim_type=?
          AND expires_at <= CURRENT_TIMESTAMP
        """,
        (claim_type,),
    )


def claim_pending_cloud_key_rows(
    engagement_id: int,
    db_path: Path,
    *,
    cloud_service_placeholders: str,
    pattern_clause: str,
    query_tail_params: tuple[Any, ...],
    only_unattempted: bool,
    limit: int,
) -> tuple[list[dict[str, Any]], str, list[int]]:
    owner = _claim_owner()
    lease_modifier = f"+{_lease_seconds()} seconds"
    claimed_rows: list[dict[str, Any]] = []
    claimed_key_ids: list[int] = []
    con = sqlite3.connect(db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute("BEGIN IMMEDIATE")
        _purge_stale(con, "key")
        rows = con.execute(
            f"""
            SELECT ksf.id,
                   ksf.engagement_id,
                   ksf.domain,
                   ksf.service,
                   ksf.pattern_name,
                   ksf.source_backend,
                   ksf.source_url,
                   ksf.repo_name,
                   ksf.key_enc,
                   ksf.validation_detail
            FROM key_scanner_findings ksf
            LEFT JOIN validation_claims vc
              ON vc.engagement_id = ksf.engagement_id
             AND vc.claim_type = 'key'
             AND vc.key_id = ksf.id
            WHERE ksf.engagement_id=?
              AND (
                    ksf.service IN ({cloud_service_placeholders})
                    OR ({pattern_clause})
                  )
              AND COALESCE(ksf.validation_state, 'UNCONFIRMED') IN ('UNCONFIRMED', 'ERROR')
              AND (? = 0 OR ksf.validated_at IS NULL)
              AND vc.id IS NULL
            ORDER BY ksf.id ASC
            LIMIT ?
            """,
            (
                engagement_id,
                *query_tail_params,
                1 if only_unattempted else 0,
                max(0, int(limit)),
            ),
        ).fetchall()
        for row in rows:
            key_id = int(row["id"])
            cursor = con.execute(
                """
                INSERT OR IGNORE INTO validation_claims
                    (engagement_id, claim_type, key_id, owner, expires_at)
                VALUES (?, 'key', ?, ?, datetime('now', ?))
                """,
                (engagement_id, key_id, owner, lease_modifier),
            )
            if cursor.rowcount != 1:
                continue
            claimed_key_ids.append(key_id)
            claimed_rows.append(dict(row))
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    return claimed_rows, owner, claimed_key_ids


def claim_pending_cloud_asset_rows(
    engagement_id: int,
    db_path: Path,
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], str, list[tuple[str, str]]]:
    owner = _claim_owner()
    lease_modifier = f"+{_lease_seconds()} seconds"
    claimed_rows: list[dict[str, Any]] = []
    claimed_assets: list[tuple[str, str]] = []
    con = sqlite3.connect(db_path, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute("BEGIN IMMEDIATE")
        _purge_stale(con, "asset")
        ca_type_expr = _normalized_cloud_asset_type_sql("ca.asset_type")
        cvr_type_expr = _normalized_cloud_asset_type_sql("cvr.asset_type")
        vc_type_expr = _normalized_cloud_asset_type_sql("vc.asset_type")
        rows = con.execute(
            f"""
            SELECT ca.asset_type,
                   ca.identifier,
                   COALESCE(NULLIF(ca.provider_identifier, ''), ca.identifier) AS provider_identifier
            FROM cloud_assets ca
            LEFT JOIN cloud_validation_results cvr
              ON cvr.engagement_id = ca.engagement_id
             AND {cvr_type_expr} = {ca_type_expr}
             AND LOWER(cvr.identifier) = LOWER(ca.identifier)
            LEFT JOIN validation_claims vc
              ON vc.engagement_id = ca.engagement_id
             AND vc.claim_type = 'asset'
             AND {vc_type_expr} = {ca_type_expr}
             AND LOWER(vc.identifier) = LOWER(ca.identifier)
            WHERE ca.engagement_id=?
              AND cvr.id IS NULL
              AND vc.id IS NULL
            ORDER BY ca.id ASC
            LIMIT ?
            """,
            (engagement_id, max(0, int(limit))),
        ).fetchall()
        claimed_keys: set[tuple[str, str]] = set()
        for row in rows:
            asset_type = str(row["asset_type"] or "")
            identifier = str(row["identifier"] or "")
            if not asset_type.strip() or not identifier.strip():
                continue
            normalized_key = (
                _normalize_cloud_asset_type(asset_type),
                identifier.strip().lower(),
            )
            if normalized_key in claimed_keys:
                continue
            claimed_keys.add(normalized_key)
            cursor = con.execute(
                """
                INSERT OR IGNORE INTO validation_claims
                    (engagement_id, claim_type, asset_type, identifier, owner, expires_at)
                VALUES (?, 'asset', ?, ?, ?, datetime('now', ?))
                """,
                (engagement_id, asset_type, identifier, owner, lease_modifier),
            )
            if cursor.rowcount != 1:
                continue
            claimed_assets.append((asset_type, identifier))
            claimed_rows.append(dict(row))
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    return claimed_rows, owner, claimed_assets


def release_validation_key_claims(
    engagement_id: int,
    db_path: Path,
    *,
    owner: str,
    key_ids: list[int],
) -> None:
    if not key_ids:
        return
    con = sqlite3.connect(db_path)
    try:
        placeholders = ",".join("?" for _ in key_ids)
        con.execute(
            f"""
            DELETE FROM validation_claims
            WHERE engagement_id=?
              AND claim_type='key'
              AND owner=?
              AND key_id IN ({placeholders})
            """,
            (engagement_id, owner, *key_ids),
        )
        con.commit()
    finally:
        con.close()


def release_validation_asset_claims(
    engagement_id: int,
    db_path: Path,
    *,
    owner: str,
    assets: list[tuple[str, str]],
) -> None:
    if not assets:
        return
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            DELETE FROM validation_claims
            WHERE engagement_id=?
              AND claim_type='asset'
              AND owner=?
              AND asset_type=?
              AND identifier=?
            """,
            [(engagement_id, owner, asset_type, identifier) for asset_type, identifier in assets],
        )
        con.commit()
    finally:
        con.close()
