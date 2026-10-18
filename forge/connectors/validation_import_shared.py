from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from forge.active_validation.evidence import active_validation_proof_summary
from forge.opsec.scope_gate import scope_entries_from_payload
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

MAX_VALIDATION_XML_BYTES = 10 * 1024 * 1024

@dataclass(frozen=True)
class ValidationArtifactImportConfig:
    connector_id: str
    engagement_id: int
    report_path: Path | None = None
    target: str = ""
    operator: str = "connector-import"
    dry_run: bool = False
    limit: int | None = None

@dataclass(frozen=True)
class _ValidationEvidence:
    target_url: str
    title: str
    severity: str
    confidence: str
    proof_type: str
    scanner: str
    metadata: Mapping[str, Any]

def _insert_validation_job(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    item: _ValidationEvidence,
    artifact_hash: str,
    external_id: str,
    report_path: Path | None,
    operator: str,
) -> int:
    metadata = {
        "connector_id": connector_id,
        "source": "validation_artifact_import",
        "artifact_hash": artifact_hash,
        "external_id": external_id,
        "artifact_name": str(report_path.name if report_path else ""),
        "proof_type": item.proof_type,
        "scanner": item.scanner,
        "severity": item.severity,
        "confidence": item.confidence,
        **dict(item.metadata),
    }
    cur = con.execute(
        """
        INSERT INTO active_validation_jobs (
            engagement_id, target_ref, target_kind, method, mode,
            status, approved, safe_profile, max_steps, requested_by,
            metadata_json, approved_at
        )
        VALUES (?, ?, 'service', 'fixture_replay', 'lab',
                'completed', 0, 'non_destructive', 1, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            engagement_id,
            item.target_url,
            str(operator or "connector-import"),
            json.dumps(_clean_mapping(metadata), sort_keys=True),
        ),
    )
    return int(cur.lastrowid)

def _insert_validation_run(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    connector_id: str,
    item: _ValidationEvidence,
    artifact_hash: str,
    external_id: str,
    operator: str,
) -> None:
    evidence: dict[str, Any] = {
        "job": {
            "id": job_id,
            "target_ref": item.target_url,
            "target_kind": "service",
            "method": "fixture_replay",
            "mode": "lab",
        },
        "source": "validation_artifact_import",
        "connector_id": connector_id,
        "artifact_hash": artifact_hash,
        "external_id": external_id,
        "target_url": item.target_url,
        "method": "fixture_replay",
        "proof_type": item.proof_type,
        "scanner": item.scanner,
        "finding": {
            "title": item.title,
            "severity": item.severity,
            "confidence": item.confidence,
        },
        "artifact_evidence": dict(item.metadata),
        "network_execution": False,
        "request_response_captured": False,
        "body_captured": False,
        "destructive_actions": False,
        "lateral_movement": False,
        "post_exploitation": False,
    }
    evidence["proof_summary"] = active_validation_proof_summary(
        {
            "method": {"id": "fixture_replay", "proof_kind": item.proof_type},
            "result": "evidence_imported",
            "evidence": evidence,
        }
    )
    con.execute(
        """
        INSERT INTO active_validation_runs (
            engagement_id, job_id, status, result, operator, evidence_json,
            completed_at
        )
        VALUES (?, ?, 'completed', 'evidence_imported', ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            engagement_id,
            job_id,
            str(operator or "connector-import"),
            json.dumps(_clean_mapping(evidence), sort_keys=True),
        ),
    )

def _audit_validation_import(
    con: sqlite3.Connection,
    config: ValidationArtifactImportConfig,
    *,
    result: Mapping[str, Any],
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'validation_artifact_import', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            str(result.get("connector_id") or config.connector_id),
            str(result.get("target") or "*"),
            (
                f"completed parsed={int(result.get('parsed_count') or 0)} "
                f"jobs={int(result.get('persisted_job_count') or 0)} "
                f"runs={int(result.get('persisted_run_count') or 0)} "
                f"duplicates={int(result.get('duplicate_count') or 0)} "
                f"skipped={int(result.get('skipped_count') or 0)}"
            ),
            str(config.operator or "connector-import"),
        ),
    )

def _scope_for_engagement(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?",
        (int(engagement_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"engagement not found: {engagement_id}")
    try:
        payload = json.loads(str(row["scope_json"] or "[]"))
    except json.JSONDecodeError:
        payload = []
    return scope_entries_from_payload(payload)

def _external_id(
    *,
    connector_id: str,
    artifact_hash: str,
    item: _ValidationEvidence,
) -> str:
    basis = "\n".join(
        [
            connector_id,
            artifact_hash,
            item.target_url,
            item.title.lower(),
            item.proof_type,
        ]
    )
    return "sha256:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()

def _existing_import_job_id(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    external_id: str,
) -> int | None:
    rows = con.execute(
        """
        SELECT id, metadata_json
        FROM active_validation_jobs
        WHERE engagement_id=?
          AND method='fixture_replay'
          AND mode='lab'
          AND status='completed'
        """,
        (int(engagement_id),),
    ).fetchall()
    for row in rows:
        try:
            metadata = json.loads(str(row["metadata_json"] or "{}"))
        except json.JSONDecodeError:
            metadata = {}
        if isinstance(metadata, dict) and metadata.get("external_id") == external_id:
            return int(row["id"])
    return None

def _normalized_limit(value: int | None) -> int | None:
    if value is None:
        return None
    return max(1, min(int(value), 10000))

def _normalize_target_url(value: object) -> str:
    text = strip_sensitive_url_query(str(value or "").strip())
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return parsed._replace(netloc=parsed.netloc.lower()).geturl()

def _normalize_severity(value: object) -> str:
    text = str(value or "").strip().lower()
    aliases = {
        "information": "info",
        "informational": "info",
        "medium": "medium",
        "moderate": "medium",
        "high": "high",
        "critical": "critical",
        "low": "low",
    }
    return aliases.get(text, text if text in {"info", "low", "medium", "high", "critical"} else "info")

def _clean_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in values.items():
        if value in (None, "", [], {}):
            continue
        lowered = str(key).lower()
        if any(token in lowered for token in ("password", "secret", "token", "authorization")):
            continue
        clean[str(key)] = value
    return clean

def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None
