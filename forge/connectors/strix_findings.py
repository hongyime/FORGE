"""Offline import of Strix JSON findings as scoped active-validation evidence.

Backlog item: Do Next #18 — ``strix_findings_import`` connector.
Research: ``docs/competitive_research_strix_cairn_muraena.md`` §1.5, §5.4 Wave 1.

This mirrors :mod:`forge.connectors.validation_import` (which handles Burp
Suite / JUnit DAST XML) for a different input format. Strix emits a JSON
findings report; we accept it as import-only, scope-gated validation
evidence and never shell out to Strix, never auto-promote exploits to
reportable findings, and never persist raw request/response bodies.

The input shape is::

    {
      "schema": "strix.findings.v1",
      "findings": [
        {
          "title": "SQL injection in /search",
          "severity": "high",
          "description": "...",
          "proof": "payload: ...; response bytes: ...",
          "cvss_score": 8.6,
          "owasp_category": "A03:2021 - Injection",
          "affected_url": "https://api.acme.example/search?q=..."
        },
        ...
      ]
    }

The ``findings`` key is required; everything else is best-effort. Items
without an in-scope ``affected_url`` are skipped with a reason. All items
land as ``active_validation_jobs`` + ``active_validation_runs`` rows with
``method='fixture_replay'`` / ``mode='lab'`` — exactly matching how the
Burp XML path records evidence. Downstream reporting treats this as
non-reportable until the normal validation gate promotes it, same as any
other import.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from forge.connectors.validation_import_shared import (
    MAX_VALIDATION_XML_BYTES,
    ValidationArtifactImportConfig,
    _audit_validation_import,
    _clean_mapping,
    _existing_import_job_id,
    _insert_validation_job,
    _insert_validation_run,
    _normalize_severity,
    _normalize_target_url,
    _normalized_limit,
    _scope_for_engagement,
    _ValidationEvidence,
)
from forge.opsec.scope_gate import ScopeViolationError, assert_url_in_scope
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query
from forge.utils.intel.observations import redact_unsafe_text

__all__ = [
    "SUPPORTED_STRIX_IMPORT_CONNECTORS",
    "MAX_STRIX_JSON_BYTES",
    "StrixFindingsImportConfig",
    "import_strix_findings",
    "parse_strix_findings_json",
]

SUPPORTED_STRIX_IMPORT_CONNECTORS = ("strix_findings_import",)
MAX_STRIX_JSON_BYTES = MAX_VALIDATION_XML_BYTES  # 10 MiB cap, same as XML path.

# ``StrixFindingsImportConfig`` is a type-alias/wrapper so callers can
# import a strix-labelled config while keeping the exact shape of
# ValidationArtifactImportConfig the CLI already passes.
StrixFindingsImportConfig = ValidationArtifactImportConfig


def import_strix_findings(
    con: sqlite3.Connection,
    config: ValidationArtifactImportConfig,
    *,
    report_text: str | None = None,
) -> dict[str, Any]:
    """Import a Strix JSON findings report as scoped active-validation evidence.

    Mirrors :func:`forge.connectors.validation_import.import_validation_artifact`
    for Strix's JSON schema. See module docstring for the input shape.
    """

    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    if connector_id not in SUPPORTED_STRIX_IMPORT_CONNECTORS:
        raise ValueError(
            "strix findings import connector must be one of "
            f"{', '.join(SUPPORTED_STRIX_IMPORT_CONNECTORS)}"
        )
    engagement_id = int(config.engagement_id)
    scope = _scope_for_engagement(con, engagement_id)
    text = report_text if report_text is not None else _read_report_text(config.report_path)
    artifact_hash = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    candidates = parse_strix_findings_json(text)
    limit = _normalized_limit(config.limit)
    selected = candidates[:limit] if limit is not None else candidates
    omitted_by_limit = max(0, len(candidates) - len(selected))
    target_filter = _normalize_target_url(config.target)
    persisted_jobs = 0
    persisted_runs = 0
    duplicate_count = 0
    skipped: list[dict[str, str]] = []

    for item in selected:
        if target_filter and not item.target_url.startswith(target_filter):
            skipped.append({"reason": "target_url_not_matched", "target_url": item.target_url})
            continue
        try:
            assert_url_in_scope(item.target_url, scope)
        except ScopeViolationError:
            skipped.append({"reason": "target_url_out_of_scope", "target_url": item.target_url})
            continue
        if config.dry_run:
            continue
        external_id = _strix_external_id(
            connector_id=connector_id,
            artifact_hash=artifact_hash,
            item=item,
        )
        if _existing_import_job_id(
            con,
            engagement_id=engagement_id,
            external_id=external_id,
        ):
            duplicate_count += 1
            continue
        job_id = _insert_validation_job(
            con,
            engagement_id=engagement_id,
            connector_id=connector_id,
            item=item,
            artifact_hash=artifact_hash,
            external_id=external_id,
            report_path=config.report_path,
            operator=config.operator,
        )
        persisted_jobs += 1
        _insert_validation_run(
            con,
            engagement_id=engagement_id,
            job_id=job_id,
            connector_id=connector_id,
            item=item,
            artifact_hash=artifact_hash,
            external_id=external_id,
            operator=config.operator,
        )
        persisted_runs += 1

    result = {
        "schema_version": "forge.connector.strix_findings_import.v1",
        "execution_policy": (
            "dry_run_no_validation_evidence_written"
            if config.dry_run
            else "writes_active_validation_artifact_evidence"
        ),
        "connector_id": connector_id,
        "engagement_id": engagement_id,
        "target": target_filter,
        "status": "completed",
        "parsed_count": len(candidates),
        "total_count": len(candidates),
        "selected_count": len(selected),
        "omitted_count": omitted_by_limit + len(skipped),
        "omitted_by_limit_count": omitted_by_limit,
        "persisted_count": persisted_runs,
        "persisted_job_count": persisted_jobs,
        "persisted_run_count": persisted_runs,
        "duplicate_count": duplicate_count,
        "would_persist_count": max(0, len(selected) - len(skipped)) if config.dry_run else 0,
        "skipped_count": len(skipped),
        "skipped": skipped[:25],
        "source": "strix_findings_import",
        "report_file": str(config.report_path or ""),
        "artifact_hash": artifact_hash,
        "privacy": "Strix JSON is parsed locally; proof text is truncated and secret-looking URL query parameters are stripped.",
    }
    if not config.dry_run:
        _audit_validation_import(con, config, result=result)
        con.commit()
    return result


def parse_strix_findings_json(text: str) -> list[_ValidationEvidence]:
    """Parse a Strix JSON findings report into bounded validation evidence.

    Accepts either a top-level ``{"findings": [...]}`` object or a bare
    JSON array ``[{...}, {...}]``. Returns deduped
    :class:`_ValidationEvidence` rows ready for the scoped persistence
    path.
    """

    payload = _parse_strix_json(text)
    findings = _extract_findings(payload)
    rows: list[_ValidationEvidence] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in findings:
        if not isinstance(raw, Mapping):
            continue
        target_url = _normalize_target_url(raw.get("affected_url"))
        if not target_url:
            continue
        title = _bounded_text(raw.get("title"), 180) or "Strix finding"
        severity = _strix_severity(raw)
        confidence = _bounded_text(raw.get("confidence"), 40)
        proof_text = _sanitize_text(raw.get("proof"), 480)
        description = _sanitize_text(raw.get("description"), 480)
        owasp = _bounded_text(raw.get("owasp_category"), 80)
        cvss = _coerce_cvss(raw.get("cvss_score"))
        strix_id = _bounded_text(raw.get("id"), 80)
        references = _normalize_references(raw.get("references"))
        tags = _normalize_tags(raw.get("tags"))
        metadata: dict[str, Any] = {
            "strix_id": strix_id,
            "owasp_category": owasp,
            "cvss_score": cvss,
            "description": description,
            "proof": proof_text,
            "references": references,
            "tags": tags,
            "request_response_captured": False,
            "body_captured": False,
            "destructive_actions": False,
        }
        key = (target_url, title.lower(), "strix_findings_json")
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            _ValidationEvidence(
                target_url=target_url,
                title=title,
                severity=severity,
                confidence=confidence,
                proof_type="strix_findings_json",
                scanner="strix",
                metadata=_clean_mapping(metadata),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _read_report_text(path: Path | None) -> str:
    if path is None:
        raise ValueError("report_path is required")
    size = path.stat().st_size
    if size > MAX_STRIX_JSON_BYTES:
        raise ValueError("strix findings JSON is too large")
    return path.read_text(encoding="utf-8")


def _parse_strix_json(text: str) -> Any:
    if len(text.encode("utf-8")) > MAX_STRIX_JSON_BYTES:
        raise ValueError("strix findings JSON is too large")
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("strix findings report is not valid JSON") from exc


def _extract_findings(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        findings = payload.get("findings")
        if findings is None:
            # Also support ``results`` and ``issues`` keys for forward compat.
            findings = payload.get("results") or payload.get("issues") or []
        if isinstance(findings, list):
            return [item for item in findings if isinstance(item, Mapping)]
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    return []


def _strix_severity(raw: Mapping[str, Any]) -> str:
    severity = raw.get("severity")
    if severity:
        return _normalize_severity(severity)
    cvss = _coerce_cvss(raw.get("cvss_score"))
    if cvss is None:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "info"


def _coerce_cvss(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if parsed < 0.0:
        return 0.0
    if parsed > 10.0:
        return 10.0
    return round(parsed, 1)


def _normalize_references(value: object) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        items: list[str] = []
        for entry in value:
            cleaned = _bounded_text(entry, 240)
            if cleaned and cleaned not in items:
                items.append(cleaned)
            if len(items) >= 10:
                break
        return items
    cleaned = _bounded_text(value, 240)
    return [cleaned] if cleaned else []


def _normalize_tags(value: object) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value]
    else:
        return []
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        cleaned = _bounded_text(part, 48).lower()
        if cleaned and cleaned not in out:
            out.append(cleaned)
        if len(out) >= 20:
            break
    return out


def _bounded_text(value: object, limit: int) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]


def _sanitize_text(value: object, limit: int) -> str:
    # Strix proof/description is free-form text. Pass through the shared
    # unsafe-text redactor first so embedded ``token=...``, ``password=...``,
    # private keys, and ``user:password@`` URL credentials are blanked
    # BEFORE the URL-query sanitiser runs.
    redacted = redact_unsafe_text(_bounded_text(value, limit))
    return strip_sensitive_url_query(redacted)


def _strix_external_id(
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
