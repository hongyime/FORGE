from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from forge.active_validation.evidence import active_validation_proof_summary
from forge.opsec.scope_gate import (
    ScopeViolationError,
    assert_url_in_scope,
    scope_entries_from_payload,
)
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

SUPPORTED_VALIDATION_IMPORT_CONNECTORS = ("burp_dast_xml",)
MAX_VALIDATION_XML_BYTES = 10 * 1024 * 1024
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


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


def import_validation_artifact(
    con: sqlite3.Connection,
    config: ValidationArtifactImportConfig,
    *,
    report_text: str | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    if connector_id not in SUPPORTED_VALIDATION_IMPORT_CONNECTORS:
        raise ValueError(
            "validation import connector must be one of "
            f"{', '.join(SUPPORTED_VALIDATION_IMPORT_CONNECTORS)}"
        )
    engagement_id = int(config.engagement_id)
    scope = _scope_for_engagement(con, engagement_id)
    text = report_text if report_text is not None else _read_report_text(config.report_path)
    artifact_hash = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    root = _parse_xml(text)
    candidates = _parse_validation_xml(root)
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
        external_id = _external_id(connector_id=connector_id, artifact_hash=artifact_hash, item=item)
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
        "schema_version": "forge.connector.validation_artifact_import.v1",
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
        "source": "validation_artifact_import",
        "report_file": str(config.report_path or ""),
        "artifact_hash": artifact_hash,
        "privacy": "Scanner XML is parsed locally; request/response bodies and secrets are not persisted.",
    }
    if not config.dry_run:
        _audit_validation_import(con, config, result=result)
        con.commit()
    return result


def _parse_validation_xml(root: ElementTree.Element) -> list[_ValidationEvidence]:
    tag = _tag_name(root.tag)
    if tag == "issues" or root.find(".//issue") is not None:
        return _dedupe_evidence(_parse_burp_issues(root))
    if tag in {"testsuite", "testsuites"} or root.find(".//testcase") is not None:
        return _dedupe_evidence(_parse_junit_cases(root))
    return []


def _parse_burp_issues(root: ElementTree.Element) -> list[_ValidationEvidence]:
    rows: list[_ValidationEvidence] = []
    for issue in root.findall(".//issue"):
        title = _bounded_text(_child_text(issue, "name") or _child_text(issue, "type"), 180)
        host = _child_text(issue, "host")
        path = _child_text(issue, "path") or _child_text(issue, "location")
        target_url = _normalize_target_url(urljoin(_host_base_url(host), path or ""))
        if not target_url:
            continue
        severity = _normalize_severity(_child_text(issue, "severity"))
        confidence = _bounded_text(_child_text(issue, "confidence"), 40)
        metadata = {
            "issue_type": _bounded_text(_child_text(issue, "type"), 80),
            "serial_number": _bounded_text(_child_text(issue, "serialNumber"), 80),
            "location": strip_sensitive_url_query(_bounded_text(_child_text(issue, "location"), 300)),
            "request_response_captured": False,
            "body_captured": False,
        }
        rows.append(
            _ValidationEvidence(
                target_url=target_url,
                title=title or "Burp DAST finding",
                severity=severity,
                confidence=confidence,
                proof_type="burp_issue_xml",
                scanner="burp",
                metadata=_clean_mapping(metadata),
            )
        )
    return rows


def _parse_junit_cases(root: ElementTree.Element) -> list[_ValidationEvidence]:
    rows: list[_ValidationEvidence] = []
    for testcase in root.findall(".//testcase"):
        failure = testcase.find("failure")
        error = testcase.find("error")
        evidence_node = failure if failure is not None else error
        if evidence_node is None:
            continue
        source_text = " ".join(
            filter(
                None,
                [
                    testcase.get("classname"),
                    testcase.get("name"),
                    evidence_node.get("message"),
                    evidence_node.text,
                ],
            )
        )
        target_url = _first_url(source_text)
        if not target_url:
            continue
        metadata = {
            "testcase": _bounded_text(testcase.get("name"), 180),
            "classname": _bounded_text(testcase.get("classname"), 180),
            "failure_type": _bounded_text(evidence_node.get("type") or _tag_name(evidence_node.tag), 80),
            "message": _sanitize_text(evidence_node.get("message"), 300),
            "body_captured": False,
        }
        rows.append(
            _ValidationEvidence(
                target_url=target_url,
                title=_bounded_text(evidence_node.get("message") or testcase.get("name"), 180)
                or "JUnit DAST validation",
                severity=_severity_from_text(source_text),
                confidence="",
                proof_type="junit_xml",
                scanner="junit",
                metadata=_clean_mapping(metadata),
            )
        )
    return rows


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


def _read_report_text(path: Path | None) -> str:
    if path is None:
        raise ValueError("report_path is required")
    size = path.stat().st_size
    if size > MAX_VALIDATION_XML_BYTES:
        raise ValueError("validation artifact XML is too large")
    return path.read_text(encoding="utf-8")


def _parse_xml(text: str) -> ElementTree.Element:
    lowered = text[:2048].lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("validation artifact XML with DOCTYPE/ENTITY is not accepted")
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ValueError("validation artifact is not valid XML") from exc


def _normalized_limit(value: int | None) -> int | None:
    if value is None:
        return None
    return max(1, min(int(value), 10000))


def _dedupe_evidence(items: list[_ValidationEvidence]) -> list[_ValidationEvidence]:
    rows: list[_ValidationEvidence] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (item.target_url, item.title.lower(), item.proof_type)
        if key in seen:
            continue
        seen.add(key)
        rows.append(item)
    return rows


def _tag_name(value: object) -> str:
    text = str(value or "")
    if "}" in text:
        text = text.rsplit("}", 1)[-1]
    return text.lower()


def _child_text(parent: ElementTree.Element, name: str) -> str:
    for child in list(parent):
        if _tag_name(child.tag) == name.lower():
            return _sanitize_text(child.text, 1000)
    return ""


def _host_base_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text.rstrip("/") + "/"
    return "https://" + text.strip("/").rstrip("/") + "/"


def _normalize_target_url(value: object) -> str:
    text = strip_sensitive_url_query(str(value or "").strip())
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return parsed._replace(netloc=parsed.netloc.lower()).geturl()


def _first_url(value: object) -> str:
    match = _URL_RE.search(str(value or ""))
    return _normalize_target_url(match.group(0)) if match else ""


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


def _severity_from_text(value: object) -> str:
    lowered = str(value or "").lower()
    for severity in ("critical", "high", "medium", "moderate", "low", "informational", "info"):
        if severity in lowered:
            return _normalize_severity(severity)
    return "info"


def _sanitize_text(value: object, limit: int) -> str:
    return strip_sensitive_url_query(_bounded_text(value, limit))


def _bounded_text(value: object, limit: int) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]


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
