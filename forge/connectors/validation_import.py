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

from forge.connectors.strix_findings import import_strix_findings
from forge.connectors.validation_import_shared import (
    MAX_VALIDATION_XML_BYTES,
    ValidationArtifactImportConfig,
    _ValidationEvidence,
    _audit_validation_import,
    _clean_mapping,
    _existing_import_job_id,
    _external_id,
    _insert_validation_job,
    _insert_validation_run,
    _normalize_severity,
    _normalize_target_url,
    _normalized_limit,
    _scope_for_engagement,
)
from forge.opsec.scope_gate import (
    ScopeViolationError,
    assert_url_in_scope,
    scope_entries_from_payload,
)
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

SUPPORTED_VALIDATION_IMPORT_CONNECTORS = ("burp_dast_xml",)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def import_validation_artifact(
    con: sqlite3.Connection,
    config: ValidationArtifactImportConfig,
    *,
    report_text: str | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    # Delegate the JSON-shaped Strix connector to its own module so the XML
    # path below stays XML-only. See backlog #18 / strix_findings.py.
    if connector_id == "strix_findings_import":
        return import_strix_findings(con, config, report_text=report_text)
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




def _first_url(value: object) -> str:
    match = _URL_RE.search(str(value or ""))
    return _normalize_target_url(match.group(0)) if match else ""




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
