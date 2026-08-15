from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from forge.opsec.scope_gate import assert_in_scope, scope_entries_from_payload
from forge.secrets.lifecycle import sync_secret_lifecycle

SUPPORTED_SECRET_IMPORT_CONNECTORS = ("gitleaks_local", "trufflehog_local")


@dataclass(frozen=True)
class SecretScanImportConfig:
    connector_id: str
    engagement_id: int
    domain: str
    report_path: Path | None = None
    repo_name: str = ""
    operator: str = "connector-import"


@dataclass(frozen=True)
class ParsedSecretFinding:
    source_backend: str
    service: str
    pattern_name: str
    source_url: str
    repo_name: str
    key_redacted: str
    validation_state: str
    validation_detail: str


def import_secret_scan_report(
    con: sqlite3.Connection,
    config: SecretScanImportConfig,
    *,
    report_text: str | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = _normalize_connector(config.connector_id)
    domain = str(config.domain or "").strip().lower().strip(".")
    if not domain:
        raise ValueError("domain is required for imported secret findings")
    _assert_domain_in_scope(con, int(config.engagement_id), domain)
    text = report_text
    if text is None:
        if config.report_path is None:
            raise ValueError("report_path is required")
        text = config.report_path.read_text(encoding="utf-8")

    findings = parse_secret_scan_report(
        connector_id,
        text,
        repo_name=config.repo_name,
    )
    persisted = 0
    skipped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.source_url, finding.pattern_name)
        if key in seen:
            skipped.append(
                {
                    "reason": "duplicate_in_report",
                    "source_url": finding.source_url,
                    "pattern_name": finding.pattern_name,
                }
            )
            continue
        seen.add(key)
        if not finding.source_url or not finding.pattern_name:
            skipped.append({"reason": "missing_required_fields"})
            continue
        _upsert_key_scanner_finding(
            con,
            engagement_id=int(config.engagement_id),
            domain=domain,
            finding=finding,
        )
        persisted += 1

    lifecycle = sync_secret_lifecycle(con, int(config.engagement_id))
    result = {
        "connector_id": connector_id,
        "engagement_id": int(config.engagement_id),
        "domain": domain,
        "status": "completed",
        "parsed_count": len(findings),
        "persisted_count": persisted,
        "skipped_count": len(skipped),
        "skipped": skipped,
        "lifecycle_synced": int(lifecycle.get("synced") or 0),
        "secret_material_policy": "Raw scanner secrets are used only to compute redacted display values; they are not persisted.",
    }
    _audit_secret_import(
        con,
        config,
        connector_id=connector_id,
        domain=domain,
        result=result,
    )
    con.commit()
    return result


def parse_secret_scan_report(
    connector_id: str,
    report_text: str,
    *,
    repo_name: str = "",
) -> list[ParsedSecretFinding]:
    connector = _normalize_connector(connector_id)
    if connector == "gitleaks_local":
        return _parse_gitleaks_report(report_text, repo_name=repo_name)
    if connector == "trufflehog_local":
        return _parse_trufflehog_report(report_text, repo_name=repo_name)
    raise ValueError(f"Unsupported secret import connector: {connector_id}")


def _parse_gitleaks_report(report_text: str, *, repo_name: str = "") -> list[ParsedSecretFinding]:
    payload = _json_document(report_text)
    rows = payload if isinstance(payload, list) else []
    findings: list[ParsedSecretFinding] = []
    for raw_item in rows:
        if not isinstance(raw_item, Mapping):
            continue
        rule_id = _field(raw_item, "RuleID", "rule_id", "ruleID", "rule")
        description = _field(raw_item, "Description", "description")
        pattern_name = rule_id or description or "gitleaks"
        file_path = _field(raw_item, "File", "file")
        line = _field(raw_item, "StartLine", "Line", "line", "start_line")
        fingerprint = _field(raw_item, "Fingerprint", "fingerprint")
        link = _field(raw_item, "Link", "link")
        source_url = _source_url(
            backend="gitleaks",
            repo_name=repo_name,
            repository="",
            file_path=file_path,
            line=line,
            link=link,
            fingerprint=fingerprint or _stable_hash(json.dumps(_scrub_item(raw_item), sort_keys=True)),
        )
        secret_value = _field(raw_item, "Secret", "secret")
        redacted = _redacted_secret(secret_value) or _redacted_secret(_field(raw_item, "Match", "match"))
        findings.append(
            ParsedSecretFinding(
                source_backend="gitleaks",
                service=_service_from_pattern(pattern_name),
                pattern_name=str(pattern_name),
                source_url=source_url,
                repo_name=repo_name,
                key_redacted=redacted or f"redacted:{_stable_hash(source_url)[:12]}",
                validation_state="UNCONFIRMED",
                validation_detail=_detail(
                    "IMPORTED:gitleaks_json",
                    rule=pattern_name,
                    file=file_path,
                    line=line,
                    fingerprint=_stable_hash(fingerprint)[:16] if fingerprint else "",
                ),
            )
        )
    return findings


def _parse_trufflehog_report(report_text: str, *, repo_name: str = "") -> list[ParsedSecretFinding]:
    rows = _json_lines_or_document(report_text)
    findings: list[ParsedSecretFinding] = []
    for raw_item in rows:
        if not isinstance(raw_item, Mapping):
            continue
        detector = _field(raw_item, "DetectorName", "detector_name", "DetectorType") or "trufflehog"
        source_name = _field(raw_item, "SourceName", "source_name")
        source = _trufflehog_source(raw_item)
        repository = str(source.get("repository") or "")
        file_path = str(source.get("file") or "")
        line = str(source.get("line") or "")
        raw_secret = _field(raw_item, "Redacted", "redacted") or _field(
            raw_item,
            "Raw",
            "RawV2",
            "raw",
        )
        secret_hash = _stable_hash(_field(raw_item, "Raw", "RawV2", "raw") or raw_secret or source_name)
        source_url = _source_url(
            backend="trufflehog",
            repo_name=repo_name,
            repository=repository,
            file_path=file_path,
            line=line,
            link="",
            fingerprint=f"{detector}:{secret_hash}",
        )
        verified = bool(raw_item.get("Verified") is True)
        method = "VALIDATED:trufflehog_verified" if verified else "IMPORTED:trufflehog_json"
        findings.append(
            ParsedSecretFinding(
                source_backend="trufflehog",
                service=_service_from_pattern(detector),
                pattern_name=str(detector),
                source_url=source_url,
                repo_name=repo_name or _repo_name_from_url(repository),
                key_redacted=_redacted_secret(raw_secret) or f"redacted:{secret_hash[:12]}",
                validation_state="ACTIVE" if verified else "UNCONFIRMED",
                validation_detail=_detail(
                    method,
                    detector=detector,
                    source=source_name,
                    file=file_path,
                    line=line,
                    verified=str(verified).lower(),
                ),
            )
        )
    return findings


def _json_document(report_text: str) -> Any:
    text = str(report_text or "").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("secret scan report is not valid JSON") from exc


def _json_lines_or_document(report_text: str) -> list[Any]:
    text = str(report_text or "").strip()
    if not text:
        return []
    if text.startswith("["):
        payload = _json_document(text)
        return payload if isinstance(payload, list) else []
    rows: list[Any] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON line in secret scan report at line {line_no}") from exc
    return rows


def _field(mapping: Mapping[str, Any], *names: str) -> str:
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for name in names:
        value = lowered.get(name.lower())
        if isinstance(value, (Mapping, list, tuple, set)):
            continue
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _trufflehog_source(item: Mapping[str, Any]) -> dict[str, Any]:
    metadata = item.get("SourceMetadata")
    if not isinstance(metadata, Mapping):
        return {}
    data = metadata.get("Data")
    if not isinstance(data, Mapping):
        return {}
    for value in data.values():
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _source_url(
    *,
    backend: str,
    repo_name: str,
    repository: str,
    file_path: str,
    line: object,
    link: str,
    fingerprint: str,
) -> str:
    if link:
        base = link
    elif repository:
        base = repository.rstrip("/")
        if file_path:
            base = f"{base}/{file_path.lstrip('/')}"
    else:
        repo = repo_name or "local"
        base = f"{backend}://{repo}/{file_path.lstrip('/') if file_path else 'finding'}"
    line_text = str(line or "").strip()
    if line_text and "#L" not in base:
        base = f"{base}#L{line_text}"
    suffix = _stable_hash(fingerprint or base)[:16]
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}finding={suffix}"


def _redacted_secret(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "..." in text and len(text) <= 80:
        return text[:80]
    compact = "".join(text.split())
    if len(compact) <= 8:
        return "[REDACTED]"
    return f"{compact[:4]}...{compact[-4:]}"


def _stable_hash(value: object) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()


def _scrub_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): "[REDACTED]" if str(key).lower() in {"secret", "match", "raw", "rawv2"} else value
        for key, value in item.items()
    }


def _detail(prefix: str, **fields: object) -> str:
    parts = []
    for key, value in fields.items():
        text = str(value or "").strip()
        if text:
            parts.append(f"{key}={text[:120]}")
    return f"{prefix}:{';'.join(parts)}" if parts else prefix


def _service_from_pattern(pattern: object) -> str:
    text = str(pattern or "").strip().lower()
    checks = (
        ("aws", ("aws", "amazon", "iam")),
        ("github", ("github", "ghp", "gho", "ghu", "ghs", "ghr")),
        ("gitlab", ("gitlab",)),
        ("google", ("google", "gcp", "firebase", "gcs")),
        ("azure", ("azure", "microsoft")),
        ("slack", ("slack", "xox")),
        ("stripe", ("stripe", "sk_live", "sk_test")),
        ("sendgrid", ("sendgrid",)),
        ("twilio", ("twilio",)),
        ("openai", ("openai",)),
        ("anthropic", ("anthropic", "claude")),
        ("discord", ("discord",)),
        ("telegram", ("telegram",)),
    )
    for service, markers in checks:
        if any(marker in text for marker in markers):
            return service
    return text.replace(" ", "_")[:80] or "unknown"


def _repo_name_from_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    path = parsed.path.strip("/")
    if parsed.netloc and path:
        return path.removesuffix(".git")
    return text


def _normalize_connector(connector_id: str) -> str:
    connector = str(connector_id or "").strip().lower()
    if connector not in SUPPORTED_SECRET_IMPORT_CONNECTORS:
        raise ValueError(
            "secret import connector must be one of "
            f"{', '.join(SUPPORTED_SECRET_IMPORT_CONNECTORS)}"
        )
    return connector


def _assert_domain_in_scope(
    con: sqlite3.Connection,
    engagement_id: int,
    domain: str,
) -> None:
    row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?",
        (int(engagement_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"engagement not found: {engagement_id}")
    try:
        scope_payload = json.loads(str(row["scope_json"] or "[]"))
    except json.JSONDecodeError:
        scope_payload = []
    assert_in_scope(domain, scope_entries_from_payload(scope_payload))


def _upsert_key_scanner_finding(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    domain: str,
    finding: ParsedSecretFinding,
) -> None:
    con.execute(
        """
        INSERT INTO key_scanner_findings
            (engagement_id, domain, service, pattern_name, source_backend,
             source_url, repo_name, key_redacted, key_enc, validation_state,
             validation_detail, validated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, CASE WHEN ?='ACTIVE' THEN CURRENT_TIMESTAMP ELSE NULL END)
        ON CONFLICT(engagement_id, source_url, pattern_name) DO UPDATE SET
            domain=excluded.domain,
            service=excluded.service,
            source_backend=excluded.source_backend,
            repo_name=COALESCE(NULLIF(excluded.repo_name, ''), key_scanner_findings.repo_name),
            key_redacted=excluded.key_redacted,
            validation_state=CASE
                WHEN excluded.validation_state='ACTIVE' THEN 'ACTIVE'
                ELSE key_scanner_findings.validation_state
            END,
            validation_detail=excluded.validation_detail,
            validated_at=CASE
                WHEN excluded.validation_state='ACTIVE' THEN CURRENT_TIMESTAMP
                ELSE key_scanner_findings.validated_at
            END
        """,
        (
            int(engagement_id),
            domain,
            finding.service,
            finding.pattern_name,
            finding.source_backend,
            finding.source_url,
            finding.repo_name,
            finding.key_redacted,
            finding.validation_state,
            finding.validation_detail,
            finding.validation_state,
        ),
    )


def _audit_secret_import(
    con: sqlite3.Connection,
    config: SecretScanImportConfig,
    *,
    connector_id: str,
    domain: str,
    result: Mapping[str, Any],
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'secret_scan_import', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            connector_id,
            domain,
            (
                f"completed parsed={int(result.get('parsed_count') or 0)} "
                f"persisted={int(result.get('persisted_count') or 0)} "
                f"skipped={int(result.get('skipped_count') or 0)}"
            ),
            str(config.operator or "connector-import"),
        ),
    )


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None
