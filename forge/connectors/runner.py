from __future__ import annotations

import json
import ipaddress
import re
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from forge.connectors.binaries import resolve_connector_binary
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, scope_entries_from_payload
from forge.secrets.importers import SecretScanImportConfig, import_secret_scan_report
from forge.standards.vulnerabilities import vulnerability_standards_metadata
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

SUPPORTED_EXECUTABLE_CONNECTORS = (
    "projectdiscovery_subfinder",
    "projectdiscovery_httpx",
    "projectdiscovery_nuclei",
    "projectdiscovery_katana",
)
SUPPORTED_SECRET_EXECUTABLE_CONNECTORS = ("gitleaks_local", "trufflehog_local")
_NUCLEI_DEFAULT_SEVERITIES = ("low", "medium", "high", "critical")
_NUCLEI_ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")
_CONNECTOR_DEFAULT_RESULT_LIMIT = 500
_CONNECTOR_MAX_RESULT_LIMIT = 5000
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_CPE_RE = re.compile(r"cpe:2\.3:[A-Za-z0-9_.*~!@$%^&()+={}\[\]|:;,.<>/?`#-]+", re.IGNORECASE)
_CVSS_VECTOR_RE = re.compile(r"^CVSS:(?P<version>\d+(?:\.\d+)?)/", re.IGNORECASE)

ProcessRunner = Callable[[Sequence[str], float], subprocess.CompletedProcess[str]]
WhichResolver = Callable[[str], str | None]


@dataclass(frozen=True)
class ConnectorRunConfig:
    connector_id: str
    engagement_id: int
    target: str
    timeout_seconds: float = 120.0
    dry_run: bool = False
    operator: str = "connector-runner"
    template_paths: tuple[str, ...] = ()
    severity_filter: tuple[str, ...] = _NUCLEI_DEFAULT_SEVERITIES
    rate_limit_per_second: int = 5
    max_results: int = _CONNECTOR_DEFAULT_RESULT_LIMIT


@dataclass(frozen=True)
class SecretConnectorRunConfig:
    connector_id: str
    engagement_id: int
    domain: str
    source_path: Path
    repo_name: str = ""
    timeout_seconds: float = 300.0
    dry_run: bool = False
    operator: str = "connector-runner"


def run_connector(
    con: sqlite3.Connection,
    config: ConnectorRunConfig,
    *,
    which: WhichResolver | None = None,
    process_runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip()
    if connector_id not in SUPPORTED_EXECUTABLE_CONNECTORS:
        raise ValueError(
            "executable connector must be one of "
            f"{', '.join(SUPPORTED_EXECUTABLE_CONNECTORS)}"
        )
    if connector_id == "projectdiscovery_httpx":
        return _run_projectdiscovery_httpx(
            con,
            config,
            which=which or resolve_connector_binary,
            process_runner=process_runner or _default_process_runner,
        )
    if connector_id == "projectdiscovery_katana":
        return _run_projectdiscovery_katana(
            con,
            config,
            which=which or resolve_connector_binary,
            process_runner=process_runner or _default_process_runner,
        )
    if connector_id == "projectdiscovery_nuclei":
        return _run_projectdiscovery_nuclei(
            con,
            config,
            which=which or resolve_connector_binary,
            process_runner=process_runner or _default_process_runner,
        )
    return _run_projectdiscovery_subfinder(
        con,
        config,
        which=which or resolve_connector_binary,
        process_runner=process_runner or _default_process_runner,
    )


def run_secret_scan_connector(
    con: sqlite3.Connection,
    config: SecretConnectorRunConfig,
    *,
    which: WhichResolver | None = None,
    process_runner: ProcessRunner | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    if connector_id not in SUPPORTED_SECRET_EXECUTABLE_CONNECTORS:
        raise ValueError(
            "secret executable connector must be one of "
            f"{', '.join(SUPPORTED_SECRET_EXECUTABLE_CONNECTORS)}"
        )
    source_path = _normalize_existing_source_path(config.source_path)
    domain = str(config.domain or "").strip().lower().strip(".")
    _assert_scoped(domain, _scope_for_engagement(con, int(config.engagement_id)))
    timeout = max(1.0, min(float(config.timeout_seconds or 300.0), 1800.0))
    resolver = which or resolve_connector_binary
    runner = process_runner or _default_process_runner
    binary_name = "gitleaks" if connector_id == "gitleaks_local" else "trufflehog"
    binary = resolver(binary_name)
    if config.dry_run:
        command = _secret_scan_command(
            connector_id,
            binary or binary_name,
            source_path,
            report_path=Path("<report-path>"),
        )
        result = _secret_scan_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            command=command,
            status="planned",
            reason="",
            returncode=None,
            import_result={},
        )
        _audit_secret_scan_run(con, config, result=result)
        con.commit()
        return result
    if not binary:
        command = _secret_scan_command(
            connector_id,
            binary_name,
            source_path,
            report_path=Path("<report-path>"),
        )
        result = _secret_scan_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            command=command,
            status="failed",
            reason="missing_binary",
            returncode=None,
            import_result={},
        )
        _audit_secret_scan_run(con, config, result=result)
        con.commit()
        return result
    if connector_id == "gitleaks_local":
        return _run_gitleaks_secret_scan(
            con,
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            binary=binary,
            timeout=timeout,
            process_runner=runner,
        )
    return _run_trufflehog_secret_scan(
        con,
        config,
        connector_id=connector_id,
        domain=domain,
        source_path=source_path,
        binary=binary,
        timeout=timeout,
        process_runner=runner,
    )


def _run_projectdiscovery_subfinder(
    con: sqlite3.Connection,
    config: ConnectorRunConfig,
    *,
    which: WhichResolver,
    process_runner: ProcessRunner,
) -> dict[str, Any]:
    target = _normalize_hostname(config.target)
    if not target:
        raise ValueError("target is required")
    scope = _scope_for_engagement(con, int(config.engagement_id))
    _assert_scoped(target, scope)
    timeout = max(1.0, min(float(config.timeout_seconds or 120.0), 900.0))
    binary = which("subfinder") if not config.dry_run else which("subfinder") or "subfinder"
    args = [binary, "-d", target, "-silent", "-json"]
    if config.dry_run:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="planned",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    if not binary:
        result = _result_payload(
            config,
            target=target,
            command=["subfinder", "-d", target, "-silent", "-json"],
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    try:
        completed = process_runner(args, timeout)
    except FileNotFoundError:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    except subprocess.TimeoutExpired:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="timeout",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    discovered_hosts = _parse_subfinder_hosts(completed.stdout)[
        : _normalize_connector_result_limit(config.max_results)
    ]
    persisted: list[str] = []
    skipped: list[dict[str, str]] = []
    for host in discovered_hosts:
        try:
            _assert_scoped(host, scope)
        except ScopeViolationError as exc:
            skipped.append({"host": host, "reason": "out_of_scope", "detail": str(exc)[:240]})
            continue
        if _persist_subdomain_seed(con, int(config.engagement_id), host, target):
            persisted.append(host)

    status = "completed" if int(completed.returncode or 0) == 0 else "failed"
    result = _result_payload(
        config,
        target=target,
        command=args,
        status=status,
        returncode=int(completed.returncode or 0),
        discovered=discovered_hosts,
        persisted=persisted,
        skipped=skipped,
        reason="" if status == "completed" else "nonzero_exit",
        stderr=_bounded_text(completed.stderr, 1000),
    )
    _audit_connector_run(con, config, target=target, result=result)
    con.commit()
    return result


def _run_projectdiscovery_katana(
    con: sqlite3.Connection,
    config: ConnectorRunConfig,
    *,
    which: WhichResolver,
    process_runner: ProcessRunner,
) -> dict[str, Any]:
    target, target_host = _normalize_katana_target(config.target)
    if not target or not target_host:
        raise ValueError("target must be a hostname or http(s) URL")
    scope = _scope_for_engagement(con, int(config.engagement_id))
    _assert_scoped(target, scope)
    timeout = max(1.0, min(float(config.timeout_seconds or 120.0), 900.0))
    binary = which("katana") if not config.dry_run else which("katana") or "katana"
    args = [
        binary,
        "-u",
        target,
        "-j",
        "-silent",
        "-no-color",
        "-d",
        "2",
        "-rl",
        "10",
    ]
    if config.dry_run:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="planned",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    if not binary:
        result = _result_payload(
            config,
            target=target,
            command=[
                "katana",
                "-u",
                target,
                "-j",
                "-silent",
                "-no-color",
                "-d",
                "2",
                "-rl",
                "10",
            ],
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    try:
        completed = process_runner(args, timeout)
    except FileNotFoundError:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    except subprocess.TimeoutExpired:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="timeout",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    discovered = _parse_katana_results(completed.stdout, target_host=target_host)[
        : _normalize_connector_result_limit(config.max_results)
    ]
    persisted: list[str] = []
    skipped: list[dict[str, str]] = []
    for item in discovered:
        url = str(item.get("url") or "").strip()
        try:
            _assert_scoped(url, scope)
        except ScopeViolationError as exc:
            skipped.append({"url": url, "reason": "out_of_scope", "detail": str(exc)[:240]})
            continue
        if _persist_katana_result(con, int(config.engagement_id), item, target=target):
            persisted.append(url)

    discovered_urls = [str(item.get("url") or "") for item in discovered]
    status = "completed" if int(completed.returncode or 0) == 0 else "failed"
    result = _result_payload(
        config,
        target=target,
        command=args,
        status=status,
        returncode=int(completed.returncode or 0),
        discovered=discovered_urls,
        persisted=persisted,
        skipped=skipped,
        reason="" if status == "completed" else "nonzero_exit",
        stderr=_bounded_text(completed.stderr, 1000),
    )
    _audit_connector_run(con, config, target=target, result=result)
    con.commit()
    return result


def _run_projectdiscovery_httpx(
    con: sqlite3.Connection,
    config: ConnectorRunConfig,
    *,
    which: WhichResolver,
    process_runner: ProcessRunner,
) -> dict[str, Any]:
    target, target_host = _normalize_httpx_target(config.target)
    if not target or not target_host:
        raise ValueError("target must be a hostname or http(s) URL")
    scope = _scope_for_engagement(con, int(config.engagement_id))
    _assert_scoped(target, scope)
    timeout = max(1.0, min(float(config.timeout_seconds or 120.0), 900.0))
    binary = which("httpx") if not config.dry_run else which("httpx") or "httpx"
    args = [
        binary,
        "-u",
        target,
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
    ]
    if config.dry_run:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="planned",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    if not binary:
        result = _result_payload(
            config,
            target=target,
            command=[
                "httpx",
                "-u",
                target,
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-server",
            ],
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    try:
        completed = process_runner(args, timeout)
    except FileNotFoundError:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    except subprocess.TimeoutExpired:
        result = _result_payload(
            config,
            target=target,
            command=args,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="timeout",
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    discovered = _parse_httpx_results(completed.stdout, target=target, target_host=target_host)[
        : _normalize_connector_result_limit(config.max_results)
    ]
    persisted: list[str] = []
    skipped: list[dict[str, str]] = []
    for item in discovered:
        url = str(item.get("url") or "").strip()
        try:
            _assert_scoped(url, scope)
        except ScopeViolationError as exc:
            skipped.append({"url": url, "reason": "out_of_scope", "detail": str(exc)[:240]})
            continue
        if _persist_httpx_result(con, int(config.engagement_id), item, target=target):
            persisted.append(url)

    discovered_urls = [str(item.get("url") or "") for item in discovered]
    status = "completed" if int(completed.returncode or 0) == 0 else "failed"
    result = _result_payload(
        config,
        target=target,
        command=args,
        status=status,
        returncode=int(completed.returncode or 0),
        discovered=discovered_urls,
        persisted=persisted,
        skipped=skipped,
        reason="" if status == "completed" else "nonzero_exit",
        stderr=_bounded_text(completed.stderr, 1000),
    )
    _audit_connector_run(con, config, target=target, result=result)
    con.commit()
    return result


def _run_projectdiscovery_nuclei(
    con: sqlite3.Connection,
    config: ConnectorRunConfig,
    *,
    which: WhichResolver,
    process_runner: ProcessRunner,
) -> dict[str, Any]:
    target, target_host = _normalize_katana_target(config.target)
    if not target or not target_host:
        raise ValueError("target must be a hostname or http(s) URL")
    scope = _scope_for_engagement(con, int(config.engagement_id))
    _assert_scoped(target, scope)
    timeout = max(1.0, min(float(config.timeout_seconds or 120.0), 900.0))
    templates = _normalize_nuclei_templates(config.template_paths)
    severities = _normalize_nuclei_severities(config.severity_filter)
    rate_limit = _normalize_nuclei_rate_limit(config.rate_limit_per_second)
    binary = which("nuclei") if not config.dry_run else which("nuclei") or "nuclei"
    command = _nuclei_command(binary or "nuclei", target, templates, severities, rate_limit)
    if not templates:
        result = _nuclei_result_payload(
            config,
            target=target,
            command=command,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_templates",
            templates=templates,
            severities=severities,
            rate_limit=rate_limit,
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    if config.dry_run:
        result = _nuclei_result_payload(
            config,
            target=target,
            command=command,
            status="planned",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            templates=templates,
            severities=severities,
            rate_limit=rate_limit,
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    if not binary:
        result = _nuclei_result_payload(
            config,
            target=target,
            command=_nuclei_command("nuclei", target, templates, severities, rate_limit),
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
            templates=templates,
            severities=severities,
            rate_limit=rate_limit,
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    try:
        completed = process_runner(command, timeout)
    except FileNotFoundError:
        result = _nuclei_result_payload(
            config,
            target=target,
            command=command,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="missing_binary",
            templates=templates,
            severities=severities,
            rate_limit=rate_limit,
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result
    except subprocess.TimeoutExpired:
        result = _nuclei_result_payload(
            config,
            target=target,
            command=command,
            status="failed",
            returncode=None,
            discovered=[],
            persisted=[],
            skipped=[],
            reason="timeout",
            templates=templates,
            severities=severities,
            rate_limit=rate_limit,
        )
        _audit_connector_run(con, config, target=target, result=result)
        con.commit()
        return result

    findings = _parse_nuclei_results(completed.stdout, target_host=target_host)[
        : _normalize_connector_result_limit(config.max_results)
    ]
    persisted: list[str] = []
    skipped: list[dict[str, str]] = []
    for item in findings:
        finding_target = str(item.get("target_url") or "").strip()
        try:
            _assert_scoped(finding_target, scope)
        except ScopeViolationError as exc:
            skipped.append(
                {
                    "url": finding_target,
                    "template_id": str(item.get("template_id") or ""),
                    "reason": "out_of_scope",
                    "detail": str(exc)[:240],
                }
            )
            continue
        if _persist_nuclei_result(con, int(config.engagement_id), item, target=target):
            persisted.append(_nuclei_finding_label(item))

    discovered = [_nuclei_finding_label(item) for item in findings]
    status = "completed" if int(completed.returncode or 0) == 0 else "failed"
    result = _nuclei_result_payload(
        config,
        target=target,
        command=command,
        status=status,
        returncode=int(completed.returncode or 0),
        discovered=discovered,
        persisted=persisted,
        skipped=skipped,
        reason="" if status == "completed" else "nonzero_exit",
        stderr=_bounded_text(completed.stderr, 1000),
        templates=templates,
        severities=severities,
        rate_limit=rate_limit,
    )
    _audit_connector_run(con, config, target=target, result=result)
    con.commit()
    return result


def _run_gitleaks_secret_scan(
    con: sqlite3.Connection,
    config: SecretConnectorRunConfig,
    *,
    connector_id: str,
    domain: str,
    source_path: Path,
    binary: str,
    timeout: float,
    process_runner: ProcessRunner,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="forge-gitleaks-") as tmp_dir:
        report_path = Path(tmp_dir) / "gitleaks.json"
        command = _secret_scan_command(
            connector_id,
            binary,
            source_path,
            report_path=report_path,
        )
        completed = _run_secret_process(command, timeout, process_runner)
        if isinstance(completed, dict):
            result = _secret_scan_result(
                config,
                connector_id=connector_id,
                domain=domain,
                source_path=source_path,
                command=command,
                status="failed",
                reason=str(completed["reason"]),
                returncode=None,
                import_result={},
            )
            _audit_secret_scan_run(con, config, result=result)
            con.commit()
            return result
        report_text = _read_report_or_stdout(report_path, completed.stdout)
        if int(completed.returncode or 0) != 0 and not report_text.strip():
            result = _secret_scan_result(
                config,
                connector_id=connector_id,
                domain=domain,
                source_path=source_path,
                command=command,
                status="failed",
                reason="nonzero_exit",
                returncode=int(completed.returncode or 0),
                import_result={},
            )
            _audit_secret_scan_run(con, config, result=result)
            con.commit()
            return result
        return _import_secret_scan_output(
            con,
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            command=command,
            returncode=int(completed.returncode or 0),
            report_text=report_text,
        )


def _run_trufflehog_secret_scan(
    con: sqlite3.Connection,
    config: SecretConnectorRunConfig,
    *,
    connector_id: str,
    domain: str,
    source_path: Path,
    binary: str,
    timeout: float,
    process_runner: ProcessRunner,
) -> dict[str, Any]:
    command = _secret_scan_command(
        connector_id,
        binary,
        source_path,
        report_path=None,
    )
    completed = _run_secret_process(command, timeout, process_runner)
    if isinstance(completed, dict):
        result = _secret_scan_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            command=command,
            status="failed",
            reason=str(completed["reason"]),
            returncode=None,
            import_result={},
        )
        _audit_secret_scan_run(con, config, result=result)
        con.commit()
        return result
    if int(completed.returncode or 0) != 0 and not str(completed.stdout or "").strip():
        result = _secret_scan_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            command=command,
            status="failed",
            reason="nonzero_exit",
            returncode=int(completed.returncode or 0),
            import_result={},
        )
        _audit_secret_scan_run(con, config, result=result)
        con.commit()
        return result
    return _import_secret_scan_output(
        con,
        config,
        connector_id=connector_id,
        domain=domain,
        source_path=source_path,
        command=command,
        returncode=int(completed.returncode or 0),
        report_text=str(completed.stdout or ""),
    )


def _import_secret_scan_output(
    con: sqlite3.Connection,
    config: SecretConnectorRunConfig,
    *,
    connector_id: str,
    domain: str,
    source_path: Path,
    command: Sequence[str],
    returncode: int,
    report_text: str,
) -> dict[str, Any]:
    try:
        import_result = import_secret_scan_report(
            con,
            SecretScanImportConfig(
                connector_id=connector_id,
                engagement_id=int(config.engagement_id),
                domain=domain,
                repo_name=config.repo_name or source_path.name,
                operator=config.operator,
            ),
            report_text=report_text,
        )
    except ValueError:
        result = _secret_scan_result(
            config,
            connector_id=connector_id,
            domain=domain,
            source_path=source_path,
            command=command,
            status="failed",
            reason="invalid_report",
            returncode=returncode,
            import_result={},
        )
        _audit_secret_scan_run(con, config, result=result)
        con.commit()
        return result
    result = _secret_scan_result(
        config,
        connector_id=connector_id,
        domain=domain,
        source_path=source_path,
        command=command,
        status="completed",
        reason="",
        returncode=returncode,
        import_result=import_result,
    )
    _audit_secret_scan_run(con, config, result=result)
    con.commit()
    return result


def _normalize_existing_source_path(value: Path) -> Path:
    path = Path(value).expanduser()
    if not path.exists():
        raise ValueError(f"source path does not exist: {path}")
    return path.resolve()


def _secret_scan_command(
    connector_id: str,
    binary: str,
    source_path: Path,
    *,
    report_path: Path | None,
) -> list[str]:
    if connector_id == "gitleaks_local":
        scan_mode = "git" if source_path.is_dir() and (source_path / ".git").exists() else "dir"
        command = [
            binary,
            scan_mode,
            str(source_path),
            "--no-banner",
            "--no-color",
            "--redact=100",
            "--report-format",
            "json",
            "--exit-code",
            "0",
        ]
        if report_path is not None:
            command.extend(["--report-path", str(report_path)])
        return command
    if connector_id == "trufflehog_local":
        return [
            binary,
            "filesystem",
            str(source_path),
            "--results=verified,unknown",
            "--json",
        ]
    raise ValueError(f"Unsupported secret executable connector: {connector_id}")


def _run_secret_process(
    command: Sequence[str],
    timeout: float,
    process_runner: ProcessRunner,
) -> subprocess.CompletedProcess[str] | dict[str, str]:
    try:
        return process_runner(command, timeout)
    except FileNotFoundError:
        return {"reason": "missing_binary"}
    except subprocess.TimeoutExpired:
        return {"reason": "timeout"}


def _read_report_or_stdout(report_path: Path, stdout: object) -> str:
    if report_path.exists():
        return report_path.read_text(encoding="utf-8")
    return str(stdout or "")


def _secret_scan_result(
    config: SecretConnectorRunConfig,
    *,
    connector_id: str,
    domain: str,
    source_path: Path,
    command: Sequence[str],
    status: str,
    reason: str,
    returncode: int | None,
    import_result: Mapping[str, Any],
) -> dict[str, Any]:
    timeout = max(1.0, min(float(config.timeout_seconds or 300.0), 1800.0))
    dry_run = bool(config.dry_run)
    process_executed = returncode is not None
    payload = {
        "connector_id": connector_id,
        "engagement_id": int(config.engagement_id),
        "domain": domain,
        "source_path": str(source_path),
        "status": status,
        "dry_run": bool(config.dry_run),
        "command": list(command),
        "returncode": returncode,
        "reason": reason,
        "parsed_count": int(import_result.get("parsed_count") or 0),
        "persisted_count": int(import_result.get("persisted_count") or 0),
        "skipped_count": int(import_result.get("skipped_count") or 0),
        "lifecycle_synced": int(import_result.get("lifecycle_synced") or 0),
        "secret_material_policy": "Scanner stdout/report bodies are parsed in memory; raw secret material is not returned or audited.",
    }
    payload.update(
        {
            "gates": [
                _gate_payload("engagement_scope", required=True, status="passed"),
                _gate_payload("local_source_path", required=True, status="passed"),
                _gate_payload("secret_redaction", required=True, status="passed"),
                _gate_payload(
                    "process_execution",
                    required=not dry_run,
                    status=(
                        "skipped_preview"
                        if dry_run
                        else ("executed" if process_executed else "blocked")
                    ),
                    reason=reason if reason in {"missing_binary", "timeout"} else "",
                ),
            ],
            "budgets": {
                "concurrency": 1,
                "depth": 0,
                "queue_items": 1,
                "timeout_seconds": timeout,
                "preview_network_requests": 0,
            },
            "plan": {
                "will_execute_process": not dry_run and reason != "missing_binary",
                "process_executed": process_executed,
                "will_touch_network": False,
                "will_parse_report_in_memory": not dry_run and process_executed,
                "will_return_raw_secret_material": False,
                "will_create_audit_row": True,
            },
        }
    )
    return payload


def _audit_secret_scan_run(
    con: sqlite3.Connection,
    config: SecretConnectorRunConfig,
    *,
    result: Mapping[str, Any],
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    reason = _bounded_text(result.get("reason"), 80)
    parts = [
        str(result["status"]),
        f"parsed={result['parsed_count']}",
        f"persisted={result['persisted_count']}",
        f"skipped={result['skipped_count']}",
    ]
    if reason:
        parts.append(f"reason={reason}")
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'secret_scan_run', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            str(result["connector_id"]),
            str(result["domain"]),
            " ".join(parts),
            str(config.operator or "connector-runner"),
        ),
    )


def _default_process_runner(
    args: Sequence[str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
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


def _assert_scoped(target: str, scope: list[str]) -> None:
    assert_in_scope(target, scope)


def _normalize_hostname(value: object) -> str:
    text = str(value or "").strip().lower().strip(".")
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        parsed = urlparse(text)
        text = str(parsed.hostname or "").strip().lower().strip(".")
    if "@" in text or "/" in text or "\\" in text or any(ch.isspace() for ch in text):
        return ""
    if len(text) > 253:
        return ""
    return text


def _normalize_httpx_target(value: object) -> tuple[str, str]:
    text = str(value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return "", ""
    if text.lower().startswith(("http://", "https://")):
        try:
            parsed = urlparse(text)
        except ValueError:
            return "", ""
        host = str(parsed.hostname or "").strip().lower().strip(".")
        if not host or parsed.username or parsed.password:
            return "", ""
        scheme = str(parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return "", ""
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        clean_path = parsed.path or ""
        clean_query = parsed.query or ""
        return urlunparse((scheme, netloc, clean_path, "", clean_query, "")), host
    host = _normalize_hostname(text)
    return host, host


def _normalize_katana_target(value: object) -> tuple[str, str]:
    target, host = _normalize_httpx_target(value)
    if not target or not host:
        return "", ""
    if target.startswith(("http://", "https://")):
        return target, host
    return f"https://{host}", host


def _parse_subfinder_hosts(stdout: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for raw_line in str(stdout or "").splitlines():
        host = _subfinder_host_from_line(raw_line)
        if not host or host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def _subfinder_host_from_line(raw_line: str) -> str:
    line = str(raw_line or "").strip()
    if not line:
        return ""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return _normalize_hostname(line)
    if not isinstance(payload, dict):
        return ""
    for key in ("host", "name", "subdomain", "domain", "input"):
        host = _normalize_hostname(payload.get(key))
        if host:
            return host
    return ""


def _parse_katana_results(stdout: str, *, target_host: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in str(stdout or "").splitlines():
        for item in _katana_results_from_line(raw_line, target_host=target_host):
            url = str(item.get("url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            results.append(item)
    return results


def _katana_results_from_line(raw_line: str, *, target_host: str) -> list[dict[str, Any]]:
    line = str(raw_line or "").strip()
    if not line:
        return []
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        url = _httpx_url_from_candidate(line, default_host=target_host)
        return [_katana_item(url, payload={}, target_host=target_host)] if url else []
    if not isinstance(payload, dict):
        return []
    urls: list[str] = []
    for candidate in _katana_url_candidates(payload):
        url = _httpx_url_from_candidate(candidate, default_host=target_host)
        if url and url not in urls:
            urls.append(url)
    return [_katana_item(url, payload=payload, target_host=target_host) for url in urls]


def _katana_url_candidates(payload: Mapping[str, Any]) -> list[object]:
    candidates: list[object] = []
    for key in ("url", "endpoint", "target", "location", "href"):
        candidates.append(payload.get(key))
    for parent_key in ("request", "response"):
        parent = payload.get(parent_key)
        if not isinstance(parent, Mapping):
            continue
        for key in ("url", "endpoint", "source", "location"):
            candidates.append(parent.get(key))
    return candidates


def _katana_item(url: str, *, payload: Mapping[str, Any], target_host: str) -> dict[str, Any]:
    host = _url_host(url) or target_host
    title = _bounded_text(payload.get("title"), 240)
    method = _bounded_text(payload.get("method") or _nested_payload_value(payload, "request", "method"), 40)
    source = _bounded_text(payload.get("source"), 240)
    tag = _bounded_text(payload.get("tag") or payload.get("attribute"), 80)
    item: dict[str, Any] = {
        "url": url,
        "final_url": url,
        "host": host,
        "title": title or "katana crawl",
    }
    if method:
        item["method"] = method
    if source:
        item["source"] = source
    if tag:
        item["tag"] = tag
    return item


def _nested_payload_value(
    payload: Mapping[str, Any],
    parent_key: str,
    child_key: str,
) -> object:
    parent = payload.get(parent_key)
    if isinstance(parent, Mapping):
        return parent.get(child_key)
    return None


def _parse_httpx_results(stdout: str, *, target: str, target_host: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in str(stdout or "").splitlines():
        item = _httpx_result_from_line(raw_line, target=target, target_host=target_host)
        url = str(item.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        results.append(item)
    return results


def _parse_nuclei_results(stdout: str, *, target_host: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw_line in str(stdout or "").splitlines():
        item = _nuclei_result_from_line(raw_line, target_host=target_host)
        if not item:
            continue
        key = (
            str(item.get("target_url") or ""),
            str(item.get("template_id") or ""),
            str(item.get("matcher_name") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        results.append(item)
    return results


def _nuclei_result_from_line(raw_line: str, *, target_host: str) -> dict[str, Any]:
    line = str(raw_line or "").strip()
    if not line:
        return {}
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, Mapping):
        return {}
    info = payload.get("info") if isinstance(payload.get("info"), Mapping) else {}
    classification = (
        info.get("classification")
        if isinstance(info, Mapping) and isinstance(info.get("classification"), Mapping)
        else {}
    )
    target_url = _nuclei_target_url(payload, target_host=target_host)
    template_id = _bounded_text(
        payload.get("template-id")
        or payload.get("template_id")
        or payload.get("templateID")
        or payload.get("id"),
        220,
    )
    if not target_url or not template_id:
        return {}
    severity = _nuclei_db_severity(
        info.get("severity") if isinstance(info, Mapping) else payload.get("severity")
    )
    title = _bounded_text(info.get("name") if isinstance(info, Mapping) else "", 240)
    description = _bounded_text(
        info.get("description") if isinstance(info, Mapping) else "",
        1000,
    )
    matcher_name = _bounded_text(payload.get("matcher-name") or payload.get("matcher_name"), 160)
    cve_ids = _extract_standard_ids(
        _CVE_RE,
        classification.get("cve-id") if isinstance(classification, Mapping) else None,
        classification.get("cve_id") if isinstance(classification, Mapping) else None,
        title,
        description,
        template_id,
    )
    cwe_ids = _extract_standard_ids(
        _CWE_RE,
        classification.get("cwe-id") if isinstance(classification, Mapping) else None,
        classification.get("cwe_id") if isinstance(classification, Mapping) else None,
        description,
    )
    cpe_matches = _extract_standard_ids(
        _CPE_RE,
        classification.get("cpe") if isinstance(classification, Mapping) else None,
        classification.get("cpe-match") if isinstance(classification, Mapping) else None,
        classification.get("cpe_matches") if isinstance(classification, Mapping) else None,
        description,
        transform=str.lower,
    )
    attack_techniques = _extract_standard_ids(_ATTACK_RE, description)
    cvss_score = _float_or_none(
        classification.get("cvss-score") if isinstance(classification, Mapping) else None
    )
    if cvss_score is None and isinstance(classification, Mapping):
        cvss_score = _float_or_none(classification.get("cvss_score"))
    cvss_vector = _bounded_text(
        classification.get("cvss-metrics") if isinstance(classification, Mapping) else "",
        240,
    )
    if not cvss_vector and isinstance(classification, Mapping):
        cvss_vector = _bounded_text(
            classification.get("cvss_vector") or classification.get("cvss-vector"),
            240,
        )
    cvss_version = _cvss_version_from_vector(cvss_vector)
    standards_seed = {
        "source": "projectdiscovery_nuclei",
        "connector_id": "projectdiscovery_nuclei",
        "template_id": template_id,
        "template_path": _bounded_text(payload.get("template-path") or payload.get("template_path"), 260),
        "template_url": _safe_reference_url(payload.get("template-url") or payload.get("template_url")),
        "matcher_name": matcher_name,
        "match_type": _bounded_text(payload.get("type"), 80),
        "matched_at": target_url,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "cpe_matches": cpe_matches,
        "attack_techniques": attack_techniques,
        "tags": _string_list(info.get("tags") if isinstance(info, Mapping) else None)[:25],
        "reference_count": len(_nuclei_reference_urls(info.get("reference") if isinstance(info, Mapping) else None)),
        "extracted_result_count": _count_listish(payload.get("extracted-results") or payload.get("extracted_results")),
    }
    existing_refs = []
    template_url = str(standards_seed.get("template_url") or "")
    if template_url:
        existing_refs.append(
            {
                "source_name": "nuclei-template",
                "external_id": template_id,
                "url": template_url,
            }
        )
    standards_seed["stix_external_refs"] = existing_refs
    row_for_standards = {
        "vuln_type": "nuclei_template",
        "target_url": target_url,
        "parameter": template_id,
        "severity": severity,
        "title": title or template_id,
        "description": description,
        "evidence": _nuclei_evidence(
            template_id=template_id,
            target_url=target_url,
            matcher_name=matcher_name,
            severity=severity,
        ),
        "cve_id": cve_ids[0] if cve_ids else "",
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "cwe_ids": json.dumps(cwe_ids, sort_keys=True),
        "cpe_matches": json.dumps(cpe_matches, sort_keys=True),
        "attack_techniques": json.dumps(attack_techniques, sort_keys=True),
        "standards_json": json.dumps(
            {key: value for key, value in standards_seed.items() if value not in ("", [], {})},
            sort_keys=True,
        ),
    }
    standards = vulnerability_standards_metadata(row_for_standards)
    return {
        **row_for_standards,
        "template_id": template_id,
        "matcher_name": matcher_name,
        "standards": standards,
        "stix_external_refs_json": json.dumps(
            standards.get("stix_external_refs") or [],
            sort_keys=True,
        ),
    }


def _httpx_result_from_line(raw_line: str, *, target: str, target_host: str) -> dict[str, Any]:
    line = str(raw_line or "").strip()
    if not line:
        return {}
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        url = _httpx_url_from_candidate(line, default_host=target_host)
        return {"url": url, "host": _url_host(url) or target_host} if url else {}
    if not isinstance(payload, dict):
        return {}
    url = ""
    for key in ("url", "final_url", "input"):
        url = _httpx_url_from_candidate(payload.get(key), default_host=target_host)
        if url:
            break
    if not url:
        url = _httpx_url_from_candidate(target, default_host=target_host)
    if not url:
        return {}
    host = _url_host(url) or _normalize_hostname(payload.get("host")) or target_host
    final_url = _httpx_url_from_candidate(
        payload.get("final_url") or payload.get("location"),
        default_host=host,
    )
    return {
        "url": url,
        "final_url": final_url or url,
        "host": host,
        "title": _bounded_text(payload.get("title"), 240),
        "status_code": _int_or_none(payload.get("status_code") or payload.get("status-code")),
        "tech": _string_list(payload.get("tech") or payload.get("technologies")),
        "webserver": _bounded_text(
            payload.get("webserver") or payload.get("web_server") or payload.get("server"),
            160,
        ),
        "content_type": _bounded_text(payload.get("content_type") or payload.get("content-type"), 160),
        "content_length": _int_or_none(payload.get("content_length") or payload.get("content-length")),
        "response_time": _bounded_text(payload.get("response_time") or payload.get("time"), 80),
        "ip": _httpx_ip(payload),
        "port": _httpx_port(payload, url),
    }


def _httpx_url_from_candidate(value: object, *, default_host: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return ""
    if text.lower().startswith(("http://", "https://")):
        try:
            parsed = urlparse(text)
        except ValueError:
            return ""
        host = str(parsed.hostname or "").strip().lower().strip(".")
        if not host or parsed.username or parsed.password:
            return ""
        scheme = str(parsed.scheme or "").lower()
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        return urlunparse((scheme, netloc, parsed.path or "", "", parsed.query or "", ""))
    host = _normalize_hostname(text) or str(default_host or "").strip().lower().strip(".")
    if not host:
        return ""
    return f"https://{host}"


def _url_host(value: object) -> str:
    try:
        return str(urlparse(str(value or "")).hostname or "").strip().lower().strip(".")
    except ValueError:
        return ""


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, str):
        raw_items = [item.strip() for item in value.split(",")]
    else:
        raw_items = []
    seen: set[str] = set()
    items: list[str] = []
    for raw_item in raw_items:
        item = _bounded_text(raw_item, 80)
        if not item or item in seen:
            continue
        seen.add(item)
        items.append(item)
    return items[:25]


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _httpx_ip(payload: Mapping[str, Any]) -> str:
    candidates: list[object] = []
    for key in ("ip", "host"):
        candidates.append(payload.get(key))
    raw_a = payload.get("a")
    if isinstance(raw_a, list):
        candidates.extend(raw_a)
    else:
        candidates.append(raw_a)
    for candidate in candidates:
        text = str(candidate or "").strip()
        if not text:
            continue
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            continue
    return ""


def _httpx_port(payload: Mapping[str, Any], url: str) -> int | None:
    port = _int_or_none(payload.get("port"))
    if port is not None:
        return port
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.port:
        return int(parsed.port)
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _persist_subdomain_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    host: str,
    target: str,
) -> bool:
    metadata = {
        "connector_id": "projectdiscovery_subfinder",
        "tool": "subfinder",
        "target": target,
        "safety": "passive",
    }
    cur = con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, 'subdomain', 'discovered', 'pending', 1, 0.8, ?)
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            confidence=MAX(engagement_seeds.confidence, excluded.confidence),
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (engagement_id, host, json.dumps(metadata, sort_keys=True)),
    )
    return int(cur.rowcount or 0) > 0


def _persist_httpx_result(
    con: sqlite3.Connection,
    engagement_id: int,
    item: Mapping[str, Any],
    *,
    target: str,
) -> bool:
    url = str(item.get("url") or "").strip()
    if not url:
        return False
    final_url = str(item.get("final_url") or url).strip()
    host = str(item.get("host") or _url_host(url)).strip().lower()
    metadata = _httpx_metadata(item, target=target)
    inserted = False
    if _table_exists(con, "crawl_results") and not _crawl_result_exists(con, engagement_id, url, final_url):
        con.execute(
            """
            INSERT INTO crawl_results
                (engagement_id, url, final_url, title, tech_stack_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(engagement_id),
                url,
                final_url,
                str(item.get("title") or "httpx probe").strip()[:240],
                json.dumps(metadata, sort_keys=True),
            ),
        )
        inserted = True
    inserted = _persist_crawl_url_seed(con, engagement_id, url, metadata) or inserted
    ip = str(item.get("ip") or "").strip()
    if ip and host:
        host_id = _persist_httpx_host(con, engagement_id, ip=ip, hostname=host, metadata=metadata)
        if host_id is not None:
            inserted = (
                _persist_httpx_service(
                    con,
                    host_id=host_id,
                    url=url,
                    port=_int_or_none(item.get("port")),
                    metadata=metadata,
                )
                or inserted
            )
    return inserted


def _persist_katana_result(
    con: sqlite3.Connection,
    engagement_id: int,
    item: Mapping[str, Any],
    *,
    target: str,
) -> bool:
    url = str(item.get("url") or "").strip()
    if not url:
        return False
    metadata = _katana_metadata(item, target=target)
    inserted = False
    if _table_exists(con, "crawl_results") and not _crawl_result_exists(con, engagement_id, url, url):
        con.execute(
            """
            INSERT INTO crawl_results
                (engagement_id, url, final_url, title, tech_stack_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(engagement_id),
                url,
                url,
                str(item.get("title") or "katana crawl").strip()[:240],
                json.dumps(metadata, sort_keys=True),
            ),
        )
        inserted = True
    inserted = _persist_crawl_url_seed(con, engagement_id, url, metadata) or inserted
    return inserted


def _persist_nuclei_result(
    con: sqlite3.Connection,
    engagement_id: int,
    item: Mapping[str, Any],
    *,
    target: str,
) -> bool:
    if not _table_exists(con, "vulnerability_findings"):
        return False
    columns = _table_columns(con, "vulnerability_findings")
    payload: dict[str, Any] = {
        "engagement_id": int(engagement_id),
        "vuln_type": "nuclei_template",
        "target_url": str(item.get("target_url") or "").strip(),
        "parameter": str(item.get("parameter") or item.get("template_id") or "").strip(),
        "severity": _nuclei_db_severity(item.get("severity")),
        "title": _bounded_text(item.get("title") or item.get("template_id"), 240),
        "description": _bounded_text(item.get("description"), 1000),
        "evidence": _bounded_text(item.get("evidence"), 512),
        "cve_id": _bounded_text(item.get("cve_id"), 80),
        "cvss_score": _float_or_none(item.get("cvss_score")),
        "cvss_version": _bounded_text(item.get("cvss_version"), 20),
        "cvss_vector": _bounded_text(item.get("cvss_vector"), 240),
        "cwe_ids": str(item.get("cwe_ids") or "[]"),
        "cpe_matches": str(item.get("cpe_matches") or "[]"),
        "attack_techniques": str(item.get("attack_techniques") or "[]"),
        "stix_external_refs_json": str(item.get("stix_external_refs_json") or "[]"),
        "standards_json": json.dumps(item.get("standards") or {}, sort_keys=True),
    }
    payload["standards_json"] = _nuclei_standards_json(
        payload["standards_json"],
        target=target,
        template_id=payload["parameter"],
    )
    payload = {key: value for key, value in payload.items() if key in columns}
    target_url = str(payload.get("target_url") or "")
    parameter = str(payload.get("parameter") or "")
    if not target_url or not parameter:
        return False
    existing = con.execute(
        """
        SELECT *
        FROM vulnerability_findings
        WHERE engagement_id=? AND vuln_type=? AND target_url=? AND parameter=?
        """,
        (int(engagement_id), "nuclei_template", target_url, parameter),
    ).fetchone()
    if existing is None:
        cols = ", ".join(payload.keys())
        placeholders = ", ".join("?" for _ in payload)
        con.execute(
            f"INSERT INTO vulnerability_findings ({cols}) VALUES ({placeholders})",
            tuple(payload.values()),
        )
        return True
    update_payload = {
        key: value
        for key, value in payload.items()
        if key not in {"engagement_id", "vuln_type", "target_url", "parameter"}
    }
    if all(_stored_value_matches(existing, key, value) for key, value in update_payload.items()):
        return False
    assignments = ", ".join(f"{key}=?" for key in update_payload)
    con.execute(
        f"""
        UPDATE vulnerability_findings
        SET {assignments}, found_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND vuln_type=? AND target_url=? AND parameter=?
        """,
        (
            *update_payload.values(),
            int(engagement_id),
            "nuclei_template",
            target_url,
            parameter,
        ),
    )
    return True


def _httpx_metadata(item: Mapping[str, Any], *, target: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "connector_id": "projectdiscovery_httpx",
        "tool": "httpx",
        "target": target,
        "safety": "read_only_scope_gated",
    }
    for key in (
        "host",
        "status_code",
        "tech",
        "webserver",
        "content_type",
        "content_length",
        "response_time",
        "ip",
        "port",
    ):
        value = item.get(key)
        if value not in (None, "", []):
            metadata[key] = value
    return metadata


def _katana_metadata(item: Mapping[str, Any], *, target: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "connector_id": "projectdiscovery_katana",
        "tool": "katana",
        "target": target,
        "safety": "read_only_scope_gated",
        "depth_limit": 2,
        "rate_limit_per_second": 10,
    }
    for key in ("host", "method", "source", "tag"):
        value = item.get(key)
        if value not in (None, "", []):
            metadata[key] = value
    return metadata


def _crawl_result_exists(
    con: sqlite3.Connection,
    engagement_id: int,
    url: str,
    final_url: str,
) -> bool:
    row = con.execute(
        """
        SELECT 1
        FROM crawl_results
        WHERE engagement_id=?
          AND (url=? OR final_url=? OR url=? OR final_url=?)
        LIMIT 1
        """,
        (int(engagement_id), url, url, final_url, final_url),
    ).fetchone()
    return row is not None


def _persist_crawl_url_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    url: str,
    metadata: Mapping[str, Any],
) -> bool:
    if not _table_exists(con, "engagement_seeds"):
        return False
    cur = con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, 'url', 'discovered', 'pending', 1, 0.74, ?)
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            confidence=MAX(engagement_seeds.confidence, excluded.confidence),
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (int(engagement_id), url, json.dumps(dict(metadata), sort_keys=True)),
    )
    return int(cur.rowcount or 0) > 0


def _persist_httpx_host(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    ip: str,
    hostname: str,
    metadata: Mapping[str, Any],
) -> int | None:
    if not _table_exists(con, "hosts"):
        return None
    host_context = json.dumps(dict(metadata), sort_keys=True)
    con.execute(
        """
        INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, in_scope)
        VALUES (?, ?, ?, 'unknown', ?, 1)
        ON CONFLICT(engagement_id, ip) DO UPDATE SET
            hostname=CASE
                WHEN excluded.hostname != '' THEN excluded.hostname
                ELSE hosts.hostname
            END,
            host_context=excluded.host_context,
            in_scope=1
        """,
        (int(engagement_id), ip, hostname, host_context),
    )
    row = con.execute(
        "SELECT id FROM hosts WHERE engagement_id=? AND ip=?",
        (int(engagement_id), ip),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def _persist_httpx_service(
    con: sqlite3.Connection,
    *,
    host_id: int,
    url: str,
    port: int | None,
    metadata: Mapping[str, Any],
) -> bool:
    if port is None or not _table_exists(con, "services"):
        return False
    scheme = str(urlparse(url).scheme or "https").lower()
    service_name = "https" if scheme == "https" else "http"
    banner = _bounded_text(metadata.get("webserver"), 240)
    cur = con.execute(
        """
        INSERT INTO services (host_id, port, protocol, service_name, banner, version)
        VALUES (?, ?, 'tcp', ?, ?, ?)
        ON CONFLICT(host_id, port, protocol) DO UPDATE SET
            service_name=excluded.service_name,
            banner=excluded.banner,
            version=excluded.version
        """,
        (int(host_id), int(port), service_name, banner, ""),
    )
    return int(cur.rowcount or 0) > 0


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    return {
        str(row["name"] if isinstance(row, sqlite3.Row) else row[1])
        for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _audit_connector_run(
    con: sqlite3.Connection,
    config: ConnectorRunConfig,
    *,
    target: str,
    result: dict[str, Any],
) -> None:
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'connector_run', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            str(config.connector_id),
            target,
            _connector_audit_result(result),
            str(config.operator or "connector-runner"),
        ),
    )


def _normalize_connector_result_limit(value: object) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = _CONNECTOR_DEFAULT_RESULT_LIMIT
    return max(1, min(parsed, _CONNECTOR_MAX_RESULT_LIMIT))


def _connector_timeout_budget(config: ConnectorRunConfig) -> float:
    return max(1.0, min(float(config.timeout_seconds or 120.0), 900.0))


def _connector_depth_budget(connector_id: str) -> int:
    return 2 if connector_id == "projectdiscovery_katana" else 0


def _connector_rate_budget(config: ConnectorRunConfig) -> int:
    connector_id = str(config.connector_id or "").strip()
    if connector_id == "projectdiscovery_nuclei":
        return _normalize_nuclei_rate_limit(config.rate_limit_per_second)
    if connector_id == "projectdiscovery_katana":
        return 10
    return 1


def _gate_payload(
    gate_id: str,
    *,
    required: bool,
    status: str,
    reason: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": gate_id,
        "required": required,
        "status": status,
    }
    if reason:
        payload["reason"] = reason
    return payload


def _connector_execution_contract(
    config: ConnectorRunConfig,
    *,
    status: str,
    reason: str,
    returncode: int | None,
) -> dict[str, Any]:
    connector_id = str(config.connector_id or "").strip()
    dry_run = bool(config.dry_run)
    process_executed = returncode is not None
    gates = [
        _gate_payload("engagement_scope", required=True, status="passed"),
        _gate_payload("output_scope_filter", required=True, status="passed"),
        _gate_payload("result_limit", required=True, status="bounded"),
        _gate_payload(
            "process_execution",
            required=not dry_run,
            status=(
                "skipped_preview"
                if dry_run
                else ("executed" if process_executed else "blocked")
            ),
            reason=reason if reason in {"missing_binary", "timeout", "missing_templates"} else "",
        ),
    ]
    if connector_id == "projectdiscovery_nuclei":
        gates.append(
            _gate_payload(
                "templates_pinned",
                required=True,
                status="blocked" if reason == "missing_templates" else "passed",
                reason="missing_templates" if reason == "missing_templates" else "",
            )
        )
        gates.append(_gate_payload("rate_limit", required=True, status="bounded"))
    if connector_id == "projectdiscovery_katana":
        gates.append(_gate_payload("crawl_depth", required=True, status="bounded"))
        gates.append(_gate_payload("rate_limit", required=True, status="bounded"))
    budgets = {
        "concurrency": 1,
        "depth": _connector_depth_budget(connector_id),
        "queue_items": 1,
        "max_results": _normalize_connector_result_limit(config.max_results),
        "timeout_seconds": _connector_timeout_budget(config),
        "rate_limit_per_second": _connector_rate_budget(config),
    }
    would_execute = (
        not dry_run
        and reason not in {"missing_binary", "missing_templates"}
        and status != "planned"
    )
    return {
        "gates": gates,
        "budgets": budgets,
        "plan": {
            "will_execute_process": would_execute,
            "process_executed": process_executed,
            "will_touch_network": would_execute,
            "will_persist_scoped_results": process_executed,
            "will_store_raw_stdout": False,
            "will_create_audit_row": True,
        },
    }


def _result_payload(
    config: ConnectorRunConfig,
    *,
    target: str,
    command: Sequence[str],
    status: str,
    returncode: int | None,
    discovered: list[str],
    persisted: list[str],
    skipped: list[dict[str, str]],
    reason: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    payload = {
        "connector_id": str(config.connector_id),
        "engagement_id": int(config.engagement_id),
        "target": target,
        "status": status,
        "dry_run": bool(config.dry_run),
        "command": list(command),
        "returncode": returncode,
        "discovered_count": len(discovered),
        "persisted_count": len(persisted),
        "skipped_count": len(skipped),
        "discovered": discovered,
        "persisted": persisted,
        "skipped": skipped,
        "reason": reason,
        "stderr": stderr,
    }
    payload.update(
        _connector_execution_contract(
            config,
            status=status,
            reason=reason,
            returncode=returncode,
        )
    )
    return payload


def _nuclei_result_payload(
    config: ConnectorRunConfig,
    *,
    target: str,
    command: Sequence[str],
    status: str,
    returncode: int | None,
    discovered: list[str],
    persisted: list[str],
    skipped: list[dict[str, str]],
    templates: tuple[str, ...],
    severities: tuple[str, ...],
    rate_limit: int,
    reason: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    payload = _result_payload(
        config,
        target=target,
        command=command,
        status=status,
        returncode=returncode,
        discovered=discovered,
        persisted=persisted,
        skipped=skipped,
        reason=reason,
        stderr=stderr,
    )
    payload.update(
        {
            "source": "nuclei_jsonl",
            "finding_count": len(discovered),
            "template_count": len(templates),
            "template_paths": [_bounded_text(item, 260) for item in templates],
            "severity_filter": list(severities),
            "rate_limit_per_second": int(rate_limit),
        }
    )
    return payload


def _bounded_text(value: object, limit: int) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]


def _normalize_nuclei_templates(value: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _bounded_text(item, 260)
        lowered = text.lower()
        if not text or text in seen:
            continue
        if (
            text.startswith("-")
            or "://" in lowered
            or any(ch in text for ch in ('"', "'", ";", "|", "&", ">", "<"))
        ):
            raise ValueError("nuclei templates must be explicit local paths or template IDs")
        seen.add(text)
        out.append(text)
        if len(out) >= 25:
            break
    return tuple(out)


def _normalize_nuclei_severities(value: Sequence[str]) -> tuple[str, ...]:
    raw = value or _NUCLEI_DEFAULT_SEVERITIES
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        for part in str(item or "").split(","):
            text = part.strip().lower()
            if not text or text in seen:
                continue
            if text not in _NUCLEI_ALLOWED_SEVERITIES:
                raise ValueError(
                    "nuclei severity must be one of "
                    f"{', '.join(_NUCLEI_ALLOWED_SEVERITIES)}"
                )
            seen.add(text)
            out.append(text)
    return tuple(out or _NUCLEI_DEFAULT_SEVERITIES)


def _normalize_nuclei_rate_limit(value: object) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = 5
    return max(1, min(parsed, 25))


def _nuclei_command(
    binary: str,
    target: str,
    templates: tuple[str, ...],
    severities: tuple[str, ...],
    rate_limit: int,
) -> list[str]:
    args = [
        binary,
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-no-color",
        "-rl",
        str(rate_limit),
        "-severity",
        ",".join(severities),
    ]
    for template in templates:
        args.extend(["-t", template])
    return args


def _nuclei_target_url(payload: Mapping[str, Any], *, target_host: str) -> str:
    candidates: list[object] = [
        payload.get("matched-at"),
        payload.get("matched_at"),
        payload.get("url"),
        payload.get("host"),
        payload.get("target"),
    ]
    for parent_key in ("request", "response", "meta"):
        parent = payload.get(parent_key)
        if isinstance(parent, Mapping):
            candidates.extend([parent.get("url"), parent.get("endpoint"), parent.get("host")])
    for candidate in candidates:
        url = _httpx_url_from_candidate(candidate, default_host=target_host)
        if url:
            return strip_sensitive_url_query(url)
    return ""


def _nuclei_db_severity(value: object) -> str:
    text = str(value or "").strip().upper()
    if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return text
    if text in {"INFORMATIONAL", "UNKNOWN"}:
        return "INFO"
    return "INFO"


def _extract_standard_ids(
    pattern: re.Pattern[str],
    *values: object,
    transform=str.upper,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for item in _listish_strings(raw):
            for match in pattern.findall(item):
                text = transform(str(match or "").strip())
                if text and text not in seen:
                    seen.add(text)
                    out.append(text)
    return out[:50]


def _listish_strings(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        raw_items = list(value.values())
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        raw_items = [value]
    out: list[str] = []
    for item in raw_items:
        if isinstance(item, (list, tuple, set)):
            out.extend(_listish_strings(item))
            continue
        out.append(str(item or ""))
    return out


def _float_or_none(value: object) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _cvss_version_from_vector(value: object) -> str:
    match = _CVSS_VECTOR_RE.match(str(value or "").strip())
    return match.group("version") if match else ""


def _safe_reference_url(value: object) -> str:
    url = _httpx_url_from_candidate(value, default_host="")
    return strip_sensitive_url_query(url) if url else ""


def _nuclei_reference_urls(value: object) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for item in _listish_strings(value):
        safe = _safe_reference_url(item)
        if safe and safe not in seen:
            seen.add(safe)
            urls.append(safe)
    return urls[:25]


def _count_listish(value: object) -> int:
    return len([item for item in _listish_strings(value) if str(item or "").strip()])


def _nuclei_evidence(
    *,
    template_id: str,
    target_url: str,
    matcher_name: str,
    severity: str,
) -> str:
    parts = [
        f"nuclei_template={_bounded_text(template_id, 160)}",
        f"matched_at={strip_sensitive_url_query(target_url)}",
        f"severity={_bounded_text(severity, 20)}",
    ]
    if matcher_name:
        parts.append(f"matcher={_bounded_text(matcher_name, 80)}")
    return " ".join(parts)[:512]


def _nuclei_finding_label(item: Mapping[str, Any]) -> str:
    return " ".join(
        part
        for part in (
            _bounded_text(item.get("severity"), 20),
            _bounded_text(item.get("template_id") or item.get("parameter"), 160),
            _bounded_text(item.get("target_url"), 240),
        )
        if part
    )


def _nuclei_standards_json(value: object, *, target: str, template_id: str) -> str:
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = {}
    payload = dict(parsed) if isinstance(parsed, Mapping) else {}
    payload["source_target"] = target
    payload["template_id"] = template_id
    payload["raw_evidence_persisted"] = False
    return json.dumps(payload, sort_keys=True)


def _stored_value_matches(row: sqlite3.Row, key: str, expected: object) -> bool:
    try:
        current = row[key]
    except (IndexError, KeyError):
        return False
    if isinstance(expected, float):
        try:
            return float(current) == expected
        except (TypeError, ValueError):
            return False
    return str(current or "") == str(expected or "")


def _connector_audit_result(result: dict[str, Any]) -> str:
    parts = [
        str(result["status"]),
        f"discovered={result['discovered_count']}",
        f"persisted={result['persisted_count']}",
        f"skipped={result['skipped_count']}",
    ]
    budgets = result.get("budgets") if isinstance(result.get("budgets"), Mapping) else {}
    if budgets.get("max_results"):
        parts.append(f"max_results={budgets['max_results']}")
    reason = _bounded_text(result.get("reason"), 80)
    if reason:
        parts.append(f"reason={reason}")
    return " ".join(parts)
