from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.opsec.scope_gate import (
    ScopeViolationError,
    assert_in_scope,
    assert_url_in_scope,
    scope_entries_from_payload,
)
from forge.utils.intel.provider_urls import (
    normalize_provider_url,
    persist_provider_url_candidate,
    provider_url_hostname,
)

SUPPORTED_DISCOVERY_IMPORT_CONNECTORS = ("shodan_host_lookup", "censys_lookup", "urlscan_search")


@dataclass(frozen=True)
class DiscoveryReportImportConfig:
    connector_id: str
    engagement_id: int
    report_path: Path | None = None
    target: str = ""
    operator: str = "connector-import"


@dataclass(frozen=True)
class _ImportedService:
    port: int
    protocol: str
    service_name: str = ""
    banner: str = ""
    version: str = ""


@dataclass(frozen=True)
class _ImportedHost:
    ip: str
    names: tuple[str, ...]
    services: tuple[_ImportedService, ...]
    metadata: Mapping[str, Any]
    urls: tuple[str, ...] = ()


def import_discovery_report(
    con: sqlite3.Connection,
    config: DiscoveryReportImportConfig,
    *,
    report_text: str | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    if connector_id not in SUPPORTED_DISCOVERY_IMPORT_CONNECTORS:
        raise ValueError(
            "discovery import connector must be one of "
            f"{', '.join(SUPPORTED_DISCOVERY_IMPORT_CONNECTORS)}"
        )
    engagement_id = int(config.engagement_id)
    scope = _scope_for_engagement(con, engagement_id)
    target = _normalize_target(config.target)
    if target:
        assert_in_scope(target, scope)
    text = report_text
    if text is None:
        if config.report_path is None:
            raise ValueError("report_path is required")
        text = config.report_path.read_text(encoding="utf-8")
    payload = _json_document(text)
    imported_hosts = _parse_discovery_report(connector_id, payload)
    provider_source = _provider_source_for_connector(connector_id)
    persisted_hosts = 0
    persisted_services = 0
    persisted_seeds = 0
    persisted_urls = 0
    persisted_crawl_rows = 0
    skipped_urls = 0
    skipped: list[dict[str, str]] = []
    for imported in imported_hosts:
        decision = _scope_decision(imported, scope=scope, target=target)
        if not decision["allowed"]:
            skipped.append(
                {
                    "reason": str(decision["reason"]),
                    "ip": imported.ip,
                    "names": ",".join(imported.names[:3]),
                }
            )
            continue
        host_id, host_changed = _upsert_host(
            con,
            engagement_id=engagement_id,
            connector_id=connector_id,
            imported=imported,
            attribution_basis=str(decision["basis"]),
        )
        persisted_hosts += 1 if host_changed else 0
        for service in imported.services:
            if _upsert_service(con, host_id=host_id, service=service):
                persisted_services += 1
        for seed_value, seed_type in _seed_candidates(imported, scope=scope):
            if _upsert_seed(
                con,
                engagement_id=engagement_id,
                connector_id=connector_id,
                seed_value=seed_value,
                seed_type=seed_type,
                target=target,
            ):
                persisted_seeds += 1
        for url in imported.urls:
            try:
                assert_url_in_scope(url, scope)
            except ScopeViolationError:
                skipped_urls += 1
                continue
            persisted_url = persist_provider_url_candidate(
                con,
                engagement_id,
                url,
                discovery=provider_source,
                metadata={
                    "connector_id": connector_id,
                    "target": target,
                    "source": "provider_report_import",
                    "provider_sources": [provider_source],
                    "attribution_basis": str(decision["basis"]),
                },
                confidence=0.75,
            )
            persisted_urls += 1 if persisted_url["seed_inserted"] else 0
            persisted_crawl_rows += 1 if persisted_url["crawl_inserted"] else 0
    result = {
        "connector_id": connector_id,
        "engagement_id": engagement_id,
        "target": target,
        "status": "completed",
        "parsed_count": len(imported_hosts),
        "persisted_count": persisted_hosts,
        "persisted_host_count": persisted_hosts,
        "persisted_service_count": persisted_services,
        "persisted_seed_count": persisted_seeds,
        "persisted_url_seed_count": persisted_urls,
        "persisted_crawl_result_count": persisted_crawl_rows,
        "skipped_count": len(skipped),
        "skipped_url_count": skipped_urls,
        "skipped": skipped[:25],
        "source": "provider_report_import",
        "report_file": str(config.report_path or ""),
        "privacy": "Provider report bodies and API keys are not returned or audited.",
    }
    _audit_discovery_import(con, config, result=result)
    con.commit()
    return result


def _parse_discovery_report(connector_id: str, payload: Any) -> list[_ImportedHost]:
    if connector_id == "shodan_host_lookup":
        return _parse_shodan_report(payload)
    if connector_id == "censys_lookup":
        return _parse_censys_report(payload)
    if connector_id == "urlscan_search":
        return _parse_urlscan_report(payload)
    return []


def _provider_source_for_connector(connector_id: str) -> str:
    if connector_id == "urlscan_search":
        return "urlscan"
    if connector_id == "shodan_host_lookup":
        return "shodan"
    if connector_id == "censys_lookup":
        return "censys"
    return connector_id


def _parse_shodan_report(payload: Any) -> list[_ImportedHost]:
    items = _report_items(payload)
    hosts: list[_ImportedHost] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        ip = _normalize_ip(_field(item, "ip_str", "ip"))
        if not ip:
            continue
        domains = _list_values(item.get("domains"))
        names = _ordered_names(
            _list_values(item.get("hostnames"))
            + _nested_name_values(item)
        )
        service_rows = item.get("data") if isinstance(item.get("data"), list) else [item]
        services = tuple(
            service
            for service in (_shodan_service(row) for row in service_rows if isinstance(row, Mapping))
            if service is not None
        )
        metadata = _bounded_mapping(
            {
                "provider": "shodan",
                "org": _field(item, "org", "isp"),
                "asn": _field(item, "asn"),
                "country": _field(item, "country_name", "country_code"),
                "city": _field(item, "city"),
                "domains": ",".join(domains[:10]),
                "name_count": len(names),
                "service_count": len(services),
            }
        )
        hosts.append(_ImportedHost(ip=ip, names=tuple(names), services=services, metadata=metadata))
    return hosts


def _parse_urlscan_report(payload: Any) -> list[_ImportedHost]:
    items = _report_items(payload)
    hosts: list[_ImportedHost] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        page = item.get("page") if isinstance(item.get("page"), Mapping) else {}
        task = item.get("task") if isinstance(item.get("task"), Mapping) else {}
        urls = _ordered_urls(
            [
                page.get("url") if isinstance(page, Mapping) else "",
                task.get("url") if isinstance(task, Mapping) else "",
            ]
        )
        names = _ordered_names(
            _list_values(page.get("domain") if isinstance(page, Mapping) else "")
            + _list_values(task.get("domain") if isinstance(task, Mapping) else "")
            + [provider_url_hostname(url) for url in urls]
        )
        page_ip = _field(page, "ip") if isinstance(page, Mapping) else ""
        ip = _normalize_ip(page_ip or _field(item, "ip", "ip_str"))
        if not ip:
            continue
        services = tuple(
            service
            for service in (
                _urlscan_service(url, page if isinstance(page, Mapping) else {}) for url in urls[:1]
            )
            if service is not None
        )
        metadata = _bounded_mapping(
            {
                "provider": "urlscan",
                "asn": _field(page, "asn", "asnname") if isinstance(page, Mapping) else "",
                "country": _field(page, "country") if isinstance(page, Mapping) else "",
                "server": _field(page, "server") if isinstance(page, Mapping) else "",
                "task_source": _field(task, "source") if isinstance(task, Mapping) else "",
                "scan_id": _field(task, "uuid") if isinstance(task, Mapping) else _field(item, "_id"),
                "name_count": len(names),
                "url_count": len(urls),
                "service_count": len(services),
            }
        )
        hosts.append(
            _ImportedHost(
                ip=ip,
                names=tuple(names),
                services=services,
                metadata=metadata,
                urls=tuple(urls),
            )
        )
    return hosts


def _parse_censys_report(payload: Any) -> list[_ImportedHost]:
    items = _report_items(payload)
    hosts: list[_ImportedHost] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        ip = _normalize_ip(_field(item, "ip", "ip_str"))
        if not ip:
            continue
        services_payload = item.get("services") if isinstance(item.get("services"), list) else []
        names = _ordered_names(
            _list_values(item.get("names"))
            + _list_values(item.get("dns_names"))
            + _list_values(_nested_get(item, ("dns", "names")))
            + _censys_service_names(services_payload)
        )
        services = tuple(
            service
            for service in (
                _censys_service(row) for row in services_payload if isinstance(row, Mapping)
            )
            if service is not None
        )
        metadata = _bounded_mapping(
            {
                "provider": "censys",
                "location": _nested_get(item, ("location", "country")),
                "autonomous_system": _nested_get(item, ("autonomous_system", "asn")),
                "name_count": len(names),
                "service_count": len(services),
            }
        )
        hosts.append(_ImportedHost(ip=ip, names=tuple(names), services=services, metadata=metadata))
    return hosts


def _urlscan_service(url: str, row: Mapping[str, Any]) -> _ImportedService | None:
    normalized = normalize_provider_url(url)
    if not normalized:
        return None
    from urllib.parse import urlparse

    parsed = urlparse(normalized)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    service_name = _bounded_text(row.get("server") or parsed.scheme, 80)
    banner = _bounded_text(row.get("title") or row.get("mimeType"), 512)
    return _ImportedService(
        port=port,
        protocol="tcp",
        service_name=service_name or parsed.scheme,
        banner=banner,
        version="",
    )


def _report_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, Mapping):
        return []
    for key in ("matches", "hits", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    result = payload.get("result")
    if isinstance(result, Mapping):
        for key in ("matches", "hits", "results"):
            value = result.get(key)
            if isinstance(value, list):
                return value
        if result.get("ip") or result.get("ip_str"):
            return [result]
    if payload.get("ip") or payload.get("ip_str"):
        return [payload]
    return []


def _shodan_service(row: Mapping[str, Any]) -> _ImportedService | None:
    port = _coerce_port(row.get("port"))
    if port is None:
        return None
    service_name = _bounded_text(
        row.get("_shodan", {}).get("module")
        if isinstance(row.get("_shodan"), Mapping)
        else row.get("transport"),
        80,
    )
    product = _bounded_text(row.get("product") or row.get("devicetype") or row.get("transport"), 80)
    version = _bounded_text(row.get("version"), 120)
    banner = _bounded_text(row.get("data") or row.get("title") or row.get("html"), 512)
    return _ImportedService(
        port=port,
        protocol=_protocol(row.get("transport") or row.get("protocol")),
        service_name=service_name or product,
        banner=banner,
        version=version,
    )


def _censys_service(row: Mapping[str, Any]) -> _ImportedService | None:
    port = _coerce_port(row.get("port"))
    if port is None:
        return None
    service_name = _bounded_text(
        row.get("service_name") or row.get("extended_service_name") or row.get("transport_protocol"),
        80,
    )
    banner = _bounded_text(
        row.get("banner")
        or row.get("observed_banner")
        or _nested_get(row, ("http", "response", "html_title")),
        512,
    )
    version = _bounded_text(row.get("software") or row.get("observed_at"), 120)
    return _ImportedService(
        port=port,
        protocol=_protocol(row.get("transport_protocol") or row.get("protocol")),
        service_name=service_name,
        banner=banner,
        version=version,
    )


def _scope_decision(
    imported: _ImportedHost,
    *,
    scope: list[str],
    target: str,
) -> dict[str, Any]:
    if target and not any(_name_matches_target(name, target) for name in imported.names):
        return {"allowed": False, "reason": "target_name_not_observed", "basis": ""}
    for name in imported.names:
        try:
            assert_in_scope(name, scope)
        except ScopeViolationError:
            continue
        return {"allowed": True, "reason": "", "basis": f"name:{name}"}
    try:
        assert_in_scope(imported.ip, scope)
    except ScopeViolationError:
        return {"allowed": False, "reason": "host_out_of_scope", "basis": ""}
    return {"allowed": True, "reason": "", "basis": f"ip:{imported.ip}"}


def _upsert_host(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    imported: _ImportedHost,
    attribution_basis: str,
) -> tuple[int, bool]:
    hostname = imported.names[0] if imported.names else None
    context = dict(imported.metadata)
    context.update(
        {
            "connector_id": connector_id,
            "provider_report_import": True,
            "attribution_basis": attribution_basis,
            "hostnames": list(imported.names[:25]),
        }
    )
    cur = con.execute(
        """
        INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, in_scope)
        VALUES (?, ?, ?, 'unknown', ?, 1)
        ON CONFLICT(engagement_id, ip) DO UPDATE SET
            hostname=COALESCE(excluded.hostname, hosts.hostname),
            host_context=excluded.host_context,
            in_scope=1
        """,
        (engagement_id, imported.ip, hostname, json.dumps(context, sort_keys=True)),
    )
    row = con.execute(
        "SELECT id FROM hosts WHERE engagement_id=? AND ip=?",
        (engagement_id, imported.ip),
    ).fetchone()
    return int(row["id"]), int(cur.rowcount or 0) > 0


def _upsert_service(
    con: sqlite3.Connection,
    *,
    host_id: int,
    service: _ImportedService,
) -> bool:
    cur = con.execute(
        """
        INSERT INTO services (host_id, port, protocol, service_name, banner, version)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(host_id, port, protocol) DO UPDATE SET
            service_name=excluded.service_name,
            banner=excluded.banner,
            version=excluded.version
        """,
        (
            host_id,
            int(service.port),
            service.protocol,
            service.service_name,
            service.banner,
            service.version,
        ),
    )
    return int(cur.rowcount or 0) > 0


def _seed_candidates(imported: _ImportedHost, *, scope: list[str]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for name in imported.names:
        try:
            assert_in_scope(name, scope)
        except ScopeViolationError:
            continue
        candidates.append((name, "subdomain"))
    try:
        assert_in_scope(imported.ip, scope)
    except ScopeViolationError:
        return candidates
    seed_type = "ipv6" if ":" in imported.ip else "ipv4"
    candidates.append((imported.ip, seed_type))
    return candidates


def _upsert_seed(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    seed_value: str,
    seed_type: str,
    target: str,
) -> bool:
    metadata = {
        "connector_id": connector_id,
        "target": target,
        "source": "provider_report_import",
        "safety": "passive_api_report",
    }
    cur = con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, ?, 'discovered', 'pending', 1, 0.75, ?)
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            confidence=MAX(engagement_seeds.confidence, excluded.confidence),
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (engagement_id, seed_value, seed_type, json.dumps(metadata, sort_keys=True)),
    )
    return int(cur.rowcount or 0) > 0


def _audit_discovery_import(
    con: sqlite3.Connection,
    config: DiscoveryReportImportConfig,
    *,
    result: Mapping[str, Any],
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    parts = [
        str(result.get("status") or ""),
        f"parsed={int(result.get('parsed_count') or 0)}",
        f"hosts={int(result.get('persisted_host_count') or 0)}",
        f"services={int(result.get('persisted_service_count') or 0)}",
        f"seeds={int(result.get('persisted_seed_count') or 0)}",
        f"urls={int(result.get('persisted_url_seed_count') or 0)}",
        f"crawl={int(result.get('persisted_crawl_result_count') or 0)}",
        f"skipped={int(result.get('skipped_count') or 0)}",
        f"url_skipped={int(result.get('skipped_url_count') or 0)}",
    ]
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'discovery_report_import', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            str(result.get("connector_id") or config.connector_id),
            str(result.get("target") or "*"),
            " ".join(parts),
            str(config.operator or "connector-import"),
        ),
    )


def _json_document(text: str) -> Any:
    try:
        return json.loads(str(text or ""))
    except json.JSONDecodeError as exc:
        raise ValueError("discovery report is not valid JSON") from exc


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


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _field(mapping: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _nested_get(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    value: Any = mapping
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _list_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip().lower().strip(".") for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip().lower().strip(".")]
    return []


def _nested_name_values(item: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    ssl = item.get("ssl")
    if isinstance(ssl, Mapping):
        cert = ssl.get("cert")
        if isinstance(cert, Mapping):
            subject = cert.get("subject")
            if isinstance(subject, Mapping):
                values.extend(_list_values(subject.get("CN")))
            san = cert.get("subject_alt_names")
            values.extend(_list_values(san))
    return values


def _censys_service_names(services: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(services, list):
        return names
    for service in services:
        if not isinstance(service, Mapping):
            continue
        names.extend(_list_values(_nested_get(service, ("tls", "certificates", "leaf_data", "names"))))
        names.extend(_list_values(_nested_get(service, ("dns", "names"))))
    return names


def _ordered_names(values: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for value in values:
        name = str(value or "").strip().lower().strip(".")
        if not name or name in seen or "*" in name or " " in name:
            continue
        seen.add(name)
        names.append(name)
    return names


def _ordered_urls(values: list[object]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for value in values:
        url = normalize_provider_url(str(value or ""))
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def _normalize_ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        try:
            return str(ipaddress.ip_address(int(str(value).strip())))
        except (ValueError, TypeError):
            return ""


def _coerce_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _protocol(value: Any) -> str:
    protocol = str(value or "tcp").strip().lower()
    return protocol if protocol in {"tcp", "udp"} else "tcp"


def _normalize_target(value: object) -> str:
    return str(value or "").strip().lower().strip(".")


def _name_matches_target(name: str, target: str) -> bool:
    normalized_name = _normalize_target(name)
    normalized_target = _normalize_target(target)
    return normalized_name == normalized_target or normalized_name.endswith(f".{normalized_target}")


def _bounded_mapping(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): _bounded_text(value, 240)
        for key, value in values.items()
        if value not in (None, "", [], {})
    }


def _bounded_text(value: object, limit: int) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]
