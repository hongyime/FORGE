from __future__ import annotations

import ipaddress
import json
import sqlite3
from csv import DictReader
from io import StringIO
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.graph.assets import upsert_asset_entity, upsert_asset_relationship
from forge.connectors.runner import _nuclei_result_from_line, _persist_nuclei_result
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

SUPPORTED_DISCOVERY_IMPORT_CONNECTORS = (
    "shodan_host_lookup",
    "censys_lookup",
    "urlscan_search",
    "asset_delta_import",
    "runzero_asset_export",
    "projectdiscovery_cloud",
)
DISCOVERY_IMPORT_SCHEMA_VERSION = "forge.discovery_report_import.v1"
MAX_DISCOVERY_REPORT_BYTES = 10 * 1024 * 1024
MAX_DISCOVERY_IMPORT_ITEMS = 10000


@dataclass(frozen=True)
class DiscoveryReportImportConfig:
    connector_id: str
    engagement_id: int
    report_path: Path | None = None
    target: str = ""
    operator: str = "connector-import"
    dry_run: bool = False
    limit: int | None = None


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
        text = _read_discovery_report_text(config.report_path)
    payload = _discovery_document(connector_id, text)
    imported_hosts = _parse_discovery_report(connector_id, payload)
    imported_findings = (
        _parse_projectdiscovery_cloud_findings(
            payload,
            target_host=target or _first_scope_host(scope),
        )
        if connector_id == "projectdiscovery_cloud"
        else []
    )
    parsed_template_count = (
        _projectdiscovery_cloud_template_count(payload)
        if connector_id == "projectdiscovery_cloud"
        else 0
    )
    template_inventory = (
        _projectdiscovery_cloud_template_inventory(payload)
        if connector_id == "projectdiscovery_cloud"
        else []
    )
    item_limit = _normalize_import_limit(config.limit)
    selected_hosts = imported_hosts[:item_limit]
    selected_findings = imported_findings[:item_limit]
    selected_templates = template_inventory[:item_limit]
    total_count = len(imported_hosts) + len(imported_findings) + len(template_inventory)
    selected_count = len(selected_hosts) + len(selected_findings) + len(selected_templates)
    omitted_count = max(0, total_count - selected_count)
    dry_run = bool(config.dry_run)
    provider_source = _provider_source_for_connector(connector_id)
    persisted_hosts = 0
    persisted_services = 0
    persisted_seeds = 0
    persisted_urls = 0
    persisted_crawl_rows = 0
    persisted_graph_nodes = 0
    persisted_graph_relationships = 0
    persisted_findings = 0
    persisted_templates = 0
    skipped_urls = 0
    skipped_findings = 0
    skipped: list[dict[str, str]] = []
    for imported in selected_hosts:
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
        if dry_run:
            continue
        host_id, host_changed = _upsert_host(
            con,
            engagement_id=engagement_id,
            connector_id=connector_id,
            imported=imported,
            attribution_basis=str(decision["basis"]),
        )
        persisted_hosts += 1 if host_changed else 0
        graph = _upsert_imported_asset_graph(
            con,
            engagement_id=engagement_id,
            connector_id=connector_id,
            host_id=host_id,
            imported=imported,
            attribution_basis=str(decision["basis"]),
        )
        persisted_graph_nodes += graph["node_count"]
        persisted_graph_relationships += graph["relationship_count"]
        for service in imported.services:
            service_id, service_changed = _upsert_service(con, host_id=host_id, service=service)
            if service_changed:
                persisted_services += 1
            graph = _upsert_imported_service_graph(
                con,
                engagement_id=engagement_id,
                connector_id=connector_id,
                host_id=host_id,
                service_id=service_id,
                imported=imported,
                service=service,
            )
            persisted_graph_nodes += graph["node_count"]
            persisted_graph_relationships += graph["relationship_count"]
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
    for finding in selected_findings:
        target_url = str(finding.get("target_url") or "")
        try:
            assert_url_in_scope(target_url, scope)
        except ScopeViolationError:
            skipped_findings += 1
            continue
        if target and not _url_matches_target(target_url, target):
            skipped_findings += 1
            continue
        if dry_run:
            continue
        standards = dict(finding.get("standards") or {})
        standards["source"] = "projectdiscovery_cloud"
        standards["connector_id"] = "projectdiscovery_cloud"
        if _persist_nuclei_result(
            con,
            engagement_id,
            {**finding, "standards": standards},
            target=target or provider_url_hostname(target_url),
        ):
            persisted_findings += 1
    if connector_id == "projectdiscovery_cloud" and selected_templates and not dry_run:
        template_graph = _upsert_projectdiscovery_template_inventory(
            con,
            engagement_id=engagement_id,
            templates=selected_templates,
        )
        persisted_templates = template_graph["template_count"]
        persisted_graph_nodes += template_graph["node_count"]
    result = {
        "schema_version": DISCOVERY_IMPORT_SCHEMA_VERSION,
        "connector_id": connector_id,
        "engagement_id": engagement_id,
        "target": target,
        "status": "dry_run" if dry_run else "completed",
        "execution_policy": (
            "dry_run_no_writes" if dry_run else "applied_local_write"
        ),
        "dry_run": dry_run,
        "apply_requested": not dry_run,
        "total_count": total_count,
        "selected_count": selected_count,
        "omitted_count": omitted_count,
        "limit": None if config.limit is None else item_limit,
        "parsed_count": len(imported_hosts),
        "selected_host_count": len(selected_hosts),
        "persisted_count": persisted_hosts,
        "persisted_host_count": persisted_hosts,
        "persisted_service_count": persisted_services,
        "persisted_seed_count": persisted_seeds,
        "persisted_url_seed_count": persisted_urls,
        "persisted_crawl_result_count": persisted_crawl_rows,
        "persisted_graph_node_count": persisted_graph_nodes,
        "persisted_graph_relationship_count": persisted_graph_relationships,
        "parsed_finding_count": len(imported_findings),
        "selected_finding_count": len(selected_findings),
        "persisted_finding_count": persisted_findings,
        "skipped_finding_count": skipped_findings,
        "parsed_template_count": parsed_template_count,
        "selected_template_count": len(selected_templates),
        "persisted_template_count": persisted_templates,
        "templates": selected_templates[:50],
        "skipped_count": len(skipped),
        "skipped_url_count": skipped_urls,
        "skipped": skipped[:25],
        "source": "provider_report_import",
        "report_file": str(config.report_path or ""),
        "privacy": "Provider report bodies and API keys are not returned or audited.",
    }
    if not dry_run:
        _audit_discovery_import(con, config, result=result)
        con.commit()
    return result


def _normalize_import_limit(value: int | None) -> int:
    if value is None:
        return MAX_DISCOVERY_IMPORT_ITEMS
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return MAX_DISCOVERY_IMPORT_ITEMS
    if limit <= 0:
        return MAX_DISCOVERY_IMPORT_ITEMS
    return min(limit, MAX_DISCOVERY_IMPORT_ITEMS)


def _read_discovery_report_text(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_DISCOVERY_REPORT_BYTES:
        raise ValueError(
            "discovery report exceeds max size "
            f"{MAX_DISCOVERY_REPORT_BYTES} bytes"
        )
    return path.read_text(encoding="utf-8")


def _parse_discovery_report(connector_id: str, payload: Any) -> list[_ImportedHost]:
    if connector_id == "shodan_host_lookup":
        return _parse_shodan_report(payload)
    if connector_id == "censys_lookup":
        return _parse_censys_report(payload)
    if connector_id == "urlscan_search":
        return _parse_urlscan_report(payload)
    if connector_id in {"asset_delta_import", "runzero_asset_export"}:
        return _parse_asset_delta_report(payload, connector_id=connector_id)
    if connector_id == "projectdiscovery_cloud":
        return _parse_asset_delta_report(payload, connector_id=connector_id)
    return []


def _provider_source_for_connector(connector_id: str) -> str:
    if connector_id == "urlscan_search":
        return "urlscan"
    if connector_id == "shodan_host_lookup":
        return "shodan"
    if connector_id == "censys_lookup":
        return "censys"
    if connector_id == "runzero_asset_export":
        return "runzero"
    if connector_id == "asset_delta_import":
        return "asset_delta"
    if connector_id == "projectdiscovery_cloud":
        return "projectdiscovery_cloud"
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
        fingerprints = _censys_fingerprint_payload(item, services_payload)
        topology = _topology_payload(item)
        metadata = _bounded_mapping(
            {
                "provider": "censys",
                "source": _field(item, "source", "source_name") or "censys",
                "location": _nested_get(item, ("location", "country")),
                "autonomous_system": _nested_get(item, ("autonomous_system", "asn")),
                "fingerprint_depth": len(fingerprints),
                "topology_relationship_count": len(topology),
                "fingerprints": fingerprints,
                "topology_relationships": topology,
                "name_count": len(names),
                "service_count": len(services),
            },
            depth=4,
        )
        hosts.append(_ImportedHost(ip=ip, names=tuple(names), services=services, metadata=metadata))
    return hosts


def _parse_asset_delta_report(payload: Any, *, connector_id: str) -> list[_ImportedHost]:
    items = _report_items(payload)
    hosts: list[_ImportedHost] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        ip = _normalize_ip(
            _field(item, "ip", "ip_address", "address", "primary_ip", "public_ip")
            or _first_list_value(item.get("addresses"))
            or _first_list_value(item.get("ips"))
        )
        if not ip:
            continue
        names = _ordered_names(
            _list_values(_field(item, "hostname", "host_name", "name", "dns_name", "fqdn"))
            + _list_values(item.get("hostnames"))
            + _list_values(item.get("dns_names"))
            + _list_values(item.get("names"))
        )
        services_payload = _service_rows(item)
        services = tuple(
            service
            for service in (_asset_delta_service(row) for row in services_payload)
            if service is not None
        )
        if connector_id == "runzero_asset_export":
            provider = "runzero"
        elif connector_id == "projectdiscovery_cloud":
            provider = "projectdiscovery_cloud"
        else:
            provider = "asset_delta"
        fingerprints = _fingerprint_payload(item)
        topology = _topology_payload(item)
        metadata = _bounded_mapping(
            {
                "provider": provider,
                "asset_id": _field(item, "id", "asset_id", "uuid"),
                "source": _field(item, "source", "source_name"),
                "os": _field(item, "os", "os_name", "platform"),
                "mac": _field(item, "mac", "mac_address"),
                "hardware": _field(item, "hardware", "manufacturer", "vendor"),
                "tags": ",".join(_list_values(item.get("tags"))[:20]),
                "fingerprint_depth": len(fingerprints),
                "topology_relationship_count": len(topology),
                "fingerprints": fingerprints,
                "topology_relationships": topology,
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


def _asset_delta_service(row: Mapping[str, Any]) -> _ImportedService | None:
    port = _coerce_port(_field(row, "port", "number", "port_number"))
    if port is None:
        return None
    return _ImportedService(
        port=port,
        protocol=_protocol(_field(row, "protocol", "transport", "transport_protocol")),
        service_name=_bounded_text(
            _field(row, "service", "service_name", "name", "protocol_name"),
            80,
        ),
        banner=_bounded_text(_field(row, "banner", "product", "title"), 512),
        version=_bounded_text(_field(row, "version", "product_version"), 120),
    )


def _service_rows(item: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in ("services", "open_ports", "ports"):
        value = item.get(key)
        if not isinstance(value, list):
            continue
        rows: list[Mapping[str, Any]] = []
        for entry in value:
            if isinstance(entry, Mapping):
                rows.append(entry)
            elif _coerce_port(entry) is not None:
                rows.append({"port": entry, "protocol": "tcp"})
        return rows
    port = _coerce_port(_field(item, "port", "open_port"))
    if port is None:
        return []
    return [
        {
            "port": port,
            "protocol": _field(item, "protocol", "transport", "transport_protocol") or "tcp",
            "service_name": _field(item, "service", "service_name"),
            "banner": _field(item, "banner", "product"),
            "version": _field(item, "version", "product_version"),
        }
    ]


def _report_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, Mapping):
        return []
    for key in ("matches", "hits", "results", "assets", "items", "data"):
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


def _parse_projectdiscovery_cloud_findings(
    payload: Any,
    *,
    target_host: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in _projectdiscovery_cloud_finding_rows(payload):
        normalized = _projectdiscovery_cloud_nuclei_row(row)
        if not normalized:
            continue
        item = _nuclei_result_from_line(json.dumps(normalized), target_host=target_host)
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


def _projectdiscovery_cloud_finding_rows(payload: Any) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, Mapping):
        candidates = []
        for key in ("findings", "vulnerabilities", "issues", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                candidates.extend(value)
        scans = payload.get("scans")
        if isinstance(scans, list):
            for scan in scans:
                if not isinstance(scan, Mapping):
                    continue
                for key in ("findings", "vulnerabilities", "issues", "results"):
                    value = scan.get(key)
                    if isinstance(value, list):
                        candidates.extend(value)
        if _looks_like_projectdiscovery_finding(payload):
            candidates.append(payload)
    else:
        candidates = []
    for candidate in candidates:
        if isinstance(candidate, Mapping) and _looks_like_projectdiscovery_finding(candidate):
            rows.append(candidate)
    return rows


def _looks_like_projectdiscovery_finding(row: Mapping[str, Any]) -> bool:
    template_ref = _field(
        row,
        "template-id",
        "template_id",
        "templateID",
        "template",
        "template_name",
    )
    info = row.get("info")
    has_info = isinstance(info, Mapping) and bool(info.get("name") or info.get("severity"))
    return bool(template_ref and (_projectdiscovery_finding_url(row) or has_info))


def _projectdiscovery_cloud_nuclei_row(row: Mapping[str, Any]) -> dict[str, Any]:
    template_id = _field(
        row,
        "template-id",
        "template_id",
        "templateID",
        "template",
        "template_name",
    )
    matched_at = _projectdiscovery_finding_url(row)
    if not template_id or not matched_at:
        return {}
    info = row.get("info") if isinstance(row.get("info"), Mapping) else {}
    classification = row.get("classification")
    if not isinstance(classification, Mapping):
        classification = info.get("classification") if isinstance(info, Mapping) else {}
    tags = row.get("tags")
    if not tags and isinstance(info, Mapping):
        tags = info.get("tags")
    references = row.get("reference")
    if not references and isinstance(info, Mapping):
        references = info.get("reference")
    normalized_info = {
        "name": _field(row, "name", "title") or _field(info, "name"),
        "severity": _field(row, "severity") or _field(info, "severity"),
        "description": _field(row, "description") or _field(info, "description"),
        "tags": tags,
        "reference": references,
    }
    if isinstance(classification, Mapping):
        normalized_info["classification"] = dict(classification)
    return {
        "template-id": template_id,
        "matched-at": matched_at,
        "matcher-name": _field(row, "matcher-name", "matcher_name", "matcher"),
        "type": _field(row, "type", "protocol"),
        "template-url": _field(row, "template-url", "template_url"),
        "template-path": _field(row, "template-path", "template_path"),
        "info": {key: value for key, value in normalized_info.items() if value not in ("", [], {})},
    }


def _projectdiscovery_finding_url(row: Mapping[str, Any]) -> str:
    for key in ("matched-at", "matched_at", "url", "target", "host", "asset"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for parent_key in ("asset", "request", "response", "metadata"):
        parent = row.get(parent_key)
        if isinstance(parent, Mapping):
            for key in ("url", "endpoint", "host", "name"):
                value = parent.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _projectdiscovery_cloud_template_count(payload: Any) -> int:
    if not isinstance(payload, Mapping):
        return 0
    templates = payload.get("templates")
    if isinstance(templates, list):
        return len([item for item in templates if item])
    counts = payload.get("template_counts") or payload.get("templates_summary")
    if isinstance(counts, Mapping):
        total = counts.get("total") or counts.get("count")
        try:
            return max(0, int(total))
        except (TypeError, ValueError):
            return 0
    return 0


def _projectdiscovery_cloud_template_inventory(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, Mapping):
        return []
    raw_templates = payload.get("templates")
    if not isinstance(raw_templates, list):
        return []
    templates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_template in raw_templates[:500]:
        if isinstance(raw_template, str):
            template_id = _bounded_text(raw_template, 160)
            entry: dict[str, Any] = {"id": template_id}
        elif isinstance(raw_template, Mapping):
            template_id = _bounded_text(
                _field(
                    raw_template,
                    "id",
                    "template_id",
                    "template-id",
                    "templateID",
                    "path",
                ),
                160,
            )
            if not template_id:
                continue
            info = raw_template.get("info")
            if not isinstance(info, Mapping):
                info = {}
            entry = _bounded_mapping(
                {
                    "id": template_id,
                    "name": _field(raw_template, "name", "title") or _field(info, "name"),
                    "severity": _field(raw_template, "severity") or _field(info, "severity"),
                    "type": _field(raw_template, "type", "protocol"),
                    "tags": raw_template.get("tags") or info.get("tags"),
                    "author": raw_template.get("author") or info.get("author"),
                }
            )
        else:
            continue
        key = str(entry.get("id") or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        templates.append(entry)
    return templates


def _discovery_document(connector_id: str, text: str) -> Any:
    try:
        return json.loads(str(text or ""))
    except json.JSONDecodeError as exc:
        if connector_id not in {"asset_delta_import", "runzero_asset_export"}:
            raise ValueError("discovery report is not valid JSON") from exc
    reader = DictReader(StringIO(str(text or "")))
    return [dict(row) for row in reader if any(str(value or "").strip() for value in row.values())]


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
) -> tuple[int, bool]:
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
    row = con.execute(
        """
        SELECT id
        FROM services
        WHERE host_id=? AND port=? AND protocol=?
        """,
        (host_id, int(service.port), service.protocol),
    ).fetchone()
    if row is None:
        raise RuntimeError("service upsert failed")
    return int(row["id"]), int(cur.rowcount or 0) > 0


def _upsert_imported_asset_graph(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    host_id: int,
    imported: _ImportedHost,
    attribution_basis: str,
) -> dict[str, int]:
    hostname = imported.names[0] if imported.names else imported.ip
    metadata = dict(imported.metadata)
    metadata.update(
        {
            "connector_id": connector_id,
            "ip": imported.ip,
            "hostnames": list(imported.names[:25]),
            "attribution_basis": attribution_basis,
            "source": "provider_report_import",
        }
    )
    host_entity = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=f"host:{hostname}",
        entity_type="host",
        label=hostname,
        source_table="hosts",
        source_id=host_id,
        confidence=0.8,
        metadata=metadata,
    )
    nodes = 1
    relationships = 0
    for related in _metadata_topology_refs(imported.metadata):
        related_entity = upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=f"asset:{related['kind']}:{related['ref']}",
            entity_type="asset",
            label=related["label"],
            source_table="hosts",
            source_id=host_id,
            confidence=0.65,
            metadata={
                "connector_id": connector_id,
                "source": "asset_delta_topology",
                "topology_kind": related["kind"],
            },
        )
        nodes += 1
        upsert_asset_relationship(
            con,
            engagement_id=engagement_id,
            source_entity_id=host_entity,
            target_entity_id=related_entity,
            relationship_type="related_asset",
            confidence=0.65,
            source_table="hosts",
            source_id=host_id,
            evidence={
                "connector_id": connector_id,
                "relationship": related["kind"],
                "provider_report_import": True,
            },
        )
        relationships += 1
    return {"node_count": nodes, "relationship_count": relationships}


def _upsert_imported_service_graph(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    host_id: int,
    service_id: int,
    imported: _ImportedHost,
    service: _ImportedService,
) -> dict[str, int]:
    hostname = imported.names[0] if imported.names else imported.ip
    host_entity = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=f"host:{hostname}",
        entity_type="host",
        label=hostname,
        source_table="hosts",
        source_id=host_id,
        confidence=0.8,
        metadata={
            **dict(imported.metadata),
            "connector_id": connector_id,
            "ip": imported.ip,
            "hostnames": list(imported.names[:25]),
            "source": "provider_report_import",
        },
    )
    service_label = f"{hostname}:{service.port}/{service.protocol}"
    service_entity = upsert_asset_entity(
        con,
        engagement_id=engagement_id,
        entity_key=f"service:{service_label}",
        entity_type="service",
        label=service_label,
        source_table="services",
        source_id=service_id,
        confidence=0.8,
        metadata={
            "connector_id": connector_id,
            "service_name": service.service_name,
            "version": service.version,
            "source": "provider_report_import",
        },
    )
    upsert_asset_relationship(
        con,
        engagement_id=engagement_id,
        source_entity_id=host_entity,
        target_entity_id=service_entity,
        relationship_type="runs_service",
        confidence=0.8,
        source_table="services",
        source_id=service_id,
        evidence={
            "connector_id": connector_id,
            "port": service.port,
            "protocol": service.protocol,
        },
    )
    return {"node_count": 2, "relationship_count": 1}


def _upsert_projectdiscovery_template_inventory(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    templates: list[dict[str, Any]],
) -> dict[str, int]:
    node_count = 0
    for template in templates:
        template_id = _bounded_text(template.get("id"), 160)
        if not template_id:
            continue
        upsert_asset_entity(
            con,
            engagement_id=engagement_id,
            entity_key=f"pd_template:{template_id}",
            entity_type="evidence",
            label=template_id,
            source_table="audit_log",
            source_id=0,
            confidence=0.7,
            metadata={
                **template,
                "connector_id": "projectdiscovery_cloud",
                "source": "projectdiscovery_cloud_template_inventory",
            },
        )
        node_count += 1
    return {"template_count": node_count, "node_count": node_count}


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
        f"findings={int(result.get('persisted_finding_count') or 0)}",
        f"templates={int(result.get('parsed_template_count') or 0)}",
        f"skipped={int(result.get('skipped_count') or 0)}",
        f"url_skipped={int(result.get('skipped_url_count') or 0)}",
        f"finding_skipped={int(result.get('skipped_finding_count') or 0)}",
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


def _first_list_value(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            text = str(item or "").strip()
            if text:
                return text
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


def _censys_fingerprint_payload(
    item: Mapping[str, Any],
    services: Any,
) -> dict[str, Any]:
    payload = _fingerprint_payload(item)
    if isinstance(services, list):
        service_fingerprints: list[dict[str, Any]] = []
        for service in services[:30]:
            if not isinstance(service, Mapping):
                continue
            fingerprint = _bounded_mapping(
                {
                    "port": service.get("port"),
                    "transport_protocol": service.get("transport_protocol")
                    or service.get("protocol"),
                    "service_name": service.get("service_name")
                    or service.get("extended_service_name"),
                    "software": service.get("software"),
                    "http_title": _nested_get(service, ("http", "response", "html_title")),
                    "tls_names": _nested_get(
                        service,
                        ("tls", "certificates", "leaf_data", "names"),
                    ),
                    "certificate_fingerprint": _nested_get(
                        service,
                        ("tls", "certificates", "leaf_data", "fingerprint"),
                    )
                    or _nested_get(
                        service,
                        ("tls", "certificates", "leaf_data", "fingerprint_sha256"),
                    ),
                }
            )
            if fingerprint:
                service_fingerprints.append(fingerprint)
        if service_fingerprints:
            payload["services"] = service_fingerprints
    return payload


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


def _first_scope_host(scope: list[str]) -> str:
    for entry in scope:
        normalized = _normalize_target(entry).lstrip("*.")
        if normalized:
            return normalized
    return ""


def _name_matches_target(name: str, target: str) -> bool:
    normalized_name = _normalize_target(name)
    normalized_target = _normalize_target(target)
    return normalized_name == normalized_target or normalized_name.endswith(f".{normalized_target}")


def _url_matches_target(url: str, target: str) -> bool:
    host = provider_url_hostname(url)
    return _name_matches_target(host, target) if host else False


def _bounded_mapping(values: Mapping[str, Any], *, depth: int = 2) -> dict[str, Any]:
    return {
        str(key): _bounded_value(value, depth=depth)
        for key, value in values.items()
        if value not in (None, "", [], {})
    }


def _bounded_value(value: Any, *, depth: int = 2) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int | float):
        return value
    if depth <= 0:
        return _bounded_text(value, 240)
    if isinstance(value, Mapping):
        payload: dict[str, Any] = {}
        for raw_key, raw_value in list(value.items())[:30]:
            key = _bounded_text(raw_key, 80)
            lowered = key.lower()
            if any(fragment in lowered for fragment in ("authorization", "password", "secret", "token")):
                continue
            bounded = _bounded_value(raw_value, depth=depth - 1)
            if bounded not in (None, "", [], {}):
                payload[key] = bounded
        return payload
    if isinstance(value, list | tuple | set):
        return [_bounded_value(item, depth=depth - 1) for item in list(value)[:30]]
    return _bounded_text(value, 240)


def _bounded_text(value: object, limit: int) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]


def _fingerprint_payload(item: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in (
        "fingerprint",
        "fingerprints",
        "software",
        "technologies",
        "products",
        "os",
        "os_name",
        "hardware",
        "manufacturer",
        "vendor",
    ):
        value = item.get(key)
        if value not in (None, "", [], {}):
            if key in {"fingerprint", "fingerprints"} and isinstance(value, Mapping):
                for raw_name, raw_fingerprint in value.items():
                    name = _bounded_text(raw_name, 80)
                    if name:
                        payload[name] = _bounded_value(raw_fingerprint)
            else:
                payload[key] = _bounded_value(value)
    return payload


def _topology_payload(item: Mapping[str, Any]) -> list[dict[str, str]]:
    raw = (
        item.get("topology")
        or item.get("relationships")
        or item.get("network")
        or item.get("neighbors")
        or []
    )
    entries: list[Any]
    if isinstance(raw, Mapping):
        entries = [raw]
    elif isinstance(raw, list):
        entries = raw
    else:
        entries = []
    relationships: list[dict[str, str]] = []
    for entry in entries[:30]:
        if isinstance(entry, Mapping):
            ref = _field(entry, "ref", "id", "asset_id", "name", "hostname", "ip", "target")
            kind = _field(entry, "kind", "type", "relationship", "relationship_type") or "related"
            label = _field(entry, "label", "name", "hostname", "ip", "target") or ref
        else:
            ref = str(entry or "").strip()
            kind = "related"
            label = ref
        ref = _bounded_text(ref, 160)
        if not ref:
            continue
        relationships.append(
            {
                "kind": _bounded_text(kind, 40) or "related",
                "ref": ref,
                "label": _bounded_text(label, 160) or ref,
            }
        )
    return relationships


def _metadata_topology_refs(metadata: Mapping[str, Any]) -> list[dict[str, str]]:
    raw = metadata.get("topology_relationships")
    if not isinstance(raw, list):
        return []
    refs: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        ref = _bounded_text(item.get("ref"), 160)
        if not ref:
            continue
        refs.append(
            {
                "kind": _bounded_text(item.get("kind"), 40) or "related",
                "ref": ref,
                "label": _bounded_text(item.get("label") or ref, 160),
            }
        )
    return refs
