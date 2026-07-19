from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

import httpx

from forge.config import ForgeConfig
from forge.db.session import get_engagement_db
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope

_DEFAULT_PORTS: tuple[int, ...] = (21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080)
_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    3389: "rdp",
    8080: "http-alt",
}


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _port_scan_host_delay_seconds() -> float:
    return _float_env(
        "FORGE_PORT_SCAN_HOST_DELAY_SECONDS",
        0.0,
        minimum=0.0,
        maximum=60.0,
    )


def _port_scan_port_delay_seconds() -> float:
    return _float_env(
        "FORGE_PORT_SCAN_PORT_DELAY_SECONDS",
        0.0,
        minimum=0.0,
        maximum=30.0,
    )


def _port_scan_port_concurrency() -> int:
    return _int_env(
        "FORGE_PORT_SCAN_PORT_CONCURRENCY",
        32,
        minimum=1,
        maximum=256,
    )


def _is_placeholder_ip(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    try:
        parsed_ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if parsed_ip.is_unspecified:
        return True
    if parsed_ip.version == 4 and parsed_ip in ipaddress.ip_network("198.18.0.0/15"):
        return True
    return False


def _is_synthetic_host_row(ip: str, host_context_json: str | None = None) -> bool:
    if _is_placeholder_ip(ip):
        return True
    try:
        context = json.loads(host_context_json or "{}")
    except (TypeError, ValueError):
        context = {}
    return isinstance(context, dict) and bool(context.get("synthetic_ip"))


def _host_row_is_authorized_by_scope(ip: str, hostname: str | None, scope: Sequence[str] | None) -> bool:
    if scope is None:
        return True
    scoped_values = [str(item) for item in scope if str(item or "").strip()]
    if not scoped_values:
        return False
    candidates = [str(ip or "").strip()]
    hostname_value = str(hostname or "").strip()
    if hostname_value and hostname_value not in candidates:
        candidates.append(hostname_value)
    for candidate in candidates:
        if not candidate:
            continue
        try:
            assert_in_scope(candidate, scoped_values)
        except ScopeViolationError:
            continue
        return True
    return False


@dataclass(frozen=True)
class PortFinding:
    host_id: int
    ip: str
    port: int
    protocol: str
    service_name: str


@dataclass(frozen=True)
class PortScanIntelligence:
    host_id: int
    ip: str
    port: int
    protocol: str
    service_name: str
    scanner: str
    confidence: float
    cdn_detected: bool
    waf_detected: bool
    version: str | None


def _is_open(ip: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except (socket.gaierror, OSError):
        # Unresolvable hostname or transient network error - treat as closed.
        # Previously this propagated and aborted the whole scan (bug found
        # during tool-integration test, 2026-07-05).
        return False
    finally:
        sock.close()


def scan_host(ip: str, ports: Iterable[int], timeout: float = 0.35) -> list[int]:
    return asyncio.run(_scan_host_async(ip, list(ports), timeout))


def scan_engagement(
    engagement_id: str | int,
    db_path: Path | None = None,
    ports: Iterable[int] | None = None,
    timeout: float = 0.35,
    operator: str | None = None,
    progress_callback: Callable[[int, int, str, list[int]], None] | None = None,
    scope_override: Sequence[str] | None = None,
) -> list[PortFinding]:
    cfg = ForgeConfig.load()
    eng_id = int(engagement_id)
    target_db = db_path or cfg.engagement_db_path(str(engagement_id))
    selected_ports = list(ports or _DEFAULT_PORTS)
    op = operator or cfg.operator

    findings: list[PortFinding] = []
    conn = get_engagement_db(target_db)
    try:
        hosts = conn.execute(
            "SELECT id, ip, hostname, host_context FROM hosts WHERE engagement_id=? AND in_scope=1 ORDER BY id",
            (eng_id,),
        ).fetchall()
        total_hosts = len(hosts)
        for index, host in enumerate(hosts, start=1):
            host_id = int(host["id"])
            ip = str(host["ip"])
            hostname = str(host["hostname"] or "")
            if _is_synthetic_host_row(ip, str(host["host_context"] or "{}")):
                conn.execute(
                    """
                    INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                    VALUES (?, 'phase1', 'port_scanner', 'scan_skipped', ?, ?, ?)
                    """,
                    (
                        eng_id,
                        ip,
                        json.dumps({"reason": "synthetic_or_placeholder_ip"}),
                        op,
                    ),
                )
                if progress_callback is not None:
                    progress_callback(index, total_hosts, ip, [])
                continue
            if not _host_row_is_authorized_by_scope(ip, hostname, scope_override):
                conn.execute(
                    """
                    INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                    VALUES (?, 'phase1', 'port_scanner', 'scan_skipped', ?, ?, ?)
                    """,
                    (
                        eng_id,
                        ip,
                        json.dumps({"reason": "scheduled_scope_denied", "hostname": hostname}),
                        op,
                    ),
                )
                if progress_callback is not None:
                    progress_callback(index, total_hosts, ip, [])
                continue
            host_delay = _port_scan_host_delay_seconds()
            if host_delay > 0:
                time.sleep(host_delay)
            open_ports = asyncio.run(_scan_host_async(ip, selected_ports, timeout))
            if progress_callback is not None:
                progress_callback(index, total_hosts, ip, open_ports)
            for port in open_ports:
                service_name = _SERVICE_MAP.get(port, "unknown")
                conn.execute(
                    """
                    INSERT INTO services (host_id, port, protocol, service_name, banner, version)
                    VALUES (?, ?, 'tcp', ?, NULL, NULL)
                    ON CONFLICT(host_id, port, protocol) DO UPDATE SET service_name=excluded.service_name
                    """,
                    (host_id, port, service_name),
                )
                findings.append(
                    PortFinding(
                        host_id=host_id,
                        ip=ip,
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                    )
                )
            conn.execute(
                """
                INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'phase1', 'port_scanner', 'scan', ?, 'ok', ?)
                """,
                (eng_id, ip, op),
            )
        conn.commit()
    finally:
        conn.close()
    return findings


async def _is_open_async(ip: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        _ = reader
        return True
    except Exception:
        return False


async def _scan_host_async(
    ip: str,
    ports: Sequence[int],
    timeout: float,
    max_concurrency: int | None = None,
    port_delay: float | None = None,
) -> list[int]:
    concurrency = (
        _port_scan_port_concurrency()
        if max_concurrency is None
        else max(1, int(max_concurrency))
    )
    delay_seconds = (
        _port_scan_port_delay_seconds()
        if port_delay is None
        else max(0.0, float(port_delay))
    )
    semaphore = asyncio.Semaphore(min(concurrency, max(1, len(ports))))

    async def _check(port: int) -> bool:
        async with semaphore:
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
            return await _is_open_async(ip, port, timeout)

    checks = [asyncio.create_task(_check(port)) for port in ports]
    states = await asyncio.gather(*checks)
    return [ports[i] for i, ok in enumerate(states) if ok]


def _fetch_shodan_services(ip: str, api_key: str) -> dict[int, str]:
    try:
        from forge.utils.intel.shodan_lookup import _shodan_get  # noqa: PLC0415

        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            response = _shodan_get(
                client,
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
            )
        if response.status_code != 200:
            return {}
        data = response.json()
    except Exception:
        return {}
    output: dict[int, str] = {}
    for item in data.get("data", []):
        port = item.get("port")
        product = item.get("product")
        if isinstance(port, int) and isinstance(product, str) and product:
            output[port] = product
    return output


def _detect_cdn_waf(ip: str) -> tuple[bool, bool]:
    host = ip
    cdn_markers = ("cloudflare", "akamai", "fastly", "cloudfront")
    waf_markers = ("cloudflare", "sucuri", "imperva", "f5")
    cdn_detected = False
    waf_detected = False
    try:
        cname = socket.getfqdn(host).lower()
        cdn_detected = any(marker in cname for marker in cdn_markers)
    except Exception:
        pass
    try:
        resp = httpx.get(f"http://{host}", timeout=3.0)
        server = (resp.headers.get("server") or "").lower()
        waf_detected = any(marker in server for marker in waf_markers)
        if not cdn_detected:
            cdn_header = (
                resp.headers.get("cf-ray")
                or resp.headers.get("x-served-by")
                or resp.headers.get("x-amz-cf-id")
            )
            cdn_detected = cdn_header is not None
    except Exception:
        pass
    return cdn_detected, waf_detected


def scan_engagement_enhanced(
    engagement_id: str | int,
    db_path: Path | None = None,
    ports: Sequence[int] | None = None,
    timeout: float = 0.35,
    operator: str | None = None,
    use_shodan: bool = False,
    detect_cdn: bool = True,
    detect_waf: bool = True,
    progress_callback: Callable[[int, int, str, list[int]], None] | None = None,
    scope_override: Sequence[str] | None = None,
) -> list[PortScanIntelligence]:
    cfg = ForgeConfig.load()
    eng_id = int(engagement_id)
    target_db = db_path or cfg.engagement_db_path(str(engagement_id))
    selected_ports = list(ports or _DEFAULT_PORTS)
    op = operator or cfg.operator
    shodan_key = cfg.shodan_key if use_shodan else None
    findings: list[PortScanIntelligence] = []
    conn = get_engagement_db(target_db)
    try:
        hosts = conn.execute(
            "SELECT id, ip, hostname, host_context FROM hosts WHERE engagement_id=? AND in_scope=1 ORDER BY id",
            (eng_id,),
        ).fetchall()
        total_hosts = len(hosts)
        for index, host in enumerate(hosts, start=1):
            host_id = int(host["id"])
            ip = str(host["ip"])
            hostname = str(host["hostname"] or "")
            if _is_synthetic_host_row(ip, str(host["host_context"] or "{}")):
                conn.execute(
                    """
                    INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                    VALUES (?, 'phase1', 'port_scanner', 'enhanced_scan_skipped', ?, ?, ?)
                    """,
                    (
                        eng_id,
                        ip,
                        json.dumps({"reason": "synthetic_or_placeholder_ip"}),
                        op,
                    ),
                )
                if progress_callback is not None:
                    progress_callback(index, total_hosts, ip, [])
                continue
            if not _host_row_is_authorized_by_scope(ip, hostname, scope_override):
                conn.execute(
                    """
                    INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                    VALUES (?, 'phase1', 'port_scanner', 'enhanced_scan_skipped', ?, ?, ?)
                    """,
                    (
                        eng_id,
                        ip,
                        json.dumps({"reason": "scheduled_scope_denied", "hostname": hostname}),
                        op,
                    ),
                )
                if progress_callback is not None:
                    progress_callback(index, total_hosts, ip, [])
                continue
            host_delay = _port_scan_host_delay_seconds()
            if host_delay > 0:
                time.sleep(host_delay)
            open_ports = asyncio.run(_scan_host_async(ip, selected_ports, timeout))
            shodan_map = _fetch_shodan_services(ip, shodan_key) if shodan_key else {}
            cdn_detected = False
            waf_detected = False
            if detect_cdn or detect_waf:
                cdn_detected, waf_detected = _detect_cdn_waf(ip)
            if progress_callback is not None:
                progress_callback(index, total_hosts, ip, open_ports)
            for port in open_ports:
                service_name = _SERVICE_MAP.get(port, "unknown")
                version = shodan_map.get(port)
                scanner = "async+socket"
                confidence = 0.8
                if version:
                    scanner = "async+socket+shodan"
                    confidence = 0.92
                conn.execute(
                    """
                    INSERT INTO services (host_id, port, protocol, service_name, banner, version)
                    VALUES (?, ?, 'tcp', ?, NULL, ?)
                    ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                        service_name=excluded.service_name,
                        version=COALESCE(excluded.version, services.version)
                    """,
                    (host_id, port, service_name, version),
                )
                conn.execute(
                    """
                    INSERT INTO port_scan_results (
                        engagement_id, host, port, proto, service, version, confidence,
                        scanner, cdn_detected, waf_detected
                    ) VALUES (?, ?, ?, 'tcp', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        eng_id,
                        ip,
                        port,
                        service_name,
                        version,
                        confidence,
                        scanner,
                        1 if cdn_detected and detect_cdn else 0,
                        1 if waf_detected and detect_waf else 0,
                    ),
                )
                findings.append(
                    PortScanIntelligence(
                        host_id=host_id,
                        ip=ip,
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        scanner=scanner,
                        confidence=confidence,
                        cdn_detected=cdn_detected and detect_cdn,
                        waf_detected=waf_detected and detect_waf,
                        version=version,
                    )
                )
            conn.execute(
                """
                INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'phase1', 'port_scanner', 'enhanced_scan', ?, ?, ?)
                """,
                (
                    eng_id,
                    ip,
                    json.dumps(
                        {
                            "open_ports": len(open_ports),
                            "cdn_detected": cdn_detected and detect_cdn,
                            "waf_detected": waf_detected and detect_waf,
                        }
                    ),
                    op,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return findings
