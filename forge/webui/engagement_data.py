"""Web UI engagement report-data payload helpers."""
from __future__ import annotations

import sqlite3
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from forge.reporting.dashboard import _reportable_vulnerability_rows
from forge.webui.cloud_assets import cloud_assets_payload


def engagement_assets_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, Any]:
    crawl_rows = con.execute(
        """
        SELECT final_url, title, screenshot_path, tech_stack_json, discovered_at
        FROM crawl_results
        WHERE engagement_id=?
        ORDER BY discovered_at DESC
        LIMIT 100
        """,
        (engagement_id,),
    ).fetchall()
    port_rows = con.execute(
        """
        SELECT host, port, service, version, confidence, cdn_detected, waf_detected, scanned_at
        FROM port_scan_results
        WHERE engagement_id=?
        ORDER BY scanned_at DESC
        LIMIT 200
        """,
        (engagement_id,),
    ).fetchall()
    passive_rows = con.execute(
        """
        SELECT vuln_id, plugin, url, severity, verified, false_positive, discovered_at
        FROM passive_vulns
        WHERE engagement_id=?
          AND COALESCE(false_positive, 0)=0
        ORDER BY discovered_at DESC
        LIMIT 200
        """,
        (engagement_id,),
    ).fetchall()
    auth_rows = con.execute(
        """
        SELECT target_url, attack_type, success, tested_at
        FROM auth_test_results
        WHERE engagement_id=?
        ORDER BY tested_at DESC
        LIMIT 200
        """,
        (engagement_id,),
    ).fetchall()
    cloud_assets = cloud_assets_payload(con, engagement_id, limit=200)
    return {
        "crawl": [
            {
                "final_url": str(row[0]),
                "title": str(row[1]) if row[1] is not None else "",
                "screenshot_path": str(row[2]) if row[2] is not None else None,
                "tech_stack_json": str(row[3]) if row[3] is not None else "{}",
                "discovered_at": str(row[4]),
            }
            for row in crawl_rows
        ],
        "ports": [
            {
                "host": str(row[0]),
                "port": int(row[1]),
                "service": str(row[2]) if row[2] is not None else "",
                "version": str(row[3]) if row[3] is not None else None,
                "confidence": float(row[4]) if row[4] is not None else None,
                "cdn_detected": bool(row[5]),
                "waf_detected": bool(row[6]),
                "scanned_at": str(row[7]),
            }
            for row in port_rows
        ],
        "passive_vulns": [
            {
                "vuln_id": str(row[0]),
                "plugin": str(row[1]) if row[1] is not None else "",
                "url": str(row[2]) if row[2] is not None else "",
                "severity": str(row[3]) if row[3] is not None else "",
                "verified": bool(row[4]),
                "false_positive": bool(row[5]),
                "discovered_at": str(row[6]),
            }
            for row in passive_rows
        ],
        "auth_results": [
            {
                "target_url": str(row[0]),
                "attack_type": str(row[1]) if row[1] is not None else "",
                "success": bool(row[2]),
                "tested_at": str(row[3]),
            }
            for row in auth_rows
        ],
        "cloud_assets": cloud_assets,
    }


def engagement_assets_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, Any]:
    return engagement_assets_payload(con, engagement_id)


def vulnerability_summary_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, Any]:
    passive_rows = con.execute(
        """
        SELECT UPPER(COALESCE(severity, 'UNKNOWN')), COUNT(*)
        FROM passive_vulns
        WHERE engagement_id=?
          AND COALESCE(false_positive, 0)=0
        GROUP BY UPPER(COALESCE(severity, 'UNKNOWN'))
        """,
        (engagement_id,),
    ).fetchall()
    active_rows = _reportable_vulnerability_rows(con, engagement_id)
    auth_rows = con.execute(
        """
        SELECT success, COUNT(*)
        FROM auth_test_results
        WHERE engagement_id=?
        GROUP BY success
        """,
        (engagement_id,),
    ).fetchall()
    passive = {str(row[0]): int(row[1]) for row in passive_rows}
    active: dict[str, int] = {}
    for row in active_rows:
        severity = str(row["severity"] or "UNKNOWN").upper()
        active[severity] = active.get(severity, 0) + 1
    auth = {"success": 0, "failed": 0}
    for row in auth_rows:
        if int(row[0]) == 1:
            auth["success"] = int(row[1])
        else:
            auth["failed"] += int(row[1])
    return {"passive_vulns": passive, "vulnerability_findings": active, "auth_tests": auth}


def vulnerability_summary_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, Any]:
    return vulnerability_summary_payload(con, engagement_id)


def asset_tree_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    port_rows = con.execute(
        """
        SELECT host, port, service, scanned_at
        FROM port_scan_results
        WHERE engagement_id=?
        ORDER BY scanned_at DESC
        LIMIT 1000
        """,
        (engagement_id,),
    ).fetchall()
    crawl_rows = con.execute(
        """
        SELECT COALESCE(final_url, url), title, discovered_at
        FROM crawl_results
        WHERE engagement_id=?
        ORDER BY discovered_at DESC
        LIMIT 1000
        """,
        (engagement_id,),
    ).fetchall()

    ports_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    urls_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in port_rows:
        host = str(row[0]) if row[0] is not None else "unknown"
        ports_by_host[host].append(
            {
                "port": int(row[1]),
                "service": str(row[2]) if row[2] is not None else "",
                "scanned_at": str(row[3]),
            }
        )
    for row in crawl_rows:
        raw_url = str(row[0]) if row[0] is not None else ""
        parsed = urlparse(raw_url)
        host = parsed.netloc or "unknown"
        urls_by_host[host].append(
            {
                "url": raw_url,
                "title": str(row[1]) if row[1] is not None else "",
                "discovered_at": str(row[2]),
            }
        )

    all_hosts = sorted(set(ports_by_host.keys()) | set(urls_by_host.keys()))
    return {
        "items": [
            {
                "host": host,
                "ports": ports_by_host.get(host, []),
                "urls": urls_by_host.get(host, []),
            }
            for host in all_hosts
        ]
    }


def asset_tree_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    return asset_tree_payload(con, engagement_id)


__all__ = [
    "asset_tree_payload",
    "asset_tree_route_payload",
    "engagement_assets_payload",
    "engagement_assets_route_payload",
    "vulnerability_summary_payload",
    "vulnerability_summary_route_payload",
]
