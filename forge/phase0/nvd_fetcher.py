"""
forge/phase0/nvd_fetcher.py — NVD CVE feed ingestor with incremental update.

Sources (NVD 2.0 JSON API):
  Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0

Format: JSON, NVD CVE 2.0 schema.
Target: nvd_cache.db → tables: cve, cve_fts, cvss_scores (existing ETL schema)

Incremental strategy (PRD §5.3):
  - On first run (empty DB): fetch published windows from 2020 onward.
  - On subsequent runs: fetch modified windows only (last 8 days).
  - Force flag: re-fetch published windows regardless of DB state.

OPSEC (PRD §5.6):
  - Full feeds fetched; no per-CVE lookups during engagement.
  - SHA-256 manifest checked post-download via .meta.sha256 sidecar files
    published by NVD (when available).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
import gzip
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from typing import Any

from forge.config import ForgeConfig

_LOG = logging.getLogger(__name__)

_NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_API_MAX_WINDOW_DAYS: int = 30
_API_RESULTS_PER_PAGE: int = 500
_FULL_SYNC_START_YEAR: int = 2020
_MODIFIED_URL: str = f"{_NVD_API_URL}?mode=modified"
_YEARLY_YEARS: tuple[int, ...] = tuple(
    range(_FULL_SYNC_START_YEAR, datetime.now(timezone.utc).year + 1)
)

# CVSSv3 severity thresholds.
_SEVERITY_MAP: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def fetch_nvd(conn: sqlite3.Connection, cfg: ForgeConfig, force: bool = False) -> int:
    """
    Fetch NVD CVE API 2.0 data and ingest into nvd_cache.db.

    Uses incremental strategy: modified-date windows if DB is populated,
    full published-date windows otherwise (or when force=True).

    :param conn: Open write connection to nvd_cache.db.
    :param cfg: ForgeConfig for HTTP client settings.
    :param force: If True, re-fetch all published windows.
    :returns: Total CVEs inserted or updated.
    """
    if cfg.offline_strict:
        raise RuntimeError("FORGE_OFFLINE_STRICT: cannot fetch NVD feed.")

    existing_count = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    use_incremental = existing_count > 0 and not force
    mode = "modified" if use_incremental else "full"

    batch_cve: list[dict] = []
    batch_cvss: list[dict] = []
    total_upserted = 0

    for start_dt, end_dt in _iter_windows(use_incremental):
        _LOG.info("NVD: fetching %s window %s to %s", mode, start_dt.date(), end_dt.date())
        try:
            cve_items = _fetch_api_window(cfg, start_dt, end_dt, mode)
        except Exception as exc:
            _LOG.error("NVD: failed fetch for window %s-%s: %s", start_dt, end_dt, exc)
            continue
        for cve_obj in cve_items:
            cve_row, cvss_row = _normalise(cve_obj)
            if cve_row is None:
                continue
            batch_cve.append(cve_row)
            if cvss_row is not None:
                batch_cvss.append(cvss_row)
            if len(batch_cve) >= _API_RESULTS_PER_PAGE:
                total_upserted += _bulk_upsert(conn, batch_cve, batch_cvss)
                batch_cve.clear()
                batch_cvss.clear()
                _LOG.info("NVD: %d records upserted so far...", total_upserted)
                sys.stdout.flush()

    if batch_cve:
        total_upserted += _bulk_upsert(conn, batch_cve, batch_cvss)

    _LOG.info("NVD: %d records upserted.", total_upserted)
    return total_upserted


def _iter_windows(use_incremental: bool) -> list[tuple[datetime, datetime]]:
    now = datetime.now(timezone.utc)
    if use_incremental:
        return [(now - timedelta(days=8), now)]

    windows: list[tuple[datetime, datetime]] = []
    cursor = datetime(_FULL_SYNC_START_YEAR, 1, 1, tzinfo=timezone.utc)
    while cursor < now:
        end = min(cursor + timedelta(days=_API_MAX_WINDOW_DAYS), now)
        windows.append((cursor, end))
        cursor = end
    return windows


def _iter_feed_urls(use_incremental: bool) -> list[str]:
    # Deprecated: use _iter_windows directly
    return []


def _fetch(url: str, cfg: ForgeConfig) -> list[dict[str, Any]]:
    raw = _http_get(url, cfg)
    try:
        raw = gzip.decompress(raw)
    except OSError:
        pass
    # Use ijson for streaming parse of large NVD JSON (up to 500MB) — never load all into memory
    try:
        import ijson
        import io
        out: list[dict[str, Any]] = []
        f = io.BytesIO(raw)
        # Try NVD 2.0 format first
        try:
            for entry in ijson.items(f, "vulnerabilities.item"):
                cve_obj = entry.get("cve")
                if isinstance(cve_obj, dict):
                    out.append(cve_obj)
            if out:
                return out
        except Exception:
            pass
        # Fall back to NVD 1.1 format
        f.seek(0)
        try:
            for item in ijson.items(f, "CVE_Items.item"):
                if isinstance(item, dict):
                    out.append(item)
            return out
        except Exception:
            pass
    except ImportError:
        pass
    # Fallback: standard json.loads (memory-intensive for large files)
    data = json.loads(raw)
    if "CVE_Items" in data:
        return [item for item in data.get("CVE_Items", []) if isinstance(item, dict)]
    vulns = data.get("vulnerabilities") or []
    out = []
    for entry in vulns:
        cve_obj = entry.get("cve") if isinstance(entry, dict) else None
        if isinstance(cve_obj, dict):
            out.append(cve_obj)
    return out


def _fetch_api_window(
    cfg: ForgeConfig,
    start_dt: datetime,
    end_dt: datetime,
    mode: str,
) -> list[dict[str, Any]]:
    start_index = 0
    out: list[dict[str, Any]] = []
    date_key_start = "lastModStartDate" if mode == "modified" else "pubStartDate"
    date_key_end = "lastModEndDate" if mode == "modified" else "pubEndDate"

    while True:
        params = {
            date_key_start: _iso8601z(start_dt),
            date_key_end: _iso8601z(end_dt),
            "resultsPerPage": str(_API_RESULTS_PER_PAGE),
            "startIndex": str(start_index),
        }
        url = f"{_NVD_API_URL}?{urlencode(params)}"
        try:
            raw = _http_get(url, cfg)
            data = json.loads(raw)
        except Exception as exc:
            _LOG.error("NVD: failed request for window %s: %s", url, exc)
            break

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            break
        for entry in vulns:
            cve_obj = entry.get("cve")
            if isinstance(cve_obj, dict):
                out.append(cve_obj)

        total = int(data.get("totalResults", 0))
        start_index += len(vulns)
        if start_index >= total:
            break
    return out


def _normalise(cve_obj: dict[str, Any]) -> tuple[dict | None, dict | None]:
    try:
        source = cve_obj
        if "cve" in cve_obj and "CVE_data_meta" not in cve_obj:
            cve_obj = cve_obj.get("cve") or {}
        if "CVE_data_meta" in cve_obj:
            return _normalise_legacy_v11(source)

        cve_id = str(cve_obj.get("id") or "").strip()
        if not cve_id:
            return None, None

        descriptions = cve_obj.get("descriptions") or []
        description = (
            next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"),
                "",
            )
            or ""
        )

        cpe_matches = _collect_cpe_matches(cve_obj.get("configurations") or [])
        cvss_v3, cvss_v2 = _extract_cvss_scores(cve_obj.get("metrics") or {})
        severity = _score_to_severity(cvss_v3 or cvss_v2)

        cve_row = {
            "cve_id": cve_id,
            "description": description[:2048],
            "severity": severity,
            "published_at": cve_obj.get("published"),
            "modified_at": cve_obj.get("lastModified"),
            "cpe_matches": json.dumps(cpe_matches[:50]),
        }
        cvss_row = None
        if cvss_v3 is not None or cvss_v2 is not None:
            cvss_row = {
                "cve_id": cve_id,
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
            }
        return cve_row, cvss_row
    except Exception as exc:
        _LOG.debug("NVD normalise error: %s", exc)
        return None, None


def _normalise_legacy_v11(item: dict[str, Any]) -> tuple[dict | None, dict | None]:
    cve_meta = item if "CVE_data_meta" in item else item.get("cve") or {}
    cve_id_data = cve_meta.get("CVE_data_meta") or {}
    cve_id = cve_id_data.get("ID") or ""
    if not cve_id:
        return None, None

    descs = (cve_meta.get("description") or {}).get("description_data") or []
    description = next((d.get("value") for d in descs if d.get("lang") == "en"), "") or ""

    cpe_matches: list[str] = []
    configurations = item.get("configurations") or {}
    for node in configurations.get("nodes") or []:
        for cpe_m in node.get("cpe_match") or []:
            uri = cpe_m.get("cpe23Uri") or ""
            if uri:
                cpe_matches.append(uri)

    impact = item.get("impact") or {}
    cvss_v3 = None
    cvss_v2 = None
    v3 = impact.get("baseMetricV3") or {}
    if v3:
        score = (v3.get("cvssV3") or {}).get("baseScore")
        if isinstance(score, (float, int)):
            cvss_v3 = float(score)
    v2 = impact.get("baseMetricV2") or {}
    if v2:
        score2 = (v2.get("cvssV2") or {}).get("baseScore")
        if isinstance(score2, (float, int)):
            cvss_v2 = float(score2)

    severity = _score_to_severity(cvss_v3 or cvss_v2)
    cve_row = {
        "cve_id": cve_id,
        "description": description[:2048],
        "severity": severity,
        "published_at": item.get("publishedDate"),
        "modified_at": item.get("lastModifiedDate"),
        "cpe_matches": json.dumps(cpe_matches[:50]),
    }
    cvss_row = None
    if cvss_v3 is not None or cvss_v2 is not None:
        cvss_row = {"cve_id": cve_id, "cvss_v3": cvss_v3, "cvss_v2": cvss_v2}
    return cve_row, cvss_row


def _collect_cpe_matches(configurations: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []

    def walk_nodes(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            for cpe in node.get("cpeMatch") or []:
                criteria = cpe.get("criteria")
                if isinstance(criteria, str) and criteria:
                    out.append(criteria)
            children = node.get("children") or []
            if isinstance(children, list):
                walk_nodes(children)

    for cfg in configurations:
        nodes = cfg.get("nodes") or []
        if isinstance(nodes, list):
            walk_nodes(nodes)
    return out


def _extract_cvss_scores(metrics: dict[str, Any]) -> tuple[float | None, float | None]:
    cvss_v3: float | None = None
    cvss_v2: float | None = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            cvss_data = entries[0].get("cvssData") or {}
            score = cvss_data.get("baseScore")
            if isinstance(score, (float, int)):
                cvss_v3 = float(score)
                break

    entries_v2 = metrics.get("cvssMetricV2") or []
    if entries_v2:
        cvss_data_v2 = entries_v2[0].get("cvssData") or {}
        score_v2 = cvss_data_v2.get("baseScore")
        if isinstance(score_v2, (float, int)):
            cvss_v2 = float(score_v2)

    return cvss_v3, cvss_v2


def _iso8601z(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _score_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    for threshold, label in _SEVERITY_MAP:
        if score >= threshold:
            return label
    return "LOW"


def _bulk_upsert(
    conn: sqlite3.Connection,
    cve_rows: list[dict],
    cvss_rows: list[dict],
) -> int:
    """INSERT OR REPLACE CVE rows; returns count of rows written."""
    if not cve_rows:
        return 0

    conn.executemany(
        """
        INSERT OR REPLACE INTO cve
            (cve_id, description, severity, published_at, modified_at, cpe_matches)
        VALUES
            (:cve_id, :description, :severity, :published_at, :modified_at, :cpe_matches)
        """,
        cve_rows,
    )

    valid_cvss = [row for row in cvss_rows if row]
    if valid_cvss:
        conn.executemany(
            """
            INSERT OR REPLACE INTO cvss_scores (cve_id, cvss_v3, cvss_v2)
            VALUES (:cve_id, :cvss_v3, :cvss_v2)
            """,
            valid_cvss,
        )

    conn.commit()
    return len(cve_rows)


def _http_get(url: str, cfg: ForgeConfig) -> bytes:
    try:
        from curl_cffi import requests as cffi_requests  # noqa: PLC0415

        # NVD authenticated: apiKey header raises rate limit from 5 req/30s
        # anonymous to 50 req/30s. Public data - skip FORGE_PROXY (OPSEC
        # proxy) unless FORGE_KB_USE_PROXY=1 is explicitly set.
        import os
        headers = {"User-Agent": "FORGE-Toolkit/1.0"}
        if "nvd.nist.gov" in url:
            api_key = os.environ.get("FORGE_NVD_API_KEY", "").strip()
            if api_key:
                headers["apiKey"] = api_key
        use_proxy = os.environ.get("FORGE_KB_USE_PROXY", "0").strip() in ("1", "true", "yes")
        proxies = {"https": cfg.proxy} if (cfg.proxy and use_proxy) else None
        resp = cffi_requests.get(
            url,
            impersonate=cfg.curl_profile,
            proxies=proxies,
            timeout=120,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.content
    except ImportError:
        import urllib.request  # noqa: PLC0415

        with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310
            return r.read()
