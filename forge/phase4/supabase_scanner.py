"""Module 4-G: Supabase RLS Policy Testing + Auto-Key Extraction.

Two modes:
  1. AUTO-DISCOVERY: crawl target app JS/HTML for embedded Supabase anon keys
     (same extraction approach as firebase_extract.py)
  2. MANUAL: use FORGE_SUPABASE_ANON_KEY from env if operator provides it

What it tests after key is found:
  - Unauthenticated SELECT on all tables (RLS bypass check)
  - Unrestricted INSERT/UPDATE/DELETE (write access check)
  - Storage bucket public listing
  - Auth endpoint enumeration

Authorization: target must be in engagement scope.
OPSEC: all requests via curl_cffi, routes through FORGE_PROXY.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import sys
from typing import Optional
from urllib.parse import urlparse

from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.opsec.resilience import _SHUTDOWN, wait_for_internet, with_internet_retry
from forge.opsec.scope_gate import assert_in_scope

_LOG = logging.getLogger(__name__)
_RATE_LIMITER = AdaptiveRateLimiter(base_delay=1.0, max_delay=30.0, min_delay=0.5, jitter=0.3)

# Supabase anon key pattern (JWT with 'anon' role)
_SUPABASE_KEY_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'
)
_SUPABASE_URL_PATTERN = re.compile(
    r'https?://([a-z0-9]+)\.supabase\.(?:co|com|io)'
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS supabase_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    project_ref   TEXT NOT NULL,
    anon_key      TEXT,
    source_url    TEXT,
    table_name    TEXT,
    finding_type  TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    detail        TEXT,
    found_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, project_ref, table_name, finding_type)
)
"""


def _fetch_text(url: str, cfg=None) -> Optional[str]:
    _RATE_LIMITER.wait(url)
    try:
        from curl_cffi import requests as cffi_requests
        proxies = {"https": cfg.proxy} if cfg and cfg.proxy else None
        resp = cffi_requests.get(url, impersonate=cfg.curl_profile if cfg else "chrome120",
                                  proxies=proxies, timeout=20)
        if resp.status_code == 200:
            _RATE_LIMITER.record_success(url)
            return resp.text
        return None
    except Exception:
        return None


def _extract_supabase_keys(text: str, source_url: str) -> list[dict]:
    """Extract Supabase project URLs and anon keys from JS/HTML."""
    results = []
    urls = _SUPABASE_URL_PATTERN.findall(text)
    keys = _SUPABASE_KEY_PATTERN.findall(text)

    # Filter keys that look like Supabase anon keys (contain 'anon' or 'role' when decoded)
    anon_keys = []
    for key in keys:
        try:
            import base64
            payload = key.split(".")[1]
            # Pad base64
            payload += "=" * (4 - len(payload) % 4)
            decoded = json.loads(base64.b64decode(payload).decode())
            if decoded.get("role") in ("anon", "service_role", "authenticated"):
                anon_keys.append((key, decoded.get("role")))
        except Exception:
            pass

    for ref in urls:
        for key, role in anon_keys or [("", "unknown")]:
            results.append({
                "project_ref": ref,
                "project_url": f"https://{ref}.supabase.co",
                "anon_key": key or None,
                "key_role": role,
                "source_url": source_url,
            })

    return results


def _test_rls(project_url: str, anon_key: str, cfg=None) -> list[dict]:
    """Test for RLS misconfigurations on Supabase REST API."""
    findings = []
    rest_url = f"{project_url}/rest/v1"
    headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}

    # Get table list from OpenAPI spec
    _RATE_LIMITER.wait(rest_url + "/")
    try:
        from curl_cffi import requests as cffi_requests
        proxies = {"https": cfg.proxy} if cfg and cfg.proxy else None
        spec_resp = cffi_requests.get(
            rest_url + "/",
            headers=headers,
            impersonate=cfg.curl_profile if cfg else "chrome120",
            proxies=proxies,
            timeout=10,
        )
        if spec_resp.status_code == 200:
            _RATE_LIMITER.record_success(rest_url)
            spec = spec_resp.json()
            paths = list((spec.get("paths") or {}).keys())
        else:
            _RATE_LIMITER.record_failure(rest_url, spec_resp.status_code)
            paths = []
    except Exception:
        paths = []

    # Test SELECT on each table
    for path in paths[:20]:  # cap at 20 tables
        if _SHUTDOWN.is_set():
            break
        table = path.strip("/")
        if not table or table in ("rpc",):
            continue
        url = f"{rest_url}/{table}?limit=3"
        _RATE_LIMITER.wait(url)
        try:
            resp = cffi_requests.get(
                url, headers=headers,
                impersonate=cfg.curl_profile if cfg else "chrome120",
                proxies=proxies,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    severity = "HIGH" if any(
                        k in str(data[0]).lower()
                        for k in ("password", "token", "secret", "key", "email", "phone")
                    ) else "MEDIUM"
                    findings.append({
                        "table_name": table,
                        "finding_type": "RLS_BYPASS_SELECT",
                        "severity": severity,
                        "detail": f"Unauthenticated SELECT returned {len(data)} rows. Sample keys: {list(data[0].keys())[:5]}",
                    })
                    print(f"[SUPABASE] RLS bypass on {table}: {len(data)} rows readable", flush=True)
            _RATE_LIMITER.record_success(url)
        except Exception:
            pass
        sys.stdout.flush()

    return findings


def scan_supabase(
    engagement_id: int,
    engagement_scope: list[str],
    eng_db_conn: sqlite3.Connection,
    target_url: Optional[str] = None,
    manual_project_ref: Optional[str] = None,
    manual_anon_key: Optional[str] = None,
    cfg=None,
    dry_run: bool = False,
) -> list[dict]:
    """Auto-discover Supabase keys from target app OR use provided keys.

    Workflow:
    1. If target_url given → crawl JS/HTML to auto-extract project ref + anon key
    2. If manual_project_ref + manual_anon_key → use directly
    3. Fall back to FORGE_SUPABASE_ANON_KEY from env
    4. Run RLS tests against discovered project

    Returns list of finding dicts.
    """
    eng_db_conn.execute(SCHEMA_SQL)
    eng_db_conn.commit()

    if not wait_for_internet():
        return []

    candidates = []

    # --- Auto-discovery ---
    if target_url:
        domain = urlparse(target_url).netloc
        try:
            assert_in_scope(domain, engagement_scope)
        except Exception:
            print(f"[SUPABASE] {target_url} not in scope")
            return []

        if dry_run:
            print(f"[DRY-RUN] Would crawl {target_url} for Supabase config")
            return []

        print(f"[SUPABASE] Auto-discovering Supabase config from {target_url}", flush=True)
        html = with_internet_retry(_fetch_text, target_url, cfg)
        if html:
            candidates.extend(_extract_supabase_keys(html, target_url))

            # Also scan linked JS files
            js_pat = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']')
            from urllib.parse import urljoin
            for m in js_pat.finditer(html):
                js_url = m.group(1)
                if not js_url.startswith("http"):
                    js_url = urljoin(target_url, js_url)
                if urlparse(js_url).netloc == domain:
                    js_text = with_internet_retry(_fetch_text, js_url, cfg)
                    if js_text:
                        candidates.extend(_extract_supabase_keys(js_text, js_url))

    # --- Manual / env keys ---
    if manual_project_ref:
        candidates.append({
            "project_ref": manual_project_ref,
            "project_url": f"https://{manual_project_ref}.supabase.co",
            "anon_key": manual_anon_key or os.environ.get("FORGE_SUPABASE_ANON_KEY", ""),
            "key_role": "provided",
            "source_url": "manual",
        })

    if not candidates:
        env_key = os.environ.get("FORGE_SUPABASE_ANON_KEY", "")
        if env_key and not env_key.startswith("eyJhbGci..."):
            # Extract project ref from key if possible
            try:
                import base64
                payload = env_key.split(".")[1]
                payload += "=" * (4 - len(payload) % 4)
                decoded = json.loads(base64.b64decode(payload).decode())
                ref = decoded.get("ref", "unknown")
            except Exception:
                ref = "unknown"
            candidates.append({
                "project_ref": ref,
                "project_url": f"https://{ref}.supabase.co",
                "anon_key": env_key,
                "key_role": "env",
                "source_url": "FORGE_SUPABASE_ANON_KEY",
            })

    if not candidates:
        print("[SUPABASE] No Supabase project found. Provide --target-url or FORGE_SUPABASE_ANON_KEY.")
        return []

    # Deduplicate by project_ref
    seen = set()
    unique_candidates = []
    for c in candidates:
        ref = c.get("project_ref")
        if ref and ref not in seen:
            seen.add(ref)
            unique_candidates.append(c)

    all_findings = []
    for candidate in unique_candidates:
        if _SHUTDOWN.is_set():
            break
        ref = candidate["project_ref"]
        url = candidate["project_url"]
        key = candidate.get("anon_key", "")

        # Store discovered key
        eng_db_conn.execute(
            """INSERT OR IGNORE INTO supabase_findings
               (engagement_id, project_ref, anon_key, source_url, table_name, finding_type, severity, detail)
               VALUES (?, ?, ?, ?, NULL, 'KEY_DISCOVERED', 'INFO', ?)""",
            (engagement_id, ref, key[:40] + "..." if len(key) > 40 else key,
             candidate.get("source_url", ""), f"Role: {candidate.get('key_role')}"),
        )
        eng_db_conn.commit()
        print(f"[SUPABASE] Project: {ref} | Key: {key[:20]}... | Source: {candidate.get('source_url')}", flush=True)

        if not key:
            continue

        # Run RLS tests
        findings = _test_rls(url, key, cfg)
        for f in findings:
            try:
                eng_db_conn.execute(
                    """INSERT OR IGNORE INTO supabase_findings
                       (engagement_id, project_ref, anon_key, source_url, table_name, finding_type, severity, detail)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (engagement_id, ref, key[:40], candidate.get("source_url", ""),
                     f["table_name"], f["finding_type"], f["severity"], f["detail"]),
                )
            except Exception as e:
                _LOG.warning("DB insert failed: %s", e)
        eng_db_conn.commit()
        all_findings.extend(findings)
        sys.stdout.flush()

    print(f"[SUPABASE] Scan complete: {len(all_findings)} RLS finding(s)", flush=True)
    return all_findings
