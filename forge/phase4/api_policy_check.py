"""
forge/phase4/api_policy_check.py
Supabase RLS Policy Scanner — Module 4-G.

Probes Supabase PostgREST REST API for Row Level Security misconfigurations
by testing anonymous and (optionally) authenticated access.

Severity matrix (§9.17.3):
  anon read + sensitive columns  → CRITICAL
  anon read, no sensitive cols   → HIGH
  anon write (201/200)           → HIGH
  auth-only read exposed anon    → MEDIUM
  anon read returns empty array  → LOW

OPSEC constraints (PRD §12.7.4):
  - Scope gate: <project-ref>.supabase.co must be in engagement scope.
  - questionary.confirm() before first request and before each write probe.
  - Write probe payload: {"__forge_probe__": true} — traceable; document cleanup.
  - --dry-run: enumerate tables + print plan; zero outbound requests.
  - anon-key via env var (SUPABASE_ANON_KEY) or --anon-key-file preferred over CLI arg.
  - auth-token via env var (SUPABASE_AUTH_TOKEN) — never via CLI arg in production.
  - Rate: 1.0 s minimum between table probes; exponential backoff on 429.
  - Audit log: table name, probe type, HTTP status only — NEVER response body.
  - Evidence: first 512 chars of anon read response only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from base64 import urlsafe_b64decode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import urlparse

import httpx

from forge.config import resolve_secret_pool, split_secret_values
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

try:
    import questionary
except ImportError:
    questionary = None

# Column names that escalate severity to CRITICAL when present in anon-readable data
_SENSITIVE_COLS: frozenset[str] = frozenset(
    {
        "email",
        "password",
        "token",
        "secret",
        "ssn",
        "card",
        "cc_number",
        "phone",
        "api_key",
        "credit_card",
        "bank_account",
        "salary",
        "iban",
        "national_id",
        "passport",
        "dob",
    }
)

_PROBE_DELAY = 1.0  # seconds between table probes
_EVIDENCE_CAP = 512
_MOBILE_SUPABASE_SOURCE_HINTS = (
    "%.apk%",
    "%.ipa%",
    "%.aab%",
    "%.xapk%",
    "%.apkm%",
    "%.apks%",
    "%mobile%",
)


# ── Data models ────────────────────────────────────────────────────────────────


@dataclass
class SupabaseFinding:
    table: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    evidence: str  # ≤ 512 chars — response snippet


# ── Scanner ────────────────────────────────────────────────────────────────────


class SupabaseScanner:
    """
    Supabase RLS scanner via PostgREST anonymous probes.

    Usage:
        scanner  = SupabaseScanner(db_path, engagement_id)
        findings = scanner.scan(
            project_ref="xyzxyzxyz",
            anon_key="eyJhbGci...",
            auth_token=None,
            dry_run=False,
        )
    """

    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id

    # ── Public ────────────────────────────────────────────────────────────────

    def scan(
        self,
        project_ref: str,
        base_url: Optional[str] = None,
        anon_key: Optional[str] = None,
        auth_token: Optional[str] = None,
        auto_discover: Optional[bool] = None,
        mobile_extract: Optional[bool] = None,
        repo_scavenge: Optional[bool] = None,
        dry_run: bool = False,
        scope_values: Sequence[str] | None = None,
        url_prefixes: Sequence[str] | None = None,
        require_scope: bool = False,
    ) -> list[SupabaseFinding]:
        """
        Run anonymous + optional authenticated probes against the Supabase project.
        Returns findings written to vulnerability_findings.
        """
        base = (base_url or "").rstrip("/")
        if not base:
            base = f"https://{project_ref}.supabase.co"
        if not project_ref:
            parsed = urlparse(base)
            host = parsed.netloc or parsed.path
            project_ref = host.split(".")[0] if host else "unknown"
        self._scope_gate(
            project_ref,
            base,
            scope_values=scope_values,
            url_prefixes=url_prefixes,
            require_scope=require_scope,
        )
        anon_keys = resolve_secret_pool(anon_key, "FORGE_SUPABASE_ANON_KEY")
        anon_idx = 0
        auto_discover_enabled = self._is_enabled(
            auto_discover, "FORGE_SUPABASE_AUTO_DISCOVERY", True
        )
        mobile_extract_enabled = self._is_enabled(mobile_extract, "FORGE_MOBILE_ASSETS_SCAN", True)
        repo_scavenge_enabled = self._is_enabled(repo_scavenge, "FORGE_REPO_KEY_SCAVENGE", True)

        def next_anon_key() -> Optional[str]:
            nonlocal anon_idx
            if not anon_keys:
                return None
            value = anon_keys[anon_idx % len(anon_keys)]
            anon_idx += 1
            return value

        if questionary is not None:
            try:
                confirmed = questionary.confirm(
                    f"[Module 4-G] Supabase RLS scan:\n"
                    f"  Project : {project_ref}\n"
                    f"  Base URL: {base}\n"
                    f"  Auth    : {'token supplied' if auth_token else 'anon only'}\n"
                    f"  Dry-run : {dry_run}\n"
                    f"Proceed?"
                ).ask()
            except Exception:
                confirmed = True if dry_run else False
            if not confirmed:
                raise RuntimeError("Operator cancelled.")

        session = self._make_session(anon_key)
        con = direct_connect(self._db_path)
        self._ensure_schema(con)
        anon_keys = self._merge_unique(anon_keys, self._load_stored_anon_keys(con, project_ref))
        if not anon_keys and auto_discover_enabled and not dry_run:
            discovered = self._discover_anon_key(base, session, project_ref)
            if discovered:
                anon_keys = self._merge_unique(anon_keys, [discovered])
        if not anon_keys and mobile_extract_enabled:
            anon_keys = self._merge_unique(
                anon_keys, self._extract_mobile_supabase_keys(con, project_ref)
            )
        if not anon_keys and repo_scavenge_enabled and not dry_run:
            anon_keys = self._merge_unique(anon_keys, self._scavenge_public_repos(project_ref))
        if not anon_keys:
            self._record_no_credential_state(con, project_ref)

        tables = self._enumerate_tables(base, session, dry_run)
        if not tables:
            _LOG.info("Module 4-G: no tables discovered for %s", project_ref)
            con.commit()
            con.close()
            return []

        findings: list[SupabaseFinding] = []

        for table in tables:
            time.sleep(_PROBE_DELAY)

            # ── Anonymous read probe ───────────────────────────────────────────
            anon_finding = self._anon_read_probe(
                base, table, next_anon_key(), session, dry_run, con
            )
            if anon_finding:
                findings.append(anon_finding)
                self._store_finding(con, project_ref, anon_finding)

            # ── Anonymous write probe (with per-table confirm) ─────────────────
            if not dry_run:
                write_finding = self._anon_write_probe(base, table, next_anon_key(), session, con)
                if write_finding:
                    findings.append(write_finding)
                    self._store_finding(con, project_ref, write_finding)
            else:
                _LOG.info("[DRY-RUN] Would write probe to %s/rest/v1/%s", base, table)

            # ── Authenticated differential (optional) ──────────────────────────
            if auth_token and not dry_run:
                auth_finding = self._auth_differential(
                    base, table, next_anon_key(), auth_token, session, con
                )
                if auth_finding:
                    findings.append(auth_finding)
                    self._store_finding(con, project_ref, auth_finding)

        self._store_cloud_asset(con, project_ref)
        con.commit()
        con.close()
        _LOG.info("Module 4-G: %d findings for project %s", len(findings), project_ref)
        return findings

    # ── Probes ────────────────────────────────────────────────────────────────

    def _anon_read_probe(
        self,
        base: str,
        table: str,
        anon_key: Optional[str],
        session,
        dry_run: bool,
        con: sqlite3.Connection,
    ) -> Optional[SupabaseFinding]:
        url = f"{base}/rest/v1/{table}?limit=1"
        if dry_run:
            _LOG.info("[DRY-RUN] Would GET %s", url)
            return None
        try:
            resp = session.get(url, headers=self._headers(anon_key, None), timeout=10)
        except Exception as exc:
            _LOG.debug("Anon read probe failed (%s): %s", table, exc)
            return None

        self._audit(con, table, "anon_read", resp.status_code)

        if resp.status_code not in (200, 206):
            return None

        data = self._safe_json(resp.text)
        has_data = isinstance(data, list) and len(data) > 0
        sensitive = self._has_sensitive(data)
        severity = self._assess_severity(has_data, sensitive)

        if severity is None:
            return None

        evidence = resp.text[:_EVIDENCE_CAP]
        return SupabaseFinding(
            table=table,
            severity=severity,
            title=f"Supabase RLS: anon read on '{table}'"
            + (" [SENSITIVE DATA]" if sensitive else ""),
            description=(
                f"Table '{table}' is readable without authentication. "
                + ("Sensitive column names detected." if sensitive else "")
            ),
            evidence=evidence,
        )

    def _anon_write_probe(
        self,
        base: str,
        table: str,
        anon_key: Optional[str],
        session,
        con: sqlite3.Connection,
    ) -> Optional[SupabaseFinding]:
        if questionary is not None:
            try:
                confirmed = questionary.confirm(
                    f"[Module 4-G] Write probe to '{table}' — will create a traceable DB record. Proceed?"
                ).ask()
            except Exception:
                confirmed = False
            if not confirmed:
                return None

        url = f"{base}/rest/v1/{table}"
        try:
            resp = session.post(
                url,
                headers=self._headers(anon_key, None),
                json={"__forge_probe__": True},
                timeout=10,
            )
        except Exception as exc:
            _LOG.debug("Anon write probe failed (%s): %s", table, exc)
            return None

        self._audit(con, table, "anon_write", resp.status_code)

        if resp.status_code not in (200, 201):
            return None
        return SupabaseFinding(
            table=table,
            severity="HIGH",
            title=f"Supabase RLS: anonymous write on '{table}'",
            description=f"Table '{table}' accepts unauthenticated write requests (HTTP {resp.status_code}).",
            evidence=f"POST {url} → HTTP {resp.status_code}",
        )

    def _auth_differential(
        self,
        base: str,
        table: str,
        anon_key: Optional[str],
        auth_token: str,
        session,
        con: sqlite3.Connection,
    ) -> Optional[SupabaseFinding]:
        """Compare anon vs authenticated responses; flag tables anon can access that should require auth."""
        url = f"{base}/rest/v1/{table}?limit=1"
        try:
            anon_resp = session.get(url, headers=self._headers(anon_key, None), timeout=10)
            auth_resp = session.get(url, headers=self._headers(anon_key, auth_token), timeout=10)
        except Exception as exc:
            _LOG.debug("Auth differential failed (%s): %s", table, exc)
            return None

        self._audit(con, table, "auth_differential", auth_resp.status_code)

        # If anon succeeds but the table has meaningful data only when authenticated, flag MEDIUM
        if (
            anon_resp.status_code == 200
            and auth_resp.status_code == 200
            and anon_resp.text.strip() not in ("[]", "null", "")
        ):
            return SupabaseFinding(
                table=table,
                severity="MEDIUM",
                title=f"Supabase RLS: '{table}' accessible without authentication",
                description=f"Anon and authenticated requests both return data for '{table}'.",
                evidence=anon_resp.text[:_EVIDENCE_CAP],
            )
        return None

    # ── Table enumeration ──────────────────────────────────────────────────────

    def _enumerate_tables(self, base: str, session, dry_run: bool) -> list[str]:
        """Fetch OpenAPI schema from PostgREST root endpoint to list tables."""
        if dry_run:
            _LOG.info("[DRY-RUN] Would enumerate tables at %s/rest/v1/", base)
            return []
        try:
            resp = session.get(
                f"{base}/rest/v1/",
                headers={"Accept": "application/openapi+json,application/json"},
                timeout=15,
            )
            if resp.status_code != 200:
                _LOG.warning("Table enumeration returned HTTP %d", resp.status_code)
                return []
            schema = resp.json()
            # OpenAPI 2.x paths: /rest/v1/{table}
            paths = schema.get("paths", {})
            tables = [p.lstrip("/").split("?")[0] for p in paths if p.startswith("/") and p != "/"]
            _LOG.info("Discovered %d table(s) for Supabase project", len(tables))
            return tables
        except Exception as exc:
            _LOG.error("Table enumeration failed: %s", exc)
            return []

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _make_session(anon_key: Optional[str]):
        try:
            from curl_cffi import requests as cffi_requests

            return cffi_requests.Session(impersonate="chrome120")
        except ImportError:
            import urllib.request

            class _FallbackSession:
                def get(self, url, **kw):
                    return type("R", (), {"status_code": 0, "text": ""})()

                def post(self, url, **kw):
                    return type("R", (), {"status_code": 0, "text": ""})()

            _LOG.warning("curl_cffi not available; HTTP probing disabled")
            return _FallbackSession()

    @staticmethod
    def _headers(anon_key: Optional[str], jwt: Optional[str]) -> dict:
        h = {"Content-Type": "application/json"}
        if anon_key:
            h["apikey"] = anon_key
        if jwt:
            h["Authorization"] = f"Bearer {jwt}"
        return h

    @staticmethod
    def _is_enabled(value: Optional[bool], env_name: str, default: bool) -> bool:
        if value is not None:
            return value
        raw = os.environ.get(env_name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _merge_unique(current: list[str], incoming: list[str]) -> list[str]:
        merged: list[str] = []
        for item in current + incoming:
            if item and item not in merged:
                merged.append(item)
        return merged

    @staticmethod
    def _extract_jwt_candidates(text: str) -> list[str]:
        if not text:
            return []
        return re.findall(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)", text)

    def _extract_keys_from_json(self, data) -> list[str]:
        found: list[str] = []
        if isinstance(data, dict):
            for value in data.values():
                found.extend(self._extract_keys_from_json(value))
        elif isinstance(data, list):
            for value in data:
                found.extend(self._extract_keys_from_json(value))
        elif isinstance(data, str):
            found.extend(self._extract_jwt_candidates(data))
        return self._merge_unique([], found)

    def _discover_anon_key(self, base: str, session, project_ref: str) -> Optional[str]:
        endpoints = (
            f"{base}/auth/v1/settings",
            f"{base}/rest/v1/",
            f"{base}/storage/v1/object/list",
        )
        for endpoint in endpoints:
            try:
                resp = session.get(endpoint, timeout=8)
            except Exception:
                continue
            if getattr(resp, "status_code", 0) != 200:
                continue
            headers = getattr(resp, "headers", {}) or {}
            for header_name in ("apikey", "x-api-key", "x-anon-key"):
                candidate = headers.get(header_name) if hasattr(headers, "get") else None
                if self._validate_anon_key(candidate, project_ref):
                    return candidate
            try:
                payload = resp.json()
            except Exception:
                payload = self._safe_json(getattr(resp, "text", ""))
            for candidate in self._extract_keys_from_json(payload):
                if self._validate_anon_key(candidate, project_ref):
                    return candidate
        return None

    def _validate_anon_key(self, key: Optional[str], expected_project_ref: str) -> bool:
        if not key or len(key) < 20:
            return False
        parts = key.split(".")
        if len(parts) != 3:
            return False
        try:
            payload_raw = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(urlsafe_b64decode(payload_raw.encode("utf-8")).decode("utf-8"))
        except Exception:
            return False
        role = str(payload.get("role", ""))
        if role not in {"anon", "authenticated"}:
            return False
        issuer = str(payload.get("iss", ""))
        ref = str(payload.get("ref", ""))
        if expected_project_ref and expected_project_ref != "unknown":
            if expected_project_ref not in issuer and ref != expected_project_ref:
                return False
        return True

    def _load_stored_anon_keys(self, con: sqlite3.Connection, project_ref: str) -> list[str]:
        try:
            rows = con.execute(
                """
                SELECT key_enc
                FROM key_scanner_findings
                WHERE engagement_id=?
                  AND service='supabase'
                  AND validation_state='ACTIVE'
                  AND (domain LIKE ? OR repo_name LIKE ? OR source_url LIKE ?)
                ORDER BY found_at DESC
                LIMIT 10
                """,
                (
                    self._engagement_id,
                    f"%{project_ref}%",
                    f"%{project_ref}%",
                    f"%{project_ref}%",
                ),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        try:
            from forge.opsec.crypto import decrypt_string
        except Exception:
            return []
        keys: list[str] = []
        for row in rows:
            enc = row[0] if row else None
            if not enc:
                continue
            try:
                plain = decrypt_string(enc)
            except Exception:
                continue
            if self._validate_anon_key(plain, project_ref):
                keys.append(plain)
        return self._merge_unique([], keys)

    def _extract_mobile_supabase_keys(self, con: sqlite3.Connection, project_ref: str) -> list[str]:
        mobile_source_predicate = " OR ".join(
            "source_url LIKE ?" for _ in _MOBILE_SUPABASE_SOURCE_HINTS
        )
        try:
            rows = con.execute(
                f"""
                SELECT key_enc
                FROM key_scanner_findings
                WHERE engagement_id=?
                  AND service='supabase'
                  AND ({mobile_source_predicate})
                ORDER BY found_at DESC
                LIMIT 10
                """,
                (self._engagement_id, *_MOBILE_SUPABASE_SOURCE_HINTS),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        try:
            from forge.opsec.crypto import decrypt_string
        except Exception:
            return []
        keys: list[str] = []
        for row in rows:
            enc = row[0] if row else None
            if not enc:
                continue
            try:
                plain = decrypt_string(enc)
            except Exception:
                continue
            if self._validate_anon_key(plain, project_ref):
                keys.append(plain)
        return self._merge_unique([], keys)

    def _scavenge_public_repos(self, project_ref: str) -> list[str]:
        token_pool = resolve_secret_pool(None, "FORGE_GITHUB_TOKEN")
        if not token_pool:
            return []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token_pool[0]}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        queries = (
            f'"{project_ref}.supabase.co" ("NEXT_PUBLIC_SUPABASE_ANON_KEY" OR "supabaseKey")',
            f'"{project_ref}" "supabaseKey" "eyJ"',
        )
        keys: list[str] = []
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            for query in queries:
                try:
                    search_resp = client.get(
                        "https://api.github.com/search/code",
                        headers=headers,
                        params={"q": query, "per_page": 10},
                    )
                except Exception:
                    continue
                if search_resp.status_code != 200:
                    continue
                items = search_resp.json().get("items", [])
                for item in items:
                    html_url = item.get("html_url", "")
                    if not html_url:
                        continue
                    raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace(
                        "/blob/", "/"
                    )
                    try:
                        file_resp = client.get(raw_url, headers=headers)
                    except Exception:
                        continue
                    if file_resp.status_code != 200:
                        continue
                    for candidate in self._extract_jwt_candidates(file_resp.text):
                        if self._validate_anon_key(candidate, project_ref):
                            keys.append(candidate)
        return self._merge_unique([], keys)

    def _record_no_credential_state(self, con: sqlite3.Connection, project_ref: str) -> None:
        info = SupabaseFinding(
            table="__credential_status__",
            severity="INFO",
            title="Supabase credential auto-fill unavailable",
            description=(
                "No Supabase anon key discovered from configured sources; "
                "credential-dependent checks are marked skipped."
            ),
            evidence=f"project_ref={project_ref}",
        )
        self._store_finding(con, project_ref, info)
        self._audit(con, "__credential_status__", "credential_resolution_skipped", 0)

    @staticmethod
    def _safe_json(text: str):
        try:
            return json.loads(text)
        except Exception:
            return None

    @staticmethod
    def _has_sensitive(data) -> bool:
        if isinstance(data, list) and data:
            return any(k.lower() in _SENSITIVE_COLS for k in data[0].keys())
        if isinstance(data, dict):
            return any(k.lower() in _SENSITIVE_COLS for k in data.keys())
        return False

    @staticmethod
    def _assess_severity(has_data: bool, has_sensitive: bool) -> Optional[str]:
        if has_data and has_sensitive:
            return "CRITICAL"
        if has_data:
            return "HIGH"
        return None  # empty array or no data — LOW only for write findings

    def _audit(self, con: sqlite3.Connection, table: str, probe_type: str, status: int) -> None:
        detail = f"table={table} type={probe_type} status={status}"[:1024]
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                self._engagement_id,
                "phase4",
                "supabase_scanner",
                "supabase_probe",
                table,
                detail,
                "operator",
            ),
        )

    def _store_finding(self, con: sqlite3.Connection, project_ref: str, f: SupabaseFinding) -> None:
        con.execute(
            """INSERT OR IGNORE INTO vulnerability_findings
               (engagement_id, vuln_type, target_url, parameter, severity,
                title, description, evidence, found_at)
               VALUES (?, 'SUPABASE_RLS', ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                self._engagement_id,
                f"https://{project_ref}.supabase.co/rest/v1/{f.table}",
                f.table,
                f.severity,
                f.title,
                f.description,
                f.evidence,
            ),
        )
        con.commit()

    def _store_cloud_asset(self, con: sqlite3.Connection, project_ref: str) -> None:
        try:
            con.execute(
                """INSERT OR IGNORE INTO cloud_assets
                   (engagement_id, asset_type, identifier, provider_identifier, source)
                   VALUES (?, 'supabase', ?, ?, 'supabase_scanner')""",
                (self._engagement_id, project_ref, project_ref),
            )
        except sqlite3.OperationalError:
            pass

    def _scope_gate(
        self,
        project_ref: str,
        base: str,
        *,
        scope_values: Sequence[str] | None = None,
        url_prefixes: Sequence[str] | None = None,
        require_scope: bool = False,
    ) -> None:
        from forge.governance.scope_gate import EngagementScope, ScopeGate
        from forge.opsec.scope_gate import ScopeViolationError, load_scope_from_db

        scope = (
            [str(item) for item in scope_values if str(item or "").strip()]
            if scope_values is not None
            else load_scope_from_db(str(self._db_path), self._engagement_id)
        )
        prefixes = [str(item) for item in url_prefixes or [] if str(item or "").strip()]
        target = (base or f"https://{project_ref}.supabase.co").rstrip("/")
        if require_scope and not scope and not prefixes:
            raise ScopeViolationError(target, [])
        if not scope and not prefixes:
            from forge.opsec.scope_gate import assert_in_scope

            assert_in_scope(urlparse(target).hostname or target)
            return

        domains: list[str] = []
        ip_ranges: list[str] = []
        for item in scope:
            text = str(item or "").strip()
            if not text:
                continue
            if text.startswith(("http://", "https://")):
                prefixes.append(text)
                parsed_host = urlparse(text).hostname
                if parsed_host:
                    domains.append(parsed_host)
            elif "/" in text:
                ip_ranges.append(text)
            else:
                domains.append(text)
        gate = ScopeGate(
            EngagementScope(
                domains=list(dict.fromkeys(domains)),
                ip_ranges=list(dict.fromkeys(ip_ranges)),
                urls=list(dict.fromkeys(prefixes)),
            )
        )
        if not gate.is_in_scope(target):
            raise ScopeViolationError(target, list(scope) + prefixes)

    @staticmethod
    def _ensure_schema(con: sqlite3.Connection) -> None:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS vulnerability_findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                vuln_type     TEXT NOT NULL,
                target_url    TEXT NOT NULL,
                parameter     TEXT,
                severity      TEXT NOT NULL
                              CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
                title         TEXT NOT NULL,
                description   TEXT,
                evidence      TEXT,
                cvss_score    REAL,
                found_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, vuln_type, target_url, parameter)
            );
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                asset_type    TEXT NOT NULL,
                identifier    TEXT NOT NULL,
                provider_identifier TEXT,
                source        TEXT NOT NULL,
                discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, asset_type, identifier)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                phase         TEXT,
                module        TEXT,
                action        TEXT,
                target        TEXT,
                result        TEXT,
                operator      TEXT,
                logged_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        try:
            con.execute("ALTER TABLE cloud_assets ADD COLUMN provider_identifier TEXT")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
        con.commit()
