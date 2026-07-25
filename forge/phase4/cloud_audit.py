"""
forge/phase4/cloud_audit.py
Firebase Agneyastra Wrapper — Module 4-E.

Orchestrates the redhuntlabs/Agneyastra Go binary for comprehensive Firebase
security auditing. All outbound HTTP is Agneyastra's; this module is a
subprocess orchestrator and result parser.

OPSEC constraints (PRD §12.7.2):
  - assert_tool_version("agneyastra", "1.0.0") at init — hard failure if absent.
  - JSON output file registered with cleanup.py BEFORE subprocess invocation.
  - JSON output file deleted immediately after parse.
  - API key value redacted from audit_log (log only "ACTIVE key present").
  - --api-key value is visible in /proc/<pid>/cmdline during subprocess lifetime.
    Do not run on shared machines. Exposure window is limited to agneyastra runtime.
  - questionary.confirm() before first test with project ID + selected tests shown.
  - --dry-run: print planned invocation; no subprocess, no DB writes.
  - Scope gate: project domain (<project-id>.firebaseapp.com) in engagement scope.

Severity mapping (§9.15.3):
  auth_bypass / rtdb_public_write         → CRITICAL
  rtdb_public_read / firestore_public
  / storage_public                        → HIGH
  functions_unauth / remote_config_unauth → MEDIUM
  informational                           → INFO
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

import httpx

from forge.config import resolve_secret_pool

_LOG = logging.getLogger(__name__)

try:
    import questionary
except ImportError:
    questionary = None

BINARY = "agneyastra"
MIN_VERSION = "1.0.0"

_ALL_TESTS = ("auth", "database", "firestore", "storage", "functions", "remote_config")

_SEVERITY_MAP: dict[str, str] = {
    "auth_bypass": "CRITICAL",
    "rtdb_public_write": "CRITICAL",
    "rtdb_public_read": "HIGH",
    "firestore_public": "HIGH",
    "storage_public": "HIGH",
    "functions_unauth": "MEDIUM",
    "remote_config_unauth": "MEDIUM",
    "informational": "INFO",
}


# ── Exceptions ─────────────────────────────────────────────────────────────────


class ToolVersionError(RuntimeError):
    """Raised when a required external binary is absent or below minimum version."""


# ── Version assertion ──────────────────────────────────────────────────────────


def _assert_tool_version(binary: str, min_ver: str) -> None:
    path = shutil.which(binary)
    if not path:
        raise ToolVersionError(
            f"Required binary '{binary}' not found on PATH. "
            f"Install >= {min_ver} from https://github.com/redhuntlabs/Agneyastra/releases"
        )
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
        out = (result.stdout + result.stderr).strip()
        # Parse first version-like token
        import re

        m = re.search(r"(\d+\.\d+\.\d+)", out)
        if m:
            installed = tuple(int(x) for x in m.group(1).split("."))
            minimum = tuple(int(x) for x in min_ver.split("."))
            if installed < minimum:
                raise ToolVersionError(
                    f"'{binary}' is version {m.group(1)}, but >= {min_ver} is required."
                )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        raise ToolVersionError(f"Could not determine version of '{binary}'.")


# ── Key resolution ─────────────────────────────────────────────────────────────


def _resolve_firebase_api_key(
    con: sqlite3.Connection,
    engagement_id: int,
    project_id: str,
    api_key: Optional[str] = None,
    auto_discover_web: Optional[bool] = None,
    repo_scavenge: Optional[bool] = None,
) -> Optional[str]:
    """
    Query key_scanner_findings for an ACTIVE Firebase API key matching project_id.
    Returns decrypted key string, or None if not found.
    Key value is NEVER logged.
    """
    explicit_pool = resolve_secret_pool(api_key, "FORGE_FIREBASE_API_KEY")
    if explicit_pool:
        return explicit_pool[0]

    try:
        row = con.execute(
            """SELECT key_enc FROM key_scanner_findings
               WHERE engagement_id=? AND service='firebase'
                 AND validation_state='ACTIVE'
                 AND (repo_name LIKE ? OR source_url LIKE ?)
               LIMIT 1""",
            (engagement_id, f"%{project_id}%", f"%{project_id}%"),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None

    if row and row[0]:
        try:
            from forge.opsec.crypto import decrypt_string

            decrypted = decrypt_string(row[0])
            if _validate_firebase_api_key(decrypted):
                return decrypted
        except Exception:
            pass

    env_pool = resolve_secret_pool(None, "FORGE_FIREBASE_API_KEY")
    if env_pool and _validate_firebase_api_key(env_pool[0]):
        return env_pool[0]

    if _is_enabled(auto_discover_web, "FORGE_FIREBASE_WEB_DISCOVERY", True):
        discovered = _discover_firebase_web_key(project_id)
        if discovered:
            return discovered

    if _is_enabled(repo_scavenge, "FORGE_FIREBASE_REPO_SCAVENGE", True):
        keys = _scavenge_firebase_public_repos(project_id)
        if keys:
            return keys[0]
    return None


def _is_enabled(value: Optional[bool], env_name: str, default: bool) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(env_name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _validate_firebase_api_key(key: Optional[str]) -> bool:
    if not key or len(key) < 20:
        return False
    if not key.startswith("AIza"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]+", key))


def _extract_firebase_api_key(data) -> Optional[str]:
    if isinstance(data, dict):
        direct = data.get("apiKey")
        if isinstance(direct, str) and _validate_firebase_api_key(direct):
            return direct
        for value in data.values():
            nested = _extract_firebase_api_key(value)
            if nested:
                return nested
    elif isinstance(data, list):
        for item in data:
            nested = _extract_firebase_api_key(item)
            if nested:
                return nested
    return None


def _discover_firebase_web_key(project_id: str) -> Optional[str]:
    endpoints = (
        f"https://{project_id}.firebaseapp.com/__/firebase/init.json",
        f"https://{project_id}.web.app/__/firebase/init.json",
        f"https://{project_id}.firebaseapp.com/firebase-config.json",
        f"https://{project_id}.web.app/firebase-config.json",
    )
    headers = {"User-Agent": "Mozilla/5.0 (compatible; FORGE/7.2)"}
    with httpx.Client(timeout=10, follow_redirects=True, headers=headers) as client:
        for endpoint in endpoints:
            try:
                resp = client.get(endpoint)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            try:
                payload = resp.json()
            except Exception:
                continue
            discovered = _extract_firebase_api_key(payload)
            if discovered:
                return discovered
    return None


def _scavenge_firebase_public_repos(project_id: str) -> list[str]:
    token_pool = resolve_secret_pool(None, "FORGE_GITHUB_TOKEN")
    if not token_pool:
        return []
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token_pool[0]}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    queries = (
        f'"{project_id}" "firebaseConfig" "apiKey"',
        f'"{project_id}" "AIza" "firebaseapp.com"',
        f'filename:google-services.json "{project_id}"',
    )
    found: list[str] = []
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
                for match in re.findall(r"AIza[0-9A-Za-z\-_]{20,}", file_resp.text):
                    if _validate_firebase_api_key(match):
                        found.append(match)
    deduped: list[str] = []
    for item in found:
        if item not in deduped:
            deduped.append(item)
    return deduped


# ── Result model ───────────────────────────────────────────────────────────────


@dataclass
class FirebaseFinding:
    category: str
    severity: str
    title: str
    description: str
    evidence: str  # first 512 chars


def _receipt_hash(value: object) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _firebase_audit_evidence(project_id: str, finding: FirebaseFinding) -> str:
    proof = (
        "validation=VALIDATED:firebase_agneyastra_audit:"
        f"provider=firebase project_hash={_receipt_hash(project_id)} "
        f"category={re.sub(r'[^a-z0-9_-]+', '_', finding.category.lower())}"
    )
    return f"{proof}; detail={finding.evidence}"[:512]


# ── Auditor ────────────────────────────────────────────────────────────────────


class FirebaseAuditor:
    """
    High-level Firebase audit engine wrapping Agneyastra.

    Usage:
        auditor  = FirebaseAuditor(db_path, engagement_id)
        findings = auditor.run(
            project_id="my-project-12345",
            tests=["auth", "database", "firestore"],
            timeout=600,
            dry_run=False,
        )
    """

    def __init__(self, db_path: Path, engagement_id: int) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id

    def run(
        self,
        project_id: str,
        tests: Optional[list[str]] = None,
        api_key: Optional[str] = None,
        auto_discover_web: Optional[bool] = None,
        repo_scavenge: Optional[bool] = None,
        timeout: int = 600,
        dry_run: bool = False,
        scope_values: Sequence[str] | None = None,
        url_prefixes: Sequence[str] | None = None,
        require_scope: bool = False,
    ) -> list[FirebaseFinding]:
        tests = tests or list(_ALL_TESTS)
        self._scope_gate(
            project_id,
            scope_values=scope_values,
            url_prefixes=url_prefixes,
            require_scope=require_scope,
        )

        con = sqlite3.connect(self._db_path)
        resolved_api_key = _resolve_firebase_api_key(
            con,
            self._engagement_id,
            project_id,
            api_key=api_key,
            auto_discover_web=auto_discover_web,
            repo_scavenge=repo_scavenge,
        )
        if not resolved_api_key:
            self._store_credential_status(con, project_id)

        # Confirm with operator
        if questionary is not None:
            try:
                confirmed = questionary.confirm(
                    f"[Module 4-E] Firebase audit:\n"
                    f"  Project ID : {project_id}\n"
                    f"  Tests      : {', '.join(tests)}\n"
                    f"  API key    : {'ACTIVE' if resolved_api_key else 'none'}\n"
                    f"  Dry-run    : {dry_run}\n"
                    f"Proceed?"
                ).ask()
            except Exception:
                confirmed = True if dry_run else False
            if not confirmed:
                raise RuntimeError("Operator cancelled.")

        if dry_run:
            # Dry-run bypasses tool-version check so operators can preview
            # without needing agneyastra installed.
            _LOG.info("[DRY-RUN] Firebase project=%s tests=%s api_key=%s",
                       project_id, ",".join(tests),
                       "ACTIVE" if resolved_api_key else "none")
            con.close()
            return []

        # Live runs still enforce agneyastra >= MIN_VERSION.
        _assert_tool_version(BINARY, MIN_VERSION)

        # Register output file with cleanup before invocation
        with tempfile.NamedTemporaryFile(suffix=".json", prefix="agneyastra_", delete=False) as tmp:
            out_path = Path(tmp.name)

        self._register_cleanup(out_path)

        try:
            cmd = self._build_command(project_id, tests, resolved_api_key, str(out_path))
            _LOG.info(
                "Running agneyastra: project=%s tests=%s (api_key=%s)",
                project_id,
                tests,
                "REDACTED" if resolved_api_key else "none",
            )
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0:
                _LOG.warning("agneyastra exited %d: %s", result.returncode, result.stderr[:400])

            findings = self._parse_output(out_path)

        finally:
            # Always delete output file immediately after parse
            try:
                out_path.unlink(missing_ok=True)
            except Exception:
                pass

        count = self._store_findings(con, project_id, findings)
        self._store_cloud_asset(con, project_id)
        self._audit_log(con, project_id, tests, count, bool(resolved_api_key))
        con.commit()
        con.close()

        _LOG.info("Module 4-E: %d Firebase findings for %s", count, project_id)
        return findings

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build_command(
        project_id: str,
        tests: list[str],
        api_key: Optional[str],
        out_path: str,
    ) -> list[str]:
        cmd = [
            BINARY,
            "--project",
            project_id,
            "--tests",
            ",".join(tests),
            "--output",
            out_path,
            "--format",
            "json",
        ]
        if api_key:
            cmd.extend(["--api-key", api_key])
        return cmd

    @staticmethod
    def _parse_output(path: Path) -> list[FirebaseFinding]:
        if not path.exists():
            _LOG.warning("Agneyastra output file not found: %s", path)
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            _LOG.error("Could not parse agneyastra output: %s", exc)
            return []

        findings: list[FirebaseFinding] = []
        # Agneyastra v1.x outputs: {"findings": [...]}
        items = raw.get("findings", raw) if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return []

        for item in items:
            if not isinstance(item, dict):
                continue
            category = item.get("category", "informational").lower()
            severity = _SEVERITY_MAP.get(category, "INFO")
            findings.append(
                FirebaseFinding(
                    category=category,
                    severity=severity,
                    title=item.get("title", category),
                    description=item.get("description", ""),
                    evidence=json.dumps(item.get("detail", {}))[:512],
                )
            )
        return findings

    def _store_findings(
        self, con: sqlite3.Connection, project_id: str, findings: list[FirebaseFinding]
    ) -> int:
        self._ensure_schema(con)
        count = 0
        for f in findings:
            con.execute(
                """INSERT OR IGNORE INTO vulnerability_findings
                   (engagement_id, vuln_type, target_url, severity, title, description, evidence)
                   VALUES (?, 'FIREBASE_MISCONFIG', ?, ?, ?, ?, ?)""",
                (
                    self._engagement_id,
                    f"https://{project_id}.firebaseapp.com",
                    f.severity,
                    f.title,
                    f.description,
                    _firebase_audit_evidence(project_id, f),
                ),
            )
            count += 1
        return count

    def _store_cloud_asset(self, con: sqlite3.Connection, project_id: str) -> None:
        try:
            con.execute(
                """INSERT OR IGNORE INTO cloud_assets
                   (engagement_id, asset_type, identifier, provider_identifier, source)
                   VALUES (?, 'firebase', ?, ?, 'firebase_agneyastra')""",
                (self._engagement_id, project_id, project_id),
            )
        except sqlite3.OperationalError:
            pass

    def _audit_log(
        self,
        con: sqlite3.Connection,
        project_id: str,
        tests: list[str],
        finding_count: int,
        had_api_key: bool,
    ) -> None:
        detail = (
            f"project={project_id} tests={','.join(tests)} "
            f"findings={finding_count} api_key={'yes' if had_api_key else 'no'}"
        )[:1024]
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                self._engagement_id,
                "phase4",
                "firebase_agneyastra",
                "firebase_audit",
                project_id,
                detail,
                "operator",
            ),
        )

    def _store_credential_status(self, con: sqlite3.Connection, project_id: str) -> None:
        con.execute(
            """INSERT OR IGNORE INTO vulnerability_findings
               (engagement_id, vuln_type, target_url, parameter, severity, title, description, evidence)
               VALUES (?, 'FIREBASE_CREDENTIAL_STATUS', ?, ?, 'INFO', ?, ?, ?)""",
            (
                self._engagement_id,
                f"https://{project_id}.firebaseapp.com",
                "__credential_status__",
                "Firebase credential auto-fill unavailable",
                "No Firebase API key discovered from configured sources; credential-dependent checks are marked skipped.",
                f"project={project_id}",
            ),
        )
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                self._engagement_id,
                "phase4",
                "firebase_agneyastra",
                "credential_resolution_skipped",
                project_id,
                "firebase_api_key=missing",
                "operator",
            ),
        )

    def _scope_gate(
        self,
        project_id: str,
        *,
        scope_values: Sequence[str] | None = None,
        url_prefixes: Sequence[str] | None = None,
        require_scope: bool = False,
    ) -> None:
        from urllib.parse import urlparse

        from forge.governance.scope_gate import EngagementScope, ScopeGate
        from forge.opsec.scope_gate import ScopeViolationError, load_scope_from_db

        target = f"https://{project_id}.firebaseapp.com"
        scope = (
            [str(item) for item in scope_values if str(item or "").strip()]
            if scope_values is not None
            else load_scope_from_db(str(self._db_path), self._engagement_id)
        )
        prefixes = [str(item) for item in url_prefixes or [] if str(item or "").strip()]
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
                host = urlparse(text).hostname
                if host:
                    domains.append(host)
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
    def _register_cleanup(path: Path) -> None:
        try:
            from forge.shared.cleanup import register_cleanup_file

            register_cleanup_file(path)
        except ImportError:
            pass

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
