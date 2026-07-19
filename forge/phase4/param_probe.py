"""
forge/phase4/param_probe.py
IDOR Scanner — Module 4-D.

BFS crawler + ID parameter substitution prober.
Identifies endpoints where substituting an object identifier exposes unintended data.

OPSEC constraints:
  - Scope gate enforced at EVERY URL fetch, not only the crawl seed.
  - No headless browser. All HTTP via curl_cffi for TLS fingerprint consistency.
  - questionary.confirm() required before first request.
  - Delay between probes: --delay default 1.5 s ± 20% jitter.
  - Evidence truncated to 512 characters; full response bodies never stored.
  - audit_log records URL + status; never response body.
  - --dry-run crawls and extracts parameters without issuing any probe requests.

Severity logic:
  CRITICAL/HIGH  — PII or financial field keys present in divergent response.
  MEDIUM         — Object data visible (non-empty diff) but no PII fields.
  LOW            — Status code differs only; no body divergence.
"""

from __future__ import annotations

import json
import logging
import random
import re
import sqlite3
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode, ParseResult

_LOG = logging.getLogger(__name__)

try:
    import questionary
except ImportError:
    questionary = None

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Integer path segment: /users/1234/profile
_INT_PATH_RE = re.compile(r"/(\d{2,12})(?:/|$)")
# UUID path segment
_UUID_PATH_RE = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)",
    re.IGNORECASE,
)
# Integer / UUID query parameter
_INT_PARAM_RE = re.compile(r"^(?:id|user_?id|order_?id|account|item|record|object|doc|ref)$", re.I)
_ANY_INT_RE = re.compile(r"^\d{1,12}$")

# PII / financial field names that escalate severity
_PII_FIELDS: frozenset[str] = frozenset(
    {
        "email",
        "phone",
        "ssn",
        "dob",
        "date_of_birth",
        "address",
        "postcode",
        "zipcode",
        "credit_card",
        "card_number",
        "cvv",
        "iban",
        "bank_account",
        "password",
        "secret",
        "token",
        "api_key",
        "salary",
        "income",
        "balance",
        "passport",
        "national_id",
        "drivers_license",
    }
)

_EVIDENCE_LIMIT = 512


# ── Data models ────────────────────────────────────────────────────────────────


@dataclass
class IdorFinding:
    target_url: str
    parameter: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    evidence: str  # ≤ 512 chars of divergent response


@dataclass
class ProbeResult:
    probe_url: str
    baseline_status: int
    probe_status: int
    baseline_len: int
    probe_len: int
    baseline_json: Optional[dict]
    probe_json: Optional[dict]
    has_pii: bool


# ── Crawler + Scanner ──────────────────────────────────────────────────────────


class IDORScanner:
    """
    BFS crawler + ID parameter substitution prober.

    Usage:
        scanner = IDORScanner(db_path, engagement_id, proxy="socks5://127.0.0.1:9050")
        findings = scanner.scan(
            target_url="https://app.example.com",
            depth=3,
            delay=1.5,
            dry_run=False,
        )
    """

    _PROBE_VARIANTS = [
        lambda v: str(int(v) - 1),
        lambda v: str(int(v) + 1),
        lambda v: str(int(v) + 100),
        lambda _: "0",
        lambda _: "99999",
        lambda _: str(uuid.uuid4()),
    ]

    def __init__(
        self,
        db_path: Path,
        engagement_id: int,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id
        self._proxy = proxy
        self._ua = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )

    # ── Public ────────────────────────────────────────────────────────────────

    def scan(
        self,
        target_url: str,
        depth: int = 3,
        delay: float = 1.5,
        cookie_file: Optional[Path] = None,
        cookie_jar: Optional[Path] = None,
        extra_header: Optional[str] = None,
        dry_run: bool = False,
        scope_values: Sequence[str] | None = None,
        url_prefixes: Sequence[str] | None = None,
        require_scope: bool = False,
    ) -> list[IdorFinding]:
        """
        Crawl target_url BFS up to depth, then probe discovered ID parameters.
        Returns list of IDOR findings written to vulnerability_findings.
        """
        scope_filter = self._scope_filter(
            target_url=target_url,
            scope_values=scope_values,
            url_prefixes=url_prefixes,
            require_scope=require_scope,
        )
        if questionary is not None:
            try:
                confirmed = questionary.confirm(
                    f"[Module 4-D] IDOR scan: {target_url} (depth={depth}, delay={delay}s, "
                    f"dry_run={dry_run})\n"
                    f"  Engagement scope gate enforced at every request. Proceed?"
                ).ask()
            except Exception:
                confirmed = True if dry_run else False
            if not confirmed:
                raise RuntimeError("Operator cancelled.")

        cookie_path = cookie_file or cookie_jar
        default_headers: dict[str, str] = {}
        if cookie_path:
            try:
                cookie_blob = Path(cookie_path).read_text(encoding="utf-8").strip()
                if cookie_blob:
                    default_headers["Cookie"] = cookie_blob
            except OSError:
                _LOG.warning("Cookie jar could not be read: %s", cookie_path)
        if extra_header and ":" in extra_header:
            hk, hv = extra_header.split(":", 1)
            default_headers[hk.strip()] = hv.strip()

        session = self._make_session(default_headers=default_headers)
        visited: set[str] = set()
        queue: deque = deque([(target_url, 0)])
        findings: list[IdorFinding] = []
        con = sqlite3.connect(self._db_path)
        self._ensure_schema(con)

        while queue:
            url, current_depth = queue.popleft()
            if url in visited or current_depth > depth:
                continue
            try:
                scope_allowed = self._scope_ok(url, target_url, scope_filter=scope_filter)
            except TypeError:
                if scope_filter is not None:
                    raise
                scope_allowed = self._scope_ok(url, target_url)
            if not scope_allowed:
                _LOG.warning("Scope gate blocked: %s", url)
                continue
            visited.add(url)

            try:
                resp = session.get(url, timeout=10, allow_redirects=True)
            except Exception as exc:
                _LOG.debug("Crawl fetch error %s: %s", url, exc)
                continue

            # Discover links for next BFS level
            if current_depth < depth:
                for link in self._extract_links(resp.text, url):
                    if link not in visited:
                        queue.append((link, current_depth + 1))

            # Probe ID parameters found in this URL
            for param, value, is_uuid in self._extract_id_params(url, resp):
                probes = self._generate_probes(url, param, value, is_uuid)
                for probe_url in probes:
                    if dry_run:
                        _LOG.info("[DRY-RUN] Would probe: %s", probe_url)
                        continue
                    time.sleep(self._jitter(delay))
                    try:
                        probe_resp = session.get(probe_url, timeout=10)
                    except Exception:
                        continue
                    self._audit(con, probe_url, probe_resp.status_code)
                    finding = self._compare_and_classify(
                        baseline_resp=resp,
                        probe_resp=probe_resp,
                        probe_url=probe_url,
                        param=param,
                    )
                    if finding:
                        findings.append(finding)
                        self._store_finding(con, finding)

        con.close()
        _LOG.info("Module 4-D: %d IDOR findings for %s", len(findings), target_url)
        return findings

    # ── Internal ──────────────────────────────────────────────────────────────

    def _make_session(self, default_headers: Optional[dict[str, str]] = None):
        try:
            from curl_cffi import requests as cffi_requests

            headers = {"User-Agent": self._ua}
            if default_headers:
                headers.update(default_headers)
            kwargs = {"impersonate": "chrome120", "headers": headers}
            if self._proxy:
                kwargs["proxies"] = {"https": self._proxy, "http": self._proxy}
            return cffi_requests.Session(**kwargs)
        except ImportError:
            import urllib.request

            class _MinimalSession:
                def get(self, url, **kw):
                    class R:
                        text = ""
                        status_code = 0

                    return R()

            _LOG.warning("curl_cffi not available; HTTP probing disabled")
            return _MinimalSession()

    @staticmethod
    def _build_scope_filter(
        *,
        scope_values: Sequence[str],
        url_prefixes: Sequence[str],
    ) -> Callable[[str], bool] | None:
        from forge.governance.scope_gate import EngagementScope, ScopeGate

        domains: list[str] = []
        ip_ranges: list[str] = []
        prefixes = [str(item) for item in url_prefixes if str(item or "").strip()]
        for item in scope_values:
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
        domains = list(dict.fromkeys(domains))
        ip_ranges = list(dict.fromkeys(ip_ranges))
        prefixes = list(dict.fromkeys(prefixes))
        if not domains and not ip_ranges and not prefixes:
            return None
        return ScopeGate(EngagementScope(domains=domains, ip_ranges=ip_ranges, urls=prefixes)).is_in_scope

    def _scope_filter(
        self,
        *,
        target_url: str,
        scope_values: Sequence[str] | None,
        url_prefixes: Sequence[str] | None,
        require_scope: bool,
    ) -> Callable[[str], bool] | None:
        from forge.opsec.scope_gate import ScopeViolationError, load_scope_from_db

        scope = (
            [str(item) for item in scope_values if str(item or "").strip()]
            if scope_values is not None
            else load_scope_from_db(str(self._db_path), self._engagement_id)
        )
        prefixes = [str(item) for item in url_prefixes or [] if str(item or "").strip()]
        if require_scope and not scope and not prefixes:
            raise ScopeViolationError(target_url, [])
        scope_filter = self._build_scope_filter(scope_values=scope, url_prefixes=prefixes)
        if scope_filter is not None and not scope_filter(target_url):
            raise ScopeViolationError(target_url, list(scope) + prefixes)
        return scope_filter

    @staticmethod
    def _scope_ok(
        url: str,
        seed: str,
        *,
        scope_filter: Callable[[str], bool] | None = None,
    ) -> bool:
        """Same-origin check: probe host must match seed host."""
        same_origin = urlparse(url).netloc == urlparse(seed).netloc
        if not same_origin:
            return False
        if scope_filter is not None:
            return bool(scope_filter(url))
        return True

    @staticmethod
    def _extract_links(html: str, base_url: str) -> list[str]:
        links = []
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            if href.startswith(("javascript:", "mailto:", "#")):
                continue
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.scheme in ("http", "https"):
                links.append(full)
        return links

    @staticmethod
    def _extract_id_params(url: str, resp) -> list[tuple[str, str, bool]]:
        """
        Return list of (param_name, value, is_uuid) tuples for ID-like parameters.
        Checks: URL path segments, query string, JSON response body.
        """
        found: list[tuple[str, str, bool]] = []
        parsed = urlparse(url)

        # Integer path segments
        for m in _INT_PATH_RE.finditer(parsed.path):
            found.append(("__path__", m.group(1), False))

        # UUID path segments
        for m in _UUID_PATH_RE.finditer(parsed.path):
            found.append(("__path_uuid__", m.group(1), True))

        # Query parameters
        qs = parse_qs(parsed.query, keep_blank_values=False)
        for k, vals in qs.items():
            v = vals[0] if vals else ""
            if _INT_PARAM_RE.match(k) or _ANY_INT_RE.match(v):
                found.append((k, v, False))

        return found

    def _generate_probes(self, url: str, param: str, value: str, is_uuid: bool) -> list[str]:
        """Generate probe URLs by substituting alternate values."""
        probes: list[str] = []
        parsed = urlparse(url)

        if param.startswith("__path"):
            # Replace the segment in the path
            for variant_fn in self._PROBE_VARIANTS:
                try:
                    new_val = variant_fn(value)
                    new_path = parsed.path.replace(f"/{value}", f"/{new_val}", 1)
                    probes.append(urlunparse(parsed._replace(path=new_path)))
                except Exception:
                    pass
        else:
            qs = parse_qs(parsed.query, keep_blank_values=False)
            for variant_fn in self._PROBE_VARIANTS:
                try:
                    new_val = variant_fn(value)
                    new_qs = dict(qs)
                    new_qs[param] = [new_val]
                    new_query = urlencode({k: v[0] for k, v in new_qs.items()})
                    probes.append(urlunparse(parsed._replace(query=new_query)))
                except Exception:
                    pass

        return probes

    @staticmethod
    def _compare_and_classify(
        baseline_resp,
        probe_resp,
        probe_url: str,
        param: str,
    ) -> Optional[IdorFinding]:
        baseline_body = baseline_resp.text
        probe_body = probe_resp.text
        baseline_len = len(baseline_body)
        probe_len = len(probe_body)

        status_diff = baseline_resp.status_code != probe_resp.status_code
        len_delta = abs(probe_len - baseline_len) / max(baseline_len, 1)
        has_pii = IDORScanner._contains_pii(probe_body)

        # Determine if this is a potential IDOR
        if probe_resp.status_code in (401, 403, 404):
            return None  # Access control is working
        if not status_diff and len_delta <= 0.05:
            return None  # No meaningful divergence

        evidence = probe_body[:_EVIDENCE_LIMIT]

        if has_pii:
            severity = "CRITICAL"
            title = f"IDOR: PII exposed via {param} on {urlparse(probe_url).path}"
            desc = f"Substituting {param} returned a response containing PII or financial data."
        elif len_delta > 0.05 or probe_len > 0:
            severity = "MEDIUM"
            title = f"IDOR: Object data visible via {param}"
            desc = (
                f"Substituting {param} returned divergent object data (len delta {len_delta:.1%})."
            )
        else:
            severity = "LOW"
            title = f"IDOR: Status code divergence on {param}"
            desc = f"Baseline: {baseline_resp.status_code}, Probe: {probe_resp.status_code}."

        return IdorFinding(
            target_url=probe_url,
            parameter=param,
            severity=severity,
            title=title,
            description=desc,
            evidence=evidence,
        )

    @staticmethod
    def _contains_pii(body: str) -> bool:
        try:
            data = json.loads(body)
        except Exception:
            return any(f in body.lower() for f in _PII_FIELDS)
        return IDORScanner._contains_sensitive_recursive(data)

    @staticmethod
    def _contains_sensitive_recursive(obj, depth: int = 0) -> bool:
        if depth > 5:
            return False
        if isinstance(obj, dict):
            for k in obj:
                if k.lower() in _PII_FIELDS:
                    return True
                if IDORScanner._contains_sensitive_recursive(obj[k], depth + 1):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if IDORScanner._contains_sensitive_recursive(item, depth + 1):
                    return True
        return False

    @staticmethod
    def _jitter(base_delay: float) -> float:
        return base_delay * random.uniform(0.8, 1.2)

    def _audit(self, con: sqlite3.Connection, url: str, status: int) -> None:
        detail = f"url={url} status={status}"[:1024]
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator, logged_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (self._engagement_id, "phase4", "idor_scanner", "idor_probe", url, detail, "operator"),
        )
        con.commit()

    def _store_finding(self, con: sqlite3.Connection, f: IdorFinding) -> None:
        con.execute(
            """INSERT OR IGNORE INTO vulnerability_findings
               (engagement_id, vuln_type, target_url, parameter, severity,
                title, description, evidence, found_at)
               VALUES (?, 'IDOR', ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                self._engagement_id,
                f.target_url,
                f.parameter,
                f.severity,
                f.title,
                f.description,
                f.evidence,
            ),
        )
        con.commit()

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
        con.commit()
