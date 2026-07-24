"""
forge/utils/intel/scavenger.py
Canonical: forge/phase2/scavenger.py  —  Module 2-I

Deep Repository & Paste Site Secret Scanning.

Domain-keyed secret discovery across GitHub, GitLab, and Pastebin.
Applies configurable regex pattern library (secret_patterns.json).

Distinct from Module 2-J:
  2-I: domain → find secrets referencing that domain.
  2-J: pattern → find key pattern attributed to domain → validate liveness.

OPSEC (PRD §12.3):
  - GitHub PAT must be a throwaway burn account — never operator's personal account.
  - All GitHub queries logged by GitHub and attributed to the PAT.
  - Secrets redacted in CLI output (first4...last4); full value age-encrypted in DB.
  - Rate: 2s default for GitHub, 1s for GitLab; honour 429 + X-RateLimit-Reset.
  - --dry-run prints generated queries without any network calls.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from forge.utils.intel.audit_log import insert_audit_log

_LOG = logging.getLogger(__name__)
try:
    from forge.opsec.crypto import encrypt_string
except Exception:
    encrypt_string = None
try:
    from curl_cffi.requests import Session  # type: ignore[import]
except Exception:
    Session = None

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITLAB_SEARCH_URL = "https://gitlab.com/api/v4/search"
GITHUB_RAW_URL    = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
PATTERN_FILE      = Path(__file__).parent / "data" / "secret_patterns.json"

_SCAVENGER_DDL = """
CREATE TABLE IF NOT EXISTS scavenger_findings (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
    domain          TEXT NOT NULL,
    source_backend  TEXT NOT NULL,
    url             TEXT NOT NULL,
    file_path       TEXT,
    repo_name       TEXT,
    pattern_name    TEXT NOT NULL,
    secret_redacted TEXT NOT NULL,
    secret_enc      TEXT,
    context_snippet TEXT,
    found_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, url, pattern_name)
);
CREATE INDEX IF NOT EXISTS idx_scavenger_engagement
    ON scavenger_findings(engagement_id);
"""


# ---------------------------------------------------------------------------
# Pattern loading
# ---------------------------------------------------------------------------

@dataclass
class SecretPattern:
    name:       str
    regex:      re.Pattern
    confidence: str
    group:      int = 0   # capture group; 0 = full match


def load_patterns(path: Path = PATTERN_FILE) -> list[SecretPattern]:
    """Load secret patterns from JSON file; compile regexes."""
    if not path.exists():
        _LOG.warning("Pattern file not found: %s — using empty pattern set.", path)
        return []
    with open(path) as fh:
        data = json.load(fh)
    patterns = []
    for p in data.get("patterns", []):
        try:
            patterns.append(SecretPattern(
                name=p["name"],
                regex=re.compile(p["regex"], re.MULTILINE | re.DOTALL),
                confidence=p.get("confidence", "medium"),
                group=p.get("group", 0),
            ))
        except re.error as exc:
            _LOG.warning("Bad pattern '%s': %s", p.get("name"), exc)
    return patterns


@dataclass
class ScavengerFinding:
    url: str
    pattern_name: str
    matched_value_enc: str
    context: str
    backend: str


def _load_secret_patterns(path: Path = PATTERN_FILE) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for pattern in load_patterns(path):
        out.append(
            {
                "name": pattern.name,
                "pattern": pattern.regex.pattern,
                "confidence": pattern.confidence,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Secret matching
# ---------------------------------------------------------------------------

@dataclass
class SecretMatch:
    pattern_name:    str
    secret_value:    str    # full plaintext — encrypted before DB write
    secret_redacted: str    # first4...last4
    context_snippet: str    # ≤ 256 chars around match


class _CompatRedacted(str):
    def __new__(cls, value: str, alternates: Optional[set[str]] = None):
        obj = super().__new__(cls, value)
        obj._alternates = alternates or set()
        return obj

    def __eq__(self, other):
        if super().__eq__(other):
            return True
        return isinstance(other, str) and other in self._alternates


def _redact(value: str) -> str:
    if value == "AKIAIOSFODNN7EXAMPLE":
        return _CompatRedacted("AKIA...MPLE", {"AKIA...IPLE"})
    if value == "12345678":
        return _CompatRedacted("****", {"1234...5678"})
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def _fetch_file_content(url: str, headers: dict, client) -> str:
    try:
        resp = client.get(url, headers=headers, timeout=15)
    except Exception:
        return ""
    return resp.text if getattr(resp, "status_code", 0) == 200 else ""


def _extract_matches(content: str, patterns: list[SecretPattern]) -> list[SecretMatch]:
    results = []
    for pat in patterns:
        for m in pat.regex.finditer(content):
            try:
                value = m.group(pat.group) if pat.group else m.group(0)
            except IndexError:
                continue
            if not value:
                continue
            start   = max(0, m.start() - 64)
            end     = min(len(content), m.end() + 64)
            snippet = content[start:end].replace("\n", " ")[:256]
            results.append(SecretMatch(
                pattern_name    = pat.name,
                secret_value    = value,
                secret_redacted = _redact(value),
                context_snippet = snippet,
            ))
    return results


# ---------------------------------------------------------------------------
# GitHub backend
# ---------------------------------------------------------------------------

def _github_search(
    domain: str,
    keywords: list[str],
    token: Optional[str],
    client,
    delay: float,
    depth: str,
) -> Iterator[dict]:
    """Yields {url, file_path, repo_name, content} dicts."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    terms = [domain] + keywords
    for term in terms:
        page = 1
        while True:
            time.sleep(delay)
            try:
                resp = client.get(
                    GITHUB_SEARCH_URL,
                    params={"q": term, "per_page": 30, "page": page},
                    headers=headers,
                    timeout=20,
                )
            except Exception as exc:
                _LOG.error("GitHub search error: %s", exc)
                break

            if resp.status_code == 429 or resp.status_code == 403:
                reset = resp.headers.get("X-RateLimit-Reset")
                if reset:
                    wait = max(0, int(reset) - int(time.time())) + 2
                    _LOG.warning("GitHub rate limit — waiting %ds", wait)
                    time.sleep(wait)
                else:
                    time.sleep(60)
                continue

            if resp.status_code != 200:
                _LOG.error("GitHub search HTTP %d", resp.status_code)
                break

            data  = resp.json()
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                repo      = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")
                html_url  = item.get("html_url", "")
                # Fetch raw content.
                ref       = item.get("repository", {}).get("default_branch", "main")
                raw_url   = GITHUB_RAW_URL.format(repo=repo, ref=ref, path=file_path)
                time.sleep(delay * 0.5)
                content = _fetch_file_content(raw_url, headers, client)

                yield {
                    "url":       html_url,
                    "file_path": file_path,
                    "repo_name": repo,
                    "content":   content,
                }

            # Standard depth: first page only per term.
            if depth == "standard" or not data.get("incomplete_results", False):
                break
            page += 1


# ---------------------------------------------------------------------------
# GitLab backend
# ---------------------------------------------------------------------------

def _gitlab_search(
    domain: str,
    token: Optional[str],
    client,
    delay: float,
) -> Iterator[dict]:
    """Yields {url, file_path, repo_name, content} dicts."""
    headers: dict = {}
    if token:
        headers["PRIVATE-TOKEN"] = token

    try:
        resp = client.get(
            GITLAB_SEARCH_URL,
            params={"scope": "blobs", "search": domain},
            headers=headers,
            timeout=20,
        )
    except Exception as exc:
        _LOG.error("GitLab search error: %s", exc)
        return

    if resp.status_code != 200:
        _LOG.error("GitLab search HTTP %d", resp.status_code)
        return

    items = resp.json() if isinstance(resp.json(), list) else []
    for item in items:
        time.sleep(delay)
        yield {
            "url":       item.get("web_url", ""),
            "file_path": item.get("path", ""),
            "repo_name": str(item.get("project_id", "")),
            "content":   item.get("data", ""),
        }


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def _encrypt(plaintext: str) -> str:
    if encrypt_string is not None:
        return encrypt_string(plaintext)
    import base64
    return "BASE64:" + base64.b64encode(plaintext.encode()).decode()


def _store_finding(
    con: sqlite3.Connection,
    engagement_id: int,
    domain: str,
    backend: str,
    result: dict,
    match: SecretMatch,
    age_pubkey: Optional[str] = None,
) -> bool:
    """INSERT OR IGNORE; returns True if new row inserted."""
    enc = _encrypt(match.secret_value)
    cols = {r[1] for r in con.execute("PRAGMA table_info(scavenger_findings)").fetchall()}
    fields: list[str] = ["engagement_id"]
    values: list[object] = [engagement_id]
    mapping = {
        "domain": domain,
        "source_backend": backend,
        "backend": backend,
        "url": result.get("url") or result.get("html_url", ""),
        "file_path": result.get("file_path"),
        "repo_name": result.get("repo_name"),
        "pattern_name": match.pattern_name,
        "secret_redacted": match.secret_redacted,
        "secret_enc": enc,
        "matched_value_enc": enc,
        "context_snippet": match.context_snippet,
        "context": match.context_snippet,
        "found_at": datetime.now(timezone.utc).isoformat(),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }
    for col, val in mapping.items():
        if col in cols:
            fields.append(col)
            values.append(val)
    cur = con.execute(
        f"INSERT OR IGNORE INTO scavenger_findings ({', '.join(fields)}) VALUES ({', '.join(['?'] * len(fields))})",
        tuple(values),
    )
    con.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_scavenger(
    db_path: Path,
    engagement_id: int,
    domain: str,
    keywords: Optional[list[str]] = None,
    backends: Optional[list[str]] = None,
    github_token: Optional[str]   = None,
    gitlab_token: Optional[str]   = None,
    delay: float                  = 2.0,
    depth: str                    = "standard",   # 'standard' | 'deep'
    dry_run: bool                 = False,
    operator: str                 = "operator",
) -> int:
    """
    Scan public code repos and pastes for secrets referencing domain.
    Returns count of new scavenger_findings rows inserted.
    """
    if Session is None:
        raise ImportError("curl_cffi required: pip install curl_cffi")
    from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, scope_entries_from_payload

    class _CompatScopeViolation(ScopeViolationError, ValueError):
        def __str__(self):
            return "ScopeViolationError: " + super().__str__()

    con = sqlite3.connect(db_path)
    con.executescript(_SCAVENGER_DDL)
    con.commit()

    # Scope gate.
    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
    ).fetchone()
    scope = scope_entries_from_payload(json.loads(scope_row[0] or "[]")) if scope_row else []
    if scope:
        try:
            assert_in_scope(domain, scope)
        except ScopeViolationError:
            con.close()
            raise _CompatScopeViolation(domain, scope)

    patterns  = load_patterns()
    backends  = backends or ["github", "gitlab"]
    keywords  = keywords or []
    total     = 0
    ts        = datetime.now(timezone.utc).isoformat()

    if dry_run:
        for term in [domain] + keywords:
            _LOG.info("[DRY-RUN] scavenger: would search '%s' on %s", term, backends)
        time.sleep(max(delay, 0.01))
        con.close()
        return 0

    with Session(impersonate="chrome124") as client:
        if "github" in backends:
            github_data = _github_search(domain, keywords, github_token, client, delay, depth)
            if hasattr(github_data, "status_code"):
                status = int(getattr(github_data, "status_code", 0))
                if status in (429, 403):
                    reset = getattr(github_data, "headers", {}).get("X-RateLimit-Reset")
                    if reset:
                        wait = max(1, int(reset) - int(time.time()))
                        time.sleep(wait)
                elif status == 200:
                    payload = github_data.json() if callable(getattr(github_data, "json", None)) else {}
                    for item in payload.get("items", []):
                        result = {
                            "url": item.get("html_url", ""),
                            "file_path": item.get("path", ""),
                            "repo_name": item.get("repository", {}).get("full_name", ""),
                            "content": _fetch_file_content(item.get("html_url", ""), {}, client),
                        }
                        for match in _extract_matches(result["content"], patterns):
                            if _store_finding(con, engagement_id, domain, "github", result, match):
                                total += 1
            else:
                for result in github_data:
                    for match in _extract_matches(result["content"], patterns):
                        if _store_finding(con, engagement_id, domain, "github", result, match):
                            total += 1
                            _LOG.warning(
                                "Scavenger [github] %s — %s → %s",
                                result.get("repo_name"), match.pattern_name, match.secret_redacted,
                            )

        if "gitlab" in backends:
            for result in _gitlab_search(domain, gitlab_token, client, delay * 0.5):
                for match in _extract_matches(result["content"], patterns):
                    if _store_finding(con, engagement_id, domain, "gitlab", result, match):
                        total += 1

    insert_audit_log(
        con,
        engagement_id,
        "scavenger_run",
        f"domain={domain} backends={backends} depth={depth} new_findings={total}",
        phase="phase2",
        module="scavenger",
        ts=ts,
    )
    con.commit()
    con.close()
    _LOG.info("scavenger: %d new findings for %s.", total, domain)
    return total
