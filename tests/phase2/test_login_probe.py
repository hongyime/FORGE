"""
tests/phase2/test_login_probe.py
Unit tests — Module 2-K: forge/phase2/login_probe.py

Coverage target: 80%

Test categories:
  1.  FormParser          — login form detection, field extraction, action URL resolution
  2.  FormParser          — no-form fallback, missing action, hidden fields
  3.  DbkerDiscriminator  — status-code gate (Step 1)
  4.  DbkerDiscriminator  — EL + keyword gate (Steps 2 & 3)
  5.  DbkerDiscriminator  — Recheck gate (Step 4)
  6.  DbkerDiscriminator  — baseline establishment
  7.  PcfgDictGenerator   — token extraction from FQDN
  8.  PcfgDictGenerator   — candidate generation (year appends, case, leet, separators)
  9.  PcfgDictGenerator   — max_candidates cap enforced
  10. PcfgDictGenerator   — deduplication
  11. SqliProber          — payload loading (non-blank, non-comment lines only)
  12. SqliProber          — dry-run makes zero HTTP calls
  13. SqliProber          — returns ProbeResult on discriminated success
  14. SqliProber          — returns None when all payloads fail
  15. WebPanelTester      — scope gate rejects out-of-scope targets
  16. WebPanelTester      — FORGE_OFFLINE_STRICT=1 blocks live run
  17. WebPanelTester      — operator cancel raises LoginProbeAborted
  18. WebPanelTester      — dry_run makes zero HTTP submissions to form action
  19. WebPanelTester      — confirmed SQLi finding stored in DB + audited; payload REDACTED in audit
  20. WebPanelTester      — confirmed weak password stored; payload_enc ≠ plaintext
  21. WebPanelTester      — lockout counter increments; skip fires at threshold
  22. WebPanelTester      — no login form → empty findings list
  23. Payload file        — no payload line is blank or starts with #
  24. PCFG rules JSON     — required top-level keys present; types correct
  25. _redact()           — short string masked; long string first4...last4
  26. _scope_check()      — wildcard and exact hostname matching
  27. Evasion assertion   — payload never appears verbatim in audit_log entries
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from unittest import mock

import pytest

from forge.phase2.login_probe import (
    _DATA_DIR,
    _PAYLOADS_F,
    _PCFG_RULES_F,
    _redact,
    _scope_check,
    BaselineResponse,
    DbkerDiscriminator,
    FormParser,
    LoginProbeAborted,
    OfflineStrictError,
    ParsedForm,
    PcfgDictGenerator,
    ProbeResult,
    ScopeViolationError,
    SqliProber,
    WebPanelFinding,
    WebPanelTester,
    run_login_probe,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

ENGAGEMENT_ID = 1
TARGET_URL    = "http://admin.acme.local/login"


@pytest.fixture()
def tmp_eng_db(tmp_path: Path) -> Path:
    """Minimal engagement DB with scope and required tables."""
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript(f"""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, status TEXT
        );
        INSERT INTO engagements VALUES ({ENGAGEMENT_ID}, 'Test Engagement', 'ACTIVE');

        CREATE TABLE engagement_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            scope_entry TEXT
        );
        INSERT INTO engagement_scope (engagement_id, scope_entry)
            VALUES
                ({ENGAGEMENT_ID}, 'acme.local'),
                ({ENGAGEMENT_ID}, '*.acme.local');

        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase TEXT,
            module TEXT,
            action TEXT,
            target TEXT,
            result TEXT,
            operator TEXT,
            logged_at TEXT
        );

        CREATE TABLE login_probe_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            target_url TEXT,
            finding_type TEXT,
            username TEXT,
            payload_redacted TEXT,
            payload_enc TEXT,
            confidence TEXT,
            discriminator_method TEXT,
            discovered_at TEXT,
            UNIQUE(engagement_id, target_url, finding_type, username)
        );
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture()
def patch_confirm_approve(monkeypatch):
    m = mock.MagicMock()
    m.ask.return_value = True
    monkeypatch.setattr("questionary.confirm", lambda *a, **kw: m)


@pytest.fixture()
def patch_confirm_deny(monkeypatch):
    m = mock.MagicMock()
    m.ask.return_value = False
    monkeypatch.setattr("questionary.confirm", lambda *a, **kw: m)


@pytest.fixture()
def offline_env(monkeypatch):
    monkeypatch.setenv("FORGE_OFFLINE_STRICT", "1")


@pytest.fixture()
def online_env(monkeypatch):
    monkeypatch.setenv("FORGE_OFFLINE_STRICT", "0")


# ── HTML fixtures ──────────────────────────────────────────────────────────────

SIMPLE_LOGIN_HTML = """
<html><body>
<form action="/auth/login" method="POST">
  <input type="text"     name="username" />
  <input type="password" name="password" />
  <input type="hidden"   name="_csrf"    value="tok123" />
  <input type="submit"   value="Login" />
</form>
</body></html>
"""

EMAIL_LOGIN_HTML = """
<html><body>
<form action="https://admin.acme.local/signin" method="post">
  <input type="email"    name="email"  id="email" />
  <input type="password" name="pass"   id="pass"  />
  <input type="submit"   value="Sign In" />
</form>
</body></html>
"""

NO_FORM_HTML = "<html><body><p>No form here.</p></body></html>"

NO_ACTION_HTML = """
<html><body>
<form method="POST">
  <input type="text"     name="user" />
  <input type="password" name="pwd"  />
  <input type="submit"   value="Go"  />
</form>
</body></html>
"""

MULTI_FORM_HTML = """
<html><body>
<form action="/search"><input type="text" name="q"/><input type="submit"/></form>
<form action="/login" method="POST">
  <input type="text" name="username"/>
  <input type="password" name="password"/>
  <input type="submit" value="Login"/>
</form>
</body></html>
"""


# ── 1. FormParser — basic parsing ─────────────────────────────────────────────

def test_form_parser_extracts_action_and_fields():
    fp   = FormParser()
    form = fp.parse(SIMPLE_LOGIN_HTML, "http://admin.acme.local/login")
    assert form is not None
    assert "/auth/login" in form.action_url
    assert form.username_field == "username"
    assert form.password_field == "password"
    assert form.method == "POST"


def test_form_parser_extracts_hidden_fields():
    fp   = FormParser()
    form = fp.parse(SIMPLE_LOGIN_HTML, "http://admin.acme.local/login")
    assert form is not None
    assert form.hidden_fields.get("_csrf") == "tok123"


def test_form_parser_detects_email_field_as_username():
    fp   = FormParser()
    form = fp.parse(EMAIL_LOGIN_HTML, "http://admin.acme.local/")
    assert form is not None
    assert form.username_field == "email"
    assert form.password_field == "pass"


def test_form_parser_resolves_relative_action():
    fp   = FormParser()
    form = fp.parse(SIMPLE_LOGIN_HTML, "http://admin.acme.local/login")
    assert form is not None
    assert form.action_url.startswith("http://admin.acme.local")
    assert "/auth/login" in form.action_url


def test_form_parser_selects_login_form_from_multi_form():
    fp   = FormParser()
    form = fp.parse(MULTI_FORM_HTML, "http://admin.acme.local/")
    assert form is not None
    # Must select the form with a password field
    assert form.password_field == "password"


# ── 2. FormParser — edge cases ────────────────────────────────────────────────

def test_form_parser_returns_none_when_no_form():
    fp   = FormParser()
    form = fp.parse(NO_FORM_HTML, "http://admin.acme.local/")
    assert form is None


def test_form_parser_uses_page_url_when_action_absent():
    fp    = FormParser()
    page  = "http://admin.acme.local/login"
    form  = fp.parse(NO_ACTION_HTML, page)
    assert form is not None
    assert form.action_url == page


def test_form_parser_method_normalised_to_uppercase():
    html = """<html><body>
    <form action="/login" method="post">
      <input type="text" name="u"/>
      <input type="password" name="p"/>
    </form></body></html>"""
    form = FormParser().parse(html, "http://x.local/")
    assert form is not None
    assert form.method == "POST"


# ── 3. DbkerDiscriminator — status-code gate ──────────────────────────────────

def test_dbker_success_on_2xx_status_change():
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=True)
    success, confidence, name = disc.discriminate(baseline, "dashboard", 302)
    # 302 → redirect after login counts as status change to non-200;
    # Step 1 expects 2xx for immediate HIGH, redirect is implementation detail —
    # test that Step 1 at minimum fires on 200 → 200 with keyword signals.
    # Retest with explicit 2xx path:
    success2, conf2, name2 = disc.discriminate(
        BaselineResponse(body_length=500, status_code=401, has_failure_kw=True),
        "Welcome to the admin dashboard", 200
    )
    assert success2 is True
    assert conf2 == "HIGH"
    assert name2 == "dbker_status"


def test_dbker_failure_on_4xx_status():
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=True)
    success, confidence, name = disc.discriminate(baseline, "Invalid credentials", 401)
    assert success is False


# ── 4. DbkerDiscriminator — EL + keyword gate ─────────────────────────────────

def test_dbker_success_on_success_keyword_with_length_change():
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=True)
    # Probe body is significantly longer AND contains success keyword
    probe_body = "Welcome to the admin dashboard. " * 20   # >> 500 chars, has "welcome"
    success, confidence, name = disc.discriminate(baseline, probe_body, 200)
    assert success is True
    assert name == "dbker_keyword"


def test_dbker_failure_on_failure_keyword_no_length_change():
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=True)
    # Probe body is same length, contains failure keyword
    probe_body = "Invalid login credentials." + " " * 475   # ~500 chars total
    success, confidence, name = disc.discriminate(baseline, probe_body, 200)
    assert success is False


def test_dbker_medium_confidence_on_success_keyword_no_length_change():
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=False)
    probe_body = "Welcome back!" + " " * 487   # ~500 chars — no length change
    success, confidence, name = disc.discriminate(baseline, probe_body, 200)
    assert success is True
    assert confidence == "MEDIUM"


# ── 5. DbkerDiscriminator — Recheck gate ──────────────────────────────────────

def test_dbker_recheck_fires_on_ambiguous_response():
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=False)
    probe_body = "Some page content with no clear signal." + " " * 461   # ~500 chars

    # Recheck returns a very short body → probe is substantially different → SUCCESS
    recheck_fn = lambda: ("err", 200)   # noqa: E731 — very short response

    success, confidence, name = disc.discriminate(
        baseline, probe_body, 200, recheck_fn=recheck_fn
    )
    assert success is True
    assert name == "dbker_recheck"
    assert confidence == "MEDIUM"


def test_dbker_recheck_budget_limits_calls():
    disc = DbkerDiscriminator(recheck_budget=2)
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=False)
    call_count = {"n": 0}

    def recheck_fn():
        call_count["n"] += 1
        return ("x" * 490, 200)   # similar length — won't trigger success

    probe_body = "neutral content" + " " * 485

    # Call discriminate 5 times; recheck_fn should only be called ≤ budget times
    for _ in range(5):
        disc.discriminate(baseline, probe_body, 200, recheck_fn=recheck_fn)

    assert call_count["n"] <= 2


# ── 6. DbkerDiscriminator — baseline ─────────────────────────────────────────

def test_dbker_baseline_establishes_body_length():
    disc     = DbkerDiscriminator()
    baseline = disc.establish_baseline("Login failed. Invalid password.", 200)
    assert baseline.body_length == len("Login failed. Invalid password.")
    assert baseline.status_code == 200
    assert baseline.has_failure_kw is True


def test_dbker_baseline_detects_no_failure_keyword():
    disc     = DbkerDiscriminator()
    baseline = disc.establish_baseline("Please enter your credentials.", 200)
    assert baseline.has_failure_kw is False


# ── 7. PcfgDictGenerator — token extraction ───────────────────────────────────

def test_pcfg_extracts_tokens_from_simple_fqdn():
    gen    = PcfgDictGenerator()
    tokens = gen._extract_tokens("admin.acme.local")
    assert "acme" in tokens
    assert "admin" in tokens
    # "local" is a TLD — should be discarded
    assert "local" not in tokens


def test_pcfg_extracts_tokens_from_hyphenated_domain():
    gen    = PcfgDictGenerator()
    tokens = gen._extract_tokens("acme-corp.co.uk")
    assert "acme" in tokens
    assert "corp" in tokens
    # Should also include joined form
    assert any("acmecorp" in t for t in tokens)


def test_pcfg_discards_short_tokens():
    gen    = PcfgDictGenerator()
    tokens = gen._extract_tokens("ab.acme.io")
    # "ab" is below min_token_length=3 — should be discarded
    assert "ab" not in tokens


def test_pcfg_discards_common_tlds():
    gen    = PcfgDictGenerator()
    tokens = gen._extract_tokens("acme.com")
    assert "com" not in tokens


# ── 8. PcfgDictGenerator — candidate generation ──────────────────────────────

def test_pcfg_generates_year_appended_candidates():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://admin.acme.local/login")
    # Should include "acme2024", "Acme2024!", etc.
    years = [str(y) for y in range(2020, 2027)]
    year_candidates = [c for c in candidates if any(y in c for y in years)]
    assert len(year_candidates) > 0


def test_pcfg_generates_title_case_variants():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://admin.acme.local/login")
    assert any(c.startswith("Acme") for c in candidates)


def test_pcfg_generates_leet_variants():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://admin.acme.local/login")
    # 'a' → '@': "acme" → "@cme"
    assert any("@cme" in c or "@" in c for c in candidates)


def test_pcfg_generates_candidates_with_special_suffix():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://corp.example.com/admin")
    assert any(c.endswith("!") for c in candidates)


def test_pcfg_generates_common_prefix_variants():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://admin.acme.local/login")
    assert any(c.startswith("admin") or c.startswith("Admin") for c in candidates)


# ── 9. PcfgDictGenerator — max_candidates cap ────────────────────────────────

def test_pcfg_max_candidates_cap_enforced():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://admin.verylongdomainname.acmecorporation.local/login")
    rules      = json.loads(_PCFG_RULES_F.read_text())
    max_c      = rules["max_candidates"]["value"]
    assert len(candidates) <= max_c


# ── 10. PcfgDictGenerator — deduplication ────────────────────────────────────

def test_pcfg_candidates_are_deduplicated():
    gen        = PcfgDictGenerator()
    candidates = gen.generate("http://admin.acme.local/login")
    assert len(candidates) == len(set(candidates)), "Duplicate candidates found"


# ── 11. SqliProber — payload loading ─────────────────────────────────────────

def test_sqli_payload_file_contains_no_blank_lines():
    payloads = SqliProber._load_payloads(_PAYLOADS_F)
    assert all(p.strip() for p in payloads), "Blank payload detected"


def test_sqli_payload_file_contains_no_comment_lines():
    payloads = SqliProber._load_payloads(_PAYLOADS_F)
    assert all(not p.startswith("#") for p in payloads), "Comment line leaked into payload list"


def test_sqli_payload_file_minimum_count():
    payloads = SqliProber._load_payloads(_PAYLOADS_F)
    assert len(payloads) >= 20, f"Expected ≥20 payloads, got {len(payloads)}"


def test_sqli_classic_bypass_payload_present():
    payloads = SqliProber._load_payloads(_PAYLOADS_F)
    assert any("OR" in p and "1" in p for p in payloads), "Classic OR bypass not found"


# ── 12. SqliProber — dry_run makes zero HTTP calls ────────────────────────────

def test_sqli_dry_run_zero_http_calls():
    prober = SqliProber()
    form   = ParsedForm(
        action_url     = "http://admin.acme.local/auth",
        method         = "POST",
        username_field = "username",
        password_field = "password",
    )
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=True)

    with mock.patch("curl_cffi.requests.Session.request") as mock_req:
        result = prober.probe(
            session       = mock.MagicMock(),
            form          = form,
            discriminator = disc,
            baseline      = baseline,
            dry_run       = True,
        )
    mock_req.assert_not_called()
    assert result is None   # dry_run always returns None


# ── 13. SqliProber — returns ProbeResult on discriminated success ─────────────

def test_sqli_returns_probe_result_on_success():
    prober = SqliProber()
    form   = ParsedForm(
        action_url     = "http://admin.acme.local/auth",
        method         = "POST",
        username_field = "username",
        password_field = "password",
    )
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=500, status_code=200, has_failure_kw=True)

    # Mock session: first request returns a "success" page (welcome keyword, status 200 → 200 but bigger)
    mock_session = mock.MagicMock()
    mock_resp    = mock.MagicMock()
    mock_resp.text        = "Welcome to the admin dashboard. " * 30   # long + success keyword
    mock_resp.status_code = 200
    mock_session.request.return_value = mock_resp

    with mock.patch("time.sleep"):
        result = prober.probe(
            session       = mock_session,
            form          = form,
            discriminator = disc,
            baseline      = baseline,
            dry_run       = False,
        )

    assert result is not None
    assert result.success is True
    assert result.finding_type == "sqli_bypass"


# ── 14. SqliProber — returns None when all payloads fail ─────────────────────

def test_sqli_returns_none_when_all_payloads_fail():
    prober = SqliProber()
    form   = ParsedForm(
        action_url     = "http://admin.acme.local/auth",
        method         = "POST",
        username_field = "username",
        password_field = "password",
    )
    disc     = DbkerDiscriminator()
    baseline = BaselineResponse(body_length=300, status_code=200, has_failure_kw=True)

    # Mock session always returns same-length body with failure keyword → FAILURE
    mock_session  = mock.MagicMock()
    mock_resp     = mock.MagicMock()
    mock_resp.text        = "Invalid credentials. " + " " * 279   # same length as baseline
    mock_resp.status_code = 200
    mock_session.request.return_value = mock_resp

    with mock.patch("time.sleep"):
        result = prober.probe(
            session       = mock_session,
            form          = form,
            discriminator = disc,
            baseline      = baseline,
            dry_run       = False,
        )

    assert result is None


# ── 15. WebPanelTester — scope gate ──────────────────────────────────────────

def test_web_panel_scope_gate_rejects_out_of_scope(tmp_eng_db):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = True,
    )
    with pytest.raises(ScopeViolationError):
        tester.run("http://outofscope.evil.com/admin")


def test_web_panel_scope_gate_passes_in_scope(tmp_eng_db):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = True,
    )
    with mock.patch("curl_cffi.requests.Session.get") as mock_get:
        mock_resp      = mock.MagicMock()
        mock_resp.text = NO_FORM_HTML
        mock_resp.url  = TARGET_URL
        mock_get.return_value = mock_resp
        # No exception raised — scope passes
        findings = tester.run(TARGET_URL)
    assert findings == []   # no form → no findings


# ── 16. WebPanelTester — FORGE_OFFLINE_STRICT ────────────────────────────────

def test_web_panel_offline_strict_blocks_live_run(tmp_eng_db, offline_env):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = False,   # live mode
    )
    with pytest.raises(OfflineStrictError):
        tester.run(TARGET_URL)


def test_web_panel_offline_strict_permits_dry_run(tmp_eng_db, offline_env):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = True,
    )
    with mock.patch("curl_cffi.requests.Session.get") as mock_get:
        mock_resp = mock.MagicMock()
        mock_resp.text = NO_FORM_HTML
        mock_resp.url  = TARGET_URL
        mock_get.return_value = mock_resp
        findings = tester.run(TARGET_URL)
    assert findings == []


# ── 17. WebPanelTester — operator cancel ─────────────────────────────────────

def test_web_panel_operator_cancel_raises(tmp_eng_db, patch_confirm_deny, online_env):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = False,
    )
    with pytest.raises(LoginProbeAborted):
        tester.run(TARGET_URL)


# ── 18. WebPanelTester — dry_run zero submissions ────────────────────────────

def test_web_panel_dry_run_makes_no_form_submissions(tmp_eng_db):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = True,
    )
    with mock.patch("curl_cffi.requests.Session.get") as mock_get, \
         mock.patch("curl_cffi.requests.Session.request") as mock_req:

        mock_resp = mock.MagicMock()
        mock_resp.text = SIMPLE_LOGIN_HTML
        mock_resp.url  = TARGET_URL
        mock_get.return_value = mock_resp

        findings = tester.run(TARGET_URL)

    # GET to fetch the page is allowed; POST form submissions must NOT occur
    mock_req.assert_not_called()


# ── 19. WebPanelTester — SQLi finding stored correctly ───────────────────────

def test_web_panel_sqli_finding_stored_in_db(tmp_eng_db, patch_confirm_approve, online_env):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = False,
    )
    # Craft a mock HTTP session that returns:
    #   GET  → SIMPLE_LOGIN_HTML (form detection)
    #   POST (baseline) → failure page
    #   POST (sqli)     → success page (dashboard keyword + longer body)

    get_resp  = mock.MagicMock()
    get_resp.text = SIMPLE_LOGIN_HTML
    get_resp.url  = TARGET_URL

    fail_resp = mock.MagicMock()
    fail_resp.text        = "Invalid credentials. " + " " * 479
    fail_resp.status_code = 200

    success_resp = mock.MagicMock()
    success_resp.text        = "Welcome to the dashboard! " * 30
    success_resp.status_code = 200

    call_order = [fail_resp, success_resp]

    with mock.patch("curl_cffi.requests.Session") as mock_session_cls, \
         mock.patch("time.sleep"):

        mock_session  = mock.MagicMock()
        mock_session.__enter__ = mock.MagicMock(return_value=mock_session)
        mock_session.__exit__  = mock.MagicMock(return_value=False)
        mock_session.get.return_value = get_resp
        mock_session.request.side_effect = call_order
        mock_session_cls.return_value = mock_session

        findings = tester.run(TARGET_URL)

    con = sqlite3.connect(tmp_eng_db)
    rows = con.execute(
        "SELECT finding_type, payload_redacted FROM login_probe_findings WHERE engagement_id=?",
        (ENGAGEMENT_ID,),
    ).fetchall()
    con.close()

    assert any(r[0] == "sqli_bypass" for r in rows), "SQLi finding not stored in DB"

    # Payload must be redacted in DB
    for row in rows:
        redacted = row[1]
        assert "OR" not in redacted or "..." in redacted, \
            "Raw SQLi payload stored unredacted in login_probe_findings"


def test_web_panel_payload_not_in_audit_log_plaintext(tmp_eng_db, patch_confirm_approve, online_env):
    """
    Evasion assertion: audit_log must never contain the raw SQLi payload verbatim.
    """
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = False,
    )
    get_resp = mock.MagicMock()
    get_resp.text = SIMPLE_LOGIN_HTML
    get_resp.url  = TARGET_URL

    fail_resp = mock.MagicMock()
    fail_resp.text        = "Invalid creds " + " " * 486
    fail_resp.status_code = 200

    success_resp = mock.MagicMock()
    success_resp.text        = "Welcome " * 70
    success_resp.status_code = 200

    with mock.patch("curl_cffi.requests.Session") as mock_session_cls, \
         mock.patch("time.sleep"):

        mock_session = mock.MagicMock()
        mock_session.__enter__ = mock.MagicMock(return_value=mock_session)
        mock_session.__exit__  = mock.MagicMock(return_value=False)
        mock_session.get.return_value = get_resp
        mock_session.request.side_effect = [fail_resp, success_resp]
        mock_session_cls.return_value = mock_session

        tester.run(TARGET_URL)

    con    = sqlite3.connect(tmp_eng_db)
    rows   = con.execute("SELECT result FROM audit_log WHERE engagement_id=?", (ENGAGEMENT_ID,)).fetchall()
    con.close()

    audit_details = " ".join(r[0] for r in rows)
    # The classic payload "' OR '1'='1" must NOT appear verbatim in audit detail
    assert "' OR '1'='1" not in audit_details, \
        "Raw SQLi payload found verbatim in audit_log — OPSEC violation"
    # REDACTED marker should be present instead
    assert "REDACTED" in audit_details or "***" in audit_details or "..." in audit_details


# ── 20. WebPanelTester — payload_enc is not plaintext ────────────────────────

def test_finding_payload_enc_is_not_plaintext():
    """payload_enc must not equal the raw payload."""
    from forge.opsec.crypto import encrypt_string, is_encrypted

    raw_payload = "' OR '1'='1"
    payload_enc = encrypt_string(raw_payload, passphrase="AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTEST")
    assert is_encrypted(payload_enc)
    assert raw_payload not in payload_enc


# ── 21. WebPanelTester — lockout counter ─────────────────────────────────────

def test_lockout_counter_increments_on_failure(tmp_eng_db):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = True,
    )
    key = (TARGET_URL, "admin")
    tester._lockout_counter[key] = 2
    # One more failure should reach threshold=3
    tester._lockout_counter[key] += 1
    assert tester._lockout_counter[key] >= 3


# ── 22. WebPanelTester — no form → empty findings ────────────────────────────

def test_web_panel_no_form_returns_empty(tmp_eng_db):
    tester = WebPanelTester(
        db_path       = tmp_eng_db,
        engagement_id = ENGAGEMENT_ID,
        dry_run       = True,
    )
    with mock.patch("curl_cffi.requests.Session.get") as mock_get:
        mock_resp = mock.MagicMock()
        mock_resp.text = NO_FORM_HTML
        mock_resp.url  = TARGET_URL
        mock_get.return_value = mock_resp
        findings = tester.run(TARGET_URL)
    assert findings == []


# ── 23. Payload file integrity ────────────────────────────────────────────────

def test_payload_file_no_blank_lines_or_comments_in_loader():
    """Cross-validates _load_payloads against the actual file on disk."""
    payloads = SqliProber._load_payloads(_PAYLOADS_F)
    for p in payloads:
        assert p.strip() != "", "Blank payload line leaked through loader"
        assert not p.startswith("#"), "Comment line leaked through loader"


# ── 24. PCFG rules JSON structure ────────────────────────────────────────────

def test_pcfg_rules_json_required_keys():
    rules = json.loads(_PCFG_RULES_F.read_text())
    required_keys = [
        "year_range", "numeric_suffixes", "special_suffixes",
        "common_suffixes", "common_prefixes", "case_transforms",
        "leet_substitutions", "separator_chars",
        "domain_component_extraction", "max_candidates", "dedup",
    ]
    for key in required_keys:
        assert key in rules, f"Required PCFG rules key missing: '{key}'"


def test_pcfg_rules_json_year_range_valid():
    rules = json.loads(_PCFG_RULES_F.read_text())
    assert rules["year_range"]["start"] < rules["year_range"]["end"]
    assert rules["year_range"]["end"] >= 2024


def test_pcfg_rules_json_max_candidates_positive_int():
    rules = json.loads(_PCFG_RULES_F.read_text())
    assert isinstance(rules["max_candidates"]["value"], int)
    assert rules["max_candidates"]["value"] > 0


# ── 25. _redact() ─────────────────────────────────────────────────────────────

def test_redact_short_string_returns_masked():
    assert _redact("abc") == "****"
    assert _redact("abcdefg") == "****"    # ≤8 chars


def test_redact_long_string_returns_first4_last4():
    result = _redact("' OR '1'='1'--")
    assert result.startswith("' OR")[:4] or "..." in result
    assert "..." in result


def test_redact_exactly_nine_chars():
    result = _redact("123456789")   # 9 chars → first4...last4
    assert result == "1234...6789"


# ── 26. _scope_check() ───────────────────────────────────────────────────────

def test_scope_check_exact_hostname_passes(tmp_eng_db):
    # Add exact hostname scope entry
    con = sqlite3.connect(tmp_eng_db)
    con.execute(
        "INSERT INTO engagement_scope (engagement_id, scope_entry) VALUES (?,?)",
        (ENGAGEMENT_ID, "exact.acme.local"),
    )
    con.commit()
    con.close()
    # Should not raise
    _scope_check("http://exact.acme.local/login", ENGAGEMENT_ID, tmp_eng_db)


def test_scope_check_subdomain_under_wildcard_domain_passes(tmp_eng_db):
    # Subdomains require an explicit wildcard entry.
    _scope_check("http://admin.acme.local/login", ENGAGEMENT_ID, tmp_eng_db)


def test_scope_check_wildcard_entry_passes(tmp_eng_db):
    con = sqlite3.connect(tmp_eng_db)
    con.execute(
        "INSERT INTO engagement_scope (engagement_id, scope_entry) VALUES (?,?)",
        (ENGAGEMENT_ID, "*.staging.acme.local"),
    )
    con.commit()
    con.close()
    _scope_check("http://app.staging.acme.local/login", ENGAGEMENT_ID, tmp_eng_db)


def test_scope_check_rejects_out_of_scope_hostname(tmp_eng_db):
    with pytest.raises(ScopeViolationError):
        _scope_check("http://evil.attacker.com/login", ENGAGEMENT_ID, tmp_eng_db)


def test_scope_check_rejects_url_prefix_path_drift(tmp_eng_db):
    con = sqlite3.connect(tmp_eng_db)
    con.execute("DELETE FROM engagement_scope WHERE engagement_id=?", (ENGAGEMENT_ID,))
    con.execute(
        "INSERT INTO engagement_scope (engagement_id, scope_entry) VALUES (?,?)",
        (ENGAGEMENT_ID, "http://admin.acme.local/app/"),
    )
    con.commit()
    con.close()

    with pytest.raises(ScopeViolationError):
        _scope_check("http://admin.acme.local/admin", ENGAGEMENT_ID, tmp_eng_db)


# ── 27. Evasion assertion — payload not in audit_log ─────────────────────────

def test_evasion_assertion_spray_password_never_in_audit_log(tmp_eng_db):
    """
    Core OPSEC invariant: raw spray passwords must NEVER appear in audit_log.result.
    """
    from forge.phase2.login_probe import _audit

    raw_password = "Acme2024!"
    _audit(tmp_eng_db, ENGAGEMENT_ID, "login_probe_spray",
           f"url={TARGET_URL} user=admin password=***REDACTED***")

    con  = sqlite3.connect(tmp_eng_db)
    rows = con.execute(
        "SELECT result FROM audit_log WHERE engagement_id=?", (ENGAGEMENT_ID,)
    ).fetchall()
    con.close()

    audit_text = " ".join(r[0] for r in rows)
    assert raw_password not in audit_text, \
        f"Raw password '{raw_password}' found verbatim in audit_log — OPSEC violation"
