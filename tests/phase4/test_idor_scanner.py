"""
tests/phase4/test_idor_scanner.py
Unit + integration tests for param_probe.py (Module 4-D).
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.phase4.param_probe import (
    IDORScanner,
    IdorFinding,
    _EVIDENCE_LIMIT,
    _PII_FIELDS,
)


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            vuln_type TEXT NOT NULL, target_url TEXT NOT NULL,
            parameter TEXT, severity TEXT NOT NULL,
            title TEXT NOT NULL, description TEXT, evidence TEXT,
            cvss_score REAL,
            found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, vuln_type, target_url, parameter)
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, phase TEXT, module TEXT, action TEXT,
            target TEXT, result TEXT, operator TEXT, logged_at TEXT
        );
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture
def scanner(tmp_db: Path) -> IDORScanner:
    return IDORScanner(db_path=tmp_db, engagement_id=1)


# ══════════════════════════════════════════════════════════════════════════════
# Static helper tests
# ══════════════════════════════════════════════════════════════════════════════


class TestExtractIdParams:
    def _mock_resp(self, text=""):
        r = MagicMock()
        r.text = text
        r.status_code = 200
        return r

    def test_integer_query_param(self, scanner: IDORScanner):
        url = "https://app.example.com/api/item?id=1234"
        params = scanner._extract_id_params(url, self._mock_resp())
        names = [p[0] for p in params]
        assert "id" in names

    def test_integer_path_segment(self, scanner: IDORScanner):
        url = "https://app.example.com/users/9876/profile"
        params = scanner._extract_id_params(url, self._mock_resp())
        names = [p[0] for p in params]
        assert "__path__" in names

    def test_uuid_path_segment(self, scanner: IDORScanner):
        url = "https://app.example.com/docs/550e8400-e29b-41d4-a716-446655440000"
        params = scanner._extract_id_params(url, self._mock_resp())
        names = [p[0] for p in params]
        assert "__path_uuid__" in names

    def test_no_id_params_in_clean_url(self, scanner: IDORScanner):
        url = "https://app.example.com/about"
        params = scanner._extract_id_params(url, self._mock_resp())
        assert params == []

    def test_user_id_query_param_detected(self, scanner: IDORScanner):
        url = "https://app.example.com/profile?user_id=42"
        params = scanner._extract_id_params(url, self._mock_resp())
        names = [p[0] for p in params]
        assert "user_id" in names


class TestGenerateProbes:
    def test_probes_count(self, scanner: IDORScanner):
        probes = scanner._generate_probes("https://app.example.com/api?id=100", "id", "100", False)
        assert len(probes) >= 4

    def test_probes_include_plus_minus_1(self, scanner: IDORScanner):
        probes = scanner._generate_probes("https://app.example.com/api?id=100", "id", "100", False)
        values = []
        for p in probes:
            from urllib.parse import urlparse, parse_qs

            qs = parse_qs(urlparse(p).query)
            if "id" in qs:
                values.append(qs["id"][0])
        assert "99" in values
        assert "101" in values

    def test_probes_include_plus_100_and_sentinels(self, scanner: IDORScanner):
        probes = scanner._generate_probes(
            "https://app.example.com/api?id=1234", "id", "1234", False
        )
        values = []
        for p in probes:
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(p).query)
            values.append(qs.get("id", [""])[0])
        assert "1334" in values
        assert "0" in values
        assert "99999" in values

    def test_probes_include_uuid(self, scanner: IDORScanner):
        probes = scanner._generate_probes("https://app.example.com/api?id=100", "id", "100", True)
        uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-", re.I)
        assert any(uuid_re.search(str(p)) for p in probes)

    def test_path_segment_probes(self, scanner: IDORScanner):
        probes = scanner._generate_probes(
            "https://app.example.com/users/42/profile", "__path__", "42", False
        )
        assert any("/41/" in p or "/43/" in p for p in probes)


class TestCompareAndClassify:
    def _resp(self, status, text):
        r = MagicMock()
        r.status_code = status
        r.text = text
        return r

    def test_no_finding_on_403(self, scanner: IDORScanner):
        base = self._resp(200, '{"id":1,"name":"Alice"}')
        probe = self._resp(403, '{"error":"Forbidden"}')
        finding = scanner._compare_and_classify(base, probe, "https://x/api?id=2", "id")
        assert finding is None

    def test_no_finding_on_same_response(self, scanner: IDORScanner):
        body = '{"id":1,"status":"ok"}'
        base = self._resp(200, body)
        probe = self._resp(200, body)
        finding = scanner._compare_and_classify(base, probe, "https://x/api?id=2", "id")
        assert finding is None

    def test_critical_on_pii_fields(self, scanner: IDORScanner):
        base = self._resp(200, "{}")
        probe = self._resp(200, '{"email":"user@corp.com","phone":"555-1234"}')
        finding = scanner._compare_and_classify(base, probe, "https://x/api?id=2", "id")
        assert finding is not None
        assert finding.severity == "CRITICAL"

    def test_medium_on_non_pii_data_divergence(self, scanner: IDORScanner):
        base = self._resp(200, '{"id":1,"role":"user"}')
        probe = self._resp(
            200, '{"id":2,"role":"admin","secret_internal_note":"pay raise scheduled"}'
        )
        finding = scanner._compare_and_classify(base, probe, "https://x/api?id=2", "id")
        assert finding is not None
        assert finding.severity in ("MEDIUM", "CRITICAL")

    def test_evidence_truncated_to_512(self, scanner: IDORScanner):
        long_body = "X" * 1000
        base = self._resp(200, "")
        probe = self._resp(200, long_body)
        finding = scanner._compare_and_classify(base, probe, "https://x/api?id=2", "id")
        if finding:
            assert len(finding.evidence) <= _EVIDENCE_LIMIT


class TestContainsPII:
    def test_detects_email_key(self):
        assert IDORScanner._contains_pii('{"email":"u@c.com","id":1}')

    def test_detects_nested_pii(self):
        payload = '{"user":{"profile":{"ssn":"123-45-6789"}}}'
        assert IDORScanner._contains_pii(payload)

    def test_clean_json_no_pii(self):
        assert not IDORScanner._contains_pii('{"id":1,"status":"active"}')

    def test_non_json_string_fallback(self):
        assert IDORScanner._contains_pii("user email: someone@example.com returned")


# ══════════════════════════════════════════════════════════════════════════════
# Integration: dry-run makes zero probe requests
# ══════════════════════════════════════════════════════════════════════════════


class TestDryRun:
    def test_dry_run_no_probe_requests(self, scanner: IDORScanner):
        mock_session = MagicMock()
        crawl_resp = MagicMock()
        crawl_resp.text = "<html><body>ok</body></html>"
        crawl_resp.status_code = 200
        mock_session.get.return_value = crawl_resp

        with (
            patch.object(scanner, "_make_session", return_value=mock_session),
            patch.object(scanner, "_scope_ok", return_value=True),
            patch("forge.phase4.param_probe.questionary", create=True) as mock_q,
        ):
            mock_q.confirm.return_value.ask.return_value = True
            scanner.scan(
                target_url="https://app.example.com/api?id=1",
                depth=0,
                delay=0,
                dry_run=True,
            )

        assert mock_session.get.call_count == 1
        called_url = mock_session.get.call_args_list[0].args[0]
        assert called_url == "https://app.example.com/api?id=1"


# ══════════════════════════════════════════════════════════════════════════════
# Integration: finding stored in DB
# ══════════════════════════════════════════════════════════════════════════════


class TestFindingStorage:
    def test_finding_written_to_db(self, scanner: IDORScanner, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        finding = IdorFinding(
            target_url="https://app.example.com/api?id=2",
            parameter="id",
            severity="HIGH",
            title="IDOR test",
            description="Test description",
            evidence='{"id":2}',
        )
        scanner._store_finding(con, finding)
        row = con.execute("SELECT * FROM vulnerability_findings WHERE engagement_id=1").fetchone()
        con.close()
        assert row is not None
        assert row[2] == "IDOR"  # vuln_type

    def test_finding_deduped(self, scanner: IDORScanner, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        finding = IdorFinding(
            target_url="https://app.example.com/api?id=2",
            parameter="id",
            severity="HIGH",
            title="Dup",
            description="",
            evidence="",
        )
        scanner._store_finding(con, finding)
        scanner._store_finding(con, finding)  # second insert should be ignored
        count = con.execute("SELECT COUNT(*) FROM vulnerability_findings").fetchone()[0]
        con.close()
        assert count == 1


# ══════════════════════════════════════════════════════════════════════════════
# Scope gate
# ══════════════════════════════════════════════════════════════════════════════


class TestScopeGate:
    def test_off_domain_url_rejected(self, scanner: IDORScanner):
        seed = "https://app.example.com"
        foreign = "https://evil.attacker.com/api?id=1"
        with patch("forge.opsec.scope_gate.assert_in_scope", side_effect=RuntimeError("out")):
            assert not scanner._scope_ok(foreign, seed)

    def test_same_domain_allowed(self, scanner: IDORScanner):
        seed = "https://app.example.com"
        url = "https://app.example.com/api/v2?id=5"
        assert scanner._scope_ok(url, seed)

    def test_off_domain_link_not_fetched_during_scan(self, scanner: IDORScanner):
        mock_session = MagicMock()
        seed_resp = MagicMock()
        seed_resp.status_code = 200
        seed_resp.text = '<a href="https://evil.attacker.com/api?id=9">x</a>'

        def _scope(url: str, seed: str) -> bool:
            return "evil.attacker.com" not in url

        mock_session.get.return_value = seed_resp

        with (
            patch.object(scanner, "_make_session", return_value=mock_session),
            patch.object(scanner, "_scope_ok", side_effect=_scope),
            patch("forge.phase4.param_probe.questionary", create=True) as mock_q,
        ):
            mock_q.confirm.return_value.ask.return_value = True
            scanner.scan("https://app.example.com", depth=1, delay=0.0, dry_run=True)

        fetched = [args.args[0] for args in mock_session.get.call_args_list]
        assert all("evil.attacker.com" not in u for u in fetched)
