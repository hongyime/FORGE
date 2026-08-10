"""
tests/phase4/test_supabase_scanner.py
Unit tests for api_policy_check.py (Module 4-G).

All HTTP calls are mocked. No live Supabase connections.
"""

from __future__ import annotations

import json
import sqlite3
from base64 import urlsafe_b64encode
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from forge.phase4.api_policy_check import (
    SupabaseScanner,
    SupabaseFinding,
    _SENSITIVE_COLS,
)


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    SupabaseScanner._ensure_schema(con)
    con.commit()
    con.close()
    return db


@pytest.fixture
def scanner(tmp_db: Path) -> SupabaseScanner:
    return SupabaseScanner(db_path=tmp_db, engagement_id=1)


def _mock_resp(status: int, body: str | dict) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = json.dumps(body) if isinstance(body, (dict, list)) else body
    r.json = MagicMock(return_value=body)
    return r


def _jwt_for_project(project_ref: str, role: str = "anon") -> str:
    header = urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = (
        urlsafe_b64encode(
            json.dumps(
                {
                    "role": role,
                    "iss": f"https://{project_ref}.supabase.co/auth/v1",
                    "ref": project_ref,
                }
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    return f"{header}.{payload}.sig"


# ══════════════════════════════════════════════════════════════════════════════
# Static helpers
# ══════════════════════════════════════════════════════════════════════════════


class TestSensitiveColumnDetection:
    def test_email_key_detected(self):
        assert SupabaseScanner._has_sensitive([{"email": "u@c.com", "id": 1}])

    def test_password_key_detected(self):
        assert SupabaseScanner._has_sensitive([{"password": "hash", "role": "admin"}])

    def test_token_detected(self):
        assert SupabaseScanner._has_sensitive([{"token": "jwt..."}])

    def test_ssn_detected(self):
        assert SupabaseScanner._has_sensitive([{"ssn": "123-45-6789"}])

    def test_card_detected(self):
        assert SupabaseScanner._has_sensitive([{"card": "4111111111111111"}])

    def test_clean_data_no_sensitive(self):
        assert not SupabaseScanner._has_sensitive([{"id": 1, "name": "Alice", "role": "user"}])

    def test_empty_list_no_sensitive(self):
        assert not SupabaseScanner._has_sensitive([])

    def test_dict_input(self):
        assert SupabaseScanner._has_sensitive({"email": "x@y.com"})

    def test_all_known_sensitive_cols_flagged(self):
        for col in _SENSITIVE_COLS:
            assert SupabaseScanner._has_sensitive([{col: "value"}]), f"Column {col} not detected"


class TestAssessSeverity:
    def test_critical_when_data_and_sensitive(self):
        assert SupabaseScanner._assess_severity(has_data=True, has_sensitive=True) == "CRITICAL"

    def test_high_when_data_no_sensitive(self):
        assert SupabaseScanner._assess_severity(has_data=True, has_sensitive=False) == "HIGH"

    def test_none_when_no_data(self):
        assert SupabaseScanner._assess_severity(has_data=False, has_sensitive=False) is None

    def test_none_when_no_data_even_if_sensitive(self):
        # Can't be sensitive if no data returned
        assert SupabaseScanner._assess_severity(has_data=False, has_sensitive=True) is None


# ══════════════════════════════════════════════════════════════════════════════
# Severity matrix (PRD §9.17.3)
# ══════════════════════════════════════════════════════════════════════════════


class TestSeverityMatrix:
    def _make_finding(
        self, scanner, base, table, anon_key, session, dry_run, con, data_body, status=200
    ):
        mock_resp = _mock_resp(status, data_body)
        session.get = MagicMock(return_value=mock_resp)
        return scanner._anon_read_probe(base, table, anon_key, session, dry_run, con)

    def test_critical_sensitive_data(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        con = sqlite3.connect(tmp_db)
        finding = self._make_finding(
            scanner,
            "https://xyz.supabase.co",
            "users",
            "key",
            session,
            False,
            con,
            data_body=[{"id": 1, "email": "alice@corp.com"}],
        )
        con.close()
        assert finding is not None
        assert finding.severity == "CRITICAL"

    def test_high_non_sensitive_data(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        con = sqlite3.connect(tmp_db)
        finding = self._make_finding(
            scanner,
            "https://xyz.supabase.co",
            "products",
            "key",
            session,
            False,
            con,
            data_body=[{"id": 1, "name": "Widget", "price": 9.99}],
        )
        con.close()
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_no_finding_on_403(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        session.get = MagicMock(return_value=_mock_resp(403, {"message": "Forbidden"}))
        con = sqlite3.connect(tmp_db)
        finding = scanner._anon_read_probe(
            "https://xyz.supabase.co", "secrets", "key", session, False, con
        )
        con.close()
        assert finding is None

    def test_no_finding_on_401(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        session.get = MagicMock(return_value=_mock_resp(401, {"message": "Unauthorized"}))
        con = sqlite3.connect(tmp_db)
        finding = scanner._anon_read_probe(
            "https://xyz.supabase.co", "secrets", "key", session, False, con
        )
        con.close()
        assert finding is None

    def test_write_201_creates_high_finding(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        session.post = MagicMock(return_value=_mock_resp(201, {"id": 999}))
        con = sqlite3.connect(tmp_db)
        with patch("forge.phase4.api_policy_check.questionary", create=True) as mock_q:
            mock_q.confirm.return_value.ask.return_value = True
            finding = scanner._anon_write_probe(
                "https://xyz.supabase.co", "logs", "key", session, con
            )
        con.close()
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_write_403_no_finding(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        session.post = MagicMock(return_value=_mock_resp(403, {"message": "RLS blocks write"}))
        con = sqlite3.connect(tmp_db)
        with patch("forge.phase4.api_policy_check.questionary", create=True) as mock_q:
            mock_q.confirm.return_value.ask.return_value = True
            finding = scanner._anon_write_probe(
                "https://xyz.supabase.co", "logs", "key", session, con
            )
        con.close()
        assert finding is None


# ══════════════════════════════════════════════════════════════════════════════
# Table enumeration
# ══════════════════════════════════════════════════════════════════════════════


class TestTableEnumeration:
    def test_extracts_table_names_from_openapi(self, scanner: SupabaseScanner):
        schema = {
            "paths": {
                "/users": {"get": {}},
                "/products": {"get": {}},
                "/": {"get": {}},  # root — must be excluded
            }
        }
        session = MagicMock()
        session.get = MagicMock(return_value=_mock_resp(200, schema))
        tables = scanner._enumerate_tables("https://xyz.supabase.co", session, dry_run=False)
        assert "users" in tables
        assert "products" in tables
        assert "" not in tables  # root stripped

    def test_404_returns_empty(self, scanner: SupabaseScanner):
        session = MagicMock()
        session.get = MagicMock(return_value=_mock_resp(404, {}))
        tables = scanner._enumerate_tables("https://xyz.supabase.co", session, dry_run=False)
        assert tables == []

    def test_dry_run_returns_empty_without_requests(self, scanner: SupabaseScanner):
        session = MagicMock()
        tables = scanner._enumerate_tables("https://xyz.supabase.co", session, dry_run=True)
        session.get.assert_not_called()
        assert tables == []


# ══════════════════════════════════════════════════════════════════════════════
# Dry-run
# ══════════════════════════════════════════════════════════════════════════════


class TestDryRun:
    def test_dry_run_zero_requests(self, scanner: SupabaseScanner):
        with (
            patch.object(scanner, "_make_session") as mock_sess_fn,
            patch("forge.phase4.api_policy_check.questionary", create=True) as mock_q,
            patch.object(scanner, "_scope_gate"),
        ):
            mock_q.confirm.return_value.ask.return_value = True
            session = MagicMock()
            session.get = MagicMock()
            mock_sess_fn.return_value = session
            scanner.scan("xyzxyzxyz", dry_run=True)
        # dry_run with no tables enumerated → zero GET calls
        # (table enumeration also returns empty on dry_run)
        assert session.get.call_count == 0

    def test_dry_run_no_write_probes(self, scanner: SupabaseScanner, tmp_db: Path):
        with (
            patch.object(scanner, "_make_session", return_value=MagicMock()),
            patch.object(scanner, "_enumerate_tables", return_value=["users"]),
            patch.object(scanner, "_anon_read_probe", return_value=None) as mock_read,
            patch.object(scanner, "_anon_write_probe", return_value=None) as mock_write,
            patch("forge.phase4.api_policy_check.questionary", create=True) as mock_q,
            patch.object(scanner, "_scope_gate"),
        ):
            mock_q.confirm.return_value.ask.return_value = True
            scanner.scan("xyzxyzxyz", dry_run=True)
        mock_read.assert_called_once()
        mock_write.assert_not_called()

    def test_scope_violation_raised_before_requests(self, scanner: SupabaseScanner):
        with (
            patch(
                "forge.opsec.scope_gate.assert_in_scope", side_effect=RuntimeError("out of scope")
            ),
            patch.object(scanner, "_make_session") as mock_make_session,
        ):
            with pytest.raises(RuntimeError, match="out of scope"):
                scanner.scan("blockedproj", dry_run=True)
        mock_make_session.assert_not_called()

    def test_scan_accepts_base_url_without_project_ref(self, scanner: SupabaseScanner):
        with (
            patch.object(scanner, "_make_session", return_value=MagicMock()),
            patch.object(scanner, "_enumerate_tables", return_value=[]),
            patch("forge.phase4.api_policy_check.questionary", create=True) as mock_q,
            patch.object(scanner, "_scope_gate") as mock_scope,
        ):
            mock_q.confirm.return_value.ask.return_value = True
            findings = scanner.scan(
                project_ref="", base_url="https://xyzxyzxyz.supabase.co", dry_run=True
            )
        assert findings == []
        mock_scope.assert_called_once()

    def test_records_info_finding_when_no_anon_key(
        self, scanner: SupabaseScanner, tmp_db: Path, monkeypatch: pytest.MonkeyPatch
    ):
        # The test asserts behaviour when no anon key is resolvable from ANY
        # source. A populated developer .env (with placeholder ANON_A/ANON_B)
        # would otherwise satisfy resolve_secret_pool and skip the branch.
        monkeypatch.delenv("FORGE_SUPABASE_ANON_KEY", raising=False)
        with (
            patch.object(scanner, "_make_session", return_value=MagicMock()),
            patch.object(scanner, "_enumerate_tables", return_value=[]),
            patch("forge.phase4.api_policy_check.questionary", create=True) as mock_q,
            patch.object(scanner, "_scope_gate"),
        ):
            mock_q.confirm.return_value.ask.return_value = True
            scanner.scan(project_ref="xyzxyzxyz", dry_run=True)

        con = sqlite3.connect(tmp_db)
        row = con.execute(
            """
            SELECT severity, title, parameter
            FROM vulnerability_findings
            WHERE engagement_id=1 AND parameter='__credential_status__'
            """
        ).fetchone()
        con.close()
        assert row is not None
        assert row[0] == "INFO"
        assert "credential auto-fill unavailable" in row[1].lower()


# ══════════════════════════════════════════════════════════════════════════════
# Storage
# ══════════════════════════════════════════════════════════════════════════════


class TestStorage:
    def test_finding_written_to_db(self, scanner: SupabaseScanner, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        SupabaseScanner._ensure_schema(con)
        finding = SupabaseFinding(
            table="users",
            severity="CRITICAL",
            title="IDOR: anon read on users",
            description="PII exposed",
            evidence='{"email":"x"}',
        )
        scanner._store_finding(con, "xyzxyzxyz", finding)
        con.commit()
        row = con.execute(
            "SELECT severity FROM vulnerability_findings WHERE engagement_id=1"
        ).fetchone()
        con.close()
        assert row[0] == "CRITICAL"

    def test_finding_deduped(self, scanner: SupabaseScanner, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        SupabaseScanner._ensure_schema(con)
        f = SupabaseFinding("users", "HIGH", "t", "d", "e")
        scanner._store_finding(con, "xyzxyzxyz", f)
        scanner._store_finding(con, "xyzxyzxyz", f)  # duplicate
        count = con.execute("SELECT COUNT(*) FROM vulnerability_findings").fetchone()[0]
        con.close()
        assert count == 1

    def test_cloud_asset_stored(self, scanner: SupabaseScanner, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        SupabaseScanner._ensure_schema(con)
        scanner._store_cloud_asset(con, "my-supabase-ref")
        con.commit()
        row = con.execute(
            "SELECT * FROM cloud_assets WHERE identifier='my-supabase-ref'"
        ).fetchone()
        con.close()
        assert row is not None

    def test_audit_log_records_table_and_status_not_body(
        self, scanner: SupabaseScanner, tmp_db: Path
    ):
        con = sqlite3.connect(tmp_db)
        SupabaseScanner._ensure_schema(con)
        scanner._audit(con, "users", "anon_read", 200)
        con.commit()
        row = con.execute("SELECT result FROM audit_log LIMIT 1").fetchone()
        con.close()
        assert row is not None
        assert "users" in row[0]
        assert "200" in row[0]
        # Verify body is NOT logged
        assert "email" not in row[0]


# ══════════════════════════════════════════════════════════════════════════════
# Authenticated differential
# ══════════════════════════════════════════════════════════════════════════════


class TestAuthDifferential:
    def test_medium_finding_when_anon_equals_auth(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        anon_body = [{"id": 1, "role": "admin"}]
        session.get = MagicMock(return_value=_mock_resp(200, anon_body))
        con = sqlite3.connect(tmp_db)
        finding = scanner._auth_differential(
            "https://xyz.supabase.co", "roles", "anonkey", "authtoken", session, con
        )
        con.close()
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_no_finding_when_anon_empty(self, scanner: SupabaseScanner, tmp_db: Path):
        session = MagicMock()
        session.get = MagicMock(return_value=_mock_resp(200, []))
        con = sqlite3.connect(tmp_db)
        finding = scanner._auth_differential(
            "https://xyz.supabase.co", "empty_table", "key", "tok", session, con
        )
        con.close()
        assert finding is None


class TestCredentialResolution:
    def test_validate_anon_key_accepts_matching_project(self, scanner: SupabaseScanner):
        token = _jwt_for_project("xyzxyzxyz")
        assert scanner._validate_anon_key(token, "xyzxyzxyz")

    def test_validate_anon_key_rejects_mismatched_project(self, scanner: SupabaseScanner):
        token = _jwt_for_project("otherproj")
        assert not scanner._validate_anon_key(token, "xyzxyzxyz")

    def test_discover_anon_key_from_headers(self, scanner: SupabaseScanner):
        token = _jwt_for_project("xyzxyzxyz")
        session = MagicMock()
        resp = _mock_resp(200, {"ok": True})
        resp.headers = {"x-anon-key": token}
        session.get = MagicMock(return_value=resp)
        found = scanner._discover_anon_key("https://xyzxyzxyz.supabase.co", session, "xyzxyzxyz")
        assert found == token

    def test_discover_anon_key_from_json(self, scanner: SupabaseScanner):
        token = _jwt_for_project("xyzxyzxyz")
        session = MagicMock()
        resp = _mock_resp(200, {"config": {"anonKey": token}})
        resp.headers = {}
        session.get = MagicMock(return_value=resp)
        found = scanner._discover_anon_key("https://xyzxyzxyz.supabase.co", session, "xyzxyzxyz")
        assert found == token

    def test_extract_mobile_supabase_keys_accepts_archive_style_bundle_sources(
        self,
        scanner: SupabaseScanner,
        tmp_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from forge.db.migrations import run_migrations
        from forge.db.schema import apply_schema

        xapk_token = _jwt_for_project("xyzxyzxyz", role="anon")
        aab_token = _jwt_for_project("xyzxyzxyz", role="authenticated")
        other_token = _jwt_for_project("otherproj", role="anon")

        con = sqlite3.connect(tmp_db)
        try:
            apply_schema(con)
            run_migrations(con)
            con.executemany(
                """
                INSERT INTO key_scanner_findings
                    (engagement_id, domain, service, pattern_name, source_url, key_redacted, key_enc)
                VALUES (?, ?, 'supabase', 'supabase_mobile_config', ?, ?, ?)
                """,
                [
                    (
                        1,
                        "xyzxyzxyz",
                        "https://downloads.acme.example/mobile/client.xapk?download=1",
                        "eyJh...xapk",
                        "enc-xapk",
                    ),
                    (
                        1,
                        "xyzxyzxyz",
                        "https://downloads.acme.example/mobile/client.aab?download=1",
                        "eyJh...aab",
                        "enc-aab",
                    ),
                    (
                        1,
                        "xyzxyzxyz",
                        "https://downloads.acme.example/config.txt",
                        "eyJh...text",
                        "enc-text",
                    ),
                ],
            )
            con.commit()
            monkeypatch.setattr(
                "forge.opsec.crypto.decrypt_string",
                lambda value: {
                    "enc-xapk": xapk_token,
                    "enc-aab": aab_token,
                    "enc-text": other_token,
                }[value],
            )

            keys = scanner._extract_mobile_supabase_keys(con, "xyzxyzxyz")
        finally:
            con.close()

        assert keys == [xapk_token, aab_token]
