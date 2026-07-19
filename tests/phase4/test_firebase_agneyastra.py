"""
tests/phase4/test_firebase_agneyastra.py
Unit + integration tests for cloud_audit.py (Module 4-E).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.phase4.cloud_audit import (
    FirebaseAuditor,
    FirebaseFinding,
    ToolVersionError,
    _assert_tool_version,
    _SEVERITY_MAP,
    _resolve_firebase_api_key,
    _validate_firebase_api_key,
)


def _parse_output_fixture(data: dict) -> list[FirebaseFinding]:
    """Test helper: invoke _parse_output on in-memory data."""
    import tempfile, json, pathlib
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        p = pathlib.Path(f.name)
    findings = FirebaseAuditor._parse_output(p)
    p.unlink(missing_ok=True)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    FirebaseAuditor._ensure_schema(con)
    con.execute(
        """
        INSERT OR IGNORE INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier, source, discovered_at)
        VALUES (99, 'firebase', 'dummy-proj', 'dummy-proj', 'test', datetime('now'))
        """
    )
    con.commit(); con.close()
    return db


@pytest.fixture
def auditor(tmp_db: Path) -> FirebaseAuditor:
    return FirebaseAuditor(db_path=tmp_db, engagement_id=1)


_FIXTURE_JSON = {
    "findings": [
        {"category": "auth_bypass",       "title": "Auth bypass detected",
         "description": "Firebase auth rules allow unauthenticated writes.",
         "detail": {"endpoint": "/users"}},
        {"category": "rtdb_public_read",  "title": "RTDB public read",
         "description": "Realtime DB readable without credentials.",
         "detail": {}},
        {"category": "functions_unauth",  "title": "Cloud Function unauth",
         "description": "Function invocable without auth.",
         "detail": {}},
        {"category": "informational",     "title": "Remote config accessible",
         "description": "Remote config accessible.", "detail": {}},
    ]
}


# ══════════════════════════════════════════════════════════════════════════════
# ToolVersionError
# ══════════════════════════════════════════════════════════════════════════════

class TestToolVersionError:

    def test_missing_binary_raises(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(ToolVersionError, match="not found on PATH"):
                _assert_tool_version("agneyastra", "1.0.0")

    def test_outdated_binary_raises(self):
        with patch("shutil.which", return_value="/usr/local/bin/agneyastra"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="agneyastra 0.9.0", stderr="")
            with pytest.raises(ToolVersionError, match="0.9.0"):
                _assert_tool_version("agneyastra", "1.0.0")

    def test_valid_binary_passes(self):
        with patch("shutil.which", return_value="/usr/local/bin/agneyastra"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="agneyastra version 1.0.0", stderr="")
            _assert_tool_version("agneyastra", "1.0.0")  # should not raise


# ══════════════════════════════════════════════════════════════════════════════
# _parse_output
# ══════════════════════════════════════════════════════════════════════════════

class TestParseOutput:

    def test_parses_all_findings(self):
        findings = _parse_output_fixture(_FIXTURE_JSON)
        assert len(findings) == 4

    def test_auth_bypass_is_critical(self):
        findings = _parse_output_fixture(_FIXTURE_JSON)
        auth = next(f for f in findings if f.category == "auth_bypass")
        assert auth.severity == "CRITICAL"

    def test_rtdb_read_is_high(self):
        findings = _parse_output_fixture(_FIXTURE_JSON)
        rtdb = next(f for f in findings if f.category == "rtdb_public_read")
        assert rtdb.severity == "HIGH"

    def test_functions_unauth_is_medium(self):
        findings = _parse_output_fixture(_FIXTURE_JSON)
        func = next(f for f in findings if f.category == "functions_unauth")
        assert func.severity == "MEDIUM"

    def test_informational_category_maps_to_info(self):
        findings = _parse_output_fixture(_FIXTURE_JSON)
        info = next(f for f in findings if f.category == "informational")
        assert info.severity == "INFO"

    def test_evidence_truncated_to_512(self):
        data = {"findings": [
            {"category": "auth_bypass", "title": "t", "description": "d",
             "detail": {"x": "A" * 1000}}
        ]}
        findings = _parse_output_fixture(data)
        assert len(findings[0].evidence) <= 512

    def test_empty_findings_list(self):
        findings = _parse_output_fixture({"findings": []})
        assert findings == []

    def test_missing_file_returns_empty(self):
        findings = FirebaseAuditor._parse_output(Path("/nonexistent/file.json"))
        assert findings == []

    def test_malformed_json_returns_empty(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all{{{}}")
        findings = FirebaseAuditor._parse_output(bad)
        assert findings == []


# ══════════════════════════════════════════════════════════════════════════════
# Severity mapping completeness
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityMap:

    def test_all_critical_categories_present(self):
        assert _SEVERITY_MAP["auth_bypass"]       == "CRITICAL"
        assert _SEVERITY_MAP["rtdb_public_write"]  == "CRITICAL"

    def test_high_categories_present(self):
        assert _SEVERITY_MAP["rtdb_public_read"]   == "HIGH"
        assert _SEVERITY_MAP["firestore_public"]   == "HIGH"
        assert _SEVERITY_MAP["storage_public"]     == "HIGH"

    def test_medium_categories_present(self):
        assert _SEVERITY_MAP["functions_unauth"]      == "MEDIUM"
        assert _SEVERITY_MAP["remote_config_unauth"]  == "MEDIUM"


# ══════════════════════════════════════════════════════════════════════════════
# Dry-run
# ══════════════════════════════════════════════════════════════════════════════

class TestDryRun:

    def test_dry_run_no_subprocess(self, auditor: FirebaseAuditor):
        with patch("forge.phase4.cloud_audit._assert_tool_version"), \
             patch("forge.phase4.cloud_audit._resolve_firebase_api_key", return_value=None), \
             patch("forge.phase4.cloud_audit.questionary", create=True) as mock_q, \
             patch("subprocess.run") as mock_sub:
            mock_q.confirm.return_value.ask.return_value = True
            findings = auditor.run(
                project_id="my-proj-12345",
                tests=["auth"],
                dry_run=True,
            )
        mock_sub.assert_not_called()
        assert findings == []

    def test_dry_run_no_db_writes(self, auditor: FirebaseAuditor, tmp_db: Path):
        with patch("forge.phase4.cloud_audit._assert_tool_version"), \
             patch("forge.phase4.cloud_audit._resolve_firebase_api_key", return_value=None), \
             patch("forge.phase4.cloud_audit.questionary", create=True) as mock_q:
            mock_q.confirm.return_value.ask.return_value = True
            auditor.run(project_id="proj", tests=["auth"], dry_run=True)
        con = sqlite3.connect(tmp_db)
        count = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1"
        ).fetchone()[0]
        con.close()
        assert count == 0


class TestCredentialResolution:

    def test_validate_firebase_key_format(self):
        assert _validate_firebase_api_key("AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567")
        assert not _validate_firebase_api_key("not-a-firebase-key")

    def test_resolve_prefers_explicit_over_stored(self, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        key = _resolve_firebase_api_key(
            con,
            engagement_id=1,
            project_id="my-proj",
            api_key="AIzaSyExplicitKeyAbCdEfGhIjKlMnOpQrStUv",
            auto_discover_web=False,
            repo_scavenge=False,
        )
        con.close()
        assert key == "AIzaSyExplicitKeyAbCdEfGhIjKlMnOpQrStUv"


# ══════════════════════════════════════════════════════════════════════════════
# Integration: fixture JSON → DB rows
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:

    def test_findings_persisted_to_db(self, auditor: FirebaseAuditor, tmp_db: Path):
        findings = [
            FirebaseFinding("auth_bypass", "CRITICAL", "t", "d", "e"),
            FirebaseFinding("rtdb_public_read", "HIGH", "t2", "d2", "e2"),
        ]
        con = sqlite3.connect(tmp_db)
        FirebaseAuditor._ensure_schema(con)
        count = auditor._store_findings(con, "my-proj", findings)
        con.commit(); con.close()
        assert count == 2

        con = sqlite3.connect(tmp_db)
        rows = con.execute(
            "SELECT * FROM vulnerability_findings WHERE engagement_id=1"
        ).fetchall()
        con.close()
        assert len(rows) == 2

    def test_cloud_asset_stored(self, auditor: FirebaseAuditor, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        FirebaseAuditor._ensure_schema(con)
        auditor._store_cloud_asset(con, "my-proj-123")
        con.commit()
        row = con.execute(
            "SELECT * FROM cloud_assets WHERE identifier='my-proj-123'"
        ).fetchone()
        con.close()
        assert row is not None

    def test_api_key_not_in_audit_log(self, auditor: FirebaseAuditor, tmp_db: Path):
        con = sqlite3.connect(tmp_db)
        FirebaseAuditor._ensure_schema(con)
        auditor._audit_log(con, "my-proj", ["auth"], 3, had_api_key=True)
        con.commit()
        row = con.execute("SELECT result FROM audit_log LIMIT 1").fetchone()
        con.close()
        assert row is not None
        # The audit log must NOT contain the actual key value — only "yes"
        assert "AIZA" not in row[0]  # typical Firebase API key prefix
        assert "api_key=yes" in row[0]

    def test_cleanup_file_registered_before_parse(self, auditor: FirebaseAuditor):
        registered: list[Path] = []
        with patch("forge.phase4.cloud_audit._assert_tool_version"), \
             patch("forge.phase4.cloud_audit._resolve_firebase_api_key", return_value=None), \
             patch("forge.phase4.cloud_audit.questionary", create=True) as mock_q, \
             patch("forge.phase4.cloud_audit.FirebaseAuditor._register_cleanup",
                   side_effect=lambda p: registered.append(Path(p))), \
             patch("subprocess.run") as mock_sub, \
             patch("forge.phase4.cloud_audit.FirebaseAuditor._parse_output", return_value=[]):
            mock_q.confirm.return_value.ask.return_value = True
            mock_sub.return_value = MagicMock(returncode=0, stdout="", stderr="")
            auditor.run(project_id="proj", tests=["auth"])

        assert len(registered) == 1
        assert not registered[0].exists()

    def test_missing_key_persists_info_finding(self, auditor: FirebaseAuditor, tmp_db: Path):
        with patch("forge.phase4.cloud_audit._assert_tool_version"), \
             patch("forge.phase4.cloud_audit._resolve_firebase_api_key", return_value=None), \
             patch("forge.phase4.cloud_audit.questionary", create=True) as mock_q, \
             patch("subprocess.run") as mock_sub, \
             patch("forge.phase4.cloud_audit.FirebaseAuditor._parse_output", return_value=[]):
            mock_q.confirm.return_value.ask.return_value = True
            mock_sub.return_value = MagicMock(returncode=0, stdout="", stderr="")
            auditor.run(project_id="missing-key-proj", tests=["auth"])

        con = sqlite3.connect(tmp_db)
        row = con.execute(
            """
            SELECT severity, vuln_type, parameter
            FROM vulnerability_findings
            WHERE engagement_id=1 AND vuln_type='FIREBASE_CREDENTIAL_STATUS'
            """
        ).fetchone()
        audit = con.execute(
            """
            SELECT action, result
            FROM audit_log
            WHERE engagement_id=1 AND action='credential_resolution_skipped'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        con.close()
        assert row is not None
        assert row[0] == "INFO"
        assert row[2] == "__credential_status__"
        assert audit is not None
        assert "firebase_api_key=missing" in audit[1]
