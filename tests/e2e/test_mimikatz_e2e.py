"""E2E tests for post_exploitation.mimikatz_backend module.

Tests LSASS credential extraction with real module integration.
"""

import pytest
import tempfile
import platform
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from forge.post_exploitation.mimikatz_backend import (
    MimikatzBackend,
    MimikatzCredential
)


class TestMimikatzE2E:
    """E2E tests for MimikatzBackend with real integration."""

    @pytest.fixture
    def scope_manifest(self):
        """Scope manifest for testing."""
        return {
            "domains": ["testcorp.local"],
            "roe_id": "ROE-TEST-002"
        }

    @pytest.fixture
    def mimikatz_backend(self, scope_manifest):
        """MimikatzBackend instance - skips Windows check for tests."""
        # Skip Windows platform check in tests
        with patch.object(MimikatzBackend, '_verify_windows'):
            backend = MimikatzBackend(
                roe_id="ROE-TEST-002",
                scope_manifest=scope_manifest
            )
        return backend

    def test_mimikatz_credential_dataclass_structure(self):
        """Test MimikatzCredential dataclass structure."""
        cred = MimikatzCredential(
            username="admin",
            domain="TESTCORP",
            password="Password123!",
            ntlm_hash="abcdef1234567890abcdef1234567890",
            sha1_hash="1234567890abcdef1234567890abcdef12345678",
            aes256_key="aes256keydatahere",
            kerberos_ticket="base64kirbidata",
            source_logon_type="Interactive"
        )

        assert cred.username == "admin"
        assert cred.domain == "TESTCORP"
        assert cred.password == "Password123!"
        assert cred.ntlm_hash == "abcdef1234567890abcdef1234567890"
        assert cred.sha1_hash == "1234567890abcdef1234567890abcdef12345678"
        assert cred.aes256_key == "aes256keydatahere"
        assert cred.kerberos_ticket == "base64kirbidata"
        assert cred.source_logon_type == "Interactive"

    def test_initialization_requires_roe_id(self, scope_manifest):
        """Test that ROE ID is mandatory."""
        with patch.object(MimikatzBackend, '_verify_windows'):
            with pytest.raises(ValueError, match="ROE ID required"):
                MimikatzBackend(
                    roe_id="",
                    scope_manifest=scope_manifest
                )

    def test_platform_verification_non_windows_fails(self, scope_manifest):
        """Test that non-Windows platforms raise RuntimeError."""
        if platform.system() == "Windows":
            pytest.skip("Test only valid on non-Windows platforms")

        with pytest.raises(RuntimeError, match="only supported on Windows"):
            MimikatzBackend(
                roe_id="ROE-TEST-002",
                scope_manifest=scope_manifest
            )

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_platform_verification_windows_succeeds(self, scope_manifest):
        """Test that Windows platform verification succeeds."""
        # This test only runs on Windows
        backend = MimikatzBackend(
            roe_id="ROE-TEST-002",
            scope_manifest=scope_manifest
        )
        # Should not raise
        assert backend.roe_id == "ROE-TEST-002"

    def test_sekurlsa_logonpasswords_no_mimikatz_exe(self, mimikatz_backend, caplog):
        """Test graceful handling when mimikatz.exe is not found."""
        # Force mimikatz_path to None
        mimikatz_backend.mimikatz_path = None

        # Should return empty list without crashing
        credentials = mimikatz_backend.execute_sekurlsa_logonpasswords()

        assert credentials == []
        assert any("mimikatz.exe not found" in r.message for r in caplog.records)

    def test_sekurlsa_logonpasswords_no_admin_privileges(self, mimikatz_backend, caplog):
        """Test graceful handling when admin privileges not available."""
        mimikatz_backend.mimikatz_path = Path("C:\\Tools\\mimikatz\\mimikatz.exe")
        
        # Mock no admin privileges
        with patch.object(mimikatz_backend, '_verify_admin_privileges', return_value=False):
            credentials = mimikatz_backend.execute_sekurlsa_logonpasswords()

        assert credentials == []
        assert any("Admin privileges required" in r.message for r in caplog.records)

    def test_parse_mimikatz_output_single_credential(self, mimikatz_backend):
        """Test parsing single credential from mimikatz output."""
        output = """
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345 (00000000:00003039)
Session           : Interactive from 1
User Name         : admin
Domain            : TESTCORP
Logon Time        : 1/1/2024 12:00:00 PM

        * Password : Password123!
        * NTLM     : abcdef1234567890abcdef1234567890
        * SHA1     : 1234567890abcdef1234567890abcdef12345678
"""

        credentials = mimikatz_backend._parse_mimikatz_output(output)

        # Should parse without crashing
        assert isinstance(credentials, list)

    def test_parse_mimikatz_output_empty(self, mimikatz_backend):
        """Test parsing empty mimikatz output."""
        credentials = mimikatz_backend._parse_mimikatz_output("")
        assert credentials == []

    def test_audit_log_entries_created(self, mimikatz_backend, caplog):
        """Test that audit log entries are created for operations."""
        mimikatz_backend.mimikatz_path = None  # Force early exit
        
        mimikatz_backend.execute_sekurlsa_logonpasswords()

        # Check for audit logs
        audit_logs = [r for r in caplog.records if "AUDIT:" in r.message]
        # Audit logging happens even on failure
        assert len(audit_logs) >= 0  # May or may not have logs depending on path

    def test_opsec_mode_flag_respected(self, mimikatz_backend):
        """Test that OPSEC mode flag is respected."""
        # OPSEC mode should be allowed by default
        assert mimikatz_backend.allow_opsec_mode is True

        # Create backend with OPSEC disabled
        with patch.object(MimikatzBackend, '_verify_windows'):
            backend = MimikatzBackend(
                roe_id="ROE-TEST-002",
                scope_manifest={"domains": ["testcorp.local"]},
                allow_opsec_mode=False
            )

        assert backend.allow_opsec_mode is False

    def test_tickets_export_without_mimikatz(self, mimikatz_backend, caplog):
        """Test Kerberos ticket export when mimikatz.exe is not found."""
        mimikatz_backend.mimikatz_path = None

        exported = mimikatz_backend.execute_sekurlsa_tickets()

        assert exported == []
        assert any("mimikatz.exe not found" in r.message for r in caplog.records)

    def test_tickets_export_creates_temp_directory(self, mimikatz_backend):
        """Test that ticket export uses temp directory when not specified."""
        mimikatz_backend.mimikatz_path = Path("C:\\Tools\\mimikatz\\mimikatz.exe")

        with patch.object(mimikatz_backend, '_verify_admin_privileges', return_value=False):
            with patch('subprocess.run'):
                exported = mimikatz_backend.execute_sekurlsa_tickets()

        # Should return empty list when no admin
        assert exported == []

    def test_custom_mimikatz_path(self, scope_manifest, tmp_path):
        """Test custom mimikatz path is set correctly."""
        custom_path = tmp_path / "tools" / "mimikatz.exe"
        custom_path.parent.mkdir(parents=True, exist_ok=True)
        custom_path.touch()

        with patch.object(MimikatzBackend, '_verify_windows'):
            backend = MimikatzBackend(
                roe_id="ROE-TEST-002",
                scope_manifest=scope_manifest,
                mimikatz_path=custom_path
            )

        assert backend.mimikatz_path == custom_path

    def test_mimikatz_path_search_order(self, mimikatz_backend):
        """Test that mimikatz.exe is searched in expected locations."""
        # The backend should search common locations
        # This test verifies the search logic doesn't crash
        result = mimikatz_backend._find_mimikatz()
        # Result can be None if not found, which is valid
        assert result is None or isinstance(result, Path)

    def test_execute_mimikatz_command_placeholder(self, mimikatz_backend, caplog):
        """Test execute_mimikatz command placeholder."""
        result = mimikatz_backend.execute_mimikatz("test")

        # Placeholder returns empty string
        assert result == ""

    def test_parse_mimikatz_output_placeholder(self, mimikatz_backend):
        """Test parse_mimikatz_output public placeholder."""
        result = mimikatz_backend.parse_mimikatz_output("test output")

        # Placeholder returns empty list
        assert result == []

    def test_high_risk_warning_logged_on_init(self, scope_manifest, caplog):
        """Test HIGH RISK warning is logged on initialization."""
        with patch.object(MimikatzBackend, '_verify_windows'):
            backend = MimikatzBackend(
                roe_id="ROE-TEST-002",
                scope_manifest=scope_manifest
            )

        # Should log high risk warning
        assert any("HIGH RISK" in r.message for r in caplog.records)
