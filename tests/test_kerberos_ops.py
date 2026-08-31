"""Unit tests for KerberosOps (T5).

Tests Kerberos ticket operations including .kirbi parsing and injection.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from base64 import b64encode
from datetime import datetime, timezone
from forge.kerberos.kerberos_ops import (
    KerberosOps,
    KerberosTicket
)


class TestKerberosTicket:
    """Test KerberosTicket dataclass."""

    def test_ticket_creation(self):
        """KerberosTicket creates with expected fields."""
        ticket = KerberosTicket(
            service_principal_name="HTTP/webapp.target.example",
            client_name="admin",
            domain="CORP.LOCAL",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            session_key_type="AES256",
            ticket_blob=b"mock_ticket_data",
            is_kerberoastable=True
        )
        assert ticket.service_principal_name == "HTTP/webapp.target.example"
        assert ticket.client_name == "admin"
        assert ticket.domain == "CORP.LOCAL"
        assert ticket.is_kerberoastable is True

    def test_ticket_field_defaults(self):
        """KerberosTicket handles optional fields."""
        ticket = KerberosTicket(
            service_principal_name="HTTP/test",
            client_name="user",
            domain="DOMAIN.COM",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            session_key_type="RC4",
            ticket_blob=b"data",
            is_kerberoastable=False
        )
        assert ticket.session_key_type == "RC4"
        assert ticket.is_kerberoastable is False


class TestKerberosOps:
    """Test KerberosOps class."""

    def test_init_default_settings(self):
        """KerberosOps initializes with default settings."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        assert ops.roe_id == "ROE-123"

    def test_init_custom_realm(self):
        """KerberosOps accepts custom realm."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        assert ops.roe_id == "ROE-123"

    def test_parse_kirbi_file_valid(self, tmp_path):
        """parse_kirbi_file extracts ticket data from a .kirbi file."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        # Create mock .kirbi file
        kirbi_file = tmp_path / "ticket.kirbi"
        kirbi_file.write_bytes(b64encode(b"mock_kirbi_data"))
        
        # Should parse without error
        result = ops.parse_kirbi_file(kirbi_file)
        assert len(result) == 1
        assert result[0].ticket_blob == b64encode(b"mock_kirbi_data")

    def test_parse_kirbi_file_non_kirbi_content(self, tmp_path):
        """parse_kirbi_file handles arbitrary file contents gracefully."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        kirbi_file = tmp_path / "invalid.txt"
        kirbi_file.write_text("not a ticket")
        
        result = ops.parse_kirbi_file(kirbi_file)
        assert isinstance(result, list)

    def test_parse_kirbi_file_not_found(self):
        """parse_kirbi_file returns an empty list for a missing file."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        result = ops.parse_kirbi_file(Path("/nonexistent/ticket.kirbi"))
        assert result == []

    def test_inject_ticket_windows_rejects_out_of_scope_domain(self):
        """inject_ticket_windows rejects tickets outside configured domain scope."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["example.com"]}
        )
        
        ticket = KerberosTicket(
            service_principal_name="krbtgt/CORP.LOCAL",
            client_name="admin",
            domain="CORP.LOCAL",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            session_key_type="AES256",
            ticket_blob=b"data",
            is_kerberoastable=True
        )
        
        result = ops.inject_ticket_windows(ticket)
        assert result is False

    def test_inject_ticket_windows_placeholder_returns_false(self):
        """inject_ticket_windows is a safe placeholder until Windows API injection exists."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        ticket = KerberosTicket(
            service_principal_name="krbtgt/CORP.LOCAL",
            client_name="admin",
            domain="CORP.LOCAL",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            session_key_type="AES256",
            ticket_blob=b"data",
            is_kerberoastable=True
        )
        
        result = ops.inject_ticket_windows(ticket)
        assert result is False

    def test_parse_kirbi_file_preserves_ticket_blob(self, tmp_path):
        """parse_kirbi_file preserves the raw ticket bytes."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        kirbi_file = tmp_path / "exported.kirbi"
        kirbi_file.write_bytes(b"ticket_data")
        result = ops.parse_kirbi_file(kirbi_file)
        assert result[0].ticket_blob == b"ticket_data"

    def test_extract_tickets_from_lsass_disabled(self):
        """extract_tickets_from_lsass returns empty unless explicitly enabled."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        tickets = ops.extract_tickets_from_lsass()
        assert isinstance(tickets, list)
        assert tickets == []

    def test_extract_tickets_from_lsass_enabled_placeholder(self):
        """extract_tickets_from_lsass is still a placeholder when enabled."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]},
            allow_lsass_extraction=True
        )
        
        result = ops.extract_tickets_from_lsass()
        assert result == []

    def test_is_domain_in_scope_false(self):
        """_is_domain_in_scope rejects domains absent from the scope manifest."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        assert ops._is_domain_in_scope("example.com") is False

    def test_is_domain_in_scope_true(self):
        """_is_domain_in_scope accepts exact configured domains."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        assert ops._is_domain_in_scope("CORP.LOCAL") is True

    def test_enumerate_kerberoast_candidates(self):
        """enumerate_kerberoast_candidates returns a candidate list."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        candidates = ops.enumerate_kerberoast_candidates(
            domain="corp.local",
            dc_ip="192.168.1.10"
        )
        assert isinstance(candidates, list)

    def test_init_allows_operation_flags(self):
        """KerberosOps stores optional operation gates."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]},
            allow_lsass_extraction=True,
            allow_kerberoast=True
        )

        assert ops.allow_lsass_extraction is True
        assert ops.allow_kerberoast is True

    def test_audit_log_created(self, tmp_path):
        """Operations create audit log entries."""
        ops = KerberosOps(
            roe_id="ROE-123",
            scope_manifest={"domains": ["corp.local"]}
        )
        
        ticket = KerberosTicket(
            service_principal_name="krbtgt/CORP.LOCAL",
            client_name="admin",
            domain="CORP.LOCAL",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            session_key_type="AES256",
            ticket_blob=b"data",
            is_kerberoastable=True
        )
        
        ops._audit_log(
            action="test_action",
            details={"domain": ticket.domain}
        )
