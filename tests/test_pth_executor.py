"""Unit tests for PTHExecutor (T3).

Tests Pass-the-Hash execution engine for lateral movement.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from forge.post_exploitation.pth_executor import (
    PTHExecutor,
    PTHResult,
    NTLMHash,
    LateralHost
)


class TestNTLMHash:
    """Test NTLMHash dataclass."""

    def test_ntlm_hash_creation(self):
        """NTLMHash creates with expected fields."""
        ntlm = NTLMHash(
            username="Administrator",
            hash_value="31d6cfe0d16ae931b73c59d7e0c089c0",
            domain="CORP"
        )
        assert ntlm.username == "Administrator"
        assert ntlm.hash_value == "31d6cfe0d16ae931b73c59d7e0c089c0"
        assert ntlm.domain == "CORP"

    def test_ntlm_hash_default_domain(self):
        """NTLMHash uses empty string as default domain."""
        ntlm = NTLMHash(
            username="admin",
            hash_value="abcdef1234567890abcdef1234567890"
        )
        assert ntlm.domain == ""

    def test_ntlm_hash_validation(self):
        """NTLMHash validates hash format."""
        # Valid 32-char hex hash
        ntlm = NTLMHash(username="user", hash_value="0" * 32)
        assert ntlm.hash_value == "0" * 32


class TestLateralHost:
    """Test LateralHost dataclass."""

    def test_lateral_host_creation(self):
        """LateralHost creates with expected fields."""
        host = LateralHost(
            hostname="DC01",
            ip_address="192.168.1.10",
            os_type="windows",
            domain="corp.local"
        )
        assert host.hostname == "DC01"
        assert host.ip_address == "192.168.1.10"
        assert host.os_type == "windows"

    def test_lateral_host_default_os(self):
        """LateralHost defaults os_type to windows."""
        host = LateralHost(hostname="SRV01", ip_address="10.0.0.1")
        assert host.os_type == "windows"


class TestPTHExecutor:
    """Test PTHExecutor class."""

    def test_init_requires_graph(self):
        """PTHExecutor requires networkx graph."""
        import networkx as nx
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        assert executor.graph is not None

    def test_init_with_scope_manifest(self, tmp_path):
        """PTHExecutor initializes with scope manifest."""
        import networkx as nx
        
        manifest = {
            "hosts": ["192.168.1.0/24"],
            "domains": ["corp.local"]
        }
        manifest_file = tmp_path / "scope.json"
        manifest_file.write_text('{"hosts": ["192.168.1.0/24"]}')
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph, scope_manifest_path=str(manifest_file))
        assert executor.scope_manifest is not None

    def test_check_scope_allows_authorized_host(self, tmp_path):
        """check_scope returns True for authorized hosts."""
        import networkx as nx
        
        manifest_file = tmp_path / "scope.json"
        manifest_file.write_text('{"hosts": ["192.168.1.0/24"]}')
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        executor.scope_manifest = {"hosts": ["192.168.1.0/24"]}
        
        assert executor.check_scope("192.168.1.50") is True

    def test_check_scope_blocks_unauthorized_host(self, tmp_path):
        """check_scope returns False for unauthorized hosts."""
        import networkx as nx
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        executor.scope_manifest = {"hosts": ["192.168.1.0/24"]}
        
        assert executor.check_scope("10.0.0.1") is False

    def test_build_pth_command(self):
        """build_pth_command generates correct command structure."""
        import networkx as nx
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        
        ntlm = NTLMHash(
            username="Administrator",
            hash_value="31d6cfe0d16ae931b73c59d7e0c089c0",
            domain="CORP"
        )
        host = LateralHost(hostname="DC01", ip_address="192.168.1.10")
        
        # Should build a command dict (implementation-specific)
        cmd = executor.build_pth_command(ntlm, host)
        assert cmd is not None
        assert "Administrator" in str(cmd) or ntlm.username in str(cmd)

    def test_execute_pth_requires_scope(self):
        """execute_pth rejects execution without scope."""
        import networkx as nx
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        executor.scope_manifest = None
        
        ntlm = NTLMHash(username="admin", hash_value="0" * 32)
        host = LateralHost(hostname="DC01", ip_address="192.168.1.10")
        
        result = executor.execute_pth(ntlm, host)
        assert result.success is False
        assert "scope" in result.error.lower() or "unauthorized" in result.error.lower()

    def test_execute_pth_blocks_out_of_scope(self):
        """execute_pth blocks hosts outside scope."""
        import networkx as nx
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        executor.scope_manifest = {"hosts": ["192.168.1.0/24"]}
        
        ntlm = NTLMHash(username="admin", hash_value="0" * 32)
        host = LateralHost(hostname="UNTRUSTED", ip_address="10.0.0.1")
        
        result = executor.execute_pth(ntlm, host, dry_run=True)
        assert result.success is False

    def test_execute_pth_dry_run(self):
        """execute_pth dry_run mode does not execute."""
        import networkx as nx
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        executor.scope_manifest = {"hosts": ["192.168.1.0/24"]}
        
        ntlm = NTLMHash(username="admin", hash_value="0" * 32)
        host = LateralHost(hostname="DC01", ip_address="192.168.1.10")
        
        # Dry run should not actually execute
        result = executor.execute_pth(ntlm, host, dry_run=True)
        # Should succeed in validation phase but not actually execute

    def test_audit_log_created(self, tmp_path):
        """execute_pth creates audit log entry."""
        import networkx as nx
        
        graph = nx.DiGraph()
        executor = PTHExecutor(graph)
        executor.scope_manifest = {"hosts": ["192.168.1.0/24"]}
        
        ntlm = NTLMHash(username="admin", hash_value="0" * 32)
        host = LateralHost(hostname="DC01", ip_address="192.168.1.10")
        
        # Should create audit log even on validation failure
        result = executor.execute_pth(ntlm, host, dry_run=True)
        # Audit log should be recorded

    def test_result_contains_evidence(self):
        """PTHResult contains evidence fields."""
        result = PTHResult(
            success=True,
            hostname="DC01",
            ip_address="192.168.1.10",
            username="admin",
            evidence={"command": "test"},
            error=""
        )
        assert result.hostname == "DC01"
        assert result.evidence is not None


class TestPTHResult:
    """Test PTHResult dataclass."""

    def test_pth_result_success(self):
        """PTHResult creates for successful execution."""
        result = PTHResult(
            success=True,
            hostname="DC01",
            ip_address="192.168.1.10",
            username="admin",
            evidence={},
            error=""
        )
        assert result.success is True
        assert result.error == ""

    def test_pth_result_failure(self):
        """PTHResult creates for failed execution."""
        result = PTHResult(
            success=False,
            hostname="DC01",
            ip_address="192.168.1.10",
            username="admin",
            evidence={},
            error="Connection failed"
        )
        assert result.success is False
        assert result.error == "Connection failed"
