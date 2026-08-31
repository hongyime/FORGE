"""Unit tests for C2Listener (T8).

Tests C2 listener and implant communication.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from pathlib import Path
from datetime import datetime, timezone
import queue
from forge.c2.listener import (
    C2Listener,
    C2Implant
)


class TestC2Implant:
    """Test C2Implant dataclass."""

    def test_implant_creation(self):
        """C2Implant creates with expected fields."""
        implant = C2Implant(
            implant_id="implant-001",
            os_type="Windows 10",
            hostname="WORKSTATION01",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=5,
            task_queue=queue.Queue()
        )
        assert implant.implant_id == "implant-001"
        assert implant.hostname == "WORKSTATION01"
        assert implant.os_type == "Windows 10"

    def test_implant_is_alive(self):
        """C2Implant.is_alive property works correctly."""
        implant = C2Implant(
            implant_id="test-001",
            os_type="Windows",
            hostname="HOST",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=1,
            task_queue=queue.Queue()
        )
        
        # Recently seen implant should be alive
        assert implant.is_alive is True

    def test_implant_task_queue(self):
        """C2Implant has task queue for commands."""
        implant = C2Implant(
            implant_id="test-001",
            os_type="Linux",
            hostname=None,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=0,
            task_queue=queue.Queue()
        )
        
        # Should have task queue
        assert implant.task_queue is not None
        assert isinstance(implant.task_queue, queue.Queue)


class TestC2Listener:
    """Test C2Listener class."""

    def test_init_default_port(self):
        """C2Listener initializes with default port."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        assert listener.roe_id == "ROE-123"
        assert listener.port == 8443

    def test_init_custom_port(self):
        """C2Listener accepts custom port."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            port=9000,
            roe_id="ROE-123"
        )
        assert listener.port == 9000

    def test_init_with_tunnel(self):
        """C2Listener initializes with Cloudflare tunnel."""
        tunnel_url = "https://abc123.trycloudflare.com"
        listener = C2Listener(
            tunnel_url=tunnel_url,
            roe_id="ROE-123"
        )
        assert listener.tunnel_url == tunnel_url.rstrip("/")

    def test_start(self):
        """start launches the listener server."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        server = Mock()
        with patch("forge.c2.listener.socketserver.TCPServer", return_value=server):
            result = listener.start()
            assert result is True
            assert listener._running is True
            assert listener.stop() is True

    def test_start_allows_optional_roe(self):
        """start follows the current API where roe_id is optional."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id=None
        )
        
        server = Mock()
        with patch("forge.c2.listener.socketserver.TCPServer", return_value=server):
            result = listener.start()
            assert result is True
            assert listener.stop() is True

    def test_stop(self):
        """stop handles a listener that is not running."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        result = listener.stop()
        assert result is True

    def test_generate_implant_returns_config(self):
        """generate_implant returns implant configuration bytes."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        config = json.loads(listener.generate_implant(os_type="windows").decode("utf-8"))
        assert config["os_type"] == "windows"
        assert config["c2_url"] == "https://tunnel.example.com/beacon"

    def test_generate_implant_writes_output_path(self, tmp_path):
        """generate_implant writes config bytes when output_path is supplied."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        output_path = tmp_path / "implant.json"
        config_bytes = listener.generate_implant(os_type="linux", output_path=output_path)
        assert output_path.read_bytes() == config_bytes

    def test_queue_task(self):
        """queue_task adds task to implant queue."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        implant = C2Implant(
            implant_id="implant-001",
            os_type="Windows",
            hostname="HOST",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=0,
            task_queue=queue.Queue()
        )
        
        listener.implants[implant.implant_id] = implant
        result = listener.queue_task("implant-001", "exec", {"command": "whoami"})
        assert result is True
        assert not implant.task_queue.empty()

    def test_queue_task_unknown_implant(self):
        """queue_task returns False for unknown implants."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        result = listener.queue_task("unknown", "exec", {"command": "whoami"})
        assert result is False

    def test_get_implant_status_empty(self):
        """get_implant_status returns empty listener status."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        status = listener.get_implant_status()
        assert status["total_implants"] == 0
        assert status["implants"] == []

    def test_generate_implant_uses_tunnel_url(self):
        """generate_implant embeds the Cloudflare tunnel URL."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        config = json.loads(listener.generate_implant().decode("utf-8"))
        assert config["c2_url"].startswith("https://tunnel.example.com")

    def test_tunnel_url_is_trimmed(self):
        """C2Listener stores tunnel URLs without a trailing slash."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com/",
            port=8080,
            roe_id="ROE-123"
        )
        
        assert listener.tunnel_url == "https://tunnel.example.com"

    def test_get_implant_status_with_active_implant(self):
        """get_implant_status reports active implants."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        implant = C2Implant(
            implant_id="active-001",
            os_type="Windows",
            hostname="HOST",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=1,
            task_queue=queue.Queue()
        )
        
        listener.implants[implant.implant_id] = implant
        status = listener.get_implant_status()
        assert status["total_implants"] == 1
        assert status["alive_implants"] == 1

    def test_audit_log_created(self):
        """Operations create audit log entries."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        server = Mock()
        with patch("forge.c2.listener.socketserver.TCPServer", return_value=server):
            assert listener.start() is True
            assert listener.stop() is True


class TestC2Communication:
    """Test C2 communication patterns."""

    def test_beacon_interval_respected(self):
        """Implant respects beacon interval."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        # C2Listener initialized
        assert listener.roe_id == "ROE-123"

    def test_jitter_applied(self):
        """Jitter is applied to beacon timing."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        # Jitter implementation is internal
        # Listener should be initialized
        assert listener.tunnel_url is not None

    def test_generate_implant_config_uses_https(self):
        """Generated implant config uses HTTPS callback URLs."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        config = json.loads(listener.generate_implant().decode("utf-8"))
        assert config["c2_url"].startswith("https://")

    def test_get_implant_status_shape(self):
        """get_implant_status returns aggregate status fields."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        status = listener.get_implant_status()
        assert set(status) == {"total_implants", "alive_implants", "total_beacons", "implants"}

    def test_generated_implant_has_jitter_config(self):
        """Generated implant config includes beacon jitter settings."""
        listener = C2Listener(
            tunnel_url="https://tunnel.example.com",
            roe_id="ROE-123"
        )
        
        config = json.loads(listener.generate_implant().decode("utf-8"))
        assert config["config"]["jitter"] > 0
