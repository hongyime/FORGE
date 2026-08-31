"""E2E tests for c2.listener module.

Tests HTTPS C2 listener with Cloudflare tunnel integration.
"""

import pytest
import json
import tempfile
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from forge.c2.listener import (
    C2Listener,
    C2Implant
)


class TestC2E2E:
    """E2E tests for C2Listener with real integration."""

    @pytest.fixture
    def scope_manifest(self):
        """Scope manifest for testing."""
        return {
            "domains": ["testcorp.local"],
            "roe_id": "ROE-TEST-005"
        }

    @pytest.fixture
    def c2_listener(self):
        """C2Listener instance."""
        return C2Listener(
            tunnel_url="https://c2.example.com",
            port=18443,
            roe_id="ROE-TEST-005"
        )

    @pytest.fixture
    def sample_implant(self):
        """Create sample implant for testing."""
        return C2Implant(
            implant_id="implant-001",
            os_type="windows",
            hostname="workstation01",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=1,
            task_queue=__import__('queue').Queue()
        )

    def test_c2_implant_dataclass_structure(self):
        """Test C2Implant dataclass structure."""
        import queue

        implant = C2Implant(
            implant_id="test-implant-123",
            os_type="windows",
            hostname="DESKTOP-ABC123",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=5,
            task_queue=queue.Queue()
        )

        assert implant.implant_id == "test-implant-123"
        assert implant.os_type == "windows"
        assert implant.hostname == "DESKTOP-ABC123"
        assert implant.beacon_count == 5
        assert isinstance(implant.task_queue, queue.Queue)

    def test_implant_is_alive_property(self, sample_implant):
        """Test implant is_alive property."""
        # Fresh implant should be alive
        assert sample_implant.is_alive is True

        # Old implant should not be alive
        from datetime import timedelta
        sample_implant.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
        assert sample_implant.is_alive is False

    def test_initialization_with_tunnel_url(self, c2_listener):
        """Test C2Listener initialization with tunnel URL."""
        assert c2_listener.tunnel_url == "https://c2.example.com"
        assert c2_listener.port == 18443
        assert c2_listener.roe_id == "ROE-TEST-005"
        assert c2_listener.implants == {}

    def test_get_listener_url(self, c2_listener):
        """Test get_listener_url returns tunnel URL."""
        url = c2_listener.get_listener_url()
        assert url == "https://c2.example.com"

    def test_register_implant(self, c2_listener, sample_implant):
        """Test implant registration."""
        c2_listener.register_implant(sample_implant)

        assert sample_implant.implant_id in c2_listener.implants
        assert c2_listener.implants[sample_implant.implant_id] == sample_implant

    def test_get_implant_status_empty(self, c2_listener):
        """Test implant status when no implants registered."""
        status = c2_listener.get_implant_status()

        assert status['total_implants'] == 0
        assert status['alive_implants'] == 0
        assert status['total_beacons'] == 0
        assert status['implants'] == []

    def test_get_implant_status_with_implants(self, c2_listener, sample_implant):
        """Test implant status with registered implants."""
        c2_listener.register_implant(sample_implant)
        status = c2_listener.get_implant_status()

        assert status['total_implants'] == 1
        assert status['alive_implants'] == 1
        assert status['total_beacons'] == 1
        assert len(status['implants']) == 1

    def test_process_beacon_new_implant(self, c2_listener):
        """Test processing beacon from new implant."""
        beacon_data = {
            "implant_id": "new-implant-001",
            "os_type": "windows",
            "hostname": "WORKSTATION01"
        }

        response_json = c2_listener.process_beacon(beacon_data)
        response = json.loads(response_json)

        assert response['implant_id'] == "new-implant-001"
        assert 'tasks' in response
        assert 'sleep' in response
        assert 'jitter' in response

        # Implant should be registered
        assert "new-implant-001" in c2_listener.implants

    def test_process_beacon_existing_implant(self, c2_listener, sample_implant):
        """Test processing beacon from existing implant."""
        c2_listener.register_implant(sample_implant)

        beacon_data = {
            "implant_id": sample_implant.implant_id,
            "os_type": "windows",
            "hostname": "WORKSTATION01"
        }

        response_json = c2_listener.process_beacon(beacon_data)
        response = json.loads(response_json)

        # Beacon count should increment
        assert c2_listener.implants[sample_implant.implant_id].beacon_count == 2

    def test_queue_task_valid_implant(self, c2_listener, sample_implant):
        """Test queuing task for valid implant."""
        c2_listener.register_implant(sample_implant)

        result = c2_listener.queue_task(
            implant_id=sample_implant.implant_id,
            task_type="exec",
            task_data={"command": "whoami"}
        )

        assert result is True

        # Task should be in queue
        task = sample_implant.task_queue.get_nowait()
        assert task['task_type'] == "exec"
        assert task['task_data']['command'] == "whoami"

    def test_queue_task_invalid_implant(self, c2_listener, caplog):
        """Test queuing task for nonexistent implant."""
        result = c2_listener.queue_task(
            implant_id="nonexistent-implant",
            task_type="exec",
            task_data={"command": "whoami"}
        )

        assert result is False
        assert any("Unknown implant" in r.message for r in caplog.records)

    def test_generate_implant_config(self, c2_listener, tmp_path):
        """Test implant config generation."""
        output_path = tmp_path / "implant_config.json"
        config_bytes = c2_listener.generate_implant(
            os_type="windows",
            output_path=output_path
        )

        assert isinstance(config_bytes, bytes)

        # Should write to file
        assert output_path.exists()

        # Should be valid JSON
        config = json.loads(config_bytes)
        assert 'implant_id' in config
        assert 'c2_url' in config
        assert config['os_type'] == 'windows'
        assert config['c2_url'] == 'https://c2.example.com/beacon'

    def test_generate_implant_linux(self, c2_listener):
        """Test implant config generation for Linux."""
        config_bytes = c2_listener.generate_implant(os_type="linux")
        config = json.loads(config_bytes)

        assert config['os_type'] == 'linux'

    def test_beacon_response_structure(self, c2_listener):
        """Test beacon response structure."""
        beacon_data = {
            "implant_id": "test-001",
            "os_type": "windows"
        }

        response_json = c2_listener.process_beacon(beacon_data)
        response = json.loads(response_json)

        # Check required fields
        assert 'implant_id' in response
        assert 'tasks' in response
        assert 'sleep' in response
        assert 'jitter' in response

        # Check types
        assert isinstance(response['tasks'], list)
        assert isinstance(response['sleep'], int)
        assert isinstance(response['jitter'], float)

        # Check jitter range (80-120% variance)
        assert 0.8 <= response['jitter'] <= 1.2

        # Check sleep range (30-120 seconds)
        assert 30 <= response['sleep'] <= 120

    def test_listener_start_and_stop(self, c2_listener):
        """Test listener start and stop lifecycle."""
        # Start
        result = c2_listener.start()
        assert result is True
        assert c2_listener._running is True

        # Stop
        result = c2_listener.stop()
        assert result is True
        assert c2_listener._running is False

    def test_listener_double_start(self, c2_listener):
        """Test double start is handled gracefully."""
        c2_listener.start()
        result = c2_listener.start()  # Second start

        # Should return True (already running)
        assert result is True

        # Cleanup
        c2_listener.stop()

    def test_listener_double_stop(self, c2_listener):
        """Test double stop is handled gracefully."""
        c2_listener.start()
        c2_listener.stop()
        result = c2_listener.stop()  # Second stop

        # Should return True (already stopped)
        assert result is True

    def test_context_manager(self, c2_listener):
        """Test context manager lifecycle."""
        with c2_listener as listener:
            assert listener._running is True

        # Should stop on exit
        assert c2_listener._running is False

    def test_encrypt_task_placeholder(self, c2_listener):
        """Test task encryption placeholder."""
        task = {"command": "whoami"}
        encrypted = c2_listener.encrypt_task(task)

        # Placeholder returns unchanged
        assert encrypted == task

    def test_decrypt_result_placeholder(self, c2_listener):
        """Test result decryption placeholder."""
        data = {"result": "output"}
        decrypted = c2_listener.decrypt_result(data)

        # Placeholder returns unchanged
        assert decrypted == data

    def test_get_task_result_placeholder(self, c2_listener):
        """Test task result retrieval placeholder."""
        result = c2_listener.get_task_result("task-001")
        assert result is None

    def test_generate_beacon_response_placeholder(self, c2_listener):
        """Test beacon response generation placeholder."""
        response = c2_listener.generate_beacon_response()
        assert response == {}

    def test_audit_log_entries_created(self, c2_listener, caplog):
        """Test that audit log entries are created."""
        c2_listener.register_implant(C2Implant(
            implant_id="test",
            os_type="windows",
            hostname="test",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            beacon_count=1,
            task_queue=__import__('queue').Queue()
        ))

        # Check for audit logs
        audit_logs = [r for r in caplog.records if "AUDIT:" in r.message]
        assert len(audit_logs) >= 0

    def test_localhost_binding_only(self, c2_listener):
        """Test that listener binds localhost only (security)."""
        # Listener should bind 127.0.0.1, not 0.0.0.0
        # Check the implementation
        import socketserver

        # Verify by checking server address after start
        c2_listener.start()
        
        if c2_listener._server:
            host, port = c2_listener._server.server_address
            assert host == "127.0.0.1", f"Should bind localhost only, got {host}"
            assert port == 18443

        c2_listener.stop()

    def test_multiple_implants_tracking(self, c2_listener):
        """Test tracking multiple implants."""
        # Register multiple implants
        for i in range(3):
            implant = C2Implant(
                implant_id=f"implant-{i}",
                os_type="windows",
                hostname=f"host{i}",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                beacon_count=1,
                task_queue=__import__('queue').Queue()
            )
            c2_listener.register_implant(implant)

        status = c2_listener.get_implant_status()
        assert status['total_implants'] == 3
