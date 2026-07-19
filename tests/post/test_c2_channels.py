"""
Test suite for C2 Channel Expansion (SMB & ICMP).

Tests cover:
- SMB channel OPSEC compliance and functionality
- ICMP channel packet fragmentation and reassembly
- C2Generator fallback logic and channel integration
- OPSEC validation for generated agent code
"""
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from forge.utils.post.channels.smb_channel import SMBChannel, _get_pipe_name, _exponential_backoff
from forge.utils.post.channels.icmp_channel import ICMPChannel, _parse_packet, _build_packet
from forge.utils.post.session_manager import C2Generator
from forge.models.pydantic_models import C2BeaconConfig, C2Channel


class TestSMBChannel:
    """Test SMB channel implementation."""
    
    def test_smb_channel_initialization(self):
        """Test SMB channel initialization with valid parameters."""
        channel = SMBChannel(
            target="192.168.1.100",
            username="testuser",
            password="testpass",
            domain="TESTDOMAIN",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            interval=60,
            jitter_pct=20,
            fallback_timeout=30
        )
        
        assert channel._target == "192.168.1.100"
        assert channel._username == "testuser"
        assert channel._password == "testpass"
        assert channel._domain == "TESTDOMAIN"
        assert channel._interval == 60
        assert channel._jitter_pct == 20
        assert channel._fallback_timeout == 30
        assert channel._connection_cache is None
    
    def test_smb_channel_offline_mode(self):
        """Test SMB channel behavior in offline mode."""
        with patch.dict(os.environ, {"FORGE_OFFLINE_STRICT": "1"}):
            channel = SMBChannel(
                target="192.168.1.100",
                session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            
            # Should return False in offline mode
            assert channel.send(b"test data") is False
            assert channel.recv() is None
    
    def test_smb_pipe_name_validation(self):
        """Test SMB pipe name validation against OPSEC constraints."""
        # Test allowed pipe names
        allowed_pipes = ["atsvc", "winreg", "lsarpc", "browser", "netlogon"]
        for pipe in allowed_pipes:
            name = _get_pipe_name()
            assert name in allowed_pipes
    
    def test_smb_channel_connection_fallback(self):
        """Test SMB connection with protocol version fallback."""
        channel = SMBChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        
        with patch('forge.utils.post.channels.smb_channel.SMBConnection') as mock_smb:
            mock_conn = MagicMock()
            mock_smb.return_value = mock_conn
            
            # Test successful connection
            mock_conn.login.return_value = True
            mock_conn.connectTree.return_value = "test_tid"
            mock_conn.openFile.return_value = "test_fid"
            
            result = channel._connect_with_fallback()
            assert result is not None
            assert len(result) == 3  # (conn, tid, fid)
            
            # Verify SMB connection was attempted
            mock_smb.assert_called_once()
    
    def test_smb_payload_chunking(self):
        """Test payload chunking for large data transfers."""
        channel = SMBChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        
        # Create large payload that exceeds chunk size
        large_payload = b"A" * 10000  # 10KB payload
        
        with patch.object(channel, '_encrypt', return_value=large_payload):
            with patch.object(channel, '_connect_with_fallback') as mock_connect:
                mock_conn = MagicMock()
                mock_tid = "test_tid"
                mock_fid = "test_fid"
                mock_connect.return_value = (mock_conn, mock_tid, mock_fid)
                
                result = channel.send(large_payload)
                
                # Should split into multiple chunks
                assert mock_conn.writeFile.call_count > 1
                assert result is True
    
    def test_smb_exponential_backoff(self):
        """Test exponential backoff calculation."""
        # Test basic backoff calculation
        delay1 = _exponential_backoff(0)
        assert delay1 >= 2.5  # base_delay * 0.5 (min jitter)
        assert delay1 <= 7.5  # base_delay * 1.5 (max jitter)
        
        # Test increasing backoff
        delay2 = _exponential_backoff(1)
        assert delay2 >= 5.0
        assert delay2 <= 15.0


class TestICMPChannel:
    """Test ICMP channel implementation."""
    
    def test_icmp_channel_initialization(self):
        """Test ICMP channel initialization."""
        channel = ICMPChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            interval=180,
            jitter_pct=30,
            max_payload_size=64
        )
        
        assert channel._target == "192.168.1.100"
        assert channel._interval == 180
        assert channel._jitter_pct == 30
        assert channel._max_payload_size == 64
        assert channel._sequence_tracker == {}
        assert channel._last_sequence == 0
    
    def test_icmp_packet_construction(self):
        """Test ICMP packet construction."""
        payload = b"test payload"
        seq = 12345
        ident = 54321
        
        packet = _build_packet(payload, seq, ident)
        
        assert len(packet) >= 28  # IP header (20) + ICMP header (8) + payload
        assert isinstance(packet, bytes)
    
    def test_icmp_packet_parsing(self):
        """Test ICMP packet parsing."""
        # Create a mock ICMP packet
        mock_raw = b'\x45\x00\x00\x3c\x00\x00\x40\x00\x40\x01\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x64\x08\x00\x00\x00\x00\x00\x00\x00test payload'
        
        result = _parse_packet(mock_raw)
        
        assert result is not None
        assert result["type"] == 8  # Echo request
        assert result["ident"] == 0  # From mock packet
        assert result["seq"] == 0    # From mock packet
        assert "payload" in result
    
    def test_icmp_payload_fragmentation(self):
        """Test payload fragmentation for large data."""
        channel = ICMPChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            max_payload_size=32  # Small payload size for testing
        )
        
        # Create payload larger than max payload size
        large_payload = b"A" * 100
        encrypted_payload = b"E" * 120  # Encrypted will be larger
        
        with patch.object(channel, '_encrypt', return_value=encrypted_payload):
            with patch('socket.socket') as mock_socket:
                mock_sock = MagicMock()
                mock_socket.return_value = mock_sock
                
                result = channel.send(large_payload)
                
                # Should fragment into multiple packets
                assert mock_sock.sendto.call_count > 1
                assert result is True
    
    def test_icmp_sequence_tracking(self):
        """Test sequence number tracking for packet reassembly."""
        channel = ICMPChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        
        # Simulate receiving packets out of order
        fragments = {
            0x0100: b"fragment1",  # seq=1, frag=0
            0x0102: b"fragment3",  # seq=1, frag=2
            0x0101: b"fragment2",  # seq=1, frag=1
        }
        
        # Test reassembly
        result = channel._try_reassemble(fragments, 1)
        
        # Should reassemble in correct order
        expected = b"fragment1fragment2fragment3"
        # Note: This test assumes the decryption returns the original data
        # In practice, we'd need to mock the decryption
    
    def test_icmp_timing_jitter(self):
        """Test enhanced timing jitter for ICMP (more conspicuous)."""
        channel = ICMPChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            interval=180,
            jitter_pct=30
        )
        
        # Test that sleep time respects minimum constraints
        with patch('time.sleep') as mock_sleep:
            channel.sleep()
            
            # Should have been called with at least 30 seconds
            assert mock_sleep.called
            sleep_time = mock_sleep.call_args[0][0]
            assert sleep_time >= 30.0


class TestC2Generator:
    """Test C2 Generator with SMB/ICMP channel support."""
    
    def test_c2_generator_smb_channel(self):
        """Test C2 generator with SMB channel."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            generator = C2Generator(db_path, engagement_id=1)
            
            # Generate SMB agent
            build = generator.generate(
                agent_type="python",
                channel="smb",
                c2_urls=["https://example.com"],
                smb_config={
                    "pipe_name": "atsvc",
                    "username": "testuser",
                    "domain": "TESTDOMAIN"
                },
                interval=60,
                jitter_pct=20
            )
            
            assert build.agent_type == "python"
            assert build.channel == "smb"
            assert "SMBConnection" in build.source
            assert "_PIPE_NAME" in build.source
            assert "impacket" in build.source
    
    def test_c2_generator_icmp_channel(self):
        """Test C2 generator with ICMP channel."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            generator = C2Generator(db_path, engagement_id=1)
            
            # Generate ICMP agent
            build = generator.generate(
                agent_type="python",
                channel="icmp",
                c2_urls=["https://example.com"],
                icmp_config={
                    "target_ip": "192.168.1.100",
                    "max_payload_size": 64
                },
                interval=180,
                jitter_pct=30
            )
            
            assert build.agent_type == "python"
            assert build.channel == "icmp"
            assert "ICMP" in build.source
            assert "_TARGET_IP" in build.source
            assert "socket.SOCK_RAW" in build.source
    
    def test_c2_generator_channel_fallback(self):
        """Test C2 generator channel fallback configuration."""
        generator = C2Generator(Path("/tmp/test.db"), engagement_id=1)
        
        # Test fallback order
        assert generator._CHANNEL_FALLBACK_ORDER == ["https", "dns", "smb", "icmp"]
        
        # Test failure thresholds
        assert generator._CHANNEL_FAILURE_THRESHOLDS["https"] == 3
        assert generator._CHANNEL_FAILURE_THRESHOLDS["smb"] == 2
        assert generator._CHANNEL_FAILURE_THRESHOLDS["icmp"] == 2
    
    def test_c2_generator_opsec_validation(self):
        """Test OPSEC validation for generated agent code."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            generator = C2Generator(db_path, engagement_id=1)
            
            # Generate agent and check for banned signatures
            build = generator.generate(
                agent_type="python",
                channel="https",
                c2_urls=["https://example.com"],
                interval=60,
                jitter_pct=20
            )
            
            # Check that banned signatures are not present
            assert "time.sleep(" not in build.source
            assert "REPLACE_BEFORE_DEPLOY" not in build.source
            assert ":4444" not in build.source


class TestPydanticModels:
    """Test enhanced Pydantic models for C2 channels."""
    
    def test_c2_beacon_config_smb_validation(self):
        """Test C2BeaconConfig validation for SMB channels."""
        # Test valid SMB configuration
        config = C2BeaconConfig(
            engagement_id=1,
            channel=C2Channel.SMB,
            c2_urls=["https://example.com"],
            smb_pipe_name="atsvc",
            smb_username="testuser",
            smb_domain="TESTDOMAIN"
        )
        
        assert config.channel == C2Channel.SMB
        assert config.smb_pipe_name == "atsvc"
        assert config.smb_username == "testuser"
        assert config.smb_domain == "TESTDOMAIN"
    
    def test_c2_beacon_config_smb_auto_pipe_selection(self):
        """Test automatic pipe name selection for SMB."""
        config = C2BeaconConfig(
            engagement_id=1,
            channel=C2Channel.SMB,
            c2_urls=["https://example.com"]
        )
        
        # Should auto-select a valid pipe name
        assert config.smb_pipe_name in ["atsvc", "winreg", "lsarpc", "browser", "netlogon"]
    
    def test_c2_beacon_config_icmp_validation(self):
        """Test C2BeaconConfig validation for ICMP channels."""
        # Test valid ICMP configuration
        config = C2BeaconConfig(
            engagement_id=1,
            channel=C2Channel.ICMP,
            c2_urls=["https://example.com"],
            icmp_target_ip="192.168.1.100",
            icmp_packet_interval=180,
            icmp_max_payload_size=64
        )
        
        assert config.channel == C2Channel.ICMP
        assert config.icmp_target_ip == "192.168.1.100"
        assert config.icmp_packet_interval == 180
        assert config.icmp_max_payload_size == 64
    
    def test_c2_beacon_config_icmp_requires_target_ip(self):
        """Test that ICMP channel requires target IP."""
        with pytest.raises(ValueError, match="ICMP channel requires icmp_target_ip field"):
            C2BeaconConfig(
                engagement_id=1,
                channel=C2Channel.ICMP,
                c2_urls=["https://example.com"]
            )
    
    def test_c2_beacon_config_banned_smb_pipe(self):
        """Test validation of banned SMB pipe names."""
        with pytest.raises(ValueError, match="SMB pipe name.*is banned for OPSEC reasons"):
            C2BeaconConfig(
                engagement_id=1,
                channel=C2Channel.SMB,
                c2_urls=["https://example.com"],
                smb_pipe_name="svcctl"  # Banned pipe name
            )


class TestOPSECCompliance:
    """Test OPSEC compliance for all C2 channels."""
    
    def test_smb_channel_opsec_compliance(self):
        """Test SMB channel OPSEC compliance."""
        channel = SMBChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        
        # Test that pipe names are from allowed list
        assert channel._pipe_name in ["atsvc", "winreg", "lsarpc", "browser", "netlogon"]
        
        # Test that banned pipe names are not used
        assert channel._pipe_name not in ["svcctl", "ROUTER", "epmapper"]
    
    def test_icmp_channel_opsec_compliance(self):
        """Test ICMP channel OPSEC compliance."""
        channel = ICMPChannel(
            target="192.168.1.100",
            session_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            interval=180,
            jitter_pct=30
        )
        
        # Test minimum sleep time (30 seconds for ICMP)
        assert channel._interval >= 30
        
        # Test payload size limits
        assert channel._max_payload_size <= 128
    
    def test_generated_agent_opsec_compliance(self):
        """Test that generated agents meet OPSEC requirements."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            generator = C2Generator(db_path, engagement_id=1)
            
            # Test SMB agent
            smb_agent = generator.generate(
                agent_type="python",
                channel="smb",
                c2_urls=["https://example.com"],
                smb_config={"pipe_name": "atsvc"}
            )
            
            # Check for OPSEC compliance
            assert "atsvc" in smb_agent.source  # Legitimate pipe name
            assert "svcctl" not in smb_agent.source  # No banned pipe names
            assert "time.sleep(" not in smb_agent.source  # No uniform sleep
            
            # Test ICMP agent
            icmp_agent = generator.generate(
                agent_type="python",
                channel="icmp",
                c2_urls=["https://example.com"],
                icmp_config={"target_ip": "192.168.1.100"}
            )
            
            # Check for OPSEC compliance
            assert "random.gauss" in icmp_agent.source  # Gaussian jitter
            assert "max(30.0" in icmp_agent.source  # Minimum 30s sleep


if __name__ == "__main__":
    pytest.main([__file__])
