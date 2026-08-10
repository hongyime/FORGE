"""
forge/utils/post/channels — C2 channel backends (Module 5-G sub-components).

All channels implement the BaseChannel interface:
  send(data: bytes) -> bool
  recv(timeout: int) -> bytes | None
  close() -> None

Channel selection guidance:
  HTTP/S — default; domain fronting supported; curl_cffi Chrome fingerprint.
  DNS    — DoH via 1.1.1.1; label ≤ 40 chars; cover traffic mixing.
  SMB    — named pipes from Phase 0 LOLBin DB; atsvc/winreg only.
  ICMP   — 64-byte payload fragments; vary sequence/identifier per packet.
"""

from __future__ import annotations

from forge.utils.post.channels.http_channel import HTTPChannel
from forge.utils.post.channels.dns_channel import DNSChannel
from forge.utils.post.channels.smb_channel import SMBChannel
from forge.utils.post.channels.icmp_channel import ICMPChannel

__all__ = ["HTTPChannel", "DNSChannel", "SMBChannel", "ICMPChannel"]
