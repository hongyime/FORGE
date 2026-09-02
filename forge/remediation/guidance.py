"""Persistence remediation guidance (E1.3).

DEFENSIVE ONLY. Produces MITRE ATT&CK-linked remediation guidance for
persistence findings surfaced by ``forge.hardening.persistence_hardening``
(E1.2). Each remediation function returns a dict conforming to the
``forge.remediation.guidance.v1`` schema:

    {
        "schema_version": "forge.remediation.guidance.v1",
        "threat_type":       "<MITRE technique ID>",
        "threat_name":       "<MITRE technique name>",
        "platforms":         ["windows", "linux"],
        "detection_confirm": [<str>, ...],
        "remediation_steps": [<str>, ...],
        "references":        [<https URL>, ...],
    }

This module does not execute commands, mutate systems, or reference
offensive techniques. It only emits guidance strings for security teams
to review and apply through their normal change-control process.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

SCHEMA_VERSION = "forge.remediation.guidance.v1"

MITRE_BASE = "https://attack.mitre.org/techniques"


def _guidance(
    threat_type: str,
    threat_name: str,
    detection_confirm: List[str],
    remediation_steps: List[str],
    references: List[str],
    platforms: List[str],
) -> Dict[str, Any]:
    """Build a schema-conformant guidance dict."""
    return {
        "schema_version": SCHEMA_VERSION,
        "threat_type": threat_type,
        "threat_name": threat_name,
        "platforms": list(platforms),
        "detection_confirm": list(detection_confirm),
        "remediation_steps": list(remediation_steps),
        "references": list(references),
    }


def remediate_scheduled_task(finding: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Remediation guidance for T1053 - Scheduled Task/Job.

    Covers Windows scheduled tasks (T1053.005) and Linux cron (T1053.003).
    ``finding`` may be a PersistenceFinding-shaped mapping (with ``location``,
    ``platform``, etc.) to tailor guidance; when omitted, generic guidance is
    returned.
    """
    platforms = ["windows", "linux"]
    detection_confirm = [
        "Confirm the scheduled task or cron entry exists at the reported location "
        "and record its owner, trigger, and command line as evidence.",
        "Windows: run `schtasks /query /fo LIST /v /tn <TaskName>` and export the "
        "task XML with `schtasks /query /xml /tn <TaskName>`.",
        "Linux: inspect `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,"
        "weekly,monthly}/`, and per-user spools under `/var/spool/cron/` for the "
        "reported entry; capture file hash and mtime.",
        "Correlate task/cron creation time with authentication and process-creation "
        "logs (Windows Event ID 4698 / auditd `execve`) to identify the responsible "
        "account.",
    ]
    remediation_steps = [
        "Disable the task before removal so execution stops immediately. "
        "Windows: `schtasks /change /tn <TaskName> /disable`. "
        "Linux: comment out the cron line or `chmod -x` the drop-in file.",
        "Preserve a forensic copy of the task definition, referenced script, and "
        "any invoked binary before deletion.",
        "Delete the persistence entry. Windows: `schtasks /delete /tn <TaskName> /f`. "
        "Linux: remove the offending line from crontab via `crontab -e` or delete "
        "the drop-in file under `/etc/cron.d/`.",
        "Remove or quarantine the payload the task invoked and rotate any "
        "credentials the executing account could reach.",
        "Restrict who may create scheduled tasks: on Windows apply the "
        "'Log on as a batch job' user right and audit the Task Scheduler ACL; on "
        "Linux set `/etc/cron.allow` and remove world-writable cron paths.",
        "Enable ongoing detection: Windows Event IDs 4698/4699/4700/4701/4702, "
        "and Linux auditd rules on `/etc/crontab`, `/etc/cron.d/`, and "
        "`/var/spool/cron/`.",
    ]
    references = [
        f"{MITRE_BASE}/T1053/",
        f"{MITRE_BASE}/T1053/003/",
        f"{MITRE_BASE}/T1053/005/",
        "https://attack.mitre.org/mitigations/M1028/",
        "https://attack.mitre.org/mitigations/M1018/",
    ]
    return _guidance(
        threat_type="T1053",
        threat_name="Scheduled Task/Job",
        detection_confirm=detection_confirm,
        remediation_steps=remediation_steps,
        references=references,
        platforms=platforms,
    )


def remediate_autorun(finding: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Remediation guidance for T1547 - Boot or Logon Autostart Execution.

    Covers Windows Run/RunOnce registry keys, Startup folders, services set to
    auto-start, and Linux systemd/init autostart. ``finding`` may be a
    PersistenceFinding-shaped mapping.
    """
    platforms = ["windows", "linux"]
    detection_confirm = [
        "Enumerate autorun registry entries on Windows and confirm the reported "
        "value: `reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` "
        "and the matching `RunOnce`, `Winlogon\\Userinit`, `Winlogon\\Shell`, and "
        "per-user HKCU hives.",
        "Windows: also inspect Startup folders "
        "`%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup` and the "
        "all-users equivalent under `%ProgramData%`.",
        "Linux: list enabled units with `systemctl list-unit-files --state=enabled` "
        "and inspect `/etc/systemd/system/`, `/etc/init.d/`, `/etc/rc.local`, and "
        "`/etc/modules-load.d/` for the reported entry.",
        "Record the file hash, signer, and last-modified time of the referenced "
        "binary or unit file before making changes.",
    ]
    remediation_steps = [
        "Preserve a forensic copy of the registry key/value or unit file and the "
        "binary it references.",
        "Remove the autorun entry. Windows: `reg delete <hive>\\...\\Run /v "
        "<ValueName> /f` for both HKLM and HKCU where present, or delete the "
        "Startup shortcut. Linux: `systemctl disable --now <unit>` and remove "
        "the unit file from `/etc/systemd/system/`; comment offending lines from "
        "`/etc/rc.local`.",
        "Delete or quarantine the referenced payload and rotate credentials for "
        "any account it could access.",
        "Harden autorun locations: restrict write access on Run/RunOnce keys and "
        "Startup folders with ACLs; on Linux set `/etc/systemd/system/` to "
        "`root:root 0755` and unit files to `0644`, and monitor with file "
        "integrity monitoring (FIM).",
        "Deploy detection: Windows Sysmon Event ID 12/13/14 on Run keys, Event ID "
        "4657 for registry auditing; Linux auditd watches on "
        "`/etc/systemd/system/` and `/etc/rc.local`.",
    ]
    references = [
        f"{MITRE_BASE}/T1547/",
        f"{MITRE_BASE}/T1547/001/",
        f"{MITRE_BASE}/T1547/002/",
        f"{MITRE_BASE}/T1547/006/",
        "https://attack.mitre.org/mitigations/M1024/",
        "https://attack.mitre.org/mitigations/M1022/",
    ]
    return _guidance(
        threat_type="T1547",
        threat_name="Boot or Logon Autostart Execution",
        detection_confirm=detection_confirm,
        remediation_steps=remediation_steps,
        references=references,
        platforms=platforms,
    )


def remediate_event_trigger(finding: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Remediation guidance for T1546 - Event Triggered Execution.

    Covers WMI event subscriptions, image file execution options, Windows
    accessibility features, and Linux .bashrc/.profile trap-style triggers.
    """
    platforms = ["windows", "linux"]
    detection_confirm = [
        "Windows: enumerate WMI event subscriptions with "
        "`Get-WMIObject -Namespace root\\subscription -Class __EventFilter`, "
        "`__EventConsumer`, and `__FilterToConsumerBinding`. Capture the "
        "consumer command line as evidence.",
        "Windows: inspect Image File Execution Options via "
        "`reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image "
        "File Execution Options\"` for unexpected `Debugger` values.",
        "Linux: audit user shell init files "
        "(`~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`) and system-wide "
        "`/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc` for `trap`, "
        "`PROMPT_COMMAND`, or unexpected `source`/`eval` lines.",
        "Record file hashes and modification times of every triggering file and "
        "referenced payload before mutation.",
    ]
    remediation_steps = [
        "Preserve forensic copies of WMI filter/consumer/binding objects, IFEO "
        "registry values, or shell init files, and of any referenced payload.",
        "Windows: remove the WMI subscription with "
        "`Get-WMIObject -Namespace root\\subscription -Class "
        "__FilterToConsumerBinding | Where-Object {...} | Remove-WMIObject` for "
        "the binding, then the matching `__EventConsumer` and `__EventFilter`. "
        "Delete unauthorized `Debugger` values from Image File Execution Options.",
        "Linux: remove or revert the malicious lines in the shell init file to "
        "the known-good baseline; restore ownership `root:root 0644` for "
        "system-wide profiles and `0644` for per-user files.",
        "Delete or quarantine the referenced payload and rotate credentials for "
        "accounts whose sessions could have executed the trigger.",
        "Restrict who may create WMI subscriptions and edit IFEO: apply least "
        "privilege on the `root\\subscription` namespace and audit the "
        "`Image File Execution Options` key ACL.",
        "Deploy detection: Sysmon Event IDs 19/20/21 for WMI activity, Event ID "
        "4657 for IFEO registry writes, and auditd watches on shell init files.",
    ]
    references = [
        f"{MITRE_BASE}/T1546/",
        f"{MITRE_BASE}/T1546/003/",
        f"{MITRE_BASE}/T1546/004/",
        f"{MITRE_BASE}/T1546/012/",
        "https://attack.mitre.org/mitigations/M1040/",
        "https://attack.mitre.org/mitigations/M1024/",
    ]
    return _guidance(
        threat_type="T1546",
        threat_name="Event Triggered Execution",
        detection_confirm=detection_confirm,
        remediation_steps=remediation_steps,
        references=references,
        platforms=platforms,
    )


def remediate_hijack_execution(finding: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Remediation guidance for T1574 - Hijack Execution Flow.

    Covers DLL search-order hijack, PATH interception, LD_PRELOAD /
    LD_LIBRARY_PATH abuse, and service/binary permission weaknesses.
    """
    platforms = ["windows", "linux"]
    detection_confirm = [
        "Windows: verify signatures and paths of DLLs loaded by the affected "
        "service or application with `sigcheck.exe -e -u <path>` and compare "
        "the loaded module list (Process Explorer / `tasklist /m`) against a "
        "known-good baseline.",
        "Windows: audit service binary paths for unquoted paths and writable "
        "directories using `wmic service get name,pathname,startmode` and "
        "`icacls <path>`.",
        "Linux: inspect `/etc/ld.so.preload`, per-user and system `LD_PRELOAD` / "
        "`LD_LIBRARY_PATH` exports, and unit files' `Environment=` directives.",
        "Linux: verify PATH ordering for the affected user "
        "(`echo $PATH`) and check for world-writable directories that precede "
        "system paths.",
        "Record hashes, owners, and permissions of every hijack-candidate file "
        "(DLL, .so, service binary) before making changes.",
    ]
    remediation_steps = [
        "Preserve forensic copies of the hijacking artifact (rogue DLL, shared "
        "object, or PATH-shadowed binary) and record the parent process that "
        "loaded it.",
        "Remove the hijacking artifact: delete the rogue DLL/.so, unset the "
        "malicious `LD_PRELOAD`/`LD_LIBRARY_PATH`, and clear "
        "`/etc/ld.so.preload` entries. Windows: delete the DLL from the abused "
        "search path.",
        "Fix the underlying weakness: quote service paths on Windows "
        "(`sc config <svc> binPath= \"\\\"C:\\Path With Spaces\\svc.exe\\\"\"`), "
        "remove write permissions from directories on the DLL search path, and "
        "on Linux set `/etc/ld.so.preload` to `root:root 0644` and remove "
        "writable dirs from system PATH.",
        "Rotate credentials for any service account whose token could have been "
        "used by the hijacked process.",
        "Rebuild trust: reinstall the affected application from a known-good "
        "package, re-run `ldconfig` on Linux, and validate signatures on all "
        "loaded modules.",
        "Deploy detection: Sysmon Event ID 7 (image loaded) alerting on "
        "unsigned or unexpected paths, and auditd `open` watches on "
        "`/etc/ld.so.preload` and system library directories.",
    ]
    references = [
        f"{MITRE_BASE}/T1574/",
        f"{MITRE_BASE}/T1574/001/",
        f"{MITRE_BASE}/T1574/006/",
        f"{MITRE_BASE}/T1574/007/",
        f"{MITRE_BASE}/T1574/009/",
        "https://attack.mitre.org/mitigations/M1038/",
        "https://attack.mitre.org/mitigations/M1022/",
    ]
    return _guidance(
        threat_type="T1574",
        threat_name="Hijack Execution Flow",
        detection_confirm=detection_confirm,
        remediation_steps=remediation_steps,
        references=references,
        platforms=platforms,
    )


# Map MITRE technique IDs (and E1.2 PersistenceCheck attack_ids that fall under
# each parent technique) to the remediation function that should generate
# guidance for them.
_TECHNIQUE_ROUTER: Dict[str, Callable[[Optional[Mapping[str, Any]]], Dict[str, Any]]] = {
    "T1053": remediate_scheduled_task,
    "T1547": remediate_autorun,
    "T1546": remediate_event_trigger,
    "T1574": remediate_hijack_execution,
}


def _parent_technique(attack_id: str) -> str:
    """Return the parent MITRE technique (e.g. ``T1053.003`` -> ``T1053``)."""
    return attack_id.split(".", 1)[0] if attack_id else ""


def guidance_for_finding(finding: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Return remediation guidance for a single PersistenceFinding-shaped dict.

    ``finding`` must have an ``attack_id`` (or ``technique_id``) field. Sub-
    techniques such as ``T1053.003`` route to the parent technique's function.
    Returns ``None`` when no remediation function is registered for the
    technique.
    """
    attack_id = str(finding.get("attack_id") or finding.get("technique_id") or "")
    parent = _parent_technique(attack_id)
    func = _TECHNIQUE_ROUTER.get(parent)
    if func is None:
        return None
    return func(finding)


def guidance_from_persistence_audit(audit: Mapping[str, Any]) -> Dict[str, Any]:
    """Auto-generate remediation guidance from an E1.2 persistence audit report.

    Accepts either:
      * the output of ``forge.hardening.persistence_hardening.detect_persistence_indicators``
        (has top-level ``categories``), or
      * the output of ``generate_harden_report`` (has ``categories`` under the
        ``categories`` key).

    Emits a per-technique guidance list deduplicated on ``threat_type``, plus a
    per-finding list preserving the source location for each finding.
    """
    categories = _extract_categories(audit)

    seen_techniques: Dict[str, Dict[str, Any]] = {}
    per_finding: List[Dict[str, Any]] = []

    for cat_name, cat_data in categories.items():
        attack_id = str(cat_data.get("attack_id") or "")
        parent = _parent_technique(attack_id)
        func = _TECHNIQUE_ROUTER.get(parent)
        if func is None:
            continue
        for check in cat_data.get("checks", []) or []:
            finding = {
                "category": cat_name,
                "attack_id": attack_id,
                "location": check.get("location"),
                "severity": check.get("severity"),
                "platform": check.get("platform"),
            }
            g = func(finding)
            per_finding.append(
                {
                    "category": cat_name,
                    "location": check.get("location"),
                    "severity": check.get("severity"),
                    "guidance": g,
                }
            )
            seen_techniques.setdefault(g["threat_type"], g)

    return {
        "schema_version": "forge.remediation.guidance.audit.v1",
        "source_schema": audit.get("schema_version"),
        "engagement_id": audit.get("engagement_id"),
        "techniques": list(seen_techniques.values()),
        "findings": per_finding,
        "summary": {
            "technique_count": len(seen_techniques),
            "finding_count": len(per_finding),
        },
    }


def _extract_categories(audit: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    """Return the categories mapping from either audit report shape."""
    cats = audit.get("categories")
    if isinstance(cats, Mapping) and cats and all(
        isinstance(v, Mapping) and "checks" in v for v in cats.values()
    ):
        return cats  # detect_persistence_indicators shape
    # generate_harden_report shape: categories -> {..., categories: {...}}
    if isinstance(cats, Mapping) and "categories" in cats:
        inner = cats.get("categories")
        if isinstance(inner, Mapping):
            return inner
    return {}


__all__ = [
    "SCHEMA_VERSION",
    "remediate_scheduled_task",
    "remediate_autorun",
    "remediate_event_trigger",
    "remediate_hijack_execution",
    "guidance_for_finding",
    "guidance_from_persistence_audit",
]
