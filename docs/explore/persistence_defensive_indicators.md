# Persistence Defensive Indicators

> **Scope**: This document catalogs the **defensive** indicators FORGE surfaces
> for detecting adversary persistence. FORGE **does not** implement persistence
> features — persistence-as-a-feature is provided by **StayKit** and is out of
> scope here. This file focuses exclusively on **detection**.

---

## 1. Boundary: FORGE vs. StayKit

| Concern                              | FORGE (this repo) | StayKit          |
| ------------------------------------ | ----------------- | ---------------- |
| Establishing persistence             | ❌ Out of scope   | ✅ Feature owner |
| Registry Run key writes              | ❌                | ✅               |
| Scheduled task creation              | ❌                | ✅               |
| WMI subscription install             | ❌                | ✅               |
| **Detecting** persistence artifacts  | ✅                | ❌               |
| **Auditing** persistence-adjacent events | ✅            | ❌               |
| **Graph analysis** of exposure       | ✅ (via BloodHound integration) | ❌ |

FORGE is a **defensive toolkit**. Everything below is about observation,
correlation, and alerting — never about implementation.

---

## 2. BloodHound / SharpHound Detection Capabilities

FORGE leverages BloodHound-compatible graph data to reason about
**where persistence would be most impactful** and **which accounts/hosts to
watch**. See <https://bloodhound.readthedocs.io/> for schema and collector
reference.

### 2.1 Session Collection — `HasSession` edges

- SharpHound collects **active user sessions** on computers.
- `HasSession` edges reveal *where* a user is currently logged in.
- Defensive use: detect a user account appearing on hosts it has never touched
  before (lateral pivot precursor to persistence).

### 2.2 Admin Relationships — `AdminTo`, `HasAdmin`

- `AdminTo` maps a principal → computers where it is a local admin.
- `HasAdmin` is the inverse edge.
- Defensive use: rank hosts by **admin blast radius**. A persistence artifact
  on a high-`AdminTo` node is far more dangerous than on a leaf workstation.

### 2.3 GPO Relationships — `GpLink`, `Contains`

- GPOs linked to OUs (`GpLink`) show which policy objects apply to which
  containers.
- Defensive use: **GPO abuse** is a stealthy persistence vector. Any GPO with
  write access from a non-Tier-0 principal is a red flag. Watch for
  `GenericAll` / `GenericWrite` / `WriteDacl` on GPO nodes.

### 2.4 Kerberoastable Accounts — service principal patterns

- Accounts with SPNs are enumerable via `Get-DomainUser -SPN` (SharpHound
  captures this).
- Defensive use: kerberoastable service accounts are common persistence
  footholds. Baseline the set; alert on **new** SPNs or new members of
  privileged groups.

### 2.5 Session Timing Anomalies

- Compare `HasSession` snapshots over time.
- Defensive use: sessions established at unusual hours, on unusual hosts, or
  by accounts historically inactive → correlate with audit events below.

---

## 3. FORGE Audit Log Capabilities

FORGE ingests and normalizes Windows Security / System / WMI-Activity event
logs. The following event classes are captured and available for correlation.

### 3.1 Scheduled Task Events

| Event ID | Meaning                                    |
| -------- | ------------------------------------------ |
| 4698     | A scheduled task was **created**           |
| 4699     | A scheduled task was **deleted**           |
| 4700     | A scheduled task was **enabled**           |
| 4701     | A scheduled task was **disabled**          |
| 4702     | A scheduled task was **updated**           |

Correlate 4698/4702 with the principal SID and the task XML action — any task
whose action is `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, or a
LOLBin is worth an alert.

### 3.2 Service Creation Events

| Event ID | Source          | Meaning                             |
| -------- | --------------- | ----------------------------------- |
| 7045     | System log      | A **new service** was installed     |
| 4697     | Security log    | A service was installed (audited)   |

Watch for services with `ImagePath` pointing to user-writable directories,
unsigned binaries, or `svchost -k` groups that do not match a known template.

### 3.3 Registry Autostart Modifications

Monitor writes under:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (Userinit, Shell)
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

Enable Security event **4657** (registry value modified) with SACLs on these
keys, or ingest Sysmon event **13** (registry value set).

### 3.4 Startup Folder File Creation

Monitor file creates in:

- `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`

Sysmon event **11** (FileCreate) filtered to these paths is the canonical
source. Correlate with the creating process image.

### 3.5 WMI Subscription Events

WMI-Activity operational log:

- Event **5857** — provider loaded
- Event **5860** — temporary event consumer registered
- Event **5861** — **permanent** event consumer registered (highest signal)

Sysmon events **19 / 20 / 21** cover WmiEventFilter, WmiEventConsumer, and
WmiEventConsumerToFilter respectively. Permanent WMI subscriptions are a
classic fileless persistence vector — any 5861 or Sysmon 21 should page.

---

## 4. MITRE ATT&CK Coverage

References: <https://attack.mitre.org/>

### 4.1 T1053 — Scheduled Task / Job

- **Sub-techniques of interest**: T1053.005 (Scheduled Task).
- **FORGE detection**: Security events 4698/4699/4700/4701/4702 plus Sysmon
  event 1 for `schtasks.exe` / `taskeng.exe` / `svchost.exe -k netsvcs`
  spawning suspicious children.
- **Signal**: task actions invoking scripting hosts or LOLBins; tasks created
  by non-admin principals; tasks running as `SYSTEM` but authored by a user.
- Reference: <https://attack.mitre.org/techniques/T1053/>

### 4.2 T1547 — Boot or Logon Autostart Execution

- **Sub-techniques of interest**: T1547.001 (Registry Run Keys / Startup
  Folder), T1547.004 (Winlogon Helper DLL), T1547.009 (Shortcut Modification).
- **FORGE detection**: registry SACL / Sysmon 13 on the Run-key set in §3.3;
  Sysmon 11 on the startup folders in §3.4; hashing and signing checks on
  Userinit / Shell values.
- **Signal**: any Run-key write from a non-installer parent process; startup
  folder writes by browsers, Office, or scripting engines.
- Reference: <https://attack.mitre.org/techniques/T1547/>

### 4.3 T1546 — Event Triggered Execution

- **Sub-techniques of interest**: T1546.003 (WMI Event Subscription),
  T1546.008 (Accessibility Features), T1546.012 (IFEO Injection).
- **FORGE detection**: WMI-Activity 5861 and Sysmon 19/20/21 for WMI;
  registry monitoring on `Image File Execution Options` for IFEO; file
  integrity monitoring on accessibility binaries (`sethc.exe`, `utilman.exe`,
  `osk.exe`, `magnify.exe`, `narrator.exe`, `displayswitch.exe`, `atbroker.exe`).
- **Signal**: any permanent WMI consumer whose CommandLineTemplate contains
  a scripting host; any IFEO `Debugger` value on a system binary.
- Reference: <https://attack.mitre.org/techniques/T1546/>

### 4.4 T1574 — Hijack Execution Flow

- **Sub-techniques of interest**: T1574.001 (DLL Search Order Hijacking),
  T1574.002 (DLL Side-Loading), T1574.007 (Path Interception by PATH
  Environment Variable), T1574.011 (Services Registry Permissions Weakness).
- **FORGE detection**: Sysmon event 7 (ImageLoad) with signer/path anomaly
  filters; environment variable modification via registry SACLs on
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`;
  service DACL audits from BloodHound + `sc sdshow` snapshots.
- **Signal**: unsigned DLL loaded from a user-writable directory adjacent to
  a signed binary; PATH prepended with a writable directory; service binary
  path pointing to a directory writable by a non-privileged principal.
- Reference: <https://attack.mitre.org/techniques/T1574/>

---

## 5. Detection Recommendations

Actionable patterns — at least ten distinct signals, each independently
alertable:

1. **Session anomaly graph query**: diff yesterday's `HasSession` snapshot
   against today's; alert on any user appearing on a computer in a different
   OU than their historical set.
2. **Admin-path proximity scoring**: rank every persistence event by the
   shortest BloodHound path from the affected host to a Tier-0 asset. Short
   paths escalate first.
3. **Registry Run-key baseline**: hash all Run-key values at agent install;
   alert on any addition, deletion, or hash change.
4. **Startup folder allowlist**: maintain a per-image allowlist for the two
   startup paths in §3.4; alert on any unlisted file create.
5. **Scheduled task action classifier**: parse task XML from event 4698 and
   alert when `<Command>` resolves to a known LOLBin.
6. **Service install correlation**: on every 7045 / 4697, cross-reference
   `ImagePath` against BloodHound `AdminTo` — a new service on a high-admin
   host is a P1.
7. **Permanent WMI subscription page**: any WMI-Activity 5861 or Sysmon 21
   goes straight to on-call with the consumer's CommandLineTemplate.
8. **IFEO debugger watch**: alert on any write to
   `HKLM\...\Image File Execution Options\*\Debugger`.
9. **Accessibility binary integrity**: hourly hash check on the accessibility
   binaries listed in §4.3; alert on any mismatch against the known-good
   Microsoft catalog.
10. **DLL load anomaly**: Sysmon event 7 where the loaded DLL is unsigned
    **and** located within the loading process's working directory **and**
    the loading process is signed by Microsoft.
11. **Kerberoastable delta**: nightly diff of SPN-bearing accounts; alert on
    new SPNs, especially on accounts recently added to privileged groups.
12. **GPO write-permission audit**: BloodHound query for non-Tier-0
    principals with `GenericAll` / `GenericWrite` / `WriteDacl` /
    `WriteOwner` on any GPO node.
13. **Cross-signal correlation window**: within any 10-minute window, if a
    single host emits ≥2 of {4698, 7045, Sysmon 13 on Run key, Sysmon 21},
    treat as a composite persistence event.
14. **Baseline deviation**: maintain per-host baselines of expected autostart
    counts (tasks, services, Run keys, WMI consumers). Alert on absolute
    deltas that exceed 2σ over a 30-day window.

---

## 6. References

- BloodHound documentation: <https://bloodhound.readthedocs.io/>
- MITRE ATT&CK: <https://attack.mitre.org/>
  - T1053: <https://attack.mitre.org/techniques/T1053/>
  - T1547: <https://attack.mitre.org/techniques/T1547/>
  - T1546: <https://attack.mitre.org/techniques/T1546/>
  - T1574: <https://attack.mitre.org/techniques/T1574/>
- FORGE audit schema: see the audit-log ingestion module in this repository
  for field-level normalization of the event IDs cataloged in §3.
