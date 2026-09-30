# Competitive Upgrade: FORGE Automated Offensive Capabilities

*Research date: 2026-08-30*

## Current Repo Summary

- **Category**: Deterministic authorized ASM (Attack Surface Management) pipeline with scoped offensive capabilities
- **Target user**: Security operators, red teams, penetration testers with explicit ROE/scope authorization
- **Current capabilities**:
  - Windows credential extraction (SAM/SYSTEM/SECURITY hives via impacket secretsdump)
  - Linux persistence installation (11 methods: cron, systemd, rc.local, bashrc, profile, init.d, motd, sshrc)
  - Reverse shell generation (12 methods: bash, nc, ncat, python, php, perl, ruby, curl, wget, socat, tlong)
  - Sudo hijack attack (password interception + curl exfiltration)
  - Stealth mode (hidden files, crontab override, timestomp, IPv4 decimal encoding)
  - Web server poison (PHP reverse shells in writable directories)
  - Cleanup/anti-forensics (remove all persistence by RHOST)
  - Attack path analysis (Networkx graph, choke-point/blast-radius identification)
- **Main constraints**: ROE/scope-gated, audit-logged, deterministic, non-destructive by default, requires explicit `--attack-mode` and `FORGE_ROE_ID` for live execution
- **Stack**: Python 3.11+, impacket, networkx, click/typer CLI, SQLite/Postgres, Redis (distributed mode)
- **Maturity**: Production deployment (self-host, Docker Compose, Helm chart supported)

## Comparison Targets

| Target | Why included | Sources |
|---|---|---|
| **Mimikatz** | Industry standard for Windows credential extraction, pass-the-hash, Kerberos ticket manipulation | [GitHub gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz), [Vectra AI Mimikatz deep dive](https://www.vectra.ai/topics/mimikatz), [MITRE ATT&CK S0002](https://attack.mitre.org/software/S0002/) |
| **STS-token-decoder** | AWS STS token decoding/forensics - fills cloud credential analysis gap | [GitHub talbeerysec/STS-token-decoder](https://github.com/talbeerysec/STS-token-decoder) |
| **BloodHound** | Attack path discovery in Active Directory and hybrid Azure AD environments | [SpecterOps Blog 2024-08-02](https://specterops.io/blog/2024/08/02/hybrid-attack-paths-new-views/), [BloodHound v5.13.0 release notes](https://bloodhound.specterops.io/resources/release-notes/2024-08-01-v5-13-0) |
| **CrackMapExec/NetExec** | SMB enumeration, credential harvesting, password spraying at scale | [MITRE ATT&CK S0488](https://attack.mitre.org/software/S0488/), [Yunolay Blog 2025-12-25](https://yunolay.com/netexec-crackmapexec/) |
| **Covenant** | .NET C2 framework with web interface, multi-user collaboration, dynamic compilation | [GitHub cobbr/Covenant](https://github.com/cobbr/Covenant), [MITRE ATT&CK S1155](https://attack.mitre.org/software/S1155), [SpecterOps Blog 2025-02-17](https://specterops.io/blog/2025/02/17/entering-a-covenant-net-command-and-control/) |

## Capability Matrix

| Capability | FORGE | Mimikatz | STS-token-decoder | BloodHound | CrackMapExec | Covenant | Upgrade Potential |
|---|---|---|---|---|---|---|---|
| **Credential extraction - Windows** | Strong (impacket secretsdump) | Strong (sekurlsa::logonpasswords, LSASS memory) | N/A | N/A | Strong (SAM/LSA dump via impacket) | Strong (Mimikatz integration) | **Low** - FORGE already uses impacket equivalent |
| **Credential extraction - AWS STS tokens** | Missing | N/A | Strong (decode session tokens, recover region public keys) | N/A | N/A | N/A | **High** - Gap FORGE should fill |
| **Pass-the-hash** | Missing | Strong (sekurlsa::pth) | N/A | Graph support | Strong (-H NTLM hash) | Via Mimikatz | **Medium** - FORGE extracts hashes but not PT HASH execution |
| **Pass-the-ticket** | Missing | Strong (kerberos::ptt) | N/A | Graph support | Kerberos support (-k) | Via Mimikatz | **Medium** - Useful for AD environments |
| **Golden ticket** | Missing | Strong (kerberos::golden) | N/A | Attack path visualization | N/A | Via Mimikatz | **Low** - Requires KRBTGT hash, niche |
| **DCSync** | Missing | Strong (lsadump::dcsync) | N/A | Edge in graph | N/A | Via Mimikatz | **Low** - Requires DA, detected easily |
| **Attack path discovery - AD** | Partial (graph scoring, choke-point detection) | N/A | N/A | Strong (cypher queries, hybrid AD/Azure paths) | N/A | N/A | **Medium** - FORGE has graph, lacks AD-specific queries |
| **Attack path discovery - Cloud** | Strong (cloud asset graph, IAM chains) | N/A | N/A | Hybrid paths (v5.13.0+) | N/A | N/A | **Low** - FORGE already strong here |
| **Lateral movement** | Missing (persistence only) | N/A | N/A | Path finding | Strong (SMB relay, psexec, wmi) | Strong (remote shell) | **High** - Gap in post-exploitation |
| **Persistence** | Strong (11 doors, 12 methods, stealth) | N/A | N/A | N/A | N/A | Strong (Grunt implants) | **Low** - FORGE already strong |
| **Sudo hijack** | Strong (password interception) | N/A | N/A | N/A | N/A | N/A | **Low** - FORGE unique capability |
| **Stealth/evasion** | Strong (decimal IP, hidden files, timestomp) | Partial (mimidrv) | N/A | N/A | Limited | Obfuscation (ConfuserEx) | **Low** - FORGE already strong |
| **Web interface** | Strong (React SPA + HTMX tabs) | N/A | N/A | Strong | Strong (nxcdb) | Strong | **Low** - FORGE already strong |
| **Multi-user collaboration** | Strong (workspaces, audit trail) | N/A | N/A | Enterprise only | nxcdb | Strong | **Low** - FORGE already strong |
| **Password spraying** | Missing | N/A | N/A | N/A | Strong (--continue-on-success) | N/A | **Medium** - Optimize for existing credential stuffing |
| **SMB/network enumeration** | Partial (subfinder, httpx, nuclei) | N/A | N/A | N/A | Strong (shares, logged-on users, sessions) | N/A | **Low** - FORGE uses ProjectDiscovery suite |
| **C2 infrastructure** | Missing | N/A | N/A | N/A | N/A | Strong (listeners, profiles, grunts) | **Medium** - FORGE not a C2 framework |

## Key Findings

1. **FORGE's credential extraction matches CrackMapExec's impacket-based approach** but lacks deeper Windows credential material coverage from Mimikatz. FORGE dumps SAM/SYSTEM hives via impacket secretsdump API (no subprocess), which is quieter than running secretsdump.exe but less comprehensive than LSASS memory access (sekurlsa::logonpasswords). Source: `forge/utils/post/collectors/win_creds.py` lines 1-205, Vectra AI Mimikatz deep dive (dated 2024).

2. **FORGE lacks cloud credential forensics for AWS STS tokens.** STS-token-decoder (47 stars, 4 forks, 9 commits as of 2026-08-30) parses AWS session tokens, extracts account ID, creation timestamp, region, encrypted user data, and can recover region public keys for offline verification. FORGE extracts AWS keys from artifacts (`forge/automation_secret_auto_feed.py`) but does not decode the session token structure itself. Source: `forge/automation_secret_auto_feed.py` lines 1-407; STS-token-decoder GitHub README.

3. **FORGE's attack path analysis competes with BloodHound but lacks hybrid AD/Azure path coverage.** BloodHound v5.13.0 (2024-08-01) introduced hybrid attack paths showing synced users between on-prem AD and Entra ID via `SyncedToADUser`/`SyncedToEntraUser` edges. FORGE has cloud asset graph scoring (`forge/phase4/attack_path.py` line 23+ imports cloud graph metadata) but no AD-specific cypher queries or hybrid path primitives. Source: SpecterOps blog "Hybrid Attack Paths" 2024-08-02, BloodHound v5.13.0 release notes.

4. **FORGE's persistence capabilities exceed CrackMapExec and Covenant.** FORGE supports 11 persistence methods across 12 reverse shell techniques with stealth modes (IPv4 decimal encoding, hidden files, crontab override). CrackMapExec focuses on network enumeration and credential dumping, not persistence. Covenant uses Grunt implants with dynamic compilation but fewer persistence doors. FORGE's Linper module is comprehensive for Linux persistence. Source: `forge/hardening/linper_offensive.py` lines 1-200.

5. **FORGE lacks lateral movement primitives.** CrackMapExec provides psexec, wmiexec, smbexec, atexec, and dcomexec for remote command execution. Covenant offers remote shell through Grunt implants. FORGE can install persistence but cannot move from host to host without operator SSH/manual execution. This is a gap for red team workflows. Source: MITRE ATT&CK S0488, SpecterOps Covenant blog 2025-02-17.

6. **STS-token-decoder's approach is forensics-first, not exploitation.** It decodes session tokens offline to extract metadata (account ID, region, creation time) and verify signatures with recovered public keys. This is useful for: (a) analyzing leaked tokens without live AWS API calls, (b) identifying token age/rotation for stale credential findings, (c) determining which region keys validate against (multi-region analysis). FORGE's key validation does live AWS STS caller-identity checks but misses this offline forensic capability. Source: STS-token-decoder GitHub README, usage examples.

7. **FORGE's sudo hijack attack is unique and not found in competitor tools.** The Linper module intercepts sudo password entries via alias injection and exfiltrates to attacker-controlled RHOST via curl with decimal-encoded IP for stealth. This is a niche capability not present in Mimikatz, CrackMapExec, BloodHound, or Covenant. Source: `forge/hardening/linper_offensive.py` lines 400-438 (sudo hijack implementation).

## Recommended Upgrades

### Do Now

| Upgrade | Inspired by | Why | Effort | Next |
|---|---|---|---|---|
| **Add AWS STS token decoder module** | STS-token-decoder | FORGE already extracts AWS keys; decoding session tokens would add forensic analysis without live API calls (offline token age, account ID, region verification). Enables deeper credential findings from artifacts without AWS permissions. | Low (7-day implementation) | `to-spec` |
| **Add Pass-the-hash execution capability** | Mimikatz, CrackMapExec | FORGE extracts NTLM hashes from SAM dumps but cannot USE them for lateral movement. Adding PT HASH execution would close the loop: credential extraction → hash reuse → lateral movement. Requires explicit ROE/scope gating. | Medium (2-week implementation) | `to-spec` |
| **Add password spraying protection/optimization module** | CrackMapExec | Password spraying is common in engagements. FORGE could add: (a) lockout policy check before spraying, (b) safe throttle limits, (c) --continue-on-success flag for existing credential stuffing workflows. | Low (5-day implementation) | `to-spec` |
| **Add lateral movement primitives (SSH jump, SMB relay detection)** | CrackMapExec, BloodHound | FORGE can install persistence but cannot move between hosts programmatically. Adding: (a) SSH jump via key material, (b) SMB relay detection from credential findings, (c) lateral movement path suggestion from asset graph. | Medium (2-week implementation) | `to-spec` |

### Do Next

| Upgrade | Inspired by | Why | Effort | Next |
|---|---|---|---|---|
| **Add Kerberos ticket operations (pass-the-ticket, ticket harvesting)** | Mimikatz, BloodHound | FORGE lacks Kerberos ticket handling despite AD credential coverage. Adding: (a) kirbi file parsing, (b) ticket injection for PT HASH on Windows, (c) Kerberoast candidate identification from discovered SPNs. | Medium (3-week implementation) | `to-spec` |
| **Add hybrid AD/Azure attack path analysis** | BloodHound v5.13.0 | BloodHound shows paths across synced users between AD and Entra ID. FORGE could add: (a) `SyncedToADUser`/`SyncedToEntraUser` edge detection from cloud audit findings, (b) hybrid path queries in attack path module, (c) sync-enabled user exposure scoring. | High (4-week implementation) | `to-spec` |
| **Add Mimikatz DCShadow/DCSync detection (defensive)** | Mimikatz | DCSync is a high-severity technique (T1003.006). FORGE could add: (a) DCSync detection from DC logs (Event ID 4662), (b) DCShadow detection from replication metadata anomalies, (c) mitigation recommendations in remediation workflow. | Medium (2-week implementation) | `to-spec` |
| **Add Golden/Silver ticket detection capability** | Mimikatz, BloodHound | Golden tickets are invisible to normal authentication logs (forged TGTs). FORGE could add: (a) ticket lifetime anomaly detection, (b) KRBTGT hash change monitoring, (c) golden ticket indicators in audit findings. | Medium (3-week implementation) | `to-spec` |

### Explore

| Upgrade | Inspired by | Why | Risk | Next |
|---|---|---|---|---|
| **Integrate Mimikatz as optional backend for deeper credential extraction** | Mimikatz | LSASS memory access (sekurlsa::logonpasswords) extracts more credential material than SAM/SYSTEM hive dumps (plaintext passwords on older Windows, Kerberos keys, DPAPI masterkeys). However: requires SeDebugPrivilege, triggers EDR alerts, and is blocked by Credential Guard. High risk, high reward for engagements where allowed. | High (EDR detection, OPSEC risk, requires SYSTEM privileges, Credential Guard blocks) | `prototype` local test first |
| **Add C2 listener capabilities for long-haul persistence** | Covenant | FORGE installs persistence but lacks persistent C2 channel. Adding: (a) HTTPS listener profiles, (b) encrypted key exchange, (c) Grunt-style implant communication could enable long-term monitoring. However: significantly expands scope beyond ASM toolkit. | High (scope creep, becomes full C2 framework rather than ASM tool) | `wayfinder` to assess strategic fit |
| **Add zero-click exploitation chain automation** | NodeZero, Pentera | Autonomous attack simulation tools (NodeZero, Pentera) auto-chain exploits from initial access to domain admin. FORGE could integrate: (a) exploit chaining from vulnerability findings, (b) auto-lateral movement after credential extraction, (c) kill-chain automation.However: high OPSEC risk, requires extensive testing, may over-automate beyond ROE scope. | High (automation may exceed ROE scope, false positives cause damage, requires extensive safety gates) | `wayfinder` to assess ethical/scope boundaries |
| **Add LAPS password extraction** | Mimikatz, CrackMapExec | LAPS (Local Administrator Password Solution) stores rotated local admin passwords in AD. Mimikatz and CrackMapExec can dump these via LDAP. FORGE could extract from AD findings for lateral movement. | Medium (requires AD read access, LAPS deployment, may be considered "grey hat" even with ROE) | `to-spec` with explicit ROE gating |

## Do Not Copy

- **Mimikatz LSASS memory dump capability directly**: FORGE already extracts NTLM hashes via impacket secretsdump API (quieter than subprocess secretsdump.exe). Direct LSASS memory access with sekurlsa::logonpasswords provides more credential material but triggers EDR, requires SeDebugPrivilege, and is blocked by Credential Guard. FORGE should remain "quieter" by default but could add LSASS dump as an explicit --high-risk-opsec flag for authorized engagements.

- **CrackMapExec's aggressive password spraying defaults**: CrackMapExec defaults to continuing after first success (--continue-on-success flag). FORGE should default to conservative/safe behavior (stop on lockout warning, check lockout policy first) to avoid account lockouts during engagements.

- **Covenant's Grunt implant model**: Covenant uses persistent implants with listeners. FORGE's persistence model (Linper) is already comprehensive for Linux. Adding persistent implants moves FORGE closer to C2 framework territory, which may conflict with its ASM toolkit identity. Recommend keeping Linper as-is and not adding persistent C2 infrastructure.

- **BloodHound's complex cypher query ecosystem**: BloodHound excels at AD attack path queries but requires deep cypher knowledge. FORGE should prefer simpler, deterministic attack path scoring (critical assets, choke points, blast radius) over exposing full cypher query interface to operators.

## Proposed Next Step

**Immediate action**: Create implementation spec for **AWS STS token decoder module** (supported by STS-token-decoder's offline forensic approach, fits FORGE's artifact-analysis workflow, low effort, high value for credential findings).

**Parallel action**: Scope **pass-the-hash execution capability** (closes credential extraction → lateral movement loop, requires explicit ROE gating, medium effort).

**Strategic decision needed**: Assess whether FORGE should remain an ASM toolkit with offensive capabilities or expand toward full C2/red team automation. This affects whether lateral movement primitives (SSH jump, SMB relay) align with FORGE's identity or require a separate project.

---

## Appendix: Key Offensive Capability Mappings

### FORGE → MITRE ATT&CK Techniques

| FORGE Capability | MITRE ATT&CK Technique |
|---|---|
| WinCredCollector (SAM dump) | T1003.002 (Security Account Manager) |
| Linper persistence | T1053.003 (Scheduled Task: Cron), T1037.004 (RC Scripts), T1136.001 (Create Account: Local Account) |
| Reverse shell | T1059.004 (Command and Scripting Interpreter: Bash), T1059.006 (Python) |
| Sudo hijack | T1547.009 (Boot or Logon Autostart Execution: Shortcut Modification), T1556.001 (Domain Controller Authentication) |
| Cloud asset graph | T1580 (Pre-OS Boot: Steganography - cloud metadata discovery) |
| Attack path analysis | T1588.006 (Obtain Capabilities: Vulnerabilities), T1595.002 (Active Scanning: Vulnerability Scanning) |

### Competitor → MITRE ATT&CK Techniques

| Competitor | MITRE ATT&CK Techniques |
|---|---|
| Mimikatz | T1003.001 (LSASS Memory), T1550.002 (Pass-the-Hash), T1550.003 (Pass-the-Ticket), T1558.001 (Golden Ticket), T1003.006 (DCSync) |
| CrackMapExec | T1021.002 (SMB/Windows Admin Shares), T1110.003 (Password Spraying), T1003 (OS Credential Dumping) |
| Covenant | T1071.001 (Web Protocols), T1059.001 (PowerShell), T1573.002 (Asymmetric Cryptography) |
| BloodHound | T1087.002 (Domain Account), T1069.002 (Domain Groups), T1482 (Domain Trust Discovery) |

---

*Research sources dated: Mimikatz (Vectra AI 2024, MITRE ATT&CK S0002), STS-token-decoder (GitHub fetched 2026-08-30), BloodHound (SpecterOps blog 2024-08-02, release notes 2024-08-01), CrackMapExec (MITRE ATT&CK S0488, Yunolay blog 2025-12-25), Covenant (MITRE ATT&CK S1155, SpecterOps blog 2025-02-17).*
