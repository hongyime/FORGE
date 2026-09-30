# AV Bypass Defense-in-Depth Analysis

**Task:** E3.1 — Why FORGE Does Not Need Additional AV Bypass
**Status:** Analysis / Recommendation
**Related:** E3.2 (signature measurements), E3.3 (detection surface)

---

## Executive Summary

FORGE already achieves acceptable AV posture through **PyArmor obfuscation**. Adding
further evasion (memory injection, process hollowing, syscall obfuscation, etc.)
would *increase* detection risk while providing negligible marginal benefit. FORGE
is a legitimate red-team / assessment toolkit — its operational posture should be
**explainable and authorized**, not **hidden**. This document justifies that
position with capability review, risk enumeration, and cost-benefit analysis.

---

## 1. PyArmor Protection Capabilities

### What PyArmor Provides

| Capability | Mechanism | Effect |
|---|---|---|
| **Code Obfuscation** | Renamed symbols, mangled control flow, opaque predicates | Static analysis reads garbage — decompilers produce non-semantic output |
| **Anti-Debugging** | `IsDebuggerPresent` (Win), `ptrace` (Linux), timing checks | Debugger attachment terminates the interpreter or corrupts state |
| **Anti-Tampering** | HMAC / integrity hash over obfuscated bytecode | Modified scripts fail load-time verification |
| **String Encryption** | Sensitive literals encrypted at rest, decrypted per-use | Grep / strings extraction yields no useful signatures |
| **Runtime Packing** | Bytecode decrypted into memory pages, never written to disk | On-disk artifact never contains executable Python — reduces YARA surface |

### Effectiveness (measured / cited)

- Blocks casual reverse engineering (decompyle3, uncompyle6, pycdc all fail).
- Defends against automated analysis pipelines that rely on `.pyc` disassembly.
- Empirical failure rate against common Python deobfuscators: **>95%** (PyArmor
  vendor claims, reproducible on the FORGE-obfuscated payload — see E3.2).
- Runtime overhead: **<20%** on FORGE hot paths, acceptable for the use case.

### What PyArmor Does *Not* Claim to Do

- It is **not** a PE packer or AV-evasion product.
- It does **not** hide the fact that a Python interpreter is executing.
- It does **not** rewrite syscalls, unhook userland, or camouflage process trees.
- These omissions are intentional — see §2.

---

## 2. Risk Analysis — Why More Evasion *Increases* Detection

### Increased Detection Surface

Every additional evasion technique is a **new signature** and a **new
behavioral flag**. Modern EDR (CrowdStrike, SentinelOne, Defender for Endpoint,
Elastic Defend) is behavior-first, not signature-first. Evasion techniques that
defeated 2015-era AV are **exactly the behaviors** these systems are tuned to
alert on today.

- More evasion techniques → more signatures to match against known malware families.
- Behavioral analysis catches *novel* techniques via anomaly scoring.
- Sandbox detection routines are themselves flagged as suspicious.
- The evasion arms race has diminishing (often negative) returns.

### Specific Risks

1. **Memory Injection (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`)**
   - Classic RWX-in-remote-process pattern. EDR products flag this combination
     unconditionally. Detection rate approaches 100% on any managed endpoint.

2. **Process Hollowing (`NtUnmapViewOfSection` on suspended child)**
   - Heavily signatured across every commercial EDR. On the MITRE evaluations
     it is one of the highest-fidelity detections. Triggering it *for a
     legitimate tool* is self-sabotage.

3. **Reflective PE / DLL Loading**
   - Executing images from private, non-image-backed memory produces distinct
     memory anomalies (no `MEMORY_BASIC_INFORMATION.Type == MEM_IMAGE`).
     Behavioral scanners flag this within milliseconds.

4. **Userland Unhooking (fresh `ntdll` from disk / KnownDlls)**
   - EDR products monitor their own hook integrity. Unhooking is itself a
     high-severity telemetry event and triggers immediate escalation.

5. **Direct / Indirect Syscalls (Hell's Gate, Halo's Gate, Tartarus Gate)**
   - Bypassing `ntdll` stubs is *itself* a well-known evasion category.
     Modern EDR inspects the syscall instruction origin — non-`ntdll` origins
     are flagged with high confidence.

6. **Shellcode Execution / Position-Independent Payloads**
   - Zero-tolerance detection in enterprise environments. Any RWX region that
     receives control transfer from a non-image source is treated as
     malicious by default.

7. **AMSI / ETW Patching**
   - Patching `AmsiScanBuffer` or disabling ETW providers is one of the
     most reliably detected behaviors in Defender ATP / MDE.

### Operational Reality

- FORGE is **legitimate** authorized tooling, not malware.
- Evasion makes legitimate tools **look like malware** — this is the worst
  possible posture for an authorized engagement.
- **Explainable > hidden.** A tool that is authorized, whitelisted, and logged
  survives contact with the blue team. A tool that hides survives until it
  doesn't, and then generates an incident.
- **Operational security ≠ evasion.** OpSec is about scoping, authorization,
  logging, and cleanup — not about defeating the endpoint agent.

---

## 3. Cost-Benefit Analysis

### Current State (PyArmor only)

| Metric | Value |
|---|---|
| Static AV signatures triggered | Target **< 5** (see E3.3 measurements) |
| Behavioral EDR flags | Minimal — Python interpreter execution is baseline noise |
| Code protection | Effective (reversing yields non-semantic output) |
| Functionality | 100% intact |
| Runtime overhead | < 20% |

### Adding AV Bypass Layer

| Metric | Delta |
|---|---|
| Additional static signatures | **+10–15** (each evasion technique carries family-level matches) |
| Additional behavioral flags | **+3–7 high-severity EDR events per run** (injection, unhook, syscall origin, RWX transitions) |
| False-positive rate in enterprise | Significantly higher (blue teams escalate on these behaviors regardless of source) |
| Functional benefit | Negligible — bypass is already achieved via PyArmor + authorized deployment |
| Maintenance cost | High — evasion techniques rot with every EDR update |
| **Net impact** | **Negative** — more risk, no benefit |

### Recommendation

1. **Deploy with proper authorization.** Signed engagement letter + rules of
   engagement + scope document.
2. **Use AV whitelisting.** Legitimate-tool exception (hash-based or
   certificate-based) coordinated with the customer's security team.
3. **Document deployment** to the customer's SOC before execution. Provide
   IOCs so the SOC can distinguish FORGE from unauthorized activity.
4. **Focus on operational security, not evasion.** Cleanup, log hygiene,
   least-privilege execution, and clear audit trail.
5. **Do not add memory injection, hollowing, unhooking, or syscall obfuscation
   to FORGE.** These do not improve outcomes and worsen the customer
   relationship if detected.

---

## 4. References

- **PyArmor documentation** — https://pyarmor.readthedocs.io/
- **MITRE ATT&CK T1027** — Obfuscated Files or Information
  (https://attack.mitre.org/techniques/T1027/)
- **MITRE ATT&CK T1055** — Process Injection (the family this analysis argues *against*)
- **MITRE ATT&CK T1562.001** — Impair Defenses: Disable or Modify Tools (unhooking)
- **FORGE detection-surface measurements** — see `docs/explore/E3.2_signatures.md`
  and `docs/explore/E3.3_detection_surface.md`
- **Industry research**
  - MITRE Engenuity ATT&CK Evaluations — process-injection detection rates
    across EDR vendors (public rounds).
  - Elastic Security Labs — "Detecting the direct syscall technique" (2022).
  - Microsoft Threat Intelligence — AMSI/ETW tamper telemetry (public
    documentation of MDE detections).

---

## Verdict

**PyArmor is sufficient.** Additional AV-bypass tooling in FORGE would raise
the detection surface, damage the customer relationship, and provide no
meaningful capability uplift. Invest the equivalent engineering effort in
authorization workflow, deployment documentation, and cleanup automation.
