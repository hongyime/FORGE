# Spec: FORGE Competitive Upgrade - Do Now Tier

**Date**: 2026-08-30  
**Author**: Sisyphus (GLM 5.2)  
**Status**: DRAFT  
**Estimated Effort**: ~4.5 weeks (parallelizable to ~3 weeks)

---

## Problem

FORGE's offensive capabilities are siloed. The credential extraction loop breaks after Windows credential harvesting - no path to lateral movement, no cloud credential forensics, no hash reuse. Public IP exposure in reverse shells creates OPSEC risk. Capabilities work in isolation rather than a continuous automated offensive loop.

**Evidence**:
- `forge/hardening/linper_offensive.py` installs persistence but cannot move laterally
- `forge/utils/post/collectors/win_creds.py` extracts NTLM hashes but cannot use them
- No Cloudflare tunnel integration for callback infrastructure
- AWS STS tokens extracted but not decoded (missing forensics depth)
- Password spraying lacks lockout policy detection

---

## Goal

**Observable end state**: FORGE runs a continuous offensive loop where every capability feeds the next, with minimized public IP exposure via Cloudflare tunnel infrastructure.

1. **Cloudflare Tunnel C2 Infrastructure** - Tunnel-based callback infrastructure replaces direct reverse shells, tunnel URL injected into payloads, zero public IP leakage
2. **AWS STS Token Forensics** - Extract account ID, creation timestamp, region from session tokens, integrate into secret auto-feed
3. **Pass-the-Hash Execution** - Use extracted NTLM hashes for lateral movement via impacket psexec/wmiexec, ROE-gated
5. **Go Binary/LoTL Script Updater** - Auto-update subfinder, httpx, katana, nuclei, and Linper scripts from GitHub releases

---

## Non-Goals

- UI-only polish for existing features
- Paid threat-intel API integrations (STAY FREE-FIRST per README.md)
- Removing ROE/scope gates (fail-closed remains mandatory)
- Covenant-style implant infrastructure (see T8 below - NOW IN DO NOW)
- LSASS dump without explicit ROE opt-in

---

## Design

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KILL-CHAIN LOOP                          │
│  ┌─────────┐    ┌──────────┐    ┌──────────────┐          │
│  │ Cred    │───▶│ PT Hash  │───▶│ Lateral      │──┐       │
│  │ Extract │    │ Executor │    │ Movement     │  │       │
│  └─────────┘    └──────────┘    └──────────────┘  │       │
│       ▲                                             │       │
│       │         ┌──────────────────────────────────┘       │
│       │         │                                              │
│       └─────────┴──────────┐                                  │
│                            │                                  │
│  ┌──────────────┐    ┌─────────────┐    ┌────────────────┐  │
│  │ AWS STS      │───▶│ Secret Auto │───▶│ Spray Optimizer│  │
│  │ Forensics    │    │ Feed        │    │                │  │
│  └──────────────┘    └─────────────┘    └────────────────┘  │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │            CLOUDFLARE TUNNEL LAYER                       │ │
│  │  - Quick tunnel: cloudflared tunnel --url ...            │ │
│  │  - Tunnel URL → linper_offensive RHOST injection        │ │
│  │  - Named tunnel: forge-c2.persistent.trycloudflare.com  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Cred → PTH → Lateral Loop**:
   - `WinCredCollector` extracts SAM dump → NTLM hashes
   - `pth_executor` uses hashes with `impacket psexec/wmiexec`
   - Lateral movement installs Linper persistence on new hosts
   - New hosts feed back into credential extraction

2. **AWS STS → Secret Feed Loop**:
   - `sts_token_decoder` parses session tokens from `cloud_findings`
   - Extracted account IDs → cloud graph enrichment
   - Secrets auto-feed promotes new cloud refs to kill-chain seeds

3. **Spray → Cred Loop**:
   - `spray_optimizer` detects lockout policy before spraying
   - Successful credentials → `WinCredCollector` → hash extraction → PT HASH

4. **CF Tunnel Integration**:
   - `tunnel_manager` starts quick tunnel or loads named tunnel config
   - Tunnel URL (`https://xxx.trycloudflare.com`) replaces public IP in:
     - `linper_offensive.py` RHOST parameter
     - Reverse shell one-liners (bash, nc, python, php, perl, ruby, curl, wget, socat)
   - All callbacks route through CF tunnel → local listener (netcat/socat on localhost:4444)

---

## Invariants

- **I1**: Every offensive action requires valid ROE ID + scope manifest (attack-mode default ON per cli.py:328)
- **I2**: Cloudflare tunnel URL injection happens before payload delivery (zero public IP in transit)
- **I3**: PT HASH execution ONLY on hosts within scope manifest IP ranges
- **I4**: Password spraying respects domain lockout policy (never trigger lockout)
- **I5**: AWS STS token forensics is OFFLINE ONLY (no live AWS API calls)
- **I6**: Lateral movement primitives are SINGLE-HOP by default (configurable max depth)
- **I7**: All modules log audit trail with hash chain (existing audit_log contract)

---

### T1: Cloudflare Tunnel C2 Infrastructure

**Files**:
- `forge/c2/tunnel_manager.py` (NEW)
- `forge/c2/__init__.py` (NEW)
- `forge/hardening/linper_offensive.py` (MODIFY: add tunnel URL injection)
- `forge/cli.py` (MODIFY: add `--tunnel` flag to kill-chain)

---

### T1.5: Go Binary and LoTL Script Updater (NEW)

**Files**:
- `forge/tools/binary_updater.py` (NEW)
- `forge/tools/lotl_updater.py` (NEW)
- `forge/cli.py` (MODIFY: add `forge tools update` command)

**Implementation**:
```python
# forge/tools/binary_updater.py

"""Auto-update Go binaries and LoTL scripts from GitHub releases."""

GITHUB_RELEASE_TOOLS = {
    "subfinder": "projectdiscovery/subfinder",
    "httpx": "projectdiscovery/httpx",
    "katana": "projectdiscovery/katana",
    "nuclei": "projectdiscovery/nuclei",
    "naabu": "projectdiscovery/naabu",
    "dnsx": "projectdiscovery/dnsx",
}

LOT_SCRIPTS = {
    "linper_linux.sh": "https://raw.githubusercontent.com/.../linper_offensive.sh",
    "linper_windows.ps1": "https://raw.githubusercontent.com/.../linper_offensive.ps1",
}

class BinaryUpdater:
    def check_updates(self) -> Dict[str, str]:
        """Check GitHub releases for latest versions."""
        pass
    
    def update_binary(self, tool: str, force: bool = False) -> bool:
        """Download latest binary to tools/bin/{tool}.exe"""
        pass
    
    def update_lotl_scripts(self) -> bool:
        """Update Linper scripts from canonical source."""
        pass
```

**Verification**:
- `forge tools update --check --json` shows outdated binaries
- `forge tools update --apply` downloads latest releases
- Versions stored in `tools/bin/.versions.json`

---

## Tasks

### T1: Cloudflare Tunnel C2 Infrastructure

**Files**: 
- `forge/c2/tunnel_manager.py` (NEW)
- `forge/c2/__init__.py` (NEW)
- `forge/hardening/linper_offensive.py` (MODIFY: add tunnel URL injection)
- `forge/cli.py` (MODIFY: add `--tunnel` flag to kill-chain)

**Implementation**:
```python
# forge/c2/tunnel_manager.py

class TunnelManager:
    """Manage Cloudflare tunnel lifecycle for C2 callbacks."""
    
    def start_quick_tunnel(self, local_port: int = 4444) -> str:
        """Start quick tunnel, return public URL.
        
        Command: cloudflared tunnel --url http://localhost:{local_port}
        Output parsing: "Your quick Tunnel is ready: https://xxx.trycloudflare.com"
        """
        pass
    
    def start_named_tunnel(self, tunnel_name: str, config_path: Path) -> str:
        """Start named tunnel from config file.
        
        Command: cloudflared tunnel run --config {config_path} {tunnel_name}
        Config: ~/.cloudflared/config.yml
        """
        pass
    
    def get_tunnel_url(self) -> Optional[str]:
        """Return active tunnel URL or None."""
        pass
    
    def inject_tunnel_to_payloads(self, payloads: List[str]) -> List[str]:
        """Replace RHOST placeholder with tunnel URL in reverse shell payloads."""
        pass
    
    def stop_tunnel(self) -> None:
        """Stop active tunnel process."""
        pass
```

**Integration**:
- Add `--tunnel` flag to `forge kill-chain` (default ON when attack-mode active)
- `linper_offensive.py` imports `TunnelManager`, injects tunnel URL into reverse shell payloads
- Reverse shell listener binds localhost only (no external interface exposure)

**Verification**:
```powershell
# Start tunnel + listener
forge kill-chain target.example --engagement 1001 --tunnel --attack-mode

# Verify tunnel URL appears in payloads (no public IP)
# Verify callbacks arrive via tunnel (tcpdump shows only localhost traffic)
```

### T2: AWS STS Token Forensics Module

**Files**:
- `forge/cloud/sts_token_decoder.py` (NEW)
- `forge/automation_secret_auto_feed.py` (MODIFY: add STS decoder call)

**Implementation**:
```python
# forge/cloud/sts_token_decoder.py

@dataclass
class STSTokenInfo:
    account_id: str          # 12-digit AWS account ID
    creation_time: datetime   # Token creation timestamp
    region: str              # AWS region from token
    user_data_encrypted: str # Encrypted user identity (no decryption)
    session_name: Optional[str]
    token_type: str          # "session" | "federated" | "assumed_role"

class STSTokenDecoder:
    """Decode AWS STS session tokens offline (no API calls)."""
    
    def decode_token(self, token: str) -> Optional[STSTokenInfo]:
        """Parse AWS STS session token structure.
        
        Tokens are base64-encoded JSON Web Tokens.
        Extract: account_id, creation_time, region, encrypted_user_data
        
        NO LIVE API CALLS - offline forensics only.
        """
        pass
    
    def batch_decode_from_findings(self, engagement_db: Path) -> List[STSTokenInfo]:
        """Scan all cloud_findings for AWS credentials, decode STS tokens."""
        pass
```

**Integration**:
- `automation_secret_auto_feed.py` calls `STSTokenDecoder.batch_decode_from_findings()`
- Decoded account IDs → `cloud_accounts` table → asset graph enrichment
- Session timestamps → credential age scoring → priority ranking

**Verification**:
```powershell
# Verify token decoding from existing engagement
forge cloud sts-decode --engagement 1001 --json

# Check account IDs appear in asset graph
forge graph build --engagement 1001 --format json | jq '.cloud_accounts'
```

### T3: Pass-the-Hash Execution

**Files**:
- `forge/post_exploitation/pth_executor.py` (NEW)
- `forge/post_exploitation/__init__.py` (NEW)
- `forge/utils/post/collectors/win_creds.py` (MODIFY: feed hashes to PTH executor)

**Implementation**:
```python
# forge/post_exploitation/pth_executor.py

class PTHExecutor:
    """Execute pass-the-hash attacks with ROE gating."""
    
    def __init__(self, scope_manifest: Dict[str, Any], roe_id: str):
        self.scope_manifest = scope_manifest
        self.roe_id = roe_id
    
    def validate_target_in_scope(self, target_ip: str) -> bool:
        """Check if target IP is within scope manifest ip_ranges."""
        pass
    
    def execute_psexec(self, target: str, username: str, ntlm_hash: str, 
                       command: str, domain: str = "") -> PTHResult:
        """Execute impacket psexec.py with NTLM hash.
        
        Requires target in scope_manifest.ip_ranges.
        Logs full audit trail with roe_id.
        """
        pass
    
    def execute_wmiexec(self, target: str, username: str, ntlm_hash: str,
                        command: str, domain: str = "") -> PTHResult:
        """Execute impacket wmiexec.py with NTLM hash."""
        pass
    
    def lateral_spread(self, hashes: List[NTLMHash], scope_range: str) -> List[LateralHost]:
        """For each hash, attempt lateral movement to in-scope hosts.
        
        Returns list of newly compromised hosts for credential extraction loop.
        """
        pass
```

**Integration**:
- After `WinCredCollector` extracts hashes, call `PTHExecutor.lateral_spread()`
- Each successful lateral movement:
  - Installs Linper persistence (via `linper_offensive.py`)
  - Adds host to credential extraction queue
  - Logs audit event with source_hash → lateral_host chain

**Verification**:
```powershell
# Extract hashes, attempt lateral movement (lab environment)
forge kill-chain target.example --engagement 1001 --attack-mode --include-offensive

# Verify lateral hosts appear in asset graph
forge graph build --engagement 1001 | jq '.lateral_movement_edges'

# Audit log shows hash → lateral host chain
sqlite3 forge_data/eng_1001/engagement.db "SELECT * FROM audit_log WHERE action LIKE '%lateral%'"
```

### T4: Password Spraying Optimizer

**Files**:
- `forge/auth/spray_optimizer.py` (NEW)
- `forge/auth/__init__.py` (NEW)
- `forge/cli_post.py` (MODIFY: add spray command)

**Implementation**:
```python
# forge/auth/spray_optimizer.py

@dataclass
class SprayPolicy:
    lockout_threshold: int     # Account lockout threshold
    lockout_duration_min: int  # Lockout duration in minutes
    safe_delay_seconds: int    # Safe delay between attempts per account
    max_concurrent: int        # Max concurrent spray attempts

class SprayOptimizer:
    """Password spraying with lockout policy detection."""
    
    def detect_lockout_policy(self, domain: str) -> SprayPolicy:
        """Detect domain lockout policy via LDAP/SMB null session.
        
        Returns safe throttle limits that won't trigger lockout.
        """
        pass
    
    def spray_user_list(self, domain: str, usernames: List[str], 
                        passwords: List[str], policy: SprayPolicy,
                        continue_on_success: bool = True) -> List[CredentialMatch]:
        """Spray password list against user list with safe throttling.
        
        Throttles: max 1 attempt per account per lockout_window.
        Stops early if continue_on_success=False and first success.
        """
        pass
    
    def spray_from_breach_corpus(self, domain: str, 
                                  breach_file: Path) -> List[CredentialMatch]:
        """Spray known breach passwords for domain (DeHashed local corpus)."""
        pass
```

**Integration**:
- New CLI command: `forge auth spray --domain target.example --userlist users.txt --passwordlist pass.txt`
- Output → `WinCredCollector` → hash extraction → PT HASH loop

**Verification**:
```powershell
# Verify lockout policy detection
forge auth spray --domain target.example --detect-policy --json

# Verify safe spraying (no lockout triggered in lab AD)
forge auth spray --domain lab.local --userlist users.txt --passwordlist top100.txt

# Check audit log for spray attempts
sqlite3 forge_data/eng_1001/engagement.db "SELECT * FROM audit_log WHERE action='spray_attempt'"
```

---

## Verification Matrix

| Check | How |
|---|---|
| Unit tests | `pytest tests/test_tunnel_manager.py tests/test_sts_decoder.py tests/test_pth_executor.py tests/test_spray_optimizer.py` |
| Integration test | `pytest tests/test_offensive_loop.py -m integration` |
| Manual: Tunnel + reverse shell | `forge kill-chain target --engagement 1001 --tunnel` → verify payload contains `xxx.trycloudflare.com`, not public IP |
| Manual: PTH lateral spread | Deploy lab Windows VMs, extract hashes, verify lateral movement creates audit chain |
| Manual: Spray lockout avoidance | Lab AD domain, spray with safe throttles, verify zero lockouts in event log |
| Audit trail integrity | `forge audit manifest-verify --engagement 1001` → verify hash chain includes lateral movement events |
| Cloud graph enrichment | `forge graph build --engagement 1001` → verify STS account IDs appear in cloud_accounts nodes |

---

## Risks

| Risk | Mitigation |
|------|------------|
| **Cloudflare tunnel rate limits** (200 concurrent requests) | Document limit in tunnel_manager.py; add queue/backoff for high-volume callbacks; recommend named tunnel for production |
| **PT HASH fails on Credential Guard** | Document limitation in pth_executor.py; fallback to cloud collection; require explicit `--allow-pt-hash-isolated` flag |
| **Password spraying triggers lockout anyway** | Conservative defaults (1 attempt per 15 min per account); explicit `--force-unsafe-spray` flag for risk acceptance |
| **AWS STS token format changes** | Version detection in decoder; fail gracefully; log warning when format unknown |
| **Lateral movement infinite loop** | Max depth invariant (default 3 hops); explicit `--max-lateral-depth N` flag; cycle detection in lateral_spread() |
| **Tunnel URL rotation breaks active shells** | Named tunnel for persistence; kill-chain tracks active tunnel URL; reconnection logic in Linper payloads |
| **EDR detects pth_executor subprocess** | Use impacket Python API (not CLI subprocess); add `--stealth` flag for OPSEC mode (slower, quieter) |
| **Scope bypass via lateral movement** | Strict ip_ranges validation; audit log entry for EACH scope check; fail-closed on missing scope manifest |

---

## Dependencies

- `cloudflared` binary in PATH (already installed on Windows host)
- `impacket` Python package (already in FORGE dependencies)
- Existing `linper_offensive.py`, `win_creds.py`, `automation_secret_auto_feed.py` modules
- SQLite engagement DB schema (existing)
- Audit log infrastructure (existing)

---

## Release Gate

Before merge to `main`:

1. All unit tests pass (`pytest tests/ -m "not slow"`)
2. Integration test passes in lab environment (2 Windows VMs + 1 Linux VM)
3. Manual verification: tunnel URL appears in payloads, callbacks arrive via tunnel
4. Manual verification: PTH lateral spread creates audit chain
5. `forge doctor --json` reports all 4 modules as available
6. Audit manifest hash chain validates for engagement with lateral movement events
7. Documentation updated: README.md, DAILY_USE.md, this spec file

---

## References

- Cloudflare Quick Tunnel docs: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/
- impacket psexec: https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py
- STS-token-decoder: https://github.com/talbeerysec/STS-token-decoder
- BloodHound hybrid paths: https://bloodhound.specterops.io/resources/release-notes/2024-08-01-v5-13-0
- Existing `forge/hardening/linper_offensive.py` (offensive capabilities baseline)
- Existing `forge/cli.py:328` (attack-mode default ON)


---

### T8: C2 Listener Infrastructure (MOVED FROM EXPLORE - NOW MANDATORY)

**Files**:
- `forge/c2/listener.py` (NEW)
- `forge/c2/implant.py` (NEW)
- `forge/c2/protocol.py` (NEW)
- `forge/webui/routes/c2.py` (NEW - dashboard integration)

**Implementation**:
```python
# forge/c2/listener.py

"""HTTPS C2 listener with Cloudflare tunnel integration."""

class C2Listener:
    def __init__(self, tunnel_url: str, port: int = 8443):
        self.tunnel_url = tunnel_url
        self.port = port
        self.implants: Dict[str, Implant] = {}
    
    def start(self) -> None:
        """Start HTTPS listener on localhost:{port}, proxied via CF tunnel."""
        pass
    
    def generate_implant(self, os_type: str = "windows") -> bytes:
        """Generate implant binary with embedded C2 URL."""
        pass
    
    def handle_beacon(self, implant_id: str, data: bytes) -> bytes:
        """Process beacon from implant, return tasking."""
        pass
```

**Verification**:
- `forge c2 start --engagement 1001 --tunnel` → listener begins on localhost:8443
- Generate implant: `forge c2 generate-implant --os windows --output implant.exe`
- Verify implant beacons to `{tunnel_url}/beacon`
- Dashboard shows live implant status

---

## EDR/Defender Evasion Research (MANDATORY)

**Critical**: All FORGE offensive code MUST NOT trigger Windows Defender, CrowdStrike, Defender for Endpoint, or other EDR solutions.

**Research Required Before Implementation**:

1. **Process Injection Techniques**:
   - Avoid: `CreateRemoteThread`, `WriteProcessMemory` (heavily signatured)
   - Prefer: Process hollowing with customized stubs, or direct syscalls via `NtAllocateVirtualMemory`
   - Reference: https://github.com/WithSecureLabs/white-paper-library

2. **Binary Signing**:
   - Self-signed binaries trigger SmartScreen
   - Solution: Use legitimately signed binaries for initial access (subfinder, httpx, etc.)
   - Or: Execute in-memory only (no disk writes)

3. **Network Signatures**:
   - Avoid: Default impacket command syntax in network traffic
   - Solution: Custom protocol wrappers, encrypted C2 channels
   - CF Tunnel already provides TLS termination

4. **Registry/File Artifacts**:
   - Avoid: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (heavily monitored)
   - Prefer: WMI event subscriptions, scheduled tasks with benign names
   - Reference existing `linper_offensive.py` OPSEC techniques

5. **Memory Forensics Evasion**:
   - Load Mimikatz driver only in-memory
   - Use `mimikatz # sekurlsa::logonpasswords exit` (minimal footprint)
   - Clear event logs post-extraction

**Implementation Guidelines**:
- Add `--stealth` flag to all offensive commands (slower but quieter)
- All subprocess execution via Python API (not CLI)
- Log level: ERROR only (no INFO/DEBUG prints)
- Strings obfuscation for sensitive function names


| **EDR detects C2 listener traffic** | Use HTTPS with valid certs via CF tunnel; custom User-Agent rotation; jitter in beacon intervals (randomized sleep) |
| **Implant signatures in Defender** | In-memory execution only; polymorphic implant generation; no static signatures |

