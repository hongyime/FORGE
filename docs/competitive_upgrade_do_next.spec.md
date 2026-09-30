# Spec: FORGE Competitive Upgrade - Do Next Tier

**Date**: 2026-08-30  
**Author**: Sisyphus (GLM 5.2)  
**Status**: DRAFT  
**Estimated Effort**: ~7 weeks  
**Dependencies**: Requires Tier 1 (Do Now) completion

---

## Problem

FORGE lacks depth in two critical offensive areas:

1. **Kerberos ticket operations** - Extracted credentials include NTLM hashes but no Kerberos ticket injection or Kerberoast capabilities
2. **Hybrid AD/Azure attack paths** - Cloud graph shows AWS/Azure assets but misses synced user edges between AD and Entra ID

BloodHound v5.13.0 proves value in hybrid path discovery (SyncedToADUser/SyncedToEntraUser edges). Mimikatz demonstrates Kerberos ticket extraction/injection offensive utility.

**Evidence**:
- `forge/utils/post/collectors/win_creds.py` extracts SAM hashes, no Kerberos support
- `forge/phase4/attack_path.py` has cloud asset graph, no AD-specific queries
- Competitive matrix shows FORGE="Missing" for Pass-the-Ticket and hybrid AD/Azure paths

---

## Goal

**Observable end state**: FORGE discovers and exploits hybrid AD/Azure attack paths, with Kerberos ticket operations integrated into the offensive loop.

1. **Kerberos Ticket Operations** - Parse .kirbi files, inject tickets for PT HASH on Windows, identify Kerberoast candidates from discovered SPNs
2. **Hybrid AD/Azure Attack Path Analysis** - SyncedToADUser/SyncedToEntraUser edge detection, hybrid path queries, synced user exposure scoring

**Success criteria**:
- Kerberos ticket extraction from LSASS (optional, gated)
- Ticket injection enables domain escalation without password cracking
- Hybrid graph shows: on-prem AD user → Azure AD sync → cloud resource paths
- Kerberoast candidate list auto-generated from SPN enumeration

---

## Non-Goals

- Golden ticket attacks (requires KRBTGT hash - Tier 3 Explore)
- Full BloodHound data collector replacement (complementary, not replacement)
- Azure AD Connect exploitation (separate offensive capability)
- Paid Azure Graph API integration (free-first per README.md)

---

## Design

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                 HYBRID GRAPH LAYER                           │
│                                                               │
│  ┌──────────────┐        ┌──────────────┐                  │
│  │ On-Prem AD   │◄──────▶│  Azure AD    │                  │
│  │ User/Group   │ sync   │  User/Group  │                  │
│  └──────────────┘        └──────────────┘                  │
│         │                        │                            │
│         │                        │                            │
│         ▼                        ▼                            │
│  ┌──────────────┐        ┌──────────────┐                  │
│  │ AD Resource  │        │ Cloud Asset  │                  │
│  │ (sharepoint) │        │ (AWS S3)     │                  │
│  └──────────────┘        └──────────────┘                  │
│         │                        │                            │
│         └────────────┬───────────┘                            │
│                      │                                        │
│               ┌──────▼──────┐                                 │
│               │ Attack Path │                                 │
│               │  (Hybrid)   │                                 │
│               └─────────────┘                                 │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │            KERBEROS TICKET LAYER                        │  │
│  │  - .kirbi parsing (Rubeus/mimikatz format)              │  │
│  │  - Ticket injection (PTT on Windows)                    │  │
│  │  - Kerberoast candidate enumeration (SPN → TGS)         │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Kerberos Ticket Loop**:
   - `win_creds.py` extracts .kirbi files from engagement artifacts
   - `kerberos_ops.py` parses tickets, identifies Kerberoast candidates (SPN-enabled accounts)
   - Kerberoast attack → cracked passwords → credential feed → PT HASH
   - Ticket injection enables pass-the-ticket for domain escalation

2. **Hybrid AD/Azure Path Loop**:
   - `attack_path.py` queries both AD and Azure user tables
   - Detects `SyncedToADUser` and `SyncedToEntraUser` edges
   - Hybrid exposure scoring: on-prem AD admin + Azure sync = hybrid blast radius
   - Path recommendation: isolate sync account or break federation

---

## Invariants

- **I8**: Kerberos ticket operations require explicit `--include-kerberos` flag (disabled by default)
- **I9**: Kerberoast candidates are ENUMERATED ONLY by default (no offline cracking without `--allow-kerberoast`)
- **I10**: Hybrid AD/Azure edges are INFERRED from data (no live Azure AD Connect queries)
- **I11**: Ticket injection ONLY on Windows targets within scope manifest
- **I12**: SPN enumeration respects domain controller scope (no forest-wide enumeration without explicit flag)

---

## Tasks

### T5: Kerberos Ticket Operations

**Files**: 
- `forge/kerberos/kerberos_ops.py` (NEW)
- `forge/kerberos/__init__.py` (NEW)
- `forge/utils/post/collectors/win_creds.py` (MODIFY: extract .kirbi files)
- `forge/cli_post.py` (MODIFY: add kerberos commands)

**Implementation**:
```python
# forge/kerberos/kerberos_ops.py

@dataclass
class KerberosTicket:
    service_principal_name: str  # SPN (e.g., HTTP/webapp.target.example)
    client_name: str             # User principal name
    domain: str                  # Kerberos realm (DOMAIN.COM)
    start_time: datetime
    end_time: datetime
    session_key_type: str        # Encryption type (AES256, RC4, etc.)
    ticket_blob: bytes           # Raw .kirbi data
    is_kerberoastable: bool      # Has SPN + AES256 support

class KerberosOps:
    """Kerberos ticket parsing and injection."""
    
    def parse_kirbi_file(self, kirbi_path: Path) -> List[KerberosTicket]:
        """Parse .kirbi file (Rubeus/mimikatz format).
        
        Supports: Rubeus .kirbi, mimikatz sekurlsa::tickets output
        """
        pass
    
    def enumerate_kerberoast_candidates(self, domain: str, 
                                         dc_ip: str) -> List[KerberosTicket]:
        """Query domain controller for SPN-enabled accounts.
        
        Command: impacket GetUserSPNs.py -dc-ip {dc_ip} {domain}/user:pass
        Returns list of Kerberoast candidates (SPN accounts).
        """
        pass
    
    def inject_ticket_windows(self, ticket: KerberosTicket) -> bool:
        """Inject Kerberos ticket into current Windows session.
        
        Command: Rubeus.exe ptt /ticket:{base64_ticket}
        Requires: SeTcbPrivilege, admin rights
        """
        pass
    
    def extract_tickets_from_lsass(self) -> List[KerberosTicket]:
        """Extract Kerberos tickets from LSASS memory (optional).
        
        HIGH RISK: Requires SeDebugPrivilege, triggers EDR.
        Gate behind --allow-lsass-extraction flag.
        """
        pass
```

**Integration**:
- `win_creds.py` after SAM extraction, scan for .kirbi files in engagement artifacts
- Kerberoast candidates → credential feed with `is_kerberoastable=True` flag
- Cracked passwords (from offline Kerberoast) → PT HASH loop

**Verification**:
```powershell
# List Kerberoast candidates
forge kerberos kerberoast-candidates --domain target.example --engagement 1001

# Parse .kirbi file
forge kerberos parse-kirbi --file /path/to/ticket.kirbi --json

# Inject ticket (Windows only, requires admin)
forge kerberos inject --ticket /path/to/ticket.kirbi --engagement 1001
```

### T6: Hybrid AD/Azure Attack Path Analysis

**Files**:
- `forge/hybrid/ad_azure_sync.py` (NEW)
- `forge/hybrid/__init__.py` (NEW)
- `forge/phase4/attack_path.py` (MODIFY: add hybrid path queries)
- `forge/graph/sync_assets.py` (MODIFY: detect synced user edges)

**Implementation**:
```python
# forge/hybrid/ad_azure_sync.py

@dataclass
class SyncedUserEdge:
    ad_user: str              # On-prem AD user (CN=User,OU=Users,DC=domain,DC=com)
    azure_user: str           # Azure AD user (user@domain.com)
    sync_type: str            # "Azure AD Connect" | " federated"
    last_sync_time: Optional[datetime]
    is_admin: bool           # Has privileged role in either system

@dataclass
class HybridAttackPath:
    source: str               # Attack entry point (phishing victim, compromised cred)
    ad_path: List[str]        # Path through AD (user → group → resource)
    azure_path: List[str]     # Path through Azure (user → role → resource)
    hybrid_edges: List[SyncedUserEdge]
    blast_radius: float       # Combined exposure score (0-1)

class HybridADAzureAnalyzer:
    """Analyze hybrid AD/Azure attack paths."""
    
    def detect_synced_users(self, engagement_db: Path) -> List[SyncedUserEdge]:
        """Detect synced users by matching:
        
        1. Same username in AD users table + Azure AD users table
        2. ImmutableId present in Azure user (indicates sync)
        3. Domain federation metadata
        """
        pass
    
    def calculate_hybrid_exposure(self, synced_user: SyncedUserEdge) -> float:
        """Calculate hybrid blast radius.
        
        Factors:
        - AD group memberships (Domain Admins, Enterprise Admins)
        - Azure role assignments (Global Admin, Privileged Role Admin)
        - Sync latency (stale permissions = higher risk)
        - Federation trust (pass-through auth = higher risk)
        """
        pass
    
    def find_hybrid_paths(self, seed_user: str) -> List[HybridAttackPath]:
        """Find attack paths that cross AD/Azure boundary.
        
        BloodHound v5.13.0 approach:
        - Query SyncedToADUser edges
        - Query SyncedToEntraUser edges
        - Combine with existing attack_path.py graph traversal
        """
        pass
    
    def recommend_isolation(self, path: HybridAttackPath) -> List[str]:
        """Recommend actions to break hybrid attack path.
        
        Examples:
        - "Remove {ad_user} from Domain Admins"
        - "Break Azure AD Connect sync for {azure_user}"
        - "Enable PIM for {azure_role}"
        """
        pass
```

**Integration**:
- `attack_path.py` after building graph, call `detect_synced_users()`
- Add `SyncedToADUser` and `SyncedToEntraUser` edge types to graph schema
- Hybrid exposure score → priority ranking in dashboard/report

**Verification**:
```powershell
# Detect synced users
forge hybrid detect-sync --engagement 1001 --json

# Find hybrid attack paths
forge hybrid find-paths --seed-user admin@target.example --engagement 1001

# Calculate hybrid exposure
forge hybrid exposure-score --engagement 1001 --json

# Verify graph contains hybrid edges
forge graph build --engagement 1001 --format json | jq '.edges[] | select(.type | contains("Synced"))'
```

---

## Verification Matrix

| Check | How |
|---|---|
| Unit tests | `pytest tests/test_kerberos_ops.py tests/test_hybrid_analyzer.py` |
| Integration test | `pytest tests/test_hybrid_loop.py -m integration` |
| Manual: Kerberoast candidates | Lab AD with SPN accounts, verify candidate list matches BloodHound output |
| Manual: Ticket injection | Windows VM with .kirbi file, verify `klist` shows injected ticket |
| Manual: Hybrid path | Lab environment with Azure AD Connect, verify SyncedToADUser edges appear |
| Hybrid exposure scoring | Compare FORGE hybrid score with BloodHound v5.13.0 hybrid path output |
| Audit trail | Verify Kerberos operations create audit_log entries with ticket metadata |

---

## Risks

| Risk | Mitigation |
|------|------------|
| **Kerberoast fails on AES256-only accounts** | Document limitation; focus on RC4/legacy SPN accounts; recommend专注于 Kerberoast faible (weak encryption) |
| **Hybrid sync detection false positives** | Multi-factor verification (username match + ImmutableId + federation metadata); manual confirmation flag |
| **Ticket injection requires SeTcbPrivilege** | Document privilege requirement; fail gracefully; log warning when insufficient rights |
| **LSASS extraction banned by EDR** | Gate behind `--allow-lsass-extraction`; document OPSEC risk; prefer .kirbi file parsing (no LSASS touch) |
| **Azure AD Connect query blocked** | INFER hybrid edges from data (no live AD Connect queries); prefer artifact-based detection |
| **Hybrid path complexity explosion** | Limit to 3-hop hybrid paths by default; explicit `--max-hybrid-hops N` flag |

---

## Dependencies

- **Tier 1 completion** (Do Now: PT HASH, AWS STS forensics)
- Existing `attack_path.py` graph infrastructure
- Existing Azure credential collection (`forge/cloud/`)
- impacket (`GetUserSPNs.py` for Kerberoast enumeration)
- Rubeus (Windows-only, for ticket injection)

---

## Release Gate

Before merge to `main`:

1. All unit tests pass
2. Manual verification: Kerberoast candidates match BloodHound output
3. Manual verification: Hybrid path includes SyncedToADUser edges
4. `forge doctor --json` reports Kerberos and Hybrid modules available
5. Documentation updated: README.md, competitive_upgrade_do_now.spec.md, this file

---

## References

- BloodHound v5.13.0 release notes: https://bloodhound.specterops.io/resources/release-notes/2024-08-01-v5-13-0
- SpecterOps Hybrid Attack Paths blog: https://specterops.io/blog/2024/08/02/hybrid-attack-paths-new-views/
- Rubeus documentation: https://github.com/GhostPack/Rubeus
- impacket GetUserSPNs: https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py
