"""
forge/models/pydantic_models.py — FORGE Pydantic v2 data models.

Single source of truth for all inter-module data contracts. Every Pydantic
model used across FORGE lives here. Import from this module, not from
individual phase packages.

Schema version: v7.2
Authoritative source: PRD v7.2 §4.4, §4.5

Anti-patterns avoided (PRD §16):
  - @validator (v1) replaced with @field_validator + @classmethod
  - Untyped `dict` for credential passing replaced by LateralMovementCredential
  - SecretStr serialised only via explicit .get_secret_value(); never logged
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)


# ===========================================================================
# Shared enumerations
# ===========================================================================

class BreachSource(str, Enum):
    LOCAL    = "local_breach"
    DEHASHED = "dehashed"
    XPOSED   = "xposedornot"
    HIBP     = "hibp"
    MANUAL   = "manual"


class ValidationService(str, Enum):
    SSH   = "ssh"
    HTTP  = "http"
    RDP   = "rdp"
    SMB   = "smb"
    FTP   = "ftp"
    DBMS  = "dbms"


class EngagementStatus(str, Enum):
    PREP     = "PREP"
    ACTIVE   = "ACTIVE"
    COMPLETE = "COMPLETE"
    ARCHIVED = "ARCHIVED"


class OsFamily(str, Enum):
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class VulnType(str, Enum):
    IDOR              = "IDOR"
    FIREBASE_MISCONFIG = "FIREBASE_MISCONFIG"
    SUPABASE_RLS      = "SUPABASE_RLS"


class KeyValidationState(str, Enum):
    ACTIVE      = "ACTIVE"
    INVALID     = "INVALID"
    UNVALIDATED = "UNVALIDATED"
    ERROR       = "ERROR"


class C2Channel(str, Enum):
    HTTP = "http"
    DNS  = "dns"
    SMB  = "smb"
    ICMP = "icmp"


class CommandTargetType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    URL = "url"
    CREDENTIAL = "credential"


class CommandActionType(str, Enum):
    SCAN_PORTS = "scan_ports"
    CRAWL = "crawl"
    CONTENT_DISCOVERY = "content_discovery"
    VULN_SCAN = "vuln_scan"
    CREDENTIAL_TEST = "credential_test"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    BRUTE_FORCE_POLICY_CHECK = "brute_force_policy_check"
    SHARE_ENUMERATION = "share_enumeration"


class CommandRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CommandActionStatus(str, Enum):
    SUGGESTED = "suggested"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class CommandPolicyOutcome(str, Enum):
    AUTO_EXECUTE = "auto_execute"
    QUEUE = "queue"
    SUGGEST = "suggest"
    HIDDEN = "hidden"
    BLOCKED = "blocked"


class CommandAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    engagement_id: int
    target_type: CommandTargetType
    target_ref: str
    action_type: CommandActionType
    confidence_score: int = Field(ge=0, le=100)
    risk_level: CommandRiskLevel
    requires_approval: bool
    status: CommandActionStatus
    created_at: datetime
    updated_at: datetime
    reasoning: str
    opsec_warnings: list[str] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)
    execution_mode: Literal["manual", "autonomous"] = "manual"
    policy_outcome: CommandPolicyOutcome = CommandPolicyOutcome.SUGGEST
    policy_reason: str = ""


class CommandEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    engagement_id: int
    timestamp: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    severity: Literal["info", "warning", "critical"] = "info"
    acknowledged: bool = False
    expires_at: Optional[datetime] = None


class SentryConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: int
    enabled: bool = False
    emergency_stop: bool = False
    auto_execute_threshold: int = Field(default=95, ge=0, le=100)
    max_concurrent_auto: int = Field(default=3, ge=1, le=20)
    require_operator_approval: bool = False
    pause_on_new_critical_finding: bool = True
    paused_reason: Optional[str] = None
    whitelisted_action_types: list[CommandActionType] = Field(
        default_factory=lambda: [CommandActionType.CREDENTIAL_TEST]
    )
    action_overrides: dict[str, int] = Field(default_factory=dict)
    engagement_overrides: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ===========================================================================
# Phase 0 — Knowledge Base
# ===========================================================================

class LolbinRecord(BaseModel):
    """Normalised record from the LOLBAS/GTFOBins knowledge base."""
    model_config = ConfigDict(extra="forbid")

    name:         str
    os_family:    OsFamily
    category:     str
    description:  str
    commands:     list[str]
    mitre_ids:    list[str] = Field(default_factory=list)
    stealth_rank: int       = Field(default=5, ge=1, le=10)
    source:       str       = "lolbas"


class ExploitRecord(BaseModel):
    """Exploit-DB record, post-normalisation by exploitdb_ingestor."""
    model_config = ConfigDict(extra="forbid")

    exploit_id:  int
    title:       str
    author:      str
    platform:    str
    type_:       str = Field(alias="type")
    date_pub:    Optional[datetime] = None
    cve_ids:     list[str]          = Field(default_factory=list)
    path:        Optional[str]      = None


class CveRecord(BaseModel):
    """NVD CVE record, post-normalisation by nvd_fetcher."""
    model_config = ConfigDict(extra="forbid")

    cve_id:       str
    description:  str
    cvss_v3:      Optional[float] = None
    cvss_v2:      Optional[float] = None
    severity:     Optional[str]   = None
    published_at: Optional[datetime] = None
    modified_at:  Optional[datetime] = None
    cpe_matches:  list[str]           = Field(default_factory=list)


# ===========================================================================
# Phase 1 — Reconnaissance
# ===========================================================================

class SubdomainResult(BaseModel):
    """Single subdomain discovered during enumeration."""
    model_config = ConfigDict(extra="forbid")

    engagement_id: int
    domain:        str
    ip_addresses:  list[str] = Field(default_factory=list)
    source:        str       = "crt_sh"
    discovered_at: datetime  = Field(default_factory=datetime.utcnow)


class ServiceBanner(BaseModel):
    """Port scan result with optional banner grab."""
    model_config = ConfigDict(extra="forbid")

    host_id:      int
    port:         int
    protocol:     str     = "tcp"
    service_name: Optional[str] = None
    banner:       Optional[str] = None
    version:      Optional[str] = None


class HostContext(BaseModel):
    """
    Enriched host context written by Phase 1 and consumed by Phases 3 and 5.

    All fields are optional — populated incrementally as recon tasks complete.
    Stored as JSON in hosts.host_context.
    """
    model_config = ConfigDict(extra="allow")

    os_family:        Optional[OsFamily]   = None
    web_server:       Optional[str]        = None
    detected_cdns:    list[str]            = Field(default_factory=list)
    trusted_domains:  list[str]            = Field(default_factory=list)
    user_agent_hint:  Optional[str]        = None
    scheduled_tasks:  list[str]            = Field(default_factory=list)
    beacon_interval_hint: Optional[int]    = None


# ===========================================================================
# Phase 2 — OSINT & Credential Intelligence
# ===========================================================================

class BreachRecord(BaseModel):
    """
    Normalised credential record returned by a BreachAdapter.

    Security: password_plaintext is SecretStr. It must be age-encrypted
    before any DB write. Never pass to logging, str.format, or JSON
    serialisation without explicit .get_secret_value() + immediate del.
    """
    model_config = ConfigDict(extra="forbid")

    email:              str
    password_plaintext: Optional[SecretStr] = None
    password_hash:      Optional[str]       = None
    hash_type:          Optional[str]       = None
    breach_name:        str
    source:             BreachSource        = BreachSource.LOCAL
    confidence:         Literal["confirmed", "likely", "possible"] = "possible"


class CredentialValidationResult(BaseModel):
    """Result of a single credential validation attempt (Module 2-B)."""
    model_config = ConfigDict(extra="forbid")

    credential_id:     int
    service:           ValidationService
    host:              str
    success:           bool
    error:             Optional[str]      = None
    validated_at:      datetime           = Field(default_factory=datetime.utcnow)


class DehashedResult(BaseModel):
    """Raw result from DeHashed API, pre-normalisation (Module 2-C)."""
    model_config = ConfigDict(extra="allow")

    id:           Optional[str] = None
    email:        Optional[str] = None
    username:     Optional[str] = None
    password:     Optional[str] = None
    hashed_password: Optional[str] = None
    database_name:   Optional[str] = None


class KeyScannerFinding(BaseModel):
    """
    API key found by Module 2-J key scanner.

    OPSEC: key_value is SecretStr. It must be age-encrypted before DB write.
    The key_prefix (first 8 chars) is stored unencrypted for identification.
    Full key value is NEVER written to audit_log — only key_prefix.
    """
    model_config = ConfigDict(extra="forbid")

    engagement_id:    int
    service:          str
    key_value:        SecretStr
    key_prefix:       str        = ""          # set by model_validator
    source_url:       Optional[str]  = None
    repo_name:        Optional[str]  = None
    pattern_name:     Optional[str]  = None
    validation_state: KeyValidationState = KeyValidationState.UNVALIDATED
    found_at:         datetime         = Field(default_factory=datetime.utcnow)

    @model_validator(mode="after")
    def set_key_prefix(self) -> "KeyScannerFinding":
        if not self.key_prefix:
            raw = self.key_value.get_secret_value()
            object.__setattr__(self, "key_prefix", raw[:8])
        return self


# ===========================================================================
# Phase 3 — Evasion & Payload Generation
# ===========================================================================

class PayloadSpec(BaseModel):
    """Specification for a payload to be generated by Phase 3."""
    model_config = ConfigDict(extra="forbid")

    engagement_id:     int
    payload_type:      Literal["reverse_shell", "c2_beacon", "dropper", "stager"]
    target_os:         OsFamily
    technique:         str
    lhost:             str
    lport:             int   = Field(..., ge=1, le=65535)
    obfuscation_chain: list[str] = Field(default_factory=list)
    lots_host:         Optional[str] = None
    metadata_stripped: bool = True

    @field_validator("lport")
    @classmethod
    def warn_on_nonstandard_port(cls, v: int) -> int:
        """PRD §12.4: prefer 443, 80, or 8443 for egress evasion."""
        if v not in {80, 443, 8443}:
            import warnings  # noqa: PLC0415
            warnings.warn(
                f"Non-standard port {v} selected. Prefer 443/80/8443 to avoid "
                "egress filtering (PRD §12.4).",
                stacklevel=3,
            )
        return v


class ObfuscationResult(BaseModel):
    """Output of a single obfuscation pass."""
    model_config = ConfigDict(extra="forbid")

    criterion:      str           # e.g. 'base64_encode', 'xor_key', 'ps_concat'
    input_hash:     str           # SHA256 of input bytes
    output_hash:    str           # SHA256 of output bytes
    applied_at:     datetime = Field(default_factory=datetime.utcnow)


# ===========================================================================
# Phase 4 — Exploit Correlation & Vulnerability Discovery
# ===========================================================================

class VersionMatch(BaseModel):
    """Version string extracted from a service banner and parsed by Phase 4."""
    model_config = ConfigDict(extra="forbid")

    host_id:      int
    port:         int
    product:      str
    version:      str
    cpe:          Optional[str] = None


class ExploitCorrelation(BaseModel):
    """Result of correlating a VersionMatch against Exploit-DB + NVD."""
    model_config = ConfigDict(extra="forbid")

    version_match:  VersionMatch
    exploit_ids:    list[int]    = Field(default_factory=list)
    cve_ids:        list[str]    = Field(default_factory=list)
    max_cvss:       Optional[float] = None
    severity:       Optional[Severity] = None


class VulnerabilityFinding(BaseModel):
    """Vulnerability discovered by Modules 4-D, 4-E, or 4-G."""
    model_config = ConfigDict(extra="forbid")

    engagement_id: int
    vuln_type:     VulnType
    target_url:    str
    parameter:     Optional[str] = None
    severity:      Severity
    title:         str
    description:   Optional[str] = None
    evidence:      Optional[str] = Field(None, max_length=512)
    cvss_score:    Optional[float] = None
    found_at:      datetime = Field(default_factory=datetime.utcnow)


class CloudAsset(BaseModel):
    """Cloud resource discovered by Modules 4-E, 4-F, or 4-G."""
    model_config = ConfigDict(extra="forbid")

    engagement_id: int
    asset_type:    Literal["firebase", "supabase"]
    identifier:    str
    source:        str
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


# ===========================================================================
# Phase 5 — Post-Exploitation
# ===========================================================================

class C2BeaconConfig(BaseModel):
    """
    C2 beacon configuration (Module 5-G).

    c2_urls must be HTTPS only; HTTP is rejected at the validator.
    Format: 'https://host[:port][/path]' OR 'host.domain' (bare CDN alias).
    
    SMB/ICMP specific fields:
    - smb_pipe_name: Named pipe for SMB communication (auto-selected if not provided)
    - smb_fallback_timeout: Timeout for SMB fallback attempts (seconds)
    - icmp_target_ip: Target IP for ICMP channel
    - icmp_packet_interval: Base interval between ICMP packets (seconds)
    """
    model_config = ConfigDict(extra="forbid")

    engagement_id:   int
    host_id:         Optional[int]    = None
    beacon_interval: int              = Field(default=30, ge=5, le=3600)
    jitter_pct:      int              = Field(default=15, ge=0, le=50)
    c2_urls:         list[str]        = Field(..., min_length=1)
    channel:         C2Channel        = C2Channel.HTTP
    sleep_mask:      bool             = True
    
    # SMB-specific configuration
    smb_pipe_name:         Optional[str]  = None
    smb_fallback_timeout:  int            = Field(default=30, ge=10, le=300)
    smb_username:          Optional[str]  = None
    smb_domain:            Optional[str]  = None
    
    # ICMP-specific configuration  
    icmp_target_ip:        Optional[str]  = None
    icmp_packet_interval:  int            = Field(default=180, ge=30, le=600)
    icmp_max_payload_size: int            = Field(default=64, ge=32, le=128)

    @field_validator("c2_urls")
    @classmethod
    def validate_c2_urls(cls, v: list[str]) -> list[str]:
        pattern = re.compile(r"^https://.+|^[a-zA-Z0-9.\-]+$")
        for url in v:
            if not pattern.match(url):
                raise ValueError(f"Invalid C2 URL: {url!r}")
        return v
    
    @field_validator("smb_pipe_name")
    @classmethod
    def validate_smb_pipe_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate SMB pipe names against OPSEC constraints."""
        if v is None:
            return v
        
        # Banned pipe names that trigger security alerts
        banned_pipes = {"svcctl", "ROUTER", "epmapper"}
        if v.lower() in banned_pipes:
            raise ValueError(f"SMB pipe name '{v}' is banned for OPSEC reasons")
        
        # Allowed legitimate pipe names
        allowed_pipes = {"atsvc", "winreg", "lsarpc", "browser", "netlogon"}
        if v.lower() not in allowed_pipes:
            import warnings
            warnings.warn(
                f"SMB pipe name '{v}' not in recommended list {allowed_pipes}. "
                "Use at your own risk for OPSEC compliance.",
                stacklevel=3,
            )
        return v
    
    @field_validator("icmp_target_ip")
    @classmethod
    def validate_icmp_target_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate ICMP target IP format."""
        if v is None:
            return v
        
        # Basic IPv4 validation
        import ipaddress
        try:
            ipaddress.IPv4Address(v)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv4 address for ICMP target: {v}")
        return v
    
    @model_validator(mode="after")
    def validate_channel_specific_fields(self) -> "C2BeaconConfig":
        """Validate channel-specific required fields."""
        if self.channel == C2Channel.SMB:
            if not self.smb_pipe_name:
                # Auto-select a legitimate pipe name if not provided
                import random
                allowed_pipes = ["atsvc", "winreg", "lsarpc", "browser", "netlogon"]
                object.__setattr__(self, "smb_pipe_name", random.choice(allowed_pipes))
        
        elif self.channel == C2Channel.ICMP:
            if not self.icmp_target_ip:
                raise ValueError("ICMP channel requires icmp_target_ip field")
        
        return self


class PersistenceSpec(BaseModel):
    """Persistence technique specification for Module 5-I."""
    model_config = ConfigDict(extra="forbid")

    engagement_id:       int
    host_id:             Optional[int] = None
    technique:           str
    target_os:           OsFamily
    install_cmd:         str
    cleanup_cmd:         Optional[str] = None
    lolbins_used:        list[str]     = Field(default_factory=list)
    obfuscation_applied: bool          = False


class LateralMovementCredential(BaseModel):
    """
    Typed credential container for Module 5-J lateral movement operations.

    Auth type semantics:
      'password'    — NTLM/plaintext; password field required.
      'kerberos'    — Pass-the-Ticket; ccache_path must point to a valid ccache file.
      'certificate' — PKINIT / Schannel; cert_path and key_path both required.

    Security note:
      - password is SecretStr — never log, never serialise to JSON without
        explicit .get_secret_value() call.
      - ccache files must be treated as equivalent to plaintext credentials
        and cleaned up via `forge clean --engagement <id>`.
      - Call `del password` immediately after passing to auth adapter.
    """
    model_config = ConfigDict(extra="forbid")

    credential_id: int
    username:      str
    domain:        Optional[str] = None

    # Auth material — exactly one group must be populated (validated below).
    password:    Optional[SecretStr] = None          # 'password' auth
    ccache_path: Optional[Path]      = None          # 'kerberos' PTT
    cert_path:   Optional[Path]      = None          # 'certificate' PKINIT
    key_path:    Optional[Path]      = None          # 'certificate' private key

    auth_type: Literal["password", "kerberos", "certificate"] = "password"

    @field_validator("ccache_path", "cert_path", "key_path", mode="before")
    @classmethod
    def coerce_to_path(cls, v: object) -> Optional[Path]:
        return Path(v) if v is not None else None  # type: ignore[arg-type]

    @field_validator("auth_type")
    @classmethod
    def validate_auth_material(cls, v: str, info: Any) -> str:  # noqa: ANN401
        data = info.data  # type: ignore[attr-defined]
        if v == "password" and not data.get("password"):
            raise ValueError("auth_type='password' requires the password field.")
        if v == "kerberos" and not data.get("ccache_path"):
            raise ValueError("auth_type='kerberos' requires ccache_path.")
        if v == "certificate" and not (data.get("cert_path") and data.get("key_path")):
            raise ValueError("auth_type='certificate' requires both cert_path and key_path.")
        return v

    def get_password(self) -> Optional[str]:
        """
        Return plaintext password.

        CRITICAL: The caller must `del` the return value immediately after use.
        Example::

            pw = cred.get_password()
            try:
                adapter.authenticate(username=cred.username, password=pw)
            finally:
                del pw
        """
        if self.password is None:
            return None
        return self.password.get_secret_value()


class LateralMovementResult(BaseModel):
    """Result of a lateral movement execution attempt (Module 5-J)."""
    model_config = ConfigDict(extra="forbid")

    engagement_id:      int
    source_host_id:     Optional[int]
    target_host_id:     int
    technique:          str
    credential_id:      Optional[int]
    command:            str
    success:            Optional[bool] = None
    output:             Optional[str]  = Field(None, max_length=65_536)  # 64 KB cap §16
    scope_verified:     bool           = False
    operator_confirmed: bool           = False
    executed_at:        datetime       = Field(default_factory=datetime.utcnow)


# ===========================================================================
# Phase 6 — LLM-Assisted Reporting
# ===========================================================================

class LlmReportRequest(BaseModel):
    """Input to the Phase 6 report synthesiser."""
    model_config = ConfigDict(extra="forbid")

    engagement_id: int
    sections:      list[str] = Field(
        default_factory=lambda: [
            "executive_summary",
            "attack_narrative",
            "findings",
            "remediation",
        ]
    )
    max_tokens:    int       = Field(default=4096, ge=256, le=8192)
    model:         str       = "qwen2.5-1.5b"


class LlmReportResult(BaseModel):
    """Output from the Phase 6 report synthesiser."""
    model_config = ConfigDict(extra="forbid")

    engagement_id: int
    content:       str
    quality_score: Optional[float] = None
    validator_ok:  bool            = False
    generated_at:  datetime        = Field(default_factory=datetime.utcnow)
    model:         str             = "qwen2.5-1.5b"
    prompt_hash:   Optional[str]   = None
    response_hash: Optional[str]   = None


# ===========================================================================
# Phase 4-C — Hash Credential Bridge (dataclasses — not Pydantic; consumed
# internally by the hashcat correlator)
# ===========================================================================

@dataclass
class HashCredential:
    """Single hash-bearing credential row, loaded from DB by Phase 4-C."""
    credential_id:     int
    email:             str
    hash_type:         str
    password_hash:     str
    hash_plaintext:    Optional[str] = None   # populated if cracked; in-memory only
    hash_crack_source: Optional[str] = None   # 'hashbuster_online' | 'hashcat_offline'
    validated_service: Optional[str] = None


@dataclass
class HashCredentialSet:
    """Aggregated hash credential context for a single host, consumed by Phase 4."""
    host_ip:       str
    all_hashes:    list[HashCredential] = field(default_factory=list)
    cracked:       list[HashCredential] = field(default_factory=list)
    pending_crack: list[HashCredential] = field(default_factory=list)

    @property
    def has_any_hash(self) -> bool:
        return bool(self.all_hashes)

    @property
    def has_cracked(self) -> bool:
        return bool(self.cracked)

    @property
    def crack_pending(self) -> bool:
        return bool(self.pending_crack)

    @property
    def all_hash_ids(self) -> list[int]:
        return [c.credential_id for c in self.all_hashes]

    @property
    def cracked_ids(self) -> list[int]:
        return [c.credential_id for c in self.cracked]
