//! Exhaustive wire taxonomies. Unconstrained source strings remain strings in records.
use serde::{Deserialize, Serialize};

/// Generate a wire enum whose first listed variant is the `Default`.
macro_rules! wire_enum_default {
    ($name:ident { $first:ident => $fw:literal $(, $rest:ident => $rw:literal)* $(,)? }) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum $name {
            #[default] #[serde(rename = $fw)] $first,
            $(#[serde(rename = $rw)] $rest,)*
        }
        impl $name {
            pub const ALL: &'static [Self] = &[Self::$first, $(Self::$rest,)*];
            pub const fn as_str(self) -> &'static str {
                match self { Self::$first => $fw, $(Self::$rest => $rw,)* }
            }
        }
    };
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $wire)] $variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
        }
    };
}

// Enums with Default (first variant is the default):
wire_enum_default!(BreachSource { Local => "local_breach", Dehashed => "dehashed", Xposed => "xposedornot", Hibp => "hibp", Manual => "manual" });
wire_enum_default!(SeedSource { Operator => "operator", Scope => "scope", Discovered => "discovered", Artifact => "artifact", CrossReference => "cross_reference" });
wire_enum_default!(SeedStatus { Pending => "pending", Running => "running", Completed => "completed", Failed => "failed", Ignored => "ignored" });
// Confidence: original order (Confirmed, Likely, Possible); Possible is the default.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Confidence {
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "likely")]
    Likely,
    #[default]
    #[serde(rename = "possible")]
    Possible,
}
impl Confidence {
    pub const ALL: &'static [Self] = &[Self::Confirmed, Self::Likely, Self::Possible];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Likely => "likely",
            Self::Possible => "possible",
        }
    }
}
// Severity: original order preserved (Critical > High > Medium > Low > Info);
// Low is the default variant, so derive it explicitly.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Severity {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[default]
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "INFO")]
    Info,
}
impl Severity {
    pub const ALL: &'static [Self] = &[
        Self::Critical,
        Self::High,
        Self::Medium,
        Self::Low,
        Self::Info,
    ];
    pub const fn numeric(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

// Remaining enums (no Default needed):
wire_enum!(ValidationService { Ssh => "ssh", Http => "http", Rdp => "rdp", Smb => "smb", Ftp => "ftp", Dbms => "dbms" });
wire_enum!(EngagementStatus { Prep => "PREP", Active => "ACTIVE", Complete => "COMPLETE", Archived => "ARCHIVED" });
wire_enum!(OsFamily { Windows => "windows", Linux => "linux", Macos => "macos", Unknown => "unknown" });
wire_enum!(VulnType { Idor => "IDOR", FirebaseMisconfig => "FIREBASE_MISCONFIG", SupabaseRls => "SUPABASE_RLS" });
wire_enum!(KeyValidationState { Active => "ACTIVE", Invalid => "INVALID", Unvalidated => "UNVALIDATED", Error => "ERROR" });
wire_enum!(C2Channel { Http => "http", Dns => "dns", Smb => "smb", Icmp => "icmp" });
wire_enum!(CommandTargetType { Host => "host", Service => "service", Url => "url", Credential => "credential" });
wire_enum!(CommandActionType {
    ScanPorts => "scan_ports", Crawl => "crawl", ContentDiscovery => "content_discovery", VulnScan => "vuln_scan",
    CredentialTest => "credential_test", ExploitAttempt => "exploit_attempt", BruteForcePolicyCheck => "brute_force_policy_check", ShareEnumeration => "share_enumeration"
});
wire_enum!(CommandRiskLevel { Low => "low", Medium => "medium", High => "high", Critical => "critical" });
wire_enum!(CommandActionStatus { Suggested => "suggested", Queued => "queued", Running => "running", Succeeded => "succeeded", Failed => "failed", Cancelled => "cancelled", RolledBack => "rolled_back" });
wire_enum!(CommandPolicyOutcome { AutoExecute => "auto_execute", Queue => "queue", Suggest => "suggest", Hidden => "hidden", Blocked => "blocked" });
wire_enum!(NodeType { External => "EXTERNAL", Host => "HOST", Credential => "CREDENTIAL", Exploit => "EXPLOIT", Vuln => "VULN", Cloud => "CLOUD", Apikey => "APIKEY", Impact => "IMPACT" });
wire_enum!(OutputFormat { Mermaid => "mermaid", Dot => "dot", Json => "json", Maltego => "maltego", All => "all" });
wire_enum!(TaskState { Pending => "pending", Running => "running", Completed => "completed", Failed => "failed" });
wire_enum!(SeedType {
    Domain => "domain", Email => "email", Phone => "phone", Username => "username", Ipv4 => "ipv4", Ipv6 => "ipv6",
    Name => "name", Company => "company", Url => "url", ApkUrl => "apk_url", Subdomain => "subdomain", CloudRef => "cloud_ref", Other => "other"
});
wire_enum!(SeedRunStatus { Queued => "queued", Running => "running", Completed => "completed", Failed => "failed", Skipped => "skipped" });
wire_enum!(EntityType {
    Asset => "asset", Seed => "seed", Host => "host", Service => "service", Identity => "identity", Cloud => "cloud", Evidence => "evidence", Secret => "secret",
    Finding => "finding", Validation => "validation", Remediation => "remediation", Ticket => "ticket", Owner => "owner", Organization => "organization", Other => "other"
});
