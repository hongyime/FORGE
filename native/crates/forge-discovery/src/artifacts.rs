//! Static artifact classification and metadata extraction (T15).
//!
//! Ports `forge/phase4/artifact_parsers.py` to Rust.
//!
//! # Safety invariants (from Python)
//!
//! - **Passive**: read-only, no external process, no shell-out.
//! - **Bounded**: reads at most `MAX_READ_BYTES` (1 MiB) per artifact.
//! - **Source-gated**: caller is responsible for scope/manifest checks
//!   before handing an artifact to these functions.
//! - **No writes, no execution, no outbound network**.
//!
//! # Supported formats
//!
//! | # | Format | Extensions | Magic |
//! |---|--------|------------|-------|
//! | 1 | MSI | `.msi` | `D0 CF 11 E0` (CFBF) |
//! | 2 | DMG | `.dmg` | `6B 6F 6C 79` (koly trailer) |
//! | 3 | RPM | `.rpm` | `ED AB EE DB` |
//! | 4 | JAR/WAR/EAR | `.jar .war .ear` | `PK\x03\x04` (ZIP) |
//! | 5 | PDF | `.pdf` | `%PDF-` |
//! | 6 | OLE Office | `.doc .xls .ppt` | `D0 CF 11 E0` (CFBF) |
//! | 7 | PST/OST | `.pst .ost` | `21 42 44 4E` |
//! | 8 | KeePass | `.kdbx` | `03 D9 A2 9A` |
//! | 9 | PKCS#12 | `.pfx .p12` | (DER sequence tag) |

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum bytes read from any artifact. Matches Python `_MAX_READ_BYTES`.
pub const MAX_READ_BYTES: usize = 1_048_576; // 1 MiB

/// Maximum ZIP entry count to enumerate (decompression-bomb guard).
pub const MAX_ZIP_ENTRIES: usize = 10_000;

/// Maximum decompressed bytes per ZIP entry (decompression-bomb guard).
pub const MAX_UNCOMPRESSED_BYTES: u64 = 50 * 1_024 * 1_024; // 50 MiB

// ─── ArtifactType ─────────────────────────────────────────────────────────────

/// Recognised artifact format. Matches Python parser `format` strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Msi,
    Dmg,
    Rpm,
    /// Java web/enterprise archive (ZIP-based).
    JavaArchive,
    Pdf,
    /// OLE Compound File Binary (`.doc`/`.xls`/`.ppt`).
    OleOffice,
    /// Outlook mailbox (`.pst`/`.ost`).
    Outlook,
    /// KeePass database (`.kdbx`).
    Keepass,
    /// PKCS#12 certificate bundle (`.pfx`/`.p12`).
    Pkcs12,
    Unknown,
}

impl ArtifactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Msi => "msi",
            Self::Dmg => "dmg",
            Self::Rpm => "rpm",
            Self::JavaArchive => "java_archive",
            Self::Pdf => "pdf",
            Self::OleOffice => "ole_office",
            Self::Outlook => "outlook",
            Self::Keepass => "keepass",
            Self::Pkcs12 => "pkcs12",
            Self::Unknown => "unknown",
        }
    }
}

// ─── Confidence ───────────────────────────────────────────────────────────────

/// Parser confidence level. Matches Python `'high' | 'medium' | 'low'`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

// ─── ArtifactMetadata ─────────────────────────────────────────────────────────

/// Bounded, non-secret metadata extracted from an artifact.
///
/// Matches Python `ArtifactMetadata` dataclass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub artifact_type: ArtifactType,
    pub confidence: Confidence,
    /// Extracted metadata fields (format-specific). No secret values.
    pub fields: HashMap<String, serde_json::Value>,
    /// Non-fatal warnings from the parser.
    pub warnings: Vec<String>,
}

impl ArtifactMetadata {
    pub fn new(artifact_type: ArtifactType, confidence: Confidence) -> Self {
        Self {
            artifact_type,
            confidence,
            fields: HashMap::new(),
            warnings: vec![],
        }
    }

    pub fn with_field(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn with_warning(mut self, msg: impl Into<String>) -> Self {
        self.warnings.push(msg.into());
        self
    }
}

// ─── Classification ───────────────────────────────────────────────────────────

/// Read at most `MAX_READ_BYTES` of a file safely.
///
/// Returns `None` if the file cannot be opened or read.
pub fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let file_size = f.metadata().ok()?.len() as usize;
    let read_len = file_size.min(MAX_READ_BYTES);
    let mut buf = vec![0u8; read_len];
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// Detect the artifact format from its file extension and magic header bytes.
///
/// Returns `ArtifactType::Unknown` when no format can be determined.
pub fn classify_artifact(filename: &str, head: &[u8]) -> ArtifactType {
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    // Magic-byte patterns (checked first for reliability).
    if head.starts_with(b"PK\x03\x04") {
        // ZIP-based: could be JAR/WAR/EAR
        if matches!(ext.as_str(), "jar" | "war" | "ear") {
            return ArtifactType::JavaArchive;
        }
        return ArtifactType::JavaArchive; // generic ZIP treated as java_archive
    }
    if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        // OLE CFBF: MSI or legacy Office
        return if ext == "msi" {
            ArtifactType::Msi
        } else {
            ArtifactType::OleOffice
        };
    }
    if head.starts_with(b"%PDF-") {
        return ArtifactType::Pdf;
    }
    if head.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
        return ArtifactType::Rpm;
    }
    if head.starts_with(&[0x21, 0x42, 0x44, 0x4E]) {
        return ArtifactType::Outlook;
    }
    if head.starts_with(&[0x03, 0xD9, 0xA2, 0x9A]) {
        return ArtifactType::Keepass;
    }
    // DER sequence tag (0x30) for PKCS#12 / certificates
    if head.starts_with(&[0x30]) && matches!(ext.as_str(), "pfx" | "p12" | "cer" | "der") {
        return ArtifactType::Pkcs12;
    }

    // Extension-only fallback.
    match ext.as_str() {
        "msi" => ArtifactType::Msi,
        "dmg" => ArtifactType::Dmg,
        "rpm" => ArtifactType::Rpm,
        "jar" | "war" | "ear" => ArtifactType::JavaArchive,
        "pdf" => ArtifactType::Pdf,
        "doc" | "xls" | "ppt" | "dot" | "xla" | "pps" => ArtifactType::OleOffice,
        "pst" | "ost" => ArtifactType::Outlook,
        "kdbx" => ArtifactType::Keepass,
        "pfx" | "p12" => ArtifactType::Pkcs12,
        _ => ArtifactType::Unknown,
    }
}

// ─── DMG special case (koly trailer) ─────────────────────────────────────────

/// DMG detection uses the `koly` trailer at the END of the file, not the head.
///
/// Returns `true` when a `.dmg` file has the expected koly trailer.
pub fn is_dmg_koly(path: &Path) -> bool {
    use std::io::{Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    // koly trailer is 512 bytes at the end
    let Ok(meta) = f.metadata() else { return false };
    if meta.len() < 512 {
        return false;
    }
    if f.seek(SeekFrom::End(-512)).is_err() {
        return false;
    }
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf).is_ok() && &buf == b"koly"
}

// ─── Bomb guard ───────────────────────────────────────────────────────────────

/// Check whether a ZIP-based artifact exceeds the decompression-bomb thresholds.
///
/// Returns `(entry_count, is_bomb)`. Does NOT decompress any content.
/// Matches Python zip-bomb guard `(P1-8)`.
pub fn check_zip_bomb(path: &Path) -> (usize, bool) {
    let Ok(bytes) = std::fs::read(path) else {
        return (0, false);
    };
    if bytes.len() > MAX_READ_BYTES {
        return (0, true); // oversized on disk
    }
    let cursor = std::io::Cursor::new(bytes);
    let Ok(archive) = zip::ZipArchive::new(cursor) else {
        return (0, false);
    };
    let count = archive.len();
    if count > MAX_ZIP_ENTRIES {
        return (count, true);
    }
    (count, false)
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pdf_head() -> Vec<u8> {
        b"%PDF-1.7".to_vec()
    }

    fn zip_head() -> Vec<u8> {
        b"PK\x03\x04".to_vec()
    }

    fn ole_head() -> Vec<u8> {
        vec![0xD0, 0xCF, 0x11, 0xE0, 0x00]
    }

    fn rpm_head() -> Vec<u8> {
        vec![0xED, 0xAB, 0xEE, 0xDB, 0x00]
    }

    #[test]
    fn classify_pdf_by_magic() {
        assert_eq!(
            classify_artifact("document.pdf", &pdf_head()),
            ArtifactType::Pdf
        );
    }

    #[test]
    fn classify_war_by_magic_and_ext() {
        assert_eq!(
            classify_artifact("app.war", &zip_head()),
            ArtifactType::JavaArchive
        );
    }

    #[test]
    fn classify_msi_by_magic() {
        assert_eq!(
            classify_artifact("setup.msi", &ole_head()),
            ArtifactType::Msi
        );
    }

    #[test]
    fn classify_ole_office_by_magic() {
        assert_eq!(
            classify_artifact("report.doc", &ole_head()),
            ArtifactType::OleOffice
        );
    }

    #[test]
    fn classify_rpm_by_magic() {
        assert_eq!(
            classify_artifact("package.rpm", &rpm_head()),
            ArtifactType::Rpm
        );
    }

    #[test]
    fn classify_kdbx_by_magic() {
        let head = vec![0x03, 0xD9, 0xA2, 0x9A];
        assert_eq!(
            classify_artifact("vault.kdbx", &head),
            ArtifactType::Keepass
        );
    }

    #[test]
    fn classify_pst_by_magic() {
        let head = vec![0x21, 0x42, 0x44, 0x4E];
        assert_eq!(
            classify_artifact("mailbox.pst", &head),
            ArtifactType::Outlook
        );
    }

    #[test]
    fn classify_by_extension_fallback() {
        assert_eq!(classify_artifact("disk.dmg", &[]), ArtifactType::Dmg);
        assert_eq!(classify_artifact("bundle.pfx", &[]), ArtifactType::Pkcs12);
    }

    #[test]
    fn classify_unknown_format() {
        assert_eq!(
            classify_artifact("data.bin", &[0xFF, 0xFE]),
            ArtifactType::Unknown
        );
    }

    #[test]
    fn artifact_metadata_builder() {
        let m = ArtifactMetadata::new(ArtifactType::Pdf, Confidence::High)
            .with_field("version", serde_json::json!("1.7"))
            .with_warning("encrypted");
        assert_eq!(m.artifact_type, ArtifactType::Pdf);
        assert_eq!(m.confidence, Confidence::High);
        assert_eq!(m.fields.get("version"), Some(&serde_json::json!("1.7")));
        assert_eq!(m.warnings, vec!["encrypted"]);
    }

    #[test]
    fn max_read_bytes_is_one_mib() {
        assert_eq!(MAX_READ_BYTES, 1_048_576);
    }
}
