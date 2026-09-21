//! AES-256-GCM + PBKDF2-HMAC-SHA256 envelope — ports `forge/connectors/secrets.py`.
//!
//! Wire format is a JSON object:
//! ```json
//! {"v":1,"alg":"AES-256-GCM","kdf":"PBKDF2-HMAC-SHA256:200000",
//!  "nonce":"<base64url>","tag":"<base64url>","ciphertext":"<base64url>"}
//! ```
//!
//! The PBKDF2 KDF derives a 32-byte AES key from raw key material using the
//! fixed salt `forge.connector-secrets.v1` and 200 000 iterations.
//!
//! An authenticated additional data (AAD) context string binds the ciphertext
//! to its storage location so a ciphertext cannot be moved to a different slot.
//!
//! All public functions are **pure** — no I/O, no environment reads.
//! Callers supply key material explicitly.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

// ─── Constants (must match Python) ───────────────────────────────────────────

const KDF_SALT: &[u8] = b"forge.connector-secrets.v1";
const KDF_ITERATIONS: u32 = 200_000;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors returned by connector-secret encryption/decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretError {
    /// Key material is shorter than 32 characters.
    KeyTooShort,
    /// The stored envelope is malformed or the wrong key/context was used.
    DecryptFailed(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyTooShort => write!(
                f,
                "FORGE_ENGAGEMENT_KEY must be at least 32 characters before \
                 storing connector secrets"
            ),
            Self::DecryptFailed(msg) => write!(
                f,
                "failed to decrypt connector secret; FORGE_ENGAGEMENT_KEY may \
                 not match: {msg}"
            ),
        }
    }
}

impl std::error::Error for SecretError {}

// ─── Envelope types ───────────────────────────────────────────────────────────

/// JSON envelope stored in the DB column `secret_value_enc`.
///
/// Field names and ordering must match the Python `_encrypt_secret_value`
/// output exactly (Python uses `sort_keys=True`).
#[derive(Serialize, Deserialize)]
struct Envelope {
    /// Format version — always 1.
    v: u8,
    /// Algorithm identifier.
    alg: String,
    /// KDF identifier.
    kdf: String,
    /// Base64url-encoded 12-byte nonce.
    nonce: String,
    /// Base64url-encoded 16-byte GCM authentication tag.
    tag: String,
    /// Base64url-encoded ciphertext.
    ciphertext: String,
}

// ─── Context string ───────────────────────────────────────────────────────────

/// Build the authenticated additional data context string for a secret slot.
///
/// Format matches Python's `_secret_context`:
/// `"forge.connector_secrets.v1:{engagement_id}:{connector_id}:{secret_name}"`
pub fn secret_context(engagement_id: i64, connector_id: &str, secret_name: &str) -> String {
    format!("forge.connector_secrets.v1:{engagement_id}:{connector_id}:{secret_name}")
}

// ─── Key derivation ───────────────────────────────────────────────────────────

/// Derive a 32-byte AES key from raw `key_material`.
///
/// Uses PBKDF2-HMAC-SHA256 with the fixed salt and iteration count that
/// Python's `_derived_key` uses.
///
/// # Errors
///
/// Returns `SecretError::KeyTooShort` if `key_material` is fewer than 32
/// chars (after trimming whitespace), matching Python's validation.
pub fn derive_key(key_material: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>, SecretError> {
    let trimmed = key_material.trim();
    if trimmed.len() < 32 {
        return Err(SecretError::KeyTooShort);
    }
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    pbkdf2_hmac::<Sha256>(trimmed.as_bytes(), KDF_SALT, KDF_ITERATIONS, key.as_mut());
    Ok(key)
}

// ─── Encrypt ─────────────────────────────────────────────────────────────────

/// Encrypt `value` with AES-256-GCM using a PBKDF2-derived key.
///
/// The `context` string is used as authenticated additional data (AAD) so the
/// ciphertext is bound to its storage slot.
///
/// Returns a JSON envelope string compatible with Python's
/// `_encrypt_secret_value`.
///
/// # Errors
///
/// Returns `SecretError::KeyTooShort` if `key_material` has fewer than 32
/// characters.
pub fn encrypt(value: &str, context: &str, key_material: &str) -> Result<String, SecretError> {
    let key_bytes = derive_key(key_material)?;

    let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
        .expect("32-byte key is always valid for AES-256-GCM");

    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: value.as_bytes(),
        aad: context.as_bytes(),
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| SecretError::DecryptFailed(e.to_string()))?;

    // aes_gcm appends the 16-byte tag at the end of the ciphertext.
    let tag_start = ciphertext_with_tag.len().saturating_sub(16);
    let (ciphertext_bytes, tag_bytes) = ciphertext_with_tag.split_at(tag_start);

    let envelope = Envelope {
        v: 1,
        alg: "AES-256-GCM".to_owned(),
        kdf: format!("PBKDF2-HMAC-SHA256:{KDF_ITERATIONS}"),
        nonce: URL_SAFE.encode(nonce_bytes),
        tag: URL_SAFE.encode(tag_bytes),
        ciphertext: URL_SAFE.encode(ciphertext_bytes),
    };

    // sort_keys=True in Python — serde_json's default serialization doesn't
    // sort, but the decrypt side reads by field name so order doesn't matter
    // for roundtrip correctness. For exact byte-for-byte Python parity we
    // need sorted keys; build the object manually.
    let json = sorted_envelope_json(&envelope);
    Ok(json)
}

/// Serialise an `Envelope` with fields in alphabetical order (matching Python's
/// `json.dumps(..., sort_keys=True, separators=(",", ":"))`).
fn sorted_envelope_json(e: &Envelope) -> String {
    // Alphabetical order: alg, ciphertext, kdf, nonce, tag, v
    format!(
        "{{\"alg\":{},\"ciphertext\":{},\"kdf\":{},\"nonce\":{},\"tag\":{},\"v\":{}}}",
        serde_json::to_string(&e.alg).unwrap(),
        serde_json::to_string(&e.ciphertext).unwrap(),
        serde_json::to_string(&e.kdf).unwrap(),
        serde_json::to_string(&e.nonce).unwrap(),
        serde_json::to_string(&e.tag).unwrap(),
        e.v,
    )
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

/// Decrypt an envelope JSON string produced by `encrypt` or Python's
/// `_encrypt_secret_value`.
///
/// The `context` must match the AAD used during encryption.
///
/// # Errors
///
/// Returns `SecretError::KeyTooShort` if `key_material` is too short, or
/// `SecretError::DecryptFailed` if the envelope is malformed, the key is
/// wrong, or the AAD does not match.
pub fn decrypt(
    envelope_json: &str,
    context: &str,
    key_material: &str,
) -> Result<String, SecretError> {
    let key_bytes = derive_key(key_material)?;

    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|e| SecretError::DecryptFailed(format!("malformed envelope: {e}")))?;

    if envelope.alg != "AES-256-GCM" {
        return Err(SecretError::DecryptFailed(
            "unsupported connector secret envelope".to_owned(),
        ));
    }

    let nonce_bytes = URL_SAFE
        .decode(&envelope.nonce)
        .map_err(|e| SecretError::DecryptFailed(format!("bad nonce: {e}")))?;
    let tag_bytes = URL_SAFE
        .decode(&envelope.tag)
        .map_err(|e| SecretError::DecryptFailed(format!("bad tag: {e}")))?;
    let ciphertext_bytes = URL_SAFE
        .decode(&envelope.ciphertext)
        .map_err(|e| SecretError::DecryptFailed(format!("bad ciphertext: {e}")))?;

    if nonce_bytes.len() != NONCE_BYTES {
        return Err(SecretError::DecryptFailed(
            "nonce must be 12 bytes".to_owned(),
        ));
    }
    if tag_bytes.len() != 16 {
        return Err(SecretError::DecryptFailed(
            "tag must be 16 bytes".to_owned(),
        ));
    }

    // Reconstruct ciphertext||tag as aes_gcm expects.
    let mut combined = Vec::with_capacity(ciphertext_bytes.len() + tag_bytes.len());
    combined.extend_from_slice(&ciphertext_bytes);
    combined.extend_from_slice(&tag_bytes);

    let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
        .expect("32-byte key is always valid for AES-256-GCM");

    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: &combined,
        aad: context.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|e| SecretError::DecryptFailed(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| SecretError::DecryptFailed(format!("invalid UTF-8: {e}")))
}

// ─── Key fingerprint ─────────────────────────────────────────────────────────

/// Produce a short SHA-256 fingerprint for an engagement key, matching Python's
/// `_key_fingerprint`.
///
/// Format: `"sha256:<first 12 hex chars of SHA-256(key_material.encode())>"`
pub fn key_fingerprint(key_material: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(key_material.as_bytes());
    let hex = hex::encode(digest);
    format!("sha256:{}", &hex[..12])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> String {
        // 40-char key — longer than the 32-char minimum.
        "forge-test-key-for-unit-tests-only-1234".to_owned()
    }

    fn ctx() -> String {
        secret_context(1001, "shodan_host_lookup", "FORGE_SHODAN_API_KEY")
    }

    // ─── derive_key ──────────────────────────────────────────────────────────

    #[test]
    fn derive_key_rejects_short_material() {
        let result = derive_key("short");
        assert_eq!(result.unwrap_err(), SecretError::KeyTooShort);
    }

    #[test]
    fn derive_key_accepts_32_char_material() {
        let key = "a".repeat(32);
        assert!(derive_key(&key).is_ok());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let k1 = derive_key(&test_key()).unwrap();
        let k2 = derive_key(&test_key()).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_different_material_different_key() {
        let k1 = derive_key(&test_key()).unwrap();
        let k2 = derive_key(&"forge-test-key-for-unit-tests-only-5678".to_owned()).unwrap();
        assert_ne!(*k1, *k2);
    }

    // ─── roundtrip ───────────────────────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = "my-super-secret-api-key";
        let envelope = encrypt(plaintext, &ctx(), &test_key()).unwrap();
        let recovered = decrypt(&envelope, &ctx(), &test_key()).unwrap();
        assert_eq!(plaintext, recovered);
    }

    #[test]
    fn empty_value_roundtrip() {
        let envelope = encrypt("", &ctx(), &test_key()).unwrap();
        let recovered = decrypt(&envelope, &ctx(), &test_key()).unwrap();
        assert_eq!("", recovered);
    }

    #[test]
    fn unicode_value_roundtrip() {
        let plaintext = "🔑 secret-key-日本語";
        let envelope = encrypt(plaintext, &ctx(), &test_key()).unwrap();
        let recovered = decrypt(&envelope, &ctx(), &test_key()).unwrap();
        assert_eq!(plaintext, recovered);
    }

    // ─── envelope format ─────────────────────────────────────────────────────

    #[test]
    fn envelope_has_correct_alg_field() {
        let envelope = encrypt("v", &ctx(), &test_key()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["alg"], "AES-256-GCM");
    }

    #[test]
    fn envelope_has_correct_kdf_field() {
        let envelope = encrypt("v", &ctx(), &test_key()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["kdf"], "PBKDF2-HMAC-SHA256:200000");
    }

    #[test]
    fn envelope_has_v1() {
        let envelope = encrypt("v", &ctx(), &test_key()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["v"], 1);
    }

    #[test]
    fn envelope_nonce_is_base64url_charset() {
        let envelope = encrypt("v", &ctx(), &test_key()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        let nonce_str = parsed["nonce"].as_str().unwrap();
        // base64url charset: no '+' or '/' (standard-alphabet chars); padding
        // with '=' IS expected to match Python's base64.urlsafe_b64encode.
        assert!(!nonce_str.contains('+'));
        assert!(!nonce_str.contains('/'));
    }

    #[test]
    fn envelope_fields_sorted_alphabetically() {
        let envelope = encrypt("v", &ctx(), &test_key()).unwrap();
        // Keys in JSON order must be: alg, ciphertext, kdf, nonce, tag, v
        let keys: Vec<&str> = envelope
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .map(|f| f.trim().split(':').next().unwrap_or("").trim_matches('"'))
            .collect();
        assert_eq!(keys, ["alg", "ciphertext", "kdf", "nonce", "tag", "v"]);
    }

    // ─── failure modes ───────────────────────────────────────────────────────

    #[test]
    fn wrong_key_decrypt_fails() {
        let envelope = encrypt("secret", &ctx(), &test_key()).unwrap();
        let other_key = "different-key-material-for-testing-xxxxx".to_owned();
        let result = decrypt(&envelope, &ctx(), &other_key);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_context_decrypt_fails() {
        let envelope = encrypt("secret", &ctx(), &test_key()).unwrap();
        let wrong_ctx = secret_context(9999, "other_connector", "OTHER_KEY");
        let result = decrypt(&envelope, &wrong_ctx, &test_key());
        assert!(result.is_err());
    }

    #[test]
    fn malformed_json_decrypt_fails() {
        let result = decrypt("not-json", &ctx(), &test_key());
        assert!(matches!(result, Err(SecretError::DecryptFailed(_))));
    }

    #[test]
    fn tampered_ciphertext_decrypt_fails() {
        let mut envelope = encrypt("secret", &ctx(), &test_key()).unwrap();
        // Corrupt one character in the ciphertext field value
        let mut parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        let ct = parsed["ciphertext"].as_str().unwrap().to_owned();
        let corrupted: String = ct
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == 2 {
                    if c == 'A' { 'B' } else { 'A' }
                } else {
                    c
                }
            })
            .collect();
        parsed["ciphertext"] = serde_json::Value::String(corrupted);
        envelope = serde_json::to_string(&parsed).unwrap();
        let result = decrypt(&envelope, &ctx(), &test_key());
        assert!(result.is_err());
    }

    #[test]
    fn wrong_alg_decrypt_fails() {
        let envelope = r#"{"v":1,"alg":"DES","kdf":"PBKDF2-HMAC-SHA256:200000","nonce":"","tag":"","ciphertext":""}"#;
        let result = decrypt(envelope, &ctx(), &test_key());
        assert!(matches!(result, Err(SecretError::DecryptFailed(_))));
    }

    // ─── key_fingerprint ─────────────────────────────────────────────────────

    #[test]
    fn key_fingerprint_format() {
        let fp = key_fingerprint(&test_key());
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), 7 + 12); // "sha256:" + 12 hex chars
    }

    #[test]
    fn key_fingerprint_deterministic() {
        assert_eq!(key_fingerprint(&test_key()), key_fingerprint(&test_key()));
    }

    #[test]
    fn key_fingerprint_differs_for_different_keys() {
        let fp1 = key_fingerprint(&test_key());
        let fp2 = key_fingerprint("different-key-material-for-fingerprint-xx");
        assert_ne!(fp1, fp2);
    }
}
