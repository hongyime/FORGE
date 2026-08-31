//! Obfuscation utilities for string and code protection

use base64::{engine::general_purpose, Engine as _};
use pyo3::prelude::*;

/// Obfuscate a string using XOR + Base64
#[pyfunction]
pub fn obfuscate_string(s: String, key: u8) -> String {
    let xor_bytes: Vec<u8> = s.bytes().map(|b| b ^ key).collect();
    general_purpose::STANDARD.encode(&xor_bytes)
}

/// Deobfuscate a string
#[pyfunction]
pub fn deobfuscate_string(s: String, key: u8) -> PyResult<String> {
    let decoded = general_purpose::STANDARD
        .decode(&s)
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid base64"))?;

    let original: Vec<u8> = decoded.iter().map(|b| b ^ key).collect();

    String::from_utf8(original)
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid UTF-8"))
}

/// Obfuscate sensitive function names
pub fn obfuscate_name(name: &str) -> String {
    // Use BLAKE3 hash + base64 for consistent obfuscation
    let hash = blake3::hash(name.as_bytes());
    general_purpose::URL_SAFE_NO_PAD.encode(hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscate_roundtrip() {
        let original = "mimikatz";
        let key = 0x42;

        let obfuscated = obfuscate_string(original.to_string(), key);
        let deobfuscated = deobfuscate_string(obfuscated, key).unwrap();

        assert_eq!(original, deobfuscated);
    }
}
