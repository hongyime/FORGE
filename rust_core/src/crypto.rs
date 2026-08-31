//! Cryptographic utilities - obfuscated implementation

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use pyo3::prelude::*;
use rand::RngCore;

#[pyfunction]
pub fn aes_encrypt(plaintext: String, key_b64: String) -> PyResult<String> {
    let key_bytes = general_purpose::STANDARD
        .decode(&key_b64)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    if key_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Key must be 32 bytes",
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    // Format: nonce || ciphertext (base64)
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);

    Ok(general_purpose::STANDARD.encode(&combined))
}

#[pyfunction]
pub fn aes_decrypt(ciphertext_b64: String, key_b64: String) -> PyResult<String> {
    let key_bytes = general_purpose::STANDARD
        .decode(&key_b64)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let combined = general_purpose::STANDARD
        .decode(&ciphertext_b64)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    if combined.len() < 12 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Invalid ciphertext",
        ));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
pub fn generate_key() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    general_purpose::STANDARD.encode(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_roundtrip() {
        let key = generate_key();
        let original = "test_secret";

        let encrypted = aes_encrypt(original.to_string(), key.clone()).unwrap();
        let decrypted = aes_decrypt(encrypted, key).unwrap();

        assert_eq!(original, decrypted);
    }
}
