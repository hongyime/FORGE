//! Core offensive security modules - Rust implementation
//!
//! This module provides obfuscated, high-performance implementations of:
//! - Mimikatz-style credential extraction
//! - Kerberos ticket operations
//! - Pass-the-hash execution
//! - Password spraying optimization

pub mod credentials;
pub mod crypto;
pub mod kerberos;
pub mod obfuscation;
pub mod pth;
pub mod spray;

use pyo3::prelude::*;

/// Core result type for operations
pub type ForgeResult<T> = Result<T, ForgeError>;

#[derive(Debug, Clone)]
pub struct ForgeError {
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for ForgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ForgeError[{}]: {}", self.code, self.message)
    }
}

impl std::error::Error for ForgeError {}

/// Python module initialization
#[pymodule]
fn forge_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<kerberos::KerberosOps>()?;
    m.add_class::<credentials::CredentialExtractor>()?;
    m.add_class::<pth::PTHExecutor>()?;
    m.add_class::<spray::SprayOptimizer>()?;

    // Crypto helpers are the stable import surface used by Python integration.
    m.add_function(wrap_pyfunction!(crypto::aes_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::generate_key, m)?)?;

    // Add obfuscation utilities
    m.add_function(wrap_pyfunction!(obfuscation::obfuscate_string, m)?)?;
    m.add_function(wrap_pyfunction!(obfuscation::deobfuscate_string, m)?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kerberos_ops_creation() {
        let ops = kerberos::KerberosOps::new("ROE-TEST".to_string(), None, false, false);
        assert!(ops.is_ok());
    }

    #[test]
    fn test_spray_optimizer_creation() {
        let optimizer = spray::SprayOptimizer::new(3, 300);
        assert!(optimizer.is_ok());
    }
}
