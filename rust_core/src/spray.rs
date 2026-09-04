#![allow(clippy::useless_conversion)]
#![allow(dead_code)]

//! Password spraying optimizer - fail-closed placeholder
//!
//! This module provides a hardened SprayOptimizer that validates all inputs
//! and ALWAYS raises NotImplementedError for spray operations, never returning
//! false success. All operations require explicit authorization via allow_spray,
//! a valid non-blank ROE ID, and at least one explicitly added scoped target.

use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

const MAX_ROE_ID_BYTES: usize = 256;
const MAX_PASSWORD_BYTES: usize = 64 * 1024;
const MAX_SCOPE_TARGETS: usize = 10_000;
const MAX_TARGET_NAME_BYTES: usize = 253;

#[pyclass]
pub struct SprayOptimizer {
    max_attempts_per_user: u32,
    delay_seconds: u64,
    roe_id: String,
    allow_spray: bool,
    scope_targets: Vec<String>,
    last_attempt: Option<Instant>,
}

#[pymethods]
impl SprayOptimizer {
    #[new]
    #[pyo3(signature = (max_attempts_per_user=3, delay_seconds=300, roe_id=None, allow_spray=false))]
    pub fn new(
        max_attempts_per_user: u32,
        delay_seconds: u64,
        roe_id: Option<String>,
        allow_spray: bool,
    ) -> PyResult<Self> {
        if !(1..=10).contains(&max_attempts_per_user) {
            return Err(PyErr::new::<PyValueError, _>(
                "max_attempts_per_user must be between 1 and 10",
            ));
        }
        if delay_seconds == 0 {
            return Err(PyErr::new::<PyValueError, _>(
                "delay_seconds must be greater than zero",
            ));
        }
        let roe_id = roe_id.unwrap_or_default();
        if roe_id.len() > MAX_ROE_ID_BYTES {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "ROE ID cannot exceed {} bytes",
                MAX_ROE_ID_BYTES
            )));
        }
        if allow_spray && roe_id.trim().is_empty() {
            return Err(PyErr::new::<PyValueError, _>(
                "ROE ID required when spray is enabled",
            ));
        }

        Ok(Self {
            max_attempts_per_user,
            delay_seconds,
            roe_id,
            allow_spray,
            scope_targets: Vec::new(),
            last_attempt: None,
        })
    }

    fn add_target(&mut self, target: String) -> PyResult<()> {
        let target = target.trim();
        if target.is_empty() || target.len() > MAX_TARGET_NAME_BYTES {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "Target must contain between 1 and {} characters",
                MAX_TARGET_NAME_BYTES
            )));
        }
        if self.scope_targets.len() >= MAX_SCOPE_TARGETS {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "Target scope cannot exceed {} entries",
                MAX_SCOPE_TARGETS
            )));
        }
        if !self
            .scope_targets
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(target))
        {
            self.scope_targets.push(target.to_string());
        }
        Ok(())
    }

    #[pyo3(signature = (lockout_threshold, lockout_duration_minutes))]
    fn calculate_delay(&self, lockout_threshold: u32, lockout_duration_minutes: u32) -> u64 {
        if lockout_threshold == 0 {
            return self.delay_seconds;
        }

        std::cmp::max(
            self.delay_seconds,
            (lockout_duration_minutes as u64 * 60) / lockout_threshold as u64,
        )
    }

    fn spray(&mut self, password: &str) -> PyResult<HashMap<String, bool>> {
        self.validate_spray_preconditions(password)?;

        Err(PyErr::new::<PyNotImplementedError, _>(
            "Password spraying is not implemented in forge_core",
        ))
    }
}

impl SprayOptimizer {
    fn validate_spray_preconditions(&self, password: &str) -> PyResult<()> {
        if password.is_empty() {
            return Err(PyErr::new::<PyValueError, _>("Password cannot be blank"));
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "Password cannot exceed {} bytes",
                MAX_PASSWORD_BYTES
            )));
        }
        if !self.allow_spray {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "Password spraying not permitted: allow_spray is false",
            ));
        }
        if self.roe_id.trim().is_empty() {
            return Err(PyErr::new::<PyValueError, _>(
                "ROE ID cannot be blank for spray operations",
            ));
        }
        if self.scope_targets.is_empty() {
            return Err(PyErr::new::<PyValueError, _>(
                "At least one scoped target is required",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayResult {
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimizer_creation() {
        let optimizer = SprayOptimizer::new(3, 300, None, false);
        assert!(optimizer.is_ok());
    }

    #[test]
    fn test_optimizer_rejects_unsafe_limits_and_missing_roe() {
        assert!(SprayOptimizer::new(0, 300, None, false).is_err());
        assert!(SprayOptimizer::new(11, 300, None, false).is_err());
        assert!(SprayOptimizer::new(3, 0, None, false).is_err());
        assert!(SprayOptimizer::new(3, 300, Some(" ".to_string()), true).is_err());
    }

    #[test]
    fn test_optimizer_rejects_oversized_roe_id() {
        let long_id = "x".repeat(300);
        assert!(SprayOptimizer::new(3, 300, Some(long_id), false).is_err());
    }

    #[test]
    fn test_permission_guard_denies_spray() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let mut blocked =
                SprayOptimizer::new(3, 300, Some("ROE-TEST".to_string()), false).unwrap();
            let result = blocked.spray("password");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("not permitted"),
                "Expected permission error"
            );
        });
    }

    #[test]
    fn test_missing_scope_guard_denies_spray() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let mut allowed =
                SprayOptimizer::new(3, 300, Some("ROE-TEST".to_string()), true).unwrap();
            let result = allowed.spray("password");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("scoped target"), "Expected scope error");
        });
    }

    #[test]
    fn test_blank_password_denied() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let mut allowed =
                SprayOptimizer::new(3, 300, Some("ROE-TEST".to_string()), true).unwrap();
            allowed.add_target("host.example".to_string()).unwrap();
            let result = allowed.spray("");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("cannot be blank"),
                "Expected blank password error"
            );
        });
    }

    #[test]
    fn test_oversized_password_denied() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let mut allowed =
                SprayOptimizer::new(3, 300, Some("ROE-TEST".to_string()), true).unwrap();
            allowed.add_target("host.example".to_string()).unwrap();
            let big_pass = "x".repeat(100_000);
            let result = allowed.spray(&big_pass);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("cannot exceed"),
                "Expected size limit error"
            );
        });
    }

    #[test]
    fn test_target_bounds_enforced() {
        let mut opt = SprayOptimizer::new(3, 300, None, false).unwrap();
        assert!(opt.add_target("".to_string()).is_err());
        let long_target = "x".repeat(300);
        assert!(opt.add_target(long_target).is_err());
    }

    #[test]
    fn test_authorized_fails_closed_with_not_implemented() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let mut allowed =
                SprayOptimizer::new(3, 300, Some("ROE-TEST".to_string()), true).unwrap();
            allowed.add_target("host.example".to_string()).unwrap();
            let result = allowed.spray("password");
            assert!(result.is_err(), "Authorized spray must fail closed");
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("not implemented"),
                "Must raise NotImplementedError, not return false success"
            );
        });
    }
}
