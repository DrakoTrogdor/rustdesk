//! AD identity for the SullTec console: the machine's DNS domain + AD OU, emitted into
//! `get_sysinfo` so the management console maps each endpoint to its tenant (domain) and OU
//! with no separate reporting agent.
//!
//! Windows-only, native Win32 (no new crate, no COM, integrated auth as the machine account):
//!   * `domain` via GetComputerNameExW(ComputerNameDnsDomain) — works whenever the box is
//!     domain-joined, even with the DC offline (value is cached locally).
//!   * `ou` via GetComputerObjectNameW(NameFullyQualifiedDN) — reads the computer object's
//!     distinguishedName; needs a reachable DC.
//! Both empty on workgroup machines / when AD is unreachable, so the console shows no
//! tenant/OU rather than wrong data.

/// `(domain, ou)` — either may be empty.
pub fn domain_and_ou() -> (String, String) {
    #[cfg(windows)]
    {
        (dns_domain(), ou_path())
    }
    #[cfg(not(windows))]
    {
        (String::new(), String::new())
    }
}

#[cfg(windows)]
fn dns_domain() -> String {
    use windows::core::PWSTR;
    use windows::Win32::System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW};
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    unsafe {
        if GetComputerNameExW(ComputerNameDnsDomain, Some(PWSTR(buf.as_mut_ptr())), &mut len).is_ok() {
            return String::from_utf16_lossy(&buf[..len as usize]);
        }
    }
    String::new()
}

#[cfg(windows)]
fn computer_dn() -> String {
    use windows::core::PWSTR;
    use windows::Win32::Security::Authentication::Identity::{GetComputerObjectNameW, NameFullyQualifiedDN};
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    unsafe {
        if GetComputerObjectNameW(NameFullyQualifiedDN, Some(PWSTR(buf.as_mut_ptr())), &mut len) {
            let s = String::from_utf16_lossy(&buf[..len as usize]);
            return s.trim_end_matches('\0').to_owned();
        }
    }
    String::new()
}

/// OU path from the computer DN, outermost OU last — matches the prior agent format so the
/// console's existing OU grouping is unchanged. E.g.
/// `CN=WS01,OU=Workstations,OU=Sales,DC=corp,DC=ex,DC=com` -> `Sales/Workstations`.
#[cfg(windows)]
fn ou_path() -> String {
    let dn = computer_dn();
    if dn.is_empty() {
        return String::new();
    }
    let mut ous: Vec<String> = dn
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("OU=").or_else(|| p.strip_prefix("ou=")).map(unescape_dn)
        })
        .collect();
    ous.reverse(); // DN is most-specific-first; we want outermost-last.
    ous.join("/")
}

/// Minimal RFC 4514 unescape (handles the `\` escapes AD uses in OU names).
#[cfg(windows)]
fn unescape_dn(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}
