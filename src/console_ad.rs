//! AD identity for the SullTec console: the machine's DNS domain, NetBIOS (short) domain, and
//! AD OU, emitted into `get_sysinfo` so the management console maps each endpoint to its tenant
//! and OU with no separate reporting agent.
//!
//! Windows-only, native Win32 (no new crate, no COM, integrated auth as the machine account):
//!   * `domain_dns` via GetComputerNameExW(ComputerNameDnsDomain) — the DNS domain/suffix
//!     (e.g. `corp.example.com`); works whenever the box is domain-joined, even with the DC
//!     offline (cached locally).
//!   * `domain_netbios` via LsaQueryInformationPolicy(PolicyDnsDomainInformation) — the local
//!     LSA's cached NetBIOS domain (e.g. `CORP`); also works with the DC offline.
//!   * `ou` via GetComputerObjectNameW(NameFullyQualifiedDN) — reads the computer object's
//!     distinguishedName; needs a reachable DC.
//! All empty on workgroup machines / when AD is unreachable, so the console shows no
//! tenant/OU rather than wrong data.

/// This machine's AD identity; any field may be empty (workgroup / AD unreachable).
#[derive(Default)]
pub struct AdIdentity {
    /// DNS domain / suffix, e.g. `corp.example.com` (the console tenant key).
    pub domain_dns: String,
    /// NetBIOS (short) domain, e.g. `CORP`. Empty on workgroup machines.
    pub domain_netbios: String,
    /// OU path, outermost last, e.g. `Sales/Workstations`.
    pub ou: String,
    /// Workgroup name, e.g. `WORKGROUP` — set ONLY when NOT domain-joined (mutually exclusive
    /// with the domain fields). The console uses it as a grouping fallback.
    pub workgroup: String,
}

/// Gather this machine's AD identity (all fields empty off Windows / off-domain).
pub fn ad_identity() -> AdIdentity {
    #[cfg(windows)]
    {
        AdIdentity {
            domain_dns: dns_domain(),
            domain_netbios: netbios_domain(),
            ou: ou_path(),
            workgroup: workgroup_name(),
        }
    }
    #[cfg(not(windows))]
    {
        AdIdentity::default()
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

/// `(Name, is_domain_joined)` from the local LSA policy cache (PolicyDnsDomainInformation). Works
/// with the DC offline. The struct's `Name` is the NetBIOS domain when domain-joined and the
/// **workgroup name** otherwise; `is_domain_joined` is signalled by a non-empty DnsDomainName in
/// the same struct (which equals `dns_domain()`). Callers split it so we never show "WORKGROUP"
/// as a domain, nor a real domain as a workgroup.
#[cfg(windows)]
fn lsa_domain_name() -> (String, bool) {
    use windows::Win32::Foundation::STATUS_SUCCESS;
    use windows::Win32::Security::Authentication::Identity::{
        LsaClose, LsaFreeMemory, LsaOpenPolicy, LsaQueryInformationPolicy,
        PolicyDnsDomainInformation, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, POLICY_DNS_DOMAIN_INFO,
    };
    // POLICY_VIEW_LOCAL_INFORMATION — read-only, satisfiable by any local caller.
    const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x0000_0001;
    let attrs = LSA_OBJECT_ATTRIBUTES::default();
    let mut handle = LSA_HANDLE::default();
    let mut name_out = String::new();
    let mut is_domain = false;
    unsafe {
        if LsaOpenPolicy(None, &attrs, POLICY_VIEW_LOCAL_INFORMATION, &mut handle) != STATUS_SUCCESS {
            return (name_out, is_domain);
        }
        let mut buf: *mut core::ffi::c_void = core::ptr::null_mut();
        if LsaQueryInformationPolicy(handle, PolicyDnsDomainInformation, &mut buf) == STATUS_SUCCESS
            && !buf.is_null()
        {
            // POLICY_DNS_DOMAIN_INFO.Name is an LSA_UNICODE_STRING whose Length is in *bytes*.
            let info = &*(buf as *const POLICY_DNS_DOMAIN_INFO);
            let name = &info.Name;
            let dns = &info.DnsDomainName;
            is_domain = dns.Length > 0;
            if !name.Buffer.is_null() && name.Length > 0 {
                let units = (name.Length / 2) as usize;
                name_out = String::from_utf16_lossy(std::slice::from_raw_parts(
                    name.Buffer.0 as *const u16,
                    units,
                ));
            }
            let _ = LsaFreeMemory(Some(buf));
        }
        let _ = LsaClose(handle);
    }
    (name_out, is_domain)
}

/// NetBIOS (short) domain, e.g. `CORP`; empty on workgroup machines.
#[cfg(windows)]
fn netbios_domain() -> String {
    let (name, is_domain) = lsa_domain_name();
    if is_domain { name } else { String::new() }
}

/// Workgroup name, e.g. `WORKGROUP`; empty on domain-joined machines. The console treats this as a
/// grouping fallback (after stripping default names like WORKGROUP via its own filter).
#[cfg(windows)]
fn workgroup_name() -> String {
    let (name, is_domain) = lsa_domain_name();
    if is_domain { String::new() } else { name }
}

/// The computer object's fully-qualified DN, e.g.
/// `CN=WS01,OU=Workstations,OU=Sales,DC=corp,DC=ex,DC=com` (empty off-domain / DC unreachable).
/// Exposed for the inventory's extended-AD line; `ou_path()` derives the OU grouping from it.
#[cfg(windows)]
pub fn computer_dn() -> String {
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
