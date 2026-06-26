//! AD identity for the SullTec console: the machine's DNS domain, NetBIOS (short) domain, and
//! AD OU, emitted into `get_sysinfo` so the management console maps each endpoint to its tenant
//! and OU with no separate reporting agent.
//!
//! Windows-only, native Win32 (no new crate, no COM, integrated auth as the machine account):
//!   * `domain_dns` + `domain_netbios` via LsaQueryInformationPolicy(PolicyDnsDomainInformation) —
//!     the LSA's locally-cached DNS domain (`DnsDomainName`, e.g. `corp.example.com`) and NetBIOS
//!     domain (`Name`, e.g. `CORP`). This is the domain the machine actually JOINED, so it stays
//!     correct when the primary DNS suffix is unset/disjoint or it's an older `.local` domain, and it
//!     works with the DC offline. `domain_dns` falls back to GetComputerNameExW(ComputerNameDnsDomain)
//!     (the machine's primary DNS suffix) only when LSA reports no DNS domain.
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
        let (netbios, lsa_dns, is_domain) = lsa_domain_name();
        // AD DNS domain (the console tenant key): prefer the LSA-cached `DnsDomainName` — it's the
        // domain the box actually joined, so it's right even when the primary DNS suffix is
        // unset/disjoint or it's an older `.local` domain. Fall back to the machine's primary DNS
        // suffix (GetComputerNameExW) only when LSA reports no DNS domain.
        let domain_dns = if !lsa_dns.is_empty() { lsa_dns } else { dns_domain() };
        AdIdentity {
            domain_dns,
            // `Name` is the NetBIOS domain when joined, the workgroup name otherwise — split on
            // is_domain so we never show a workgroup as a domain (nor a real domain as a workgroup).
            domain_netbios: if is_domain { netbios.clone() } else { String::new() },
            ou: ou_path(),
            workgroup: if is_domain { String::new() } else { netbios },
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

/// `(netbios_name, dns_domain, is_domain_joined)` from the local LSA policy cache
/// (PolicyDnsDomainInformation). Works with the DC offline. `netbios_name` is the NetBIOS domain when
/// domain-joined and the **workgroup name** otherwise; `dns_domain` is the AD DNS domain
/// (`DnsDomainName`, e.g. `corp.example.com`) and is empty off-domain; `is_domain_joined` is
/// signalled by a non-empty `DnsDomainName`. This DNS domain is the authoritative console tenant key:
/// unlike the machine's primary DNS suffix (GetComputerNameExW) it survives a misconfigured/disjoint
/// suffix and older `.local` domains, because it's the domain the machine actually joined.
#[cfg(windows)]
fn lsa_domain_name() -> (String, String, bool) {
    use windows::Win32::Foundation::STATUS_SUCCESS;
    use windows::Win32::Security::Authentication::Identity::{
        LsaClose, LsaFreeMemory, LsaOpenPolicy, LsaQueryInformationPolicy,
        PolicyDnsDomainInformation, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, POLICY_DNS_DOMAIN_INFO,
    };
    // POLICY_VIEW_LOCAL_INFORMATION — read-only, satisfiable by any local caller.
    const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x0000_0001;
    let attrs = LSA_OBJECT_ATTRIBUTES::default();
    let mut handle = LSA_HANDLE::default();
    let mut netbios = String::new();
    let mut dns_name = String::new();
    let mut is_domain = false;
    unsafe {
        if LsaOpenPolicy(None, &attrs, POLICY_VIEW_LOCAL_INFORMATION, &mut handle) != STATUS_SUCCESS {
            return (netbios, dns_name, is_domain);
        }
        let mut buf: *mut core::ffi::c_void = core::ptr::null_mut();
        if LsaQueryInformationPolicy(handle, PolicyDnsDomainInformation, &mut buf) == STATUS_SUCCESS
            && !buf.is_null()
        {
            // POLICY_DNS_DOMAIN_INFO's `Name` (NetBIOS) and `DnsDomainName` are LSA_UNICODE_STRINGs
            // whose Length is in *bytes*. A workgroup has a `Name` but no `DnsDomainName`, so a
            // non-empty `DnsDomainName` is the domain-joined signal.
            let info = &*(buf as *const POLICY_DNS_DOMAIN_INFO);
            let name = &info.Name;
            let dns = &info.DnsDomainName;
            is_domain = dns.Length > 0;
            if !name.Buffer.is_null() && name.Length > 0 {
                let units = (name.Length / 2) as usize;
                netbios = String::from_utf16_lossy(std::slice::from_raw_parts(
                    name.Buffer.0 as *const u16,
                    units,
                ));
            }
            if !dns.Buffer.is_null() && dns.Length > 0 {
                let units = (dns.Length / 2) as usize;
                dns_name = String::from_utf16_lossy(std::slice::from_raw_parts(
                    dns.Buffer.0 as *const u16,
                    units,
                ));
            }
            let _ = LsaFreeMemory(Some(buf));
        }
        let _ = LsaClose(handle);
    }
    (netbios, dns_name, is_domain)
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
            p.strip_prefix("OU=").or_else(|| p.strip_prefix("ou=")).map(unescape_dn).map(sanitize_ou_component)
        })
        .collect();
    ous.reverse(); // DN is most-specific-first; we want outermost-last.
    ous.join("/")
}

/// Make an OU component safe to join with the `/` separator the console splits on. A literal `/`
/// inside an OU name is legal in AD (it isn't a DN metacharacter, so it survives `unescape_dn`) and
/// would otherwise forge an extra grouping level. Replace it with the Unicode division slash
/// (U+2215) — visually faithful but not the ASCII separator. The fork is the sole producer of this
/// path and the console splits it on ASCII `/`, so this stays consistent end-to-end with no
/// console-side change.
#[cfg(windows)]
fn sanitize_ou_component(s: String) -> String {
    s.replace('/', "\u{2215}")
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
