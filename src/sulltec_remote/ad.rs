//! The domain comes from the LSA's local cache rather than the primary DNS suffix, because that is
//! the domain the machine actually JOINED: it stays correct on a disjoint or unset suffix, and it
//! answers with the DC offline. The OU needs a reachable DC.

#[derive(Default)]
pub struct AdIdentity {
    pub domain_dns: String,
    pub domain_netbios: String,
    pub ou: String,
    pub workgroup: String,
}

pub fn ad_identity() -> AdIdentity {
    #[cfg(windows)]
    {
        let (netbios, lsa_dns, is_domain) = lsa_domain_name();
        let domain_dns = if !lsa_dns.is_empty() { lsa_dns } else { dns_domain() };
        AdIdentity {
            domain_dns,
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

#[cfg(windows)]
fn lsa_domain_name() -> (String, String, bool) {
    use windows::Win32::Foundation::STATUS_SUCCESS;
    use windows::Win32::Security::Authentication::Identity::{
        LsaClose, LsaFreeMemory, LsaOpenPolicy, LsaQueryInformationPolicy,
        PolicyDnsDomainInformation, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, POLICY_DNS_DOMAIN_INFO,
    };
    // Read-only, satisfiable by any local caller.
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

/// Reads the computer object's groups over LDAP because the SYSTEM token does not contain direct
/// domain-group memberships assigned to the computer object.
///
/// Direct membership only — `memberOf` does not expand nested groups, and resolving those means
/// walking the chain against the DC. The PRIMARY group — `Domain Computers` on a member,
/// `Domain Controllers` on a DC — is held as a RID on the object and never appears in `memberOf`.
#[cfg(windows)]
pub fn computer_groups() -> Option<Vec<String>> {
    let dn = computer_dn();
    if dn.is_empty() {
        return None;
    }
    // The DN lands inside a single-quoted PowerShell literal — strip quote characters rather than
    // trusting that it is already DN-escaped.
    let safe_dn: String = dn.chars().filter(|c| *c != '\'' && *c != '"' && !c.is_control()).take(512).collect();
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         try {{ \
           $e=[adsi]('LDAP://{safe_dn}'); \
           $n=@(@($e.Properties['memberOf']) | ForEach-Object {{ ([string]$_ -split ',')[0] -replace '^CN=','' }}); \
           $b=$e.Properties['objectSid'].Value; \
           $r=$e.Properties['primaryGroupID'].Value; \
           if($null -ne $b -and $null -ne $r) {{ \
             $d=[System.Security.Principal.SecurityIdentifier]::new($b,0).AccountDomainSid.Value; \
             $p=[adsi]('LDAP://<SID=' + $d + '-' + [int]$r + '>'); \
             $c=[string]$p.Properties['cn'].Value; \
             if($c -and ($n -notcontains $c)) {{ $n=@($n) + $c }} \
           }}; \
           ConvertTo-Json -Compress -InputObject @($n) \
         }} catch {{ }}"
    );
    let out = crate::sulltec_remote::jobs::ps_json(&script)?;
    Some(match out {
        serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
        // ConvertTo-Json emits a bare string for a single group.
        serde_json::Value::String(s) => vec![s],
        _ => Vec::new(),
    })
}
#[cfg(not(windows))]
pub fn computer_groups() -> Option<Vec<String>> {
    None
}

#[cfg(windows)]
fn ou_path() -> String {
    let dn = computer_dn();
    if dn.is_empty() {
        return String::new();
    }
    let mut ous: Vec<String> = split_dn_components(&dn)
        .iter()
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("OU=").or_else(|| p.strip_prefix("ou=")).map(unescape_dn).map(sanitize_ou_component)
        })
        .collect();
    ous.reverse(); // DN is most-specific-first.
    ous.join("/")
}

/// An RFC 4514 `\,` inside an OU/CN value is part of that value, not a component boundary — a plain
/// `split(',')` would cut such a name in two and mis-group the device.
#[cfg(windows)]
fn split_dn_components(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = dn.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push(c);
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c == ',' {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    parts
}

/// A literal `/` inside an OU name is legal in AD (it isn't a DN metacharacter, so it survives
/// `unescape_dn`) and would otherwise forge an extra grouping level in the joined path. The Unicode
/// division slash (U+2215) remains visually similar but is not parsed as a path separator.
#[cfg(windows)]
fn sanitize_ou_component(s: String) -> String {
    s.replace('/', "\u{2215}")
}

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

#[cfg(windows)]
pub fn add_identity(out: &mut serde_json::Value) {
    use serde_json::json;

    let ad = ad_identity();
    if !ad.domain_dns.is_empty() {
        out["domain"] = json!(ad.domain_dns);
    }
    if !ad.domain_netbios.is_empty() {
        out["domain_netbios"] = json!(ad.domain_netbios);
    }
    if !ad.ou.is_empty() {
        out["ou"] = json!(ad.ou);
    }
    if !ad.workgroup.is_empty() {
        out["workgroup"] = json!(ad.workgroup);
    }
    // Always emitted, empty included: an empty string is a MEASURED "no connected adapter
    // carries a suffix", which the console reads as clear-the-stored-one — where an absent key
    // means not reported, which it keeps. Skipping the key here would make a stale suffix
    // unremovable.
    out["dns_suffix"] = json!(super::jobs::inventory::primary_dns_suffix());
}
