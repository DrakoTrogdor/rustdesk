//! The domain comes from the LSA's local cache rather than the primary DNS suffix, because that is
//! the domain the machine actually JOINED: it stays correct on a disjoint or unset suffix, and it
//! answers with the DC offline. The OU needs a reachable DC.

#[cfg(windows)]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, MutexGuard, PoisonError,
};
#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
static GENERATION: AtomicU64 = AtomicU64::new(0);
#[cfg(windows)]
static CACHE: Mutex<Cache> = Mutex::new(Cache::EMPTY);

#[cfg(windows)]
struct Timing {
    reads: u32,
    total: Duration,
    max: Duration,
}

#[cfg(windows)]
impl Timing {
    const EMPTY: Self = Self { reads: 0, total: Duration::ZERO, max: Duration::ZERO };

    fn add(&mut self, took: Duration) {
        self.reads = self.reads.saturating_add(1);
        self.total = self.total.saturating_add(took);
        self.max = self.max.max(took);
    }

    fn describe(&self) -> String {
        let mean = if self.reads == 0 { 0 } else { self.total.as_millis() / u128::from(self.reads) };
        format!("{} (max {} ms, mean {mean} ms)", self.reads, self.max.as_millis())
    }
}

#[cfg(windows)]
struct ReadStats {
    local: Timing,
    directory: Timing,
    directory_failed: u32,
    last_error: Option<u32>,
    deferred: u32,
}

#[cfg(windows)]
impl ReadStats {
    const EMPTY: Self = Self {
        local: Timing::EMPTY,
        directory: Timing::EMPTY,
        directory_failed: 0,
        last_error: None,
        deferred: 0,
    };
}

#[cfg(windows)]
struct Cache {
    local_at: Option<Instant>,
    local_generation: u64,
    domain_dns: String,
    domain_netbios: String,
    workgroup: String,
    joined: Option<bool>,
    dns_suffix: Option<String>,
    ou: Option<String>,
    directory_at: Option<Instant>,
    directory_generation: u64,
    directory_failures: u32,
    directory_forced: bool,
    deferred: bool,
    invalidated_at: Option<Instant>,
    stats: ReadStats,
}

#[cfg(windows)]
impl Cache {
    const EMPTY: Self = Self {
        local_at: None,
        local_generation: 0,
        domain_dns: String::new(),
        domain_netbios: String::new(),
        workgroup: String::new(),
        joined: None,
        dns_suffix: None,
        ou: None,
        directory_at: None,
        directory_generation: 0,
        directory_failures: 0,
        directory_forced: false,
        deferred: false,
        invalidated_at: None,
        stats: ReadStats::EMPTY,
    };

    const LOCAL_EVERY: Duration = Duration::from_secs(60);
    const DIRECTORY_EVERY: Duration = Duration::from_secs(300);
    const DIRECTORY_BACKOFF_SECS: [u64; 5] = [15, 30, 60, 120, 300];
    const DIRECTORY_MIN_GAP: Duration = Duration::from_secs(15);
    const FOLLOW_UP_SECS: [u64; 2] = [60, 180];
    const SLOW_READ: Duration = Duration::from_secs(2);

    fn local_due(&self, generation: u64) -> bool {
        self.local_generation != generation || self.local_at.map_or(true, |at| at.elapsed() >= Self::LOCAL_EVERY)
    }

    fn directory_due(&self, generation: u64, now: Instant) -> bool {
        let Some(at) = self.directory_at else {
            return true;
        };
        let follow_up = self.invalidated_at.is_some_and(|t| {
            Self::FOLLOW_UP_SECS
                .iter()
                .map(|s| t + Duration::from_secs(*s))
                .any(|f| at < f && now >= f)
        });
        let wait = match self.directory_failures {
            0 => Self::DIRECTORY_EVERY,
            n => {
                let step = (n as usize - 1).min(Self::DIRECTORY_BACKOFF_SECS.len() - 1);
                Duration::from_secs(Self::DIRECTORY_BACKOFF_SECS[step])
            }
        };
        self.directory_forced
            || self.directory_generation != generation
            || follow_up
            || now.saturating_duration_since(at) >= wait
    }
}

#[cfg(windows)]
fn cache() -> MutexGuard<'static, Cache> {
    CACHE.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(windows)]
pub fn invalidate() {
    cache().invalidated_at = Some(Instant::now());
    GENERATION.fetch_add(1, Ordering::AcqRel);
}

#[cfg(windows)]
pub fn take_read_stats() -> String {
    let s = std::mem::replace(&mut cache().stats, ReadStats::EMPTY);
    let error = s.last_error.map(|e| format!(", last error {e}")).unwrap_or_default();
    format!(
        "identity reads: local {}; directory {}, {} failed{error}, {} deferred",
        s.local.describe(),
        s.directory.describe(),
        s.directory_failed,
        s.deferred
    )
}
#[cfg(not(windows))]
pub fn take_read_stats() -> String {
    String::new()
}

#[cfg(windows)]
fn refresh_local_if_due(generation: u64) {
    let first = {
        let c = cache();
        if !c.local_due(generation) {
            return;
        }
        c.local_at.is_none()
    };
    let started = Instant::now();
    let lsa = lsa_domain_name();
    let needs_fallback = match &lsa {
        Some((_, lsa_dns, _)) => lsa_dns.is_empty(),
        None => first,
    };
    let fallback = if needs_fallback { dns_domain() } else { String::new() };
    let lsa_took = started.elapsed();
    let suffix = super::jobs::inventory::primary_dns_suffix();
    let took = started.elapsed();

    let mut c = cache();
    let (was_joined, was_domain) = (c.joined, c.domain_dns.clone());
    match lsa {
        Some((netbios, lsa_dns, is_domain)) => {
            c.domain_dns = if lsa_dns.is_empty() { fallback } else { lsa_dns };
            c.domain_netbios = if is_domain { netbios.clone() } else { String::new() };
            c.workgroup = if is_domain { String::new() } else { netbios };
            c.joined = Some(is_domain);
        }
        None if first => c.domain_dns = fallback,
        None => {}
    }
    if c.joined != was_joined || c.domain_dns != was_domain {
        c.directory_forced = true;
        c.ou = None;
    }
    if c.joined == Some(false) {
        c.ou = Some(String::new());
    }
    if suffix.is_some() {
        c.dns_suffix = suffix;
    }
    c.local_at = Some(Instant::now());
    c.local_generation = generation;
    c.stats.local.add(took);
    drop(c);
    if took > Cache::SLOW_READ {
        hbb_common::log::warn!(
            "identity: local read took {} ms (LSA {} ms, DNS suffix {} ms)",
            took.as_millis(),
            lsa_took.as_millis(),
            took.saturating_sub(lsa_took).as_millis()
        );
    }
}

#[cfg(windows)]
fn refresh_directory_if_due(generation: u64) {
    {
        let mut c = cache();
        if c.joined == Some(false) || !c.directory_due(generation, Instant::now()) {
            return;
        }
        if c.directory_at.is_some_and(|at| at.elapsed() < Cache::DIRECTORY_MIN_GAP) {
            if !c.deferred {
                c.deferred = true;
                c.stats.deferred = c.stats.deferred.saturating_add(1);
            }
            return;
        }
        c.deferred = false;
        c.directory_forced = false;
    }
    let started = Instant::now();
    let dn = computer_dn_measured();
    let took = started.elapsed();

    let mut c = cache();
    c.directory_at = Some(Instant::now());
    c.directory_generation = generation;
    c.stats.directory.add(took);
    match &dn {
        Ok(dn) => {
            c.ou = Some(ou_of(dn));
            c.directory_failures = 0;
        }
        Err(code) => {
            c.directory_failures = c.directory_failures.saturating_add(1);
            c.stats.directory_failed = c.stats.directory_failed.saturating_add(1);
            c.stats.last_error = Some(*code);
        }
    }
    let failures = c.directory_failures;
    drop(c);
    match dn {
        Err(code) => hbb_common::log::warn!(
            "identity: directory read failed with error {code} after {} ms ({failures} in a row)",
            took.as_millis()
        ),
        Ok(_) if took > Cache::SLOW_READ => {
            hbb_common::log::warn!("identity: directory read took {} ms", took.as_millis())
        }
        Ok(_) => {}
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
fn lsa_domain_name() -> Option<(String, String, bool)> {
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
    let mut measured = false;
    unsafe {
        if LsaOpenPolicy(None, &attrs, POLICY_VIEW_LOCAL_INFORMATION, &mut handle) != STATUS_SUCCESS {
            return None;
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
            measured = true;
        }
        let _ = LsaClose(handle);
    }
    measured.then_some((netbios, dns_name, is_domain))
}

#[cfg(windows)]
pub fn computer_dn_measured() -> Result<String, u32> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::Security::Authentication::Identity::{GetComputerObjectNameW, NameFullyQualifiedDN};
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    unsafe {
        if GetComputerObjectNameW(NameFullyQualifiedDN, Some(PWSTR(buf.as_mut_ptr())), &mut len) {
            let s = String::from_utf16_lossy(&buf[..len as usize]);
            return Ok(s.trim_end_matches('\0').to_owned());
        }
        Err(GetLastError().0)
    }
}

#[cfg(windows)]
pub fn computer_dn() -> String {
    computer_dn_measured().unwrap_or_default()
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
fn ou_of(dn: &str) -> String {
    let mut ous: Vec<String> = split_dn_components(dn)
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

    let generation = GENERATION.load(Ordering::Acquire);
    refresh_local_if_due(generation);
    refresh_directory_if_due(generation);
    let c = cache();
    if !c.domain_dns.is_empty() {
        out["domain"] = json!(c.domain_dns);
    }
    if !c.domain_netbios.is_empty() {
        out["domain_netbios"] = json!(c.domain_netbios);
    }
    if let Some(ou) = &c.ou {
        out["ou"] = json!(ou);
    }
    if !c.workgroup.is_empty() {
        out["workgroup"] = json!(c.workgroup);
    }
    // Emitted whenever it was measured, empty included: an empty string is a MEASURED "no
    // connected adapter carries a suffix", which the console reads as clear-the-stored-one — where
    // an absent key means not reported, which it keeps. Skipping the key on an empty measurement
    // would make a stale suffix unremovable; emitting one on a FAILED measurement would blank a
    // good suffix from a machine whose adapters have not come up yet.
    if let Some(sfx) = &c.dns_suffix {
        out["dns_suffix"] = json!(sfx);
    }
}
