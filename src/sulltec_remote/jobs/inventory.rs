//! Software comes from the machine-wide `Uninstall` keys only: per-user installs live in
//! HKCU, which the service account cannot see.

use serde_json::{json, Value};

pub fn collect() -> Value {
    json!({
        "hardware": hardware(),
        "software": software(),
    })
}

fn hardware() -> Value {
    use hbb_common::sysinfo::{Disks, System};

    let mut system = System::new();
    system.refresh_memory();
    system.refresh_cpu();
    let memory_gb =
        (system.total_memory() as f64 / 1024. / 1024. / 1024. * 100.).round() / 100.;
    let mem_used_gb = (system.used_memory() as f64 / 1024. / 1024. / 1024. * 100.).round() / 100.;
    let uptime_secs = system.uptime();
    // `sysinfo` reports CPU use as the delta between two samples; the refresh above is the
    // baseline, so without this pause `cpu_usage()` answers 0.
    std::thread::sleep(std::time::Duration::from_millis(250));
    system.refresh_cpu();
    let cpu_pct = (system.global_cpu_info().cpu_usage() as f64 * 10.).round() / 10.;
    let cpus = system.cpus();
    let cpu_name = cpus.first().map(|x| x.brand()).unwrap_or_default().trim_end().to_owned();
    let cpu_freq = cpus.first().map(|x| x.frequency()).unwrap_or_default();
    let cpu = if cpu_freq > 0 {
        format!(
            "{}, {}GHz, {}/{} cores",
            cpu_name,
            (cpu_freq as f64 / 1024. * 100.).round() / 100.,
            num_cpus::get(),
            num_cpus::get_physical()
        )
    } else {
        format!("{}, {}/{} cores", cpu_name, num_cpus::get(), num_cpus::get_physical())
    };

    // A USB stick would otherwise churn the inventory.
    let disks: Vec<Value> = Disks::new_with_refreshed_list()
        .list()
        .iter()
        .filter(|d| !d.is_removable())
        .map(|d| {
            json!({
                "mount": d.mount_point().to_string_lossy(),
                "fs": d.file_system().to_string_lossy(),
                "kind": d.kind().to_string(),
                "total_gb": (d.total_space() as f64 / 1e9 * 10.).round() / 10.,
                "free_gb": (d.available_space() as f64 / 1e9 * 10.).round() / 10.,
            })
        })
        .collect();

    let mut hw = json!({
        "cpu": cpu,
        "memory_gb": memory_gb,
        "mem_used_gb": mem_used_gb,
        "cpu_pct": cpu_pct,
        "uptime_secs": uptime_secs,
        "disks": disks,
    });
    #[cfg(windows)]
    {
        if let Some(s) = smbios() {
            hw["manufacturer"] = json!(s.manufacturer);
            hw["product"] = json!(s.product);
            hw["serial"] = json!(s.serial);
            hw["bios_vendor"] = json!(s.bios_vendor);
            hw["bios_version"] = json!(s.bios_version);
            hw["bios_date"] = json!(s.bios_date);
        }
        hw["gpus"] = json!(gpus());
        hw["sessions"] = json!(sessions());
        hw["hotfixes"] = json!(hotfixes());
        hw["watched_services"] = watched_services();
        hw["roles"] = server_roles();
    }
    hw["network"] = network();
    hw
}

/// `[bool](Get-Service …)` tests EXISTENCE, not state: a stopped role service still yields its
/// token.
#[cfg(windows)]
fn server_roles() -> Value {
    // `gpo` is gated separately from `addc` because ADSI is always present on a DC but the
    // GroupPolicy module is not.
    let script = r#"$ErrorActionPreference='SilentlyContinue'
$r=@()
$svc=@{}
foreach($s in 'NTDS','DNS','DHCPServer','vmms','TermService','Duplicati'){ $svc[$s]=[bool](Get-Service -Name $s -ErrorAction SilentlyContinue) }
function HasMod($n){ [bool](Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue) }
if($svc['NTDS']){ $r+='addc'; if(HasMod 'GroupPolicy'){ $r+='gpo' } }
if($svc['DNS'] -and (HasMod 'DnsServer')){ $r+='dns' }
if($svc['DHCPServer'] -and (HasMod 'DhcpServer')){ $r+='dhcp' }
if($svc['vmms'] -and (HasMod 'Hyper-V')){ $r+='hyperv' }
if($svc['TermService']){ try { if((Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TerminalServiceSetting -ErrorAction Stop).TerminalServerMode -eq 1){ $r+='rdsh' } } catch {} }
if($svc['Duplicati']){ $r+='duplicati' }
$sys=@('SYSVOL','NETLOGON','PRINT$','FAX$','CertEnroll')
$us=@(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.ShareType -eq 'FileSystemDirectory' -and ($sys -notcontains $_.Name) })
if($us.Count -ge 1){ $r+='fileserver' }
$sp=@(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Shared })
if($sp.Count -ge 1){ $r+='print' }
try{
  $mfr=[string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Manufacturer
  if($mfr -like 'Dell*'){
    $nic=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Remote NDIS' -and $_.Status -eq 'Up' })
    if($nic.Count -ge 1){ $r+='idrac' }
  }
}catch{}
@($r) | Sort-Object -Unique | ConvertTo-Json -Compress"#;
    let tokens: Vec<Value> = match super::ps_json(script) {
        Some(Value::Array(a)) => a.into_iter().filter(|v| v.is_string()).collect(),
        Some(v @ Value::String(_)) => vec![v],
        _ => Vec::new(),
    };
    json!(tokens)
}
#[cfg(not(windows))]
fn server_roles() -> Value {
    json!([])
}

/// NAMES must match the backend's `WATCHED_SVC`: a service missing from either side is simply
/// never checked.
#[cfg(windows)]
fn watched_services() -> Value {
    const NAMES: &[&str] = &[
        "WinDefend", "WdNisSvc", "mpssvc", "SecurityHealthService", "wscsvc", "Sense",
        "wuauserv", "BITS", "UsoSvc", "gpsvc", "Netlogon", "Dnscache", "W32Time", "LanmanWorkstation",
    ];
    let list = NAMES.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(",");
    let script = format!(
        "Get-Service -Name {list} -ErrorAction SilentlyContinue | \
         Select-Object @{{n='name';e={{$_.Name}}}},@{{n='status';e={{$_.Status.ToString()}}}},@{{n='start';e={{$_.StartType.ToString()}}}} | \
         ConvertTo-Json -Compress"
    );
    let mut rows = match super::ps_json(&script) {
        Some(Value::Array(a)) => a,
        Some(v @ Value::Object(_)) => vec![v],
        _ => return json!([]),
    };
    // .NET's ServiceStartMode reports trigger-start and delayed-auto services as `Automatic`.
    // Registry labels preserve that distinction.
    let start_types = super::service_start_types();
    for r in &mut rows {
        let Some(name) = r.get("name").and_then(|n| n.as_str()).map(str::to_lowercase) else { continue };
        if let Some(label) = start_types.get(&name) {
            r["start"] = json!(label);
        }
    }
    Value::Array(rows)
}
#[cfg(not(windows))]
fn watched_services() -> Value {
    json!([])
}

#[cfg(windows)]
fn sessions() -> Vec<Value> {
    crate::platform::get_available_sessions(true)
        .into_iter()
        .map(|s| json!({ "sid": s.sid, "name": s.name }))
        .collect()
}
#[cfg(not(windows))]
fn sessions() -> Vec<Value> {
    Vec::new()
}

/// `Win32_QuickFixEngineering` surfaces only QFE-tracked updates, not every CBS package, so this
/// is narrower than everything the box has installed.
#[cfg(windows)]
fn hotfixes() -> Vec<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(super::powershell_exe())
        .args([
            "-NonInteractive",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_QuickFixEngineering | \
             Select-Object HotFixID,@{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}} | \
             ConvertTo-Json -Compress",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(out) = out else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    // ConvertTo-Json yields a bare object for a single row, an array for many.
    let rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v],
        _ => return Vec::new(),
    };
    rows.into_iter()
        .filter_map(|r| {
            let id = r.get("HotFixID").and_then(|x| x.as_str()).unwrap_or("").trim().to_owned();
            if id.is_empty() {
                return None;
            }
            let installed_on = r.get("InstalledOn").and_then(|x| x.as_str()).unwrap_or("").trim().to_owned();
            Some(json!({ "id": id, "installed_on": installed_on }))
        })
        .take(500)
        .collect()
}
#[cfg(not(windows))]
fn hotfixes() -> Vec<Value> {
    Vec::new()
}

fn network() -> Value {
    let mut v4_private: Vec<String> = Vec::new();
    let mut v4_public: Vec<String> = Vec::new();
    let mut v6_private: Vec<String> = Vec::new();
    let mut v6_public: Vec<String> = Vec::new();
    let mut primary_mac: Option<String> = None;
    // `default_net::get_interfaces()` is unavailable on the iOS simulator.
    #[cfg(not(target_os = "ios"))]
    for iface in default_net::get_interfaces() {
        for net in &iface.ipv4 {
            let a = net.addr;
            if a.is_loopback() {
                continue;
            }
            let s = a.to_string();
            if a.is_private() || a.is_link_local() {
                if a.is_private() && primary_mac.is_none() {
                    primary_mac = iface
                        .mac_addr
                        .as_ref()
                        .map(|m| m.address())
                        .filter(|m| !m.is_empty() && m != "00:00:00:00:00:00");
                }
                push_unique(&mut v4_private, s);
            } else {
                push_unique(&mut v4_public, s);
            }
        }
        for net in &iface.ipv6 {
            let a = net.addr;
            if a.is_loopback() || a.is_multicast() {
                continue;
            }
            let seg0 = a.segments()[0];
            let s = a.to_string();
            if (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xfe00) == 0xfc00 {
                push_unique(&mut v6_private, s);
            } else {
                push_unique(&mut v6_public, s);
            }
        }
    }
    let mut net = json!({
        "hostname": crate::common::hostname(),
        "ipv4_private": v4_private,
        "ipv4_public": v4_public,
        "ipv6_private": v6_private,
        "ipv6_public": v6_public,
    });
    if let Some(mac) = primary_mac {
        net["mac"] = json!(mac);
    }
    #[cfg(windows)]
    {
        net["dns_suffixes"] = json!(dns_suffixes());
        let dn = crate::sulltec_remote::ad::computer_dn();
        if !dn.is_empty() {
            net["dn"] = json!(dn);
            if let Some(groups) = crate::sulltec_remote::ad::computer_groups() {
                net["ad_groups"] = json!(groups);
            }
        }
    }
    net
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// NOT the AD/primary DNS domain from `sulltec_remote::ad::dns_domain()` — that one feeds the
/// console tenant and these deliberately do not. A static per-adapter `Domain` beating
/// `DhcpDomain` matches Windows' own precedence.
#[cfg(windows)]
fn dns_suffixes() -> Vec<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    const IFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    let mut out: Vec<String> = Vec::new();
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(IFACES, KEY_READ)
    else {
        return out;
    };
    for guid in root.enum_keys().flatten() {
        let Ok(sub) = root.open_subkey_with_flags(&guid, KEY_READ) else { continue };
        let dhcp_ip = sub.get_value::<String, _>("DhcpIPAddress").unwrap_or_default();
        let dhcp_active = !dhcp_ip.is_empty() && dhcp_ip != "0.0.0.0";
        // Static-configured adapters keep their addresses in a REG_MULTI_SZ `IPAddress`;
        // any payload beyond the multi-sz terminators means an address is configured.
        let static_active = sub
            .get_raw_value("IPAddress")
            .map(|v| v.bytes.len() > 4)
            .unwrap_or(false);
        let suffix = {
            let s = sub.get_value::<String, _>("Domain").unwrap_or_default();
            let s = s.trim().to_owned();
            if !s.is_empty() && (dhcp_active || static_active) {
                s
            } else if dhcp_active {
                sub.get_value::<String, _>("DhcpDomain").unwrap_or_default().trim().to_owned()
            } else {
                String::new()
            }
        };
        if !suffix.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(&suffix)) {
            out.push(suffix);
            if out.len() >= 8 {
                break;
            }
        }
    }
    out
}

pub fn primary_dns_suffix() -> String {
    #[cfg(windows)]
    {
        dns_suffixes().into_iter().find(|s| !s.trim().is_empty()).unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        String::new()
    }
}

fn software() -> Vec<Value> {
    #[cfg(windows)]
    {
        software_windows()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
#[derive(Default)]
struct Smbios {
    manufacturer: String,
    product: String,
    serial: String,
    bios_vendor: String,
    bios_version: String,
    bios_date: String,
}

/// `GetSystemFirmwareTable` needs no administrator rights, which is why this reads the firmware
/// table rather than WMI.
#[cfg(windows)]
fn smbios() -> Option<Smbios> {
    use windows::Win32::System::SystemInformation::{
        GetSystemFirmwareTable, FIRMWARE_TABLE_PROVIDER,
    };
    let provider = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));
    let size = unsafe { GetSystemFirmwareTable(provider, 0, None) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let n = unsafe { GetSystemFirmwareTable(provider, 0, Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return None;
    }
    // RawSMBIOSData: u8 method, u8 major, u8 minor, u8 revision, u32 length, then the table.
    parse_smbios(buf.get(8..n)?)
}

/// Walk SMBIOS structures: 4-byte header (type, formatted length, handle), formatted area,
/// then a NUL-separated string set ending with a double NUL. String fields are 1-based
/// indices into that set.
#[cfg(windows)]
fn parse_smbios(table: &[u8]) -> Option<Smbios> {
    let mut out = Smbios::default();
    let (mut have_bios, mut have_sys) = (false, false);
    let mut off = 0usize;
    while off + 4 <= table.len() {
        let stype = table[off];
        let flen = table[off + 1] as usize;
        if flen < 4 || off + flen > table.len() {
            break;
        }
        let mut strings: Vec<String> = Vec::new();
        let mut p = off + flen;
        loop {
            let start = p;
            while p < table.len() && table[p] != 0 {
                p += 1;
            }
            if p >= table.len() {
                break;
            }
            if p == start {
                p += 1;
                break;
            }
            strings.push(String::from_utf8_lossy(&table[start..p]).trim().to_owned());
            p += 1;
        }
        if strings.is_empty() && p < table.len() && table[p] == 0 {
            p += 1;
        }
        let field = |idx: usize| -> String {
            table
                .get(off + idx)
                .copied()
                .filter(|&i| i > 0)
                .and_then(|i| strings.get(i as usize - 1))
                .cloned()
                .unwrap_or_default()
        };
        match stype {
            0 => {
                out.bios_vendor = field(0x04);
                out.bios_version = field(0x05);
                out.bios_date = field(0x08);
                have_bios = true;
            }
            1 => {
                out.manufacturer = field(0x04);
                out.product = field(0x05);
                out.serial = scrub_placeholder(field(0x07));
                have_sys = true;
            }
            127 => break, // end-of-table structure
            _ => {}
        }
        if have_bios && have_sys {
            break;
        }
        off = p;
    }
    (have_bios || have_sys).then_some(out)
}

#[cfg(windows)]
fn scrub_placeholder(s: String) -> String {
    const PLACEHOLDERS: &[&str] = &[
        "to be filled by o.e.m.",
        "default string",
        "system serial number",
        "none",
        "0",
        "123456789",
    ];
    if PLACEHOLDERS.contains(&s.to_lowercase().as_str()) {
        String::new()
    } else {
        s
    }
}

/// `DISPLAY_CLASS` is Windows' display-adapter device class GUID.
#[cfg(windows)]
fn gpus() -> Vec<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    const DISPLAY_CLASS: &str =
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
    let mut out: Vec<String> = Vec::new();
    let Ok(class) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(DISPLAY_CLASS, KEY_READ)
    else {
        return out;
    };
    for name in class.enum_keys().flatten() {
        // Adapter instances are 4-digit subkeys; the class key also holds named ones like
        // "Properties".
        if name.len() != 4 || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(sub) = class.open_subkey_with_flags(&name, KEY_READ) {
            if let Ok(desc) = sub.get_value::<String, _>("DriverDesc") {
                let desc = desc.trim().to_owned();
                if !desc.is_empty() && !out.contains(&desc) {
                    out.push(desc);
                }
            }
        }
    }
    out
}

/// Both registry views are read because a 32-bit installer writes under `WOW6432Node`.
#[cfg(windows)]
fn software_windows() -> Vec<Value> {
    use std::collections::BTreeMap;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    use winreg::RegKey;
    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const MAX_ENTRIES: usize = 2000;

    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(UNINSTALL, KEY_READ | view)
        else {
            continue;
        };
        for key in root.enum_keys().flatten() {
            let Ok(sub) = root.open_subkey_with_flags(&key, KEY_READ | view) else {
                continue;
            };
            let name = sub.get_value::<String, _>("DisplayName").unwrap_or_default();
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if sub.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 {
                continue;
            }
            if !sub.get_value::<String, _>("ParentKeyName").unwrap_or_default().is_empty() {
                continue; // a patch/update row, not a product
            }
            let version = sub.get_value::<String, _>("DisplayVersion").unwrap_or_default();
            let publisher = sub.get_value::<String, _>("Publisher").unwrap_or_default();
            let install_date = sub.get_value::<String, _>("InstallDate").unwrap_or_default();
            map.insert(
                format!("{}|{}", name.to_lowercase(), version.to_lowercase()),
                json!({
                    "name": name,
                    "version": version,
                    "publisher": publisher,
                    "install_date": install_date,
                }),
            );
            if map.len() >= MAX_ENTRIES {
                break;
            }
        }
    }
    map.into_values().collect()
}
