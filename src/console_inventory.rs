//! Hardware + software inventory for the SullTec console (EXTENSION-PLAN A).
//!
//! The server pulls this: when the console believes its stored inventory for a device is
//! stale (missing, older than its TTL, or an operator pressed Refresh) it answers the
//! regular `/api/heartbeat` with `{"inventory": true}` — the same idiom stock hbbs uses to
//! force a sysinfo re-upload — and the client responds by POSTing the full inventory to
//! `/api/inventory`. Nothing is collected or sent unless the server asks.
//!
//! Collection is Windows-first (matching the deployed fleet), native and crate-free beyond
//! what the client already ships (`windows`, `winreg`, `sysinfo`):
//!   * hardware identity (manufacturer / model / serial / BIOS) from the SMBIOS firmware
//!     table via `GetSystemFirmwareTable("RSMB")` — readable by any user, DC not involved;
//!   * CPU / memory / fixed disks via the bundled `sysinfo` crate (cross-platform);
//!   * GPU names from the display-adapter class registry key;
//!   * installed software from the machine-wide `Uninstall` registry keys (both the 64-bit
//!     and 32-bit views; per-user installs are not visible to the service and are skipped).
//! Non-Windows builds return the cross-platform subset and an empty software list.

use serde_json::{json, Value};

/// Gather the full inventory payload: `{"hardware": {…}, "software": [{…}, …]}`.
pub fn collect() -> Value {
    json!({
        "hardware": hardware(),
        "software": software(),
    })
}

/// Collect-and-POST in the background, guarded so overlapping server requests can't stack
/// uploads (the server re-asks after its cooldown if an upload never lands).
#[cfg(not(any(target_os = "ios")))]
pub fn upload(heartbeat_url: String, id: String) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
    if IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    hbb_common::tokio::spawn(async move {
        // Registry/SMBIOS/disk enumeration is blocking work; keep it off the sync loop.
        let mut v = match hbb_common::tokio::task::spawn_blocking(collect).await {
            Ok(v) => v,
            Err(e) => {
                hbb_common::log::error!("inventory collect failed: {e}");
                IN_FLIGHT.store(false, Ordering::SeqCst);
                return;
            }
        };
        v["id"] = json!(id);
        v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
        let url = heartbeat_url.replace("heartbeat", "inventory");
        match crate::post_request(url, v.to_string(), "").await {
            Ok(rsp) if rsp == "INVENTORY_UPDATED" => {
                hbb_common::log::info!("inventory uploaded");
            }
            Ok(rsp) => hbb_common::log::error!("inventory upload rejected: {rsp}"),
            Err(e) => hbb_common::log::error!("inventory upload failed: {e}"),
        }
        IN_FLIGHT.store(false, Ordering::SeqCst);
    });
}

/// Hardware identity + capacity. Field set is stable JSON consumed by the console verbatim.
fn hardware() -> Value {
    use hbb_common::sysinfo::{Disks, System};

    let mut system = System::new();
    system.refresh_memory();
    system.refresh_cpu();
    let memory_gb =
        (system.total_memory() as f64 / 1024. / 1024. / 1024. * 100.).round() / 100.;
    // Live metrics (F15): used RAM, system uptime, and CPU utilisation. CPU% needs a second sample
    // after a short delay (the first establishes the baseline) — cheap on a background inventory pull.
    let mem_used_gb = (system.used_memory() as f64 / 1024. / 1024. / 1024. * 100.).round() / 100.;
    let uptime_secs = system.uptime();
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

    // Fixed disks only — removable media would churn the inventory with USB sticks.
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
        // Extended device info (EXTENSION-PLAN A): logged-on / RDP sessions + installed hotfixes,
        // carried in the hardware blob the console stores verbatim (so no new endpoint/column).
        hw["sessions"] = json!(sessions());
        hw["hotfixes"] = json!(hotfixes());
    }
    hw["network"] = network();
    hw
}

/// Logged-on Windows sessions (console + RDP) as `[{sid, name}, …]`, where `name` is e.g.
/// "Console: alice" / "rdp-tcp: bob" (empty list off-Windows). Reuses the same session
/// enumeration the RDS session picker uses.
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

/// Installed hotfixes / Windows updates as `[{id, installed_on}, …]` from
/// `Win32_QuickFixEngineering` via PowerShell (the standard "installed updates" view; note it
/// only surfaces QFE-tracked updates, not every CBS package). Bounded so the hardware blob stays
/// under the console's size cap; empty off-Windows or if the query fails.
#[cfg(windows)]
fn hotfixes() -> Vec<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
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

/// Network identity for the console's Networking section: the hostname plus every
/// interface address, bucketed into private vs public per family. The console pairs this
/// with the rendezvous-observed public IP it already holds. Loopback is dropped.
///   * IPv4 private = RFC1918 + link-local (169.254); public = anything else routable.
///   * IPv6 private = link-local (fe80::/10) + ULA (fc00::/7); public = global unicast
///     (so a box's own global IPv6, which has no NAT, shows as public).
fn network() -> Value {
    let mut v4_private: Vec<String> = Vec::new();
    let mut v4_public: Vec<String> = Vec::new();
    let mut v6_private: Vec<String> = Vec::new();
    let mut v6_public: Vec<String> = Vec::new();
    // default_net::get_interfaces() triggers undefined-symbol errors on the iOS simulator
    // (see lan.rs), and the managed fleet is desktop anyway.
    #[cfg(not(target_os = "ios"))]
    for iface in default_net::get_interfaces() {
        for net in &iface.ipv4 {
            let a = net.addr;
            if a.is_loopback() {
                continue;
            }
            let s = a.to_string();
            if a.is_private() || a.is_link_local() {
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
            // link-local fe80::/10 or ULA fc00::/7 → private; else global unicast → public.
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
    #[cfg(windows)]
    {
        net["dns_suffixes"] = json!(dns_suffixes());
        // Extended AD: the computer object's full distinguishedName (empty off-domain).
        let dn = crate::console_ad::computer_dn();
        if !dn.is_empty() {
            net["dn"] = json!(dn);
        }
    }
    net
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// Connection-specific DNS suffixes, per adapter, from
/// `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`.
/// This is the `ipconfig` "Connection-specific DNS Suffix" — present on workgroup
/// machines too (DHCP option 15), unlike the AD/primary DNS domain that
/// `console_ad::dns_domain()` reports (and which feeds the console tenant — these
/// deliberately do NOT). A static per-adapter `Domain` overrides `DhcpDomain`, matching
/// Windows semantics; adapters with no current address are skipped so suffixes from
/// stale/disconnected interfaces don't linger.
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

/// The primary connection-specific DNS suffix (first non-empty), reported to the console as a
/// device-grouping fallback for non-domain-joined boxes. Empty off Windows or when no adapter
/// reports one.
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

/// Installed software as `[{name, version, publisher, install_date}, …]`, deduped and
/// sorted by name. Empty on non-Windows.
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

/// Read the raw SMBIOS table (`GetSystemFirmwareTable("RSMB")` — no admin needed) and pull
/// the BIOS (type 0) and System (type 1) structures.
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
        // Collect this structure's string set.
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
                // empty string = end-of-set marker (the second NUL of the double NUL)
                p += 1;
                break;
            }
            strings.push(String::from_utf8_lossy(&table[start..p]).trim().to_owned());
            p += 1; // skip the terminating NUL
        }
        // A structure with no strings terminates with two NULs immediately.
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

/// OEM boards ship literal placeholder serials; show nothing rather than junk.
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

/// GPU names from the display-adapter device class key — avoids pulling in GDI/D3D APIs.
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
        // Adapter instances are 4-digit subkeys (0000, 0001, …); skip e.g. "Properties".
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

/// Machine-wide installed software from the `Uninstall` keys, both registry views.
/// Mirrors what "Apps & features" lists: hides `SystemComponent` rows and patch entries
/// that point at a parent product.
#[cfg(windows)]
fn software_windows() -> Vec<Value> {
    use std::collections::BTreeMap;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    use winreg::RegKey;
    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    /// Cap pathological registries; the server caps the stored blob anyway.
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
            // Dedupe across views/keys by (name, version); BTreeMap doubles as the sort.
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
