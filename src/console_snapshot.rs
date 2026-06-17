//! Live process + service snapshots for the SullTec console (EXTENSION-PLAN A).
//!
//! Unlike inventory (slow-changing, server-pulled on a staleness TTL), these are volatile
//! and **operator-driven**: the console requests one only while a technician is looking at
//! the device's Processes/Services page. The pull rides the same heartbeat idiom — the
//! `/api/heartbeat` response carries `{"processes": true}` and/or `{"services": true}`, and
//! the patched client answers by POSTing `/api/snapshot` with `{id, uuid, kind, data}`.
//! Nothing is collected unless asked, and the request is cleared after one heartbeat (the
//! console's refresh button / auto-refresh timer re-asks), so an idle device does no work.
//!
//! Collection (Windows-first, no new crates beyond `windows`/`winreg`/`sysinfo` already in
//! the client):
//!   * processes — `sysinfo` two-pass refresh (so CPU% is a real delta);
//!   * services  — `EnumServicesStatusExW` (one bulk SCM call → name/display/state) merged
//!     with each service's `Start` value from the registry (start type). No per-service SCM
//!     query, so it stays a single privileged call.

use serde_json::{json, Value};

/// Collect one snapshot kind as a JSON array, or `None` for an unknown kind.
pub fn collect(kind: &str) -> Option<Value> {
    match kind {
        "processes" => Some(json!(processes())),
        "services" => Some(json!(services())),
        _ => None,
    }
}

/// Collect-and-POST one kind in the background, guarded so a slow collection can't stack
/// uploads of the same kind (the console re-asks next cycle if one is dropped).
#[cfg(not(any(target_os = "ios")))]
pub fn upload(heartbeat_url: String, id: String, kind: &'static str) {
    use std::sync::Mutex;
    lazy_static::lazy_static! {
        static ref IN_FLIGHT: Mutex<std::collections::HashSet<&'static str>> = Mutex::new(Default::default());
    }
    if !IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).insert(kind) {
        return; // an upload of this kind is already running
    }
    hbb_common::tokio::spawn(async move {
        let data = hbb_common::tokio::task::spawn_blocking(move || collect(kind)).await;
        if let Ok(Some(data)) = data {
            let body = json!({
                "id": id,
                "uuid": crate::encode64(hbb_common::get_uuid()),
                "kind": kind,
                "data": data,
            });
            let url = heartbeat_url.replace("heartbeat", "snapshot");
            let bs = body.to_string();
            let header = crate::console_jobs::sign_header(&bs);
            match crate::post_request(url, bs, &header).await {
                Ok(rsp) if rsp == "SNAPSHOT_UPDATED" => hbb_common::log::info!("{kind} snapshot uploaded"),
                Ok(rsp) => hbb_common::log::error!("{kind} snapshot rejected: {rsp}"),
                Err(e) => hbb_common::log::error!("{kind} snapshot upload failed: {e}"),
            }
        } else if let Err(e) = data {
            hbb_common::log::error!("{kind} snapshot collect panicked: {e}");
        }
        IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).remove(kind);
    });
}

/// Running processes as `[{pid, name, cpu, mem_mb}, …]`, heaviest by memory first.
/// `cpu` is percent of total machine capacity (Task-Manager style: summed core usage /
/// logical CPUs), from a two-pass refresh so the delta is meaningful. Capped at 2000.
fn processes() -> Vec<Value> {
    use hbb_common::sysinfo::{System, MINIMUM_CPU_UPDATE_INTERVAL};
    let mut sys = System::new();
    // First pass seeds per-process CPU counters; the second pass (after the minimum
    // interval) turns them into a usable percentage.
    sys.refresh_processes();
    std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes();
    let ncpu = num_cpus::get().max(1) as f32;
    let mut list: Vec<Value> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            json!({
                "pid": pid.as_u32(),
                "name": p.name(),
                "cpu": ((p.cpu_usage() / ncpu) * 10.0).round() / 10.0,
                "mem_mb": (p.memory() as f64 / 1024.0 / 1024.0 * 10.0).round() / 10.0,
            })
        })
        .collect();
    list.sort_by(|a, b| {
        b["mem_mb"].as_f64().partial_cmp(&a["mem_mb"].as_f64()).unwrap_or(std::cmp::Ordering::Equal)
    });
    list.truncate(2000);
    list
}

/// Win32 services as `[{name, display, state, start}, …]`, by display name. Empty on
/// non-Windows. `state` is live (from the SCM); `start` is the configured start type
/// (from the registry).
fn services() -> Vec<Value> {
    #[cfg(windows)]
    {
        let starts = service_start_types();
        let mut list: Vec<Value> = enum_services()
            .into_iter()
            .map(|(name, display, state)| {
                let start = starts.get(&name.to_lowercase()).cloned().unwrap_or_default();
                json!({ "name": name, "display": display, "state": state, "start": start })
            })
            .collect();
        list.sort_by(|a, b| {
            a["display"].as_str().unwrap_or("").to_lowercase().cmp(&b["display"].as_str().unwrap_or("").to_lowercase())
        });
        list
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Bulk-enumerate Win32 services → `(name, display, state)`. One SCM call (two-pass for
/// sizing). Empty on any failure (e.g. SCM access denied when not running as a service).
#[cfg(windows)]
fn enum_services() -> Vec<(String, String, String)> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_PAUSED, SERVICE_RUNNING,
        SERVICE_STATE_ALL, SERVICE_STOPPED, SERVICE_WIN32,
    };

    let mut out: Vec<(String, String, String)> = Vec::new();
    unsafe {
        let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) {
            Ok(h) => h,
            Err(_) => return out,
        };
        // Pass 1: discover the required buffer size (the call fails with ERROR_MORE_DATA).
        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut returned,
            None,
            PCWSTR::null(),
        );
        if needed == 0 {
            let _ = CloseServiceHandle(scm);
            return out;
        }
        // Allocate via u64 so the ENUM_SERVICE_STATUS_PROCESSW array is pointer-aligned.
        let mut backing: Vec<u64> = vec![0u64; (needed as usize).div_ceil(8)];
        let buf: &mut [u8] =
            std::slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, backing.len() * 8);
        let ok = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf[..needed as usize]),
            &mut needed,
            &mut returned,
            None,
            PCWSTR::null(),
        );
        if ok.is_ok() {
            let arr = backing.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
            for i in 0..returned as usize {
                let e = &*arr.add(i);
                let name = pwstr(e.lpServiceName);
                if name.is_empty() {
                    continue;
                }
                let display = pwstr(e.lpDisplayName);
                let state = match e.ServiceStatusProcess.dwCurrentState {
                    SERVICE_RUNNING => "running",
                    SERVICE_STOPPED => "stopped",
                    SERVICE_PAUSED => "paused",
                    _ => "transitioning",
                };
                out.push((name, display, state.to_owned()));
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    out
}

/// `service-name (lowercase) → start type` from `HKLM\SYSTEM\CurrentControlSet\Services`.
/// The SCM enumeration gives live state but not the configured start type; the registry
/// has it without a per-service SCM query.
#[cfg(windows)]
fn service_start_types() -> std::collections::HashMap<String, String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let mut map = std::collections::HashMap::new();
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ)
    else {
        return map;
    };
    for name in root.enum_keys().flatten() {
        if let Ok(svc) = root.open_subkey_with_flags(&name, KEY_READ) {
            // `Start`: 0 boot, 1 system, 2 auto, 3 manual (demand), 4 disabled.
            if let Ok(start) = svc.get_value::<u32, _>("Start") {
                let delayed = svc.get_value::<u32, _>("DelayedAutostart").unwrap_or(0) == 1;
                let label = match start {
                    0 => "boot",
                    1 => "system",
                    2 if delayed => "automatic (delayed)",
                    2 => "automatic",
                    3 => "manual",
                    4 => "disabled",
                    _ => "",
                };
                if !label.is_empty() {
                    map.insert(name.to_lowercase(), label.to_owned());
                }
            }
        }
    }
    map
}

/// Read a NUL-terminated wide string into a `String` (empty on null pointer).
#[cfg(windows)]
unsafe fn pwstr(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
}
