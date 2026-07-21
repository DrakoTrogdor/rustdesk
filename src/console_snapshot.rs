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
        "defender" => Some(defender()),
        "winupdate" => Some(winupdate()),
        "policy" => Some(policy()),
        _ => None,
    }
}

/// Available + recently-installed Windows updates as a JSON **object** (Windows-first), via the
/// native Windows Update COM API (`Microsoft.Update.Session`) run BY the client — no `PSWindowsUpdate`
/// module, no resident agent. `{available:[{title,kb,severity,size_mb,categories,reboot}], installed:
/// [{kb,description,installed}], pending_reboot}`. The online search is slow (seconds), so it runs in
/// a blocking task off the heartbeat; an empty `available` means the search failed (WU broken/offline).
#[cfg(windows)]
fn winupdate() -> Value {
    const SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
$available=@()
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $res = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
  $available = @($res.Updates | Select-Object -First 200 | ForEach-Object {
    [PSCustomObject]@{
      title = [string]$_.Title
      kb = (@($_.KBArticleIDs) -join ',')
      severity = [string]$_.MsrcSeverity
      size_mb = [math]::Round(($_.MaxDownloadSize/1MB),1)
      categories = ((@($_.Categories) | ForEach-Object { $_.Name }) -join ', ')
      reboot = [bool]$_.InstallationBehavior.RebootBehavior
    }
  })
} catch {}
$installed = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | ForEach-Object {
  [PSCustomObject]@{ kb=[string]$_.HotFixID; description=[string]$_.Description; installed= if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' } }
})
$pending = $false
try { $pending = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch {}
[PSCustomObject]@{ available=$available; installed=$installed; pending_reboot=$pending } | ConvertTo-Json -Depth 4 -Compress
"#;
    crate::console_jobs::ps_json(SCRIPT).unwrap_or_else(|| json!({ "available": [], "installed": [], "pending_reboot": false }))
}
#[cfg(not(windows))]
fn winupdate() -> Value {
    json!({ "available": [], "installed": [], "pending_reboot": false, "error": "Windows-only" })
}

/// Compact Group-Policy health signals for the fleet-health engine (F15) — a low-cadence reduction
/// of the RSoP deep-read (`console_jobs::rsop_core`, no settings dump). Object-shaped, always returned
/// (`{available:false}` when RSoP can't be read). Raw signals only — thresholds live server-side so
/// they stay operator-tunable, exactly like the Defender/Windows-Update snapshots:
/// `{available, part_of_domain, domain, loopback, error_count, computer:{refresh_age_hours,last_refresh,
/// applied_count,denied_count}, users:[{user,refresh_age_hours,applied_count,denied_count}], security}`.
/// The health rules gate on `part_of_domain` so non-domain boxes (no gpsvc, local policy only) never
/// false-positive.
#[cfg(windows)]
fn policy() -> Value {
    let Some(core) = crate::console_jobs::rsop_core(false, None, 10) else {
        return json!({ "available": false });
    };
    let count = |o: &Value, k: &str| o.get(k).and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    let comp = core.get("computer").cloned().unwrap_or_else(|| json!({}));
    let computer = json!({
        "refresh_age_hours": comp.get("refresh_age_hours").cloned().unwrap_or_else(|| json!(-1)),
        "last_refresh": comp.get("last_refresh").cloned().unwrap_or_else(|| json!("")),
        "applied_count": count(&comp, "applied_gpos"),
        "denied_count": count(&comp, "denied_gpos"),
    });
    let users: Vec<Value> = core
        .get("users")
        .and_then(|u| u.as_array())
        .map(|arr| {
            arr.iter()
                .map(|u| {
                    json!({
                        "user": u.get("user").cloned().unwrap_or_else(|| json!("")),
                        "refresh_age_hours": u.get("refresh_age_hours").cloned().unwrap_or_else(|| json!(-1)),
                        "applied_count": count(u, "applied_gpos"),
                        "denied_count": count(u, "denied_gpos"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "available": true,
        "part_of_domain": core.get("part_of_domain").cloned().unwrap_or_else(|| json!(false)),
        "domain": core.get("domain").cloned().unwrap_or_else(|| json!("")),
        "loopback": core.get("loopback").cloned().unwrap_or_else(|| json!("NotConfigured")),
        "error_count": core.get("error_count").cloned().unwrap_or_else(|| json!(0)),
        "computer": computer,
        "users": users,
        "security": core.get("security").cloned().unwrap_or(Value::Null),
    })
}
#[cfg(not(windows))]
fn policy() -> Value {
    json!({ "available": false, "error": "Windows-only" })
}

/// Microsoft Defender status + recent threats as a JSON **object** (Windows-first). One PowerShell
/// pass: `Get-MpComputerStatus` (real-time protection, signature versions/age, last scan end times)
/// merged with `Get-MpThreat` (recent detections, capped at 50, newest first). Always returns an
/// object — `{available:false}` when Defender is absent/off — so the console panel can show
/// "unavailable" instead of a blank. Object-shaped, which the snapshot ingest accepts alongside the
/// list kinds.
#[cfg(windows)]
fn defender() -> Value {
    const SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
$s = Get-MpComputerStatus
if (-not $s) { '{"available":false}'; exit }
# Scan in progress: the scan times in Get-MpComputerStatus only update on completion, so detect a
# live scan from the Defender operational log instead - the latest scan event being a "started"
# (1000) with no later "finished"/"stopped" (1001/1002) means a scan is running.
$scan_running=$false; $scan_type=''; $scan_start=''
$ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1000,1001,1002} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($ev -and $ev.Id -eq 1000) {
  $scan_running=$true
  $scan_start=$ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
  if ($ev.Message -match 'Full Scan') { $scan_type='full' } elseif ($ev.Message -match 'Quick Scan') { $scan_type='quick' }
}
# Days since the most recent completed scan (quick or full), computed in the device's local time;
# -1 when never scanned. Drives the fleet-health "scan stale" warning.
$lastScan = @($s.QuickScanEndTime, $s.FullScanEndTime) | Where-Object { $_ -and $_.Year -gt 2000 } | Sort-Object -Descending | Select-Object -First 1
$scan_age = if ($lastScan) { [int]((New-TimeSpan -Start $lastScan -End (Get-Date)).TotalDays) } else { -1 }
$threats = @(Get-MpThreat | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 | ForEach-Object {
  [PSCustomObject]@{
    name = [string]$_.ThreatName
    severity = [int]$_.SeverityID
    active = [bool]$_.IsActive
    detected = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
  }
})
[PSCustomObject]@{
  available = $true
  rtp = [bool]$s.RealTimeProtectionEnabled
  am_service = [bool]$s.AMServiceEnabled
  antivirus = [bool]$s.AntivirusEnabled
  antispyware = [bool]$s.AntispywareEnabled
  tamper = [bool]$s.IsTamperProtected
  av_sig_version = [string]$s.AntivirusSignatureVersion
  av_sig_age = [int]$s.AntivirusSignatureAge
  as_sig_version = [string]$s.AntispywareSignatureVersion
  as_sig_age = [int]$s.AntispywareSignatureAge
  engine = [string]$s.AMEngineVersion
  product = [string]$s.AMProductVersion
  last_quick = if ($s.QuickScanEndTime) { $s.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
  last_full = if ($s.FullScanEndTime) { $s.FullScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
  scan_running = $scan_running
  scan_type = $scan_type
  scan_start = $scan_start
  scan_age_days = $scan_age
  threats = $threats
} | ConvertTo-Json -Depth 4 -Compress
"#;
    crate::console_jobs::ps_json(SCRIPT).unwrap_or_else(|| json!({ "available": false }))
}
#[cfg(not(windows))]
fn defender() -> Value {
    json!({ "available": false, "error": "Windows-only" })
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
            // Data plane: a process/service/winupdate snapshot is a bulk upload.
            match crate::post_request_timeout(url, bs, &header, crate::API_TIMEOUT_DATA).await {
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
