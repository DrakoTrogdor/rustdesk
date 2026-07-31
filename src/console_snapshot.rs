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
/// module, no resident agent. `{schema, available:[{title,kb,severity,size_mb,categories,reboot,
/// browse_only,auto_select,classifications}], installed:[{kb,description,installed}], pending_reboot}`.
/// The online search is slow (seconds), so it runs in a blocking task off the heartbeat; an empty
/// `available` means the search failed (WU broken/offline).
///
/// `browse_only` / `auto_select` are the distinction Windows itself draws — `auto_select` alone is
/// *Important*, neither is *Recommended*, `browse_only` alone is *Optional* — where a category string
/// is only a proxy for it. `classifications` is the `UpdateClassification`-typed subset of
/// `Categories`, so a consumer grading an update no longer has to pick classification names out of a
/// string that also carries product names. A consumer must treat all three as **absent, not false**
/// when they are missing: a client too old to report them has said nothing, not "no".
///
/// `schema` is the capability marker, and it is deliberately **not** per-update: it sits beside
/// `available`, so it is still answerable when the search returned nothing, and it decodes as absent
/// on every snapshot written before these fields existed. It states what actually ran and reported,
/// which a client version string cannot.
///
/// `-Depth 4` is exactly what the nesting needs: root object (0) → `available` (1) → per-update
/// object (2) → `classifications` (3) → its strings (4). One more level below a per-update field
/// would be stringified rather than serialized.
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
      browse_only = [bool]$_.BrowseOnly
      auto_select = [bool]$_.AutoSelectOnWebSites
      classifications = @(@($_.Categories) | Where-Object { [string]$_.Type -eq 'UpdateClassification' } | ForEach-Object { [string]$_.Name })
    }
  })
} catch {}
$installed = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 | ForEach-Object {
  [PSCustomObject]@{ kb=[string]$_.HotFixID; description=[string]$_.Description; installed= if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' } }
})
$pending = $false
try { $pending = [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch {}
[PSCustomObject]@{ schema=2; available=$available; installed=$installed; pending_reboot=$pending } | ConvertTo-Json -Depth 4 -Compress
"#;
    // The fallback is this build's own document with nothing in it, so it carries the marker too —
    // the shape is what `schema` describes, and a client that emits this one understands `select`.
    crate::console_jobs::ps_json(SCRIPT)
        .unwrap_or_else(|| json!({ "schema": 2, "available": [], "installed": [], "pending_reboot": false }))
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
    // A FAILED RSoP read must not become a policy snapshot full of zeroes. Every field below defaults
    // when its source key is missing, so an error object would flow straight through as "0 GPOs
    // applied, refresh age -1" — a device that looks unmanaged rather than unread, on the heartbeat
    // path the health rules consume. Report it unavailable with the reason instead.
    if core.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        return json!({
            "available": false,
            "error": core.get("error").and_then(|v| v.as_str()).unwrap_or("resultant set of policy could not be read"),
        });
    }
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

/// Row cap for one `processes` list. The diag surface stores a job result under a 256 KiB cap, and
/// a row serializes to roughly 60–80 bytes, so 2000 rows (~140 KB) leaves the headroom a host full
/// of long process names needs. Raising it trades that headroom for rows an ordinary host never has.
const PROCESS_CAP: usize = 2000;

/// The ordering [`PROCESS_CAP`] cuts against, stated verbatim in the truncation marker. A caller who
/// knows *which* rows were dropped can reason about what is missing; one handed a bare short list
/// cannot, and that is the whole difference between a partial answer and a wrong one.
const PROCESS_ORDER: &str = "mem_mb desc";

/// The row cap for `services`, and the ordering it cuts against.
///
/// `services` was the last genuinely ungoverned collector: a bare `Vec<Value>` with no cap, no marker
/// and no envelope, which grew until it tripped the backend's 256 KiB stored-result cap — and an
/// over-cap result is REPLACED WHOLESALE, so the failure was losing the entire service list rather
/// than its tail. Measured on this fleet: ~296 services against a cliff around 2,264.
///
/// 3000 sits above the cliff deliberately. The row cap is not the size bound — the byte cliff is — so
/// the point of this number is to bound ROWS on a host with an implausible service count while never
/// binding on a real one. The declaration is the feature; the number is just where it starts.
const SERVICE_CAP: usize = 3000;

/// Alphabetical by display name, which is what the console's table shows and what an operator scans.
const SERVICE_ORDER: &str = "display asc";

/// Running processes as `[{pid, name, cpu, mem_mb}, …]`, heaviest by memory first, capped at
/// [`PROCESS_CAP`] with a trailing truncation marker (see [`cap_processes`]). `cpu` is percent of
/// total machine capacity (Task-Manager style: summed core usage / logical CPUs), from a two-pass
/// refresh so the delta is meaningful.
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
    cap_rows(list, PROCESS_CAP, PROCESS_ORDER, "processes", "lowest-memory")
}

/// Cap the process list, appending a **truncation marker row** when rows were dropped. Under the cap
/// the list is returned untouched, so the common case carries no marker at all.
///
/// The marker is a row rather than the `{total, offset, count, truncated, next_offset, items}`
/// envelope the paginated diag collectors use, because `processes` is not only a diag collector: the
/// same value is pushed as a stored **snapshot** the console reads back and renders as a flat array.
/// The snapshot push is heartbeat-driven with no request body, so there is no offset for a caller to
/// send and nothing to page against — an envelope would buy nothing on that surface while emptying
/// the table that parses it. Keeping one array shape keeps both surfaces honest and identical.
///
/// The marker is deliberately unmistakable from both sides. A machine reads `truncated` / `total` /
/// `returned` / `order`; a human sees `name`, which is the field the console's Processes table
/// renders. It carries **no `pid`**, so a PID join skips it and the table's per-row Kill button stays
/// disabled on it. It goes last so `[0]` is still the heaviest process.
///
/// What is dropped is the tail of `mem_mb desc` — the lowest-memory rows, which is the worst tail to
/// lose and exactly where a small implant sits. The order is not changed to dodge that, because every
/// ordering drops *something* and heaviest-first is what the primary consumer wants; the fix is that
/// the loss is now declared, quantified, and attributed to a named ordering.
/// Shared by `processes` and `services` — one marker shape, so the console recognises a cut the same
/// way whichever list it came from, and so a second collector cannot invent a second dialect.
///
/// `lost` names WHICH rows went, and it is a parameter rather than a generic phrase because that is the
/// difference between a partial answer and a wrong one: "the 15 lowest-memory rows are missing" can be
/// reasoned about; "15 rows are missing" cannot.
///
/// ⚠ The marker deliberately carries NO field the console's action buttons key off. `processes` was
/// inert only by luck: it omits `pid` and the Kill button happens to gate on an empty pid. `services`
/// would NOT have been — its buttons gate on `name`, which is where the prose lives — so the console
/// gained an explicit marker predicate in the same release. Do not add `pid`, and do not assume a
/// future consumer gates on the same field this one does.
fn cap_rows(mut list: Vec<Value>, cap: usize, order: &str, noun: &str, lost: &str) -> Vec<Value> {
    let total = list.len();
    if total <= cap {
        return list;
    }
    let dropped = total - cap;
    list.truncate(cap);
    list.push(json!({
        "truncated": true,
        "total": total,
        "returned": cap,
        "order": order,
        "name": format!(
            "!truncated \u{2014} {total} {noun} present, {cap} shown (ordered by {order}); \
             the {dropped} {lost} rows are NOT in this list"
        ),
    }));
    list
}

#[cfg(test)]
fn cap_processes(list: Vec<Value>, cap: usize) -> Vec<Value> {
    cap_rows(list, cap, PROCESS_ORDER, "processes", "lowest-memory")
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
        cap_rows(list, SERVICE_CAP, SERVICE_ORDER, "services", "last-alphabetically")
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
pub(crate) fn service_start_types() -> std::collections::HashMap<String, String> {
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
                // A start TRIGGER is the other thing .NET's ServiceStartMode cannot express. Windows
                // starts such a service on demand and lets it idle back to Stopped, so an automatic
                // service sitting Stopped is its designed state, not a failure — `gpsvc` is the one
                // that flapped an alert this way. Presence of the subkey is the signal; its contents
                // (which trigger) do not change the conclusion.
                let triggered = svc.open_subkey_with_flags("TriggerInfo", KEY_READ).is_ok();
                let label = match (start, delayed, triggered) {
                    (0, _, _) => "boot",
                    (1, _, _) => "system",
                    (2, true, true) => "automatic (delayed, trigger start)",
                    (2, true, false) => "automatic (delayed)",
                    (2, false, true) => "automatic (trigger start)",
                    (2, false, false) => "automatic",
                    (3, _, _) => "manual",
                    (4, _, _) => "disabled",
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

#[cfg(test)]
mod process_cap_tests {
    use super::{cap_processes, cap_rows, PROCESS_CAP, PROCESS_ORDER, SERVICE_ORDER};
    use serde_json::{json, Value};

    /// `n` rows already in `mem_mb desc` order, heaviest first — what `processes()` hands the cap.
    fn rows(n: usize) -> Vec<Value> {
        (0..n)
            .map(|i| json!({ "pid": i as u32 + 1, "name": format!("p{i}.exe"), "cpu": 0.0, "mem_mb": (n - i) as f64 }))
            .collect()
    }

    fn marker(list: &[Value]) -> Option<&Value> {
        list.last().filter(|v| v.get("truncated").and_then(|t| t.as_bool()) == Some(true))
    }

    /// The common case must stay byte-identical to the pre-cap list: no marker on a host that fits,
    /// or every consumer would learn to expect one and a real truncation would stop standing out.
    #[test]
    fn under_and_at_the_cap_are_untouched() {
        for n in [0usize, 1, 7, 10] {
            let out = cap_processes(rows(n), 10);
            assert_eq!(out.len(), n, "{n} rows under a cap of 10 must pass through");
            assert!(marker(&out).is_none(), "no marker when nothing was dropped ({n} rows)");
        }
    }

    /// Over the cap: the kept rows are still the real heaviest-first prefix, and the answer declares
    /// its own incompleteness — count, true total, and the ordering the cut was taken against.
    #[test]
    fn over_the_cap_declares_the_truncation() {
        let out = cap_processes(rows(25), 10);
        assert_eq!(out.len(), 11, "10 kept rows plus one marker");

        // The prefix is untouched and still ordered heaviest-first.
        assert_eq!(out[0]["mem_mb"].as_f64(), Some(25.0));
        assert_eq!(out[9]["mem_mb"].as_f64(), Some(16.0));

        let m = marker(&out).expect("the marker is the last row");
        assert_eq!(m["total"].as_u64(), Some(25), "the TRUE total, not the returned count");
        assert_eq!(m["returned"].as_u64(), Some(10));
        assert_eq!(m["order"].as_str(), Some(PROCESS_ORDER), "a caller must know which tail it lost");

        // Marker hygiene: no `pid`, so a PID join drops it and the console's Kill button stays
        // disabled on it; the human-facing text names the count that vanished.
        assert!(m.get("pid").is_none(), "the marker must never look like a killable process");
        let name = m["name"].as_str().unwrap_or_default();
        assert!(name.starts_with("!truncated"), "the rendered name must read as a notice: {name}");
        assert!(name.contains("15 lowest-memory rows"), "say what was dropped, not just that some was: {name}");
    }

    /// `services` was the last ungoverned collector — a bare Vec that grew until it tripped the
    /// backend's 256 KiB cap, where an over-cap result is REPLACED WHOLESALE. It must now declare a cut
    /// in the SAME shape `processes` uses, and the marker must carry no field the console's Start/Stop
    /// buttons key off. (`name` holds the prose, which is exactly what those buttons gate on — hence the
    /// console-side marker predicate shipped alongside this.)
    #[test]
    fn services_declares_its_cut_in_the_shared_marker_shape() {
        let svc = |i: usize| json!({ "name": format!("svc{i}"), "display": format!("Service {i}"), "state": "running", "start": "auto" });
        let under: Vec<Value> = (0..10usize).map(svc).collect();
        assert_eq!(cap_rows(under.clone(), 3000, SERVICE_ORDER, "services", "last-alphabetically").len(), 10, "under the cap, untouched");
        assert!(cap_rows(under, 3000, SERVICE_ORDER, "services", "last-alphabetically").iter().all(|r| r.get("truncated").is_none()));

        let over: Vec<Value> = (0..25usize).map(svc).collect();
        let out = cap_rows(over, 10, SERVICE_ORDER, "services", "last-alphabetically");
        assert_eq!(out.len(), 11, "10 rows + one marker");
        let m = out.last().expect("marker");
        assert_eq!(m["truncated"], json!(true));
        assert_eq!(m["total"], json!(25), "the TRUE count, not what was returned");
        assert_eq!(m["returned"], json!(10));
        assert_eq!(m["order"].as_str(), Some(SERVICE_ORDER));
        assert!(m["name"].as_str().unwrap_or_default().contains("15 last-alphabetically"), "say WHICH rows went: {}", m["name"]);
        // Marker hygiene: nothing here may look like a real service to the action buttons.
        assert!(m.get("display").is_none() && m.get("state").is_none() && m.get("start").is_none(), "{m}");
    }

    /// The production cap must leave real headroom under the 256 KiB job-result store cap the diag
    /// surface enforces — a full page that trips that cap is rejected wholesale, so the collector
    /// pays for its own bound instead of discovering it downstream.
    #[test]
    fn the_production_cap_fits_the_job_result_store() {
        let out = cap_processes(rows(PROCESS_CAP + 5), PROCESS_CAP);
        assert_eq!(out.len(), PROCESS_CAP + 1);
        // Long, realistic process names rather than the short synthetic ones above.
        let wide: Vec<Value> = (0..PROCESS_CAP)
            .map(|i| json!({ "pid": i as u32, "name": "Microsoft.SharePoint.Portal.Worker.exe", "cpu": 12.5, "mem_mb": 1234.5 }))
            .collect();
        let bytes = Value::Array(wide).to_string().len();
        assert!(bytes < 256 * 1024, "a full page of wide rows is {bytes} bytes, over the 256 KiB store cap");
    }
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
