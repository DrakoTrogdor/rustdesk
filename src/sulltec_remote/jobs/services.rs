use super::*;

/// Win32 services as `[{name, display, state, start}, …]`, by display name. Empty on
/// non-Windows. `state` is live (from the SCM); `start` is the configured start type
/// (from the registry).
pub(super) fn services() -> Value {
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
        // A running Windows host has services, so an empty SCM enumeration is a failed read. WMI is
        // the fallback because it can enumerate hosts whose SCM bulk query returns no rows. A
        // successful fallback adds `enumeration_degraded` so callers can diagnose the disagreement.
        let mut degraded = false;
        if list.is_empty() {
            let wmi = enum_services_wmi();
            if wmi.is_empty() {
                // Return a bare `{ok:false,error}` object so the console treats this as a collector
                // failure instead of rendering an error object as a service row.
                return json!({
                    "ok": false,
                    "error": "service enumeration returned no rows through either the SCM or WMI — \
                              impossible on a running Windows host, so this is a failed read rather \
                              than an empty result",
                });
            }
            degraded = true;
            list = wmi
                .into_iter()
                .map(|(name, display, state)| {
                    let start = starts.get(&name.to_lowercase()).cloned().unwrap_or_default();
                    json!({ "name": name, "display": display, "state": state, "start": start })
                })
                .collect();
        }
        list.sort_by(|a, b| {
            a["display"].as_str().unwrap_or("").to_lowercase().cmp(&b["display"].as_str().unwrap_or("").to_lowercase())
        });
        let mut rows = cap_rows(list, SERVICE_CAP, SERVICE_ORDER, "services", "last-alphabetically");
        // The notice is appended after all service rows and does not displace a real row.
        if degraded {
            rows.push(json!({
                "enumeration_degraded": true,
                "source": "wmi",
                "detail": "the SCM service enumeration returned nothing and WMI answered instead. \
                           The rows are complete, but a host where those two disagree is itself the \
                           finding: Windows stops enumerating through the SCM once the machine \
                           carries roughly 2,200+ service registrations.",
            }));
        }
        Value::Array(rows)
    }
    #[cfg(not(windows))]
    {
        Value::Array(Vec::new())
    }
}

/// Cap a row list, appending a **truncation marker row** when rows were dropped. Under the cap
/// the list is returned untouched, so the common case carries no marker at all.
///
/// The marker exposes `truncated`, `total`, `returned`, and `order` to machines and a descriptive
/// `name` to table renderers. It goes last so the first row remains the head of the declared order.
///
/// The dropped tail is quantified and attributed to the declared ordering. All collectors use the
/// same marker shape.
///
/// `lost` identifies which portion of the declared ordering was omitted.
///
/// The marker carries no action identifier such as `pid`. Consumers must recognize marker rows
/// explicitly instead of inferring them from a missing action field.
pub(super) fn cap_rows(mut list: Vec<Value>, cap: usize, order: &str, noun: &str, lost: &str) -> Vec<Value> {
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

/// Bulk-enumerate Win32 services → `(name, display, state)`. One SCM call (two-pass for
/// sizing). Empty on any failure (e.g. SCM access denied when not running as a service).
#[cfg(windows)]
pub(super) fn enum_services() -> Vec<(String, String, String)> {
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

/// Enumerate services through WMI when the SCM path returns nothing.
///
/// WMI can return rows when `EnumServicesStatusExW` fails on hosts with thousands of service
/// registrations. It remains the fallback because it launches PowerShell and performs a WMI query.
///
/// `state` is lowercased to match the SCM path's spelling, so a consumer cannot tell which produced
/// a row from its shape — the `enumeration_degraded` marker is what says that, once, for the set.
#[cfg(windows)]
pub(super) fn enum_services_wmi() -> Vec<(String, String, String)> {
    const SCRIPT: &str = r#"@(Get-CimInstance Win32_Service -ErrorAction Stop |
  ForEach-Object { [pscustomobject]@{ n=[string]$_.Name; d=[string]$_.DisplayName; s=([string]$_.State).ToLower() } }) |
  ConvertTo-Json -Depth 3 -Compress"#;
    let Some(v) = ps_json(SCRIPT) else { return Vec::new() };
    // ConvertTo-Json collapses a one-element array to a bare object, so accept either shape.
    let rows: Vec<&serde_json::Value> = match &v {
        serde_json::Value::Array(a) => a.iter().collect(),
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Vec::new(),
    };
    rows.into_iter()
        .filter_map(|r| {
            let name = r.get("n")?.as_str()?.to_owned();
            if name.is_empty() {
                return None;
            }
            let display = r.get("d").and_then(|x| x.as_str()).unwrap_or("").to_owned();
            let state = r.get("s").and_then(|x| x.as_str()).unwrap_or("").to_owned();
            Some((name, display, state))
        })
        .collect()
}




