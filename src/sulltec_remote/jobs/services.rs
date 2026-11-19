use super::*;

pub(super) fn services() -> Value {
    #[cfg(windows)]
    {
        let starts = service_start_types();
        let accounts = service_accounts();
        let mut list: Vec<Value> = enum_services()
            .into_iter()
            .map(|(name, display, state)| {
                let start = starts.get(&name.to_lowercase()).cloned().unwrap_or_default();
                let account = accounts.as_ref().map(|a| a.get(&name.to_lowercase()).cloned());
                let mut row = json!({ "name": name, "display": display, "state": state, "start": start });
                if let Some(account) = account {
                    row["account"] = json!(account);
                }
                row
            })
            .collect();
        let mut degraded = false;
        if list.is_empty() {
            let wmi = enum_services_wmi();
            if wmi.is_empty() {
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
                .map(|(name, display, state, account)| {
                    let start = starts.get(&name.to_lowercase()).cloned().unwrap_or_default();
                    json!({ "name": name, "display": display, "state": state, "start": start, "account": account })
                })
                .collect();
        }
        list.sort_by(|a, b| {
            a["display"].as_str().unwrap_or("").to_lowercase().cmp(&b["display"].as_str().unwrap_or("").to_lowercase())
        });
        let mut rows = cap_rows(list, SERVICE_CAP, SERVICE_ORDER, "services", "last-alphabetically");
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

/// Empty on any failure — notably SCM access denied when not running as a service.
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

/// WMI still answers where `EnumServicesStatusExW` fails on hosts carrying thousands of service
/// registrations. It stays the FALLBACK because it costs a PowerShell launch and a WMI query.
#[cfg(windows)]
pub(super) fn enum_services_wmi() -> Vec<(String, String, String, Option<String>)> {
    const SCRIPT: &str = r#"@(Get-CimInstance Win32_Service -ErrorAction Stop |
  ForEach-Object { [pscustomobject]@{ n=[string]$_.Name; d=[string]$_.DisplayName; s=([string]$_.State).ToLower(); a=[string]$_.StartName } }) |
  ConvertTo-Json -Depth 3 -Compress"#;
    let Some(v) = ps_json(SCRIPT) else { return Vec::new() };
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
            let account = r.get("a").and_then(|x| x.as_str()).filter(|a| !a.is_empty()).map(str::to_owned);
            Some((name, display, state, account))
        })
        .collect()
}

#[cfg(windows)]
fn service_accounts() -> Option<std::collections::HashMap<String, String>> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let mut map = std::collections::HashMap::new();
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ)
    else {
        return None;
    };
    for name in root.enum_keys().flatten() {
        if let Ok(svc) = root.open_subkey_with_flags(&name, KEY_READ) {
            if let Ok(account) = svc.get_value::<String, _>("ObjectName") {
                if !account.is_empty() {
                    map.insert(name.to_lowercase(), account);
                }
            }
        }
    }
    Some(map)
}




