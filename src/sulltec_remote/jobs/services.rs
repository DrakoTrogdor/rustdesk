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
        // ZERO SERVICES IS IMPOSSIBLE ON A RUNNING WINDOWS HOST, so an empty enumeration is a FAILED
        // READ, not a result. `EnumServicesStatusEx` can return nothing without raising an error, and
        // then `[]` reaches the wire beside `status:"done"` — "this machine has no services" — which
        // is the R1 lie in its most alarming form, on a snapshot that feeds inventory and health.
        //
        // Measured 2026-08-02 on a Windows 11 box: pushing the service count to ~2,273 broke
        // enumeration through EVERY path at once — Get-Service returned 0, `sc query` returned 0, and
        // WMI answered "Generic failure" — while individual service lookups still worked and every
        // critical service was Running. The collector reported `result: []` with no error. Deleting
        // the extra services restored all three paths immediately.
        //
        // ⚠ SERVICE_CAP is NOT the limit and needs no change: the SCM path dies between 2,197 and
        // 2,297 services, so the OS gives up long before the 3,000-row cap binds. The cap is
        // correctly sized above the real ceiling and stays as the byte-cliff backstop; its truncation
        // marker simply cannot fire on Windows.
        //
        // WMI outlives the SCM path — measured returning all 2,297 where this one returned zero — so
        // when the fast path comes back empty, ask WMI before giving up. That is not just about
        // getting the rows: a host where SCM enumeration is dead and WMI is not IS A BROKEN HOST, and
        // the fallback firing is the signal that says so. The marker row carries
        // `enumeration_degraded` for exactly that, so the condition is diagnosable instead of
        // appearing as a healthy machine that happens to answer more slowly.
        let mut degraded = false;
        if list.is_empty() {
            let wmi = enum_services_wmi();
            if wmi.is_empty() {
                // The BARE OBJECT, not an array wrapping one. Every other collector's failure is
                // `{ok:false,error}` at the top level, and the console matches that shape before it
                // renders a table — an array holding one error object would slip past into the table
                // arm and draw a single blank row, which reads as "this host has one nameless
                // service" instead of "the read failed".
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
        // A NOTICE row, not a service — the same shape and the same skip rule as the truncation
        // marker. Appended last so it cannot displace a real row.
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
/// The marker is deliberately unmistakable from both sides. A machine reads `truncated` / `total` /
/// `returned` / `order`; a human sees `name`, which is the field the console's tables render. It
/// goes last so `[0]` is still the head of the declared ordering.
///
/// What is dropped is the tail of the declared ordering, and every ordering drops *something* — the
/// point is that the loss is declared, quantified, and attributed to a named ordering.
/// One marker shape, so the console recognises a cut the same way whichever list it came from, and
/// so a second collector cannot invent a second dialect.
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

/// The same enumeration through WMI, used ONLY when the SCM path returns nothing.
///
/// WMI outlives `EnumServicesStatusExW` on a host carrying thousands of service registrations —
/// measured returning all 2,297 where the SCM call returned zero — so this recovers the rows AND
/// identifies the failure. It is deliberately the fallback and not the primary: it costs a
/// PowerShell process and a WMI query, which is far more than the direct API.
///
/// `state` is lowercased to match the SCM path's spelling, so a consumer cannot tell which produced
/// a row from its shape — the `enumeration_degraded` marker is what says that, once, for the set.
#[cfg(windows)]
pub(super) fn enum_services_wmi() -> Vec<(String, String, String)> {
    const SCRIPT: &str = r#"@(Get-CimInstance Win32_Service -ErrorAction Stop |
  ForEach-Object { [pscustomobject]@{ n=[string]$_.Name; d=[string]$_.DisplayName; s=([string]$_.State).ToLower() } }) |
  ConvertTo-Json -Depth 3 -Compress"#;
    let Some(v) = ps_json(SCRIPT) else { return Vec::new() };
    // ConvertTo-Json collapses a one-element array to a bare object; a single service is absurd here
    // but the shape rule is the shape rule.
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




