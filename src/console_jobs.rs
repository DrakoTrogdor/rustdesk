//! Client-native job channel (EXTENSION-PLAN D). The patched client:
//!   1. enrolls an Ed25519 public key (trust-on-first-use) so the console can verify its results;
//!   2. receives queued jobs in the `/api/heartbeat` response (`{"jobs":[{id,kind,params}, …]}`);
//!   3. runs the read-only kinds natively and POSTs a **signed** result to
//!      `/api/client/jobs/{id}/result` — the signature covers `device_id\njob_id\nstatus\nresult`.
//!
//! No shared secret: the signature (verified against the pinned key) is what the server trusts,
//! replacing the retired `CONSOLE_AGENT_TOKEN` + `jobs.ps1` path. Read-only kinds only today
//! (inventory / processes / services, reusing the existing native collectors); anything else posts
//! an error result. Action/write kinds are gated on the broader security model and stay future work.

use hbb_common::config::LocalConfig;
use hbb_common::sodiumoxide::{base64, crypto::sign};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};

/// LocalConfig key holding the base64 Ed25519 secret key (seed‖pub), generated once per machine.
const KEY_OPT: &str = "console-job-key";
static ENROLLED: AtomicBool = AtomicBool::new(false);

#[inline]
fn variant() -> base64::Variant {
    // Standard base64 + padding — matches the backend's base64 STANDARD engine.
    base64::Variant::Original
}

/// Load (or first-time generate + persist) this machine's signing keypair.
fn keypair() -> (sign::PublicKey, sign::SecretKey) {
    let stored = LocalConfig::get_option(KEY_OPT);
    if let Ok(bytes) = base64::decode(&stored, variant()) {
        if let Some(sk) = sign::SecretKey::from_slice(&bytes) {
            // The Ed25519 secret key is `seed[32] ‖ pubkey[32]`; the trailing 32 bytes are the pub.
            if let Some(pk) = sign::PublicKey::from_slice(&sk.as_ref()[32..]) {
                return (pk, sk);
            }
        }
    }
    let (pk, sk) = sign::gen_keypair();
    LocalConfig::set_option(KEY_OPT.to_owned(), base64::encode(sk.as_ref(), variant()));
    (pk, sk)
}

/// Pin this machine's public key with the console (TOFU), once per process. Proactive so the key
/// is registered before any job result needs verifying. Idempotent server-side (first key wins).
pub fn ensure_enrolled(heartbeat_url: &str, id: &str) {
    if ENROLLED.load(Ordering::Relaxed) || id.is_empty() {
        return;
    }
    let (pk, _) = keypair();
    let url = heartbeat_url.replace("heartbeat", "client/enroll");
    let body = json!({ "id": id, "pubkey": base64::encode(pk.as_ref(), variant()) }).to_string();
    hbb_common::tokio::spawn(async move {
        match crate::post_request(url, body, "").await {
            Ok(rsp) => {
                let ok = serde_json::from_str::<Value>(&rsp)
                    .ok()
                    .and_then(|v| v.get("ok").and_then(|x| x.as_bool()))
                    .unwrap_or(false);
                if ok {
                    ENROLLED.store(true, Ordering::Relaxed);
                    hbb_common::log::info!("console job-channel key enrolled");
                }
            }
            Err(e) => hbb_common::log::error!("console enroll failed: {e}"),
        }
    });
}

/// Run the jobs the heartbeat delivered, each on its own task, posting a signed result.
pub fn run(heartbeat_url: String, id: String, jobs: Value) {
    let Ok(jobs) = serde_json::from_value::<Vec<Value>>(jobs) else {
        return;
    };
    for job in jobs {
        let job_id = job.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let kind = job.get("kind").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let params = job.get("params").and_then(|x| x.as_str()).map(str::to_owned);
        if job_id.is_empty() {
            continue;
        }
        let url = heartbeat_url.clone();
        let id = id.clone();
        hbb_common::tokio::spawn(async move {
            let (status, result) = run_kind(&kind, params).await;
            post_result(&url, &id, &job_id, status, &result).await;
        });
    }
}

/// Execute one read-only kind → (status, result-json-or-message). Registry/SMBIOS/process work runs
/// on a blocking thread so it can't stall the async runtime.
async fn run_kind(kind: &str, params: Option<String>) -> (&'static str, String) {
    use hbb_common::tokio::task::spawn_blocking;
    let value: Option<Value> = match kind {
        "inventory" => spawn_blocking(crate::console_inventory::collect).await.ok(),
        "processes" => spawn_blocking(|| crate::console_snapshot::collect("processes")).await.ok().flatten(),
        "services" => spawn_blocking(|| crate::console_snapshot::collect("services")).await.ok().flatten(),
        "eventlog" => spawn_blocking(move || eventlog(params.as_deref())).await.ok().flatten(),
        "schtasks" => spawn_blocking(|| ps_json_array(
            "Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Sort-Object TaskPath,TaskName | ConvertTo-Json -Compress",
            400,
        )).await.ok().flatten(),
        "startup" => spawn_blocking(|| ps_json_array(
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress",
            200,
        )).await.ok().flatten(),
        "netconn" => spawn_blocking(|| ps_json_array(
            "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress",
            300,
        )).await.ok().flatten(),
        "pnp" => spawn_blocking(|| ps_json_array(
            "Get-PnpDevice | Select-Object FriendlyName,Class,Status,InstanceId | Sort-Object Class,FriendlyName | ConvertTo-Json -Compress",
            600,
        )).await.ok().flatten(),
        // Action kinds (admin-only, console-confirmed). A short delay lets the signed result post
        // before the OS goes down.
        "reboot" => spawn_blocking(|| power_action("/r")).await.ok(),
        "shutdown" => spawn_blocking(|| power_action("/s")).await.ok(),
        _ => None,
    };
    match value {
        Some(v) => ("done", v.to_string()),
        None => ("error", format!("job kind not supported by this client: {kind}")),
    }
}

/// Recent Windows event-log entries via PowerShell `Get-WinEvent` — System + Application at
/// Critical/Error/Warning by default, newest first, bounded so the signed result stays under the
/// console's 64 KB cap. Optional `params` JSON `{log:"System,Application", level:3, count:60}`
/// overrides the defaults (`level` = max severity: 1 crit, 2 +err, 3 +warn). Empty off-Windows.
#[cfg(windows)]
fn eventlog(params: Option<&str>) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let logs = p.get("log").and_then(|x| x.as_str()).unwrap_or("System,Application");
    let level = p.get("level").and_then(|x| x.as_i64()).unwrap_or(3).clamp(1, 5);
    let count = p.get("count").and_then(|x| x.as_i64()).unwrap_or(60).clamp(1, 200);
    // Sanitize the log names (single-quoted, strip embedded quotes) and build the level list.
    let log_arr = logs
        .split(',')
        .map(|l| format!("'{}'", l.trim().replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",");
    let levels = (1..=level).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let script = format!(
        "Get-WinEvent -FilterHashtable @{{LogName=@({log_arr}); Level=@({levels})}} -MaxEvents {count} -ErrorAction SilentlyContinue | \
         Select-Object @{{n='time';e={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}},@{{n='log';e={{$_.LogName}}}},@{{n='id';e={{$_.Id}}}},@{{n='level';e={{$_.LevelDisplayName}}}},@{{n='provider';e={{$_.ProviderName}}}},@{{n='message';e={{$_.Message}}}} | \
         ConvertTo-Json -Compress -Depth 3"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(text.trim()).ok()?;
    let rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v], // ConvertTo-Json emits a bare object for a single row
        _ => return Some(json!([])),
    };
    // Collapse whitespace + char-safe truncate each message so the whole result fits the cap.
    let entries: Vec<Value> = rows
        .into_iter()
        .map(|mut r| {
            if let Some(m) = r.get("message").and_then(|x| x.as_str()) {
                let collapsed: String = m.split_whitespace().collect::<Vec<_>>().join(" ");
                let trimmed: String = collapsed.chars().take(400).collect();
                let trimmed = if trimmed.len() < collapsed.len() { format!("{trimmed}…") } else { trimmed };
                r["message"] = json!(trimmed);
            }
            r
        })
        .collect();
    Some(json!(entries))
}
#[cfg(not(windows))]
fn eventlog(_params: Option<&str>) -> Option<Value> {
    None
}

/// Run a PowerShell one-liner that emits `ConvertTo-Json` and return its rows as a JSON array,
/// capped to `max_entries` and with any over-long string field char-safe-truncated so the signed
/// result stays under the console's 64 KB cap. The shared shape for the read-only list kinds
/// (scheduled tasks / startup / network connections). Empty off-Windows.
#[cfg(windows)]
fn ps_json_array(script: &str, max_entries: usize) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(text.trim()).ok()?;
    let mut rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v], // ConvertTo-Json emits a bare object for a single row
        _ => return Some(json!([])),
    };
    rows.truncate(max_entries);
    for r in &mut rows {
        if let Some(obj) = r.as_object_mut() {
            for (_k, v) in obj.iter_mut() {
                if let Some(s) = v.as_str() {
                    if s.chars().count() > 300 {
                        *v = json!(s.chars().take(300).collect::<String>() + "…");
                    }
                }
            }
        }
    }
    Some(json!(rows))
}
#[cfg(not(windows))]
fn ps_json_array(_script: &str, _max_entries: usize) -> Option<Value> {
    None
}

/// Reboot (`/r`) or shut down (`/s`) the machine via `shutdown.exe`, with a 5 s delay so the signed
/// result posts before the OS goes down. Returns `{ok, action, in_seconds | error}` (always Some —
/// a failed `shutdown` reports `ok:false`, which the operator sees in the job's result).
#[cfg(windows)]
fn power_action(flag: &str) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let action = if flag == "/r" { "reboot" } else { "shutdown" };
    let out = std::process::Command::new("shutdown")
        .args([flag, "/t", "5", "/c", "SullTec console: requested by an operator"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) if o.status.success() => json!({ "ok": true, "action": action, "in_seconds": 5 }),
        Ok(o) => json!({ "ok": false, "action": action, "error": String::from_utf8_lossy(&o.stderr).trim() }),
        Err(e) => json!({ "ok": false, "action": action, "error": e.to_string() }),
    }
}
#[cfg(not(windows))]
fn power_action(_flag: &str) -> Value {
    json!({ "ok": false, "error": "power actions are Windows-only" })
}

/// Sign and POST a job result. The signature binds `device_id\njob_id\nstatus\nresult`.
async fn post_result(heartbeat_url: &str, device_id: &str, job_id: &str, status: &str, result: &str) {
    let (_, sk) = keypair();
    let msg = format!("{device_id}\n{job_id}\n{status}\n{result}");
    let sig = sign::sign_detached(msg.as_bytes(), &sk);
    let body = json!({
        "status": status,
        "result": result,
        "sig": base64::encode(sig.as_ref(), variant()),
    })
    .to_string();
    let url = format!("{}/{}/result", heartbeat_url.replace("heartbeat", "client/jobs"), job_id);
    match crate::post_request(url, body, "").await {
        Ok(_) => hbb_common::log::info!("console job {job_id} result posted ({status})"),
        Err(e) => hbb_common::log::error!("console job {job_id} result post failed: {e}"),
    }
}
