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
use std::sync::RwLock;

/// LocalConfig key holding the base64 Ed25519 secret key (seed‖pub), generated once per machine.
const KEY_OPT: &str = "console-job-key";
static ENROLLED: AtomicBool = AtomicBool::new(false);
/// Throttles the "key not pinned" warning to once per process (enroll retries every heartbeat).
static WARNED: AtomicBool = AtomicBool::new(false);
/// The console logon public key this device currently trusts (base64), advanced from the baked
/// anchor by walking rotation chains off the heartbeat. `None` until the first chain is seen (the
/// baked anchor is used until then). See `update_logon_chain` / `current_logon_pubkey`.
static LOGON_TRUSTED: RwLock<Option<String>> = RwLock::new(None);

/// Kinds whose params the server withholds from the heartbeat; we fetch them with a signed request.
/// (Remote scripts; file pushes — content/path; software deploys — url/dest; AD ops — reset password.)
const SENSITIVE_KINDS: &[&str] = &["script", "file-push", "deploy", "ad"];

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

/// Sign the AD identity inside a sysinfo payload so the console can bind domain/OU/tenant to this
/// machine's enrolled key. The ingest tier is unauthenticated, so without this a rogue that knows
/// the device id could spoof its tenant/grouping. Canonical message — MUST match the backend's
/// `client_api::sysinfo` verifier exactly: `SYSINFO\n{id}\n{domain}\n{domain_netbios}\n{ou}\n{workgroup}\n{dns_suffix}`.
/// Returns None when there's no AD identity to protect (off-domain / no id) — no signature needed.
pub fn sign_sysinfo(v: &Value) -> Option<String> {
    let f = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
    let id = f("id");
    let (domain, netbios, ou, wg, dns) =
        (f("domain"), f("domain_netbios"), f("ou"), f("workgroup"), f("dns_suffix"));
    if id.is_empty() || (domain.is_empty() && netbios.is_empty() && ou.is_empty() && wg.is_empty() && dns.is_empty()) {
        return None;
    }
    let msg = format!("SYSINFO\n{id}\n{domain}\n{netbios}\n{ou}\n{wg}\n{dns}");
    let (_, sk) = keypair();
    Some(base64::encode(sign::sign_detached(msg.as_bytes(), &sk).as_ref(), variant()))
}

/// Sign a request body with this machine's enrolled key for the authenticated ingest endpoints
/// (inventory / snapshot / audit). Returns the `X-ST-Sig: <base64>` header line for `post_request`'s
/// `header` arg. The console verifies the signature over the *exact received bytes* against the
/// device's pinned key, so a rogue that knows the device id can't inject fake data for it.
pub fn sign_header(body: &str) -> String {
    let (_, sk) = keypair();
    format!("X-ST-Sig: {}", base64::encode(sign::sign_detached(body.as_bytes(), &sk).as_ref(), variant()))
}

// ── Key-pair logon (§B): rotation-chain trust ────────────────────────────────────────────────

/// Baked trust anchor — the console logon public key compiled into this build (base64). Empty when
/// the feature isn't provisioned for this build, which keeps key-pair logon off (password flow).
pub fn baked_logon_pubkey() -> &'static str {
    option_env!("ST_LOGON_PUBKEY").unwrap_or("")
}

/// The logon public key this device currently trusts: the latest key reached by walking the
/// rotation chain forward from the baked anchor (set by `update_logon_chain`), or the baked anchor
/// itself before any chain has been seen. Read by the controlled-side verifier in connection.rs.
pub fn current_logon_pubkey() -> String {
    if let Ok(g) = LOGON_TRUSTED.read() {
        if let Some(k) = g.as_ref() {
            return k.clone();
        }
    }
    baked_logon_pubkey().to_owned()
}

/// Verify a rotation hop: `sig_b64` is `prev_pub`'s **attached** signature (`sig‖msg`) over
/// `CONSOLE-LOGON-ROTATE\n{new_pub_b64}` (domain-separated from the logon challenge so neither
/// signature can be repurposed as the other). `sign::verify` recovers the message; we require it
/// equals the rotation bind for the advertised new key. Mirrors the backend's `sign_logon_rotate`
/// and the logon-challenge scheme (sodiumoxide's `Signature` has no `from_slice` for detached verify).
fn verify_rotate(prev_pub_b64: &str, new_pub_b64: &str, sig_b64: &str) -> bool {
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(prev_pub_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return false;
    };
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let expected = format!("CONSOLE-LOGON-ROTATE\n{new_pub_b64}");
    matches!(sign::verify(&attached, &pk), Ok(m) if m == expected.as_bytes())
}

/// Adopt logon-key rotations advertised on the heartbeat (§B instant rotation). `chain` is the
/// console's ordered list of `{pub, sig}`. We find our baked anchor in it and walk forward,
/// verifying each hop, adopting the end-of-chain key as trusted — so an operator-initiated rotation
/// takes effect here within one heartbeat, no client rebuild. A broken or foreign chain is ignored
/// (we keep the anchor); the baked anchor is the only durable root, so a fresh baked key always wins
/// on the next client build (compromise recovery). In-memory only — re-derived each heartbeat.
pub fn update_logon_chain(chain: Option<Value>) {
    let anchor = baked_logon_pubkey();
    if anchor.is_empty() {
        return;
    }
    let Some(chain) = chain else { return };
    let Ok(entries) = serde_json::from_value::<Vec<Value>>(chain) else {
        return;
    };
    let Some(start) = entries
        .iter()
        .position(|e| e.get("pub").and_then(|x| x.as_str()) == Some(anchor))
    else {
        return; // anchor not in the advertised chain — trust only the baked anchor
    };
    let mut trusted = anchor.to_owned();
    for e in &entries[start + 1..] {
        let new_pub = e.get("pub").and_then(|x| x.as_str()).unwrap_or_default();
        let sig = e.get("sig").and_then(|x| x.as_str()).unwrap_or_default();
        if new_pub.is_empty() || sig.is_empty() || !verify_rotate(&trusted, new_pub, sig) {
            break; // stop at the last validated key
        }
        trusted = new_pub.to_owned();
    }
    if let Ok(mut g) = LOGON_TRUSTED.write() {
        if g.as_deref() != Some(trusted.as_str()) {
            hbb_common::log::info!("console logon key advanced to {trusted}");
        }
        *g = Some(trusted);
    }
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
                let v = serde_json::from_str::<Value>(&rsp).ok();
                let g = |k: &str| v.as_ref().and_then(|v| v.get(k).and_then(|x| x.as_bool())).unwrap_or(false);
                // Stop enrolling only once OUR key is the *pinned* one. If a different key is on file
                // (this machine was reinstalled since first enrollment), keep retrying each heartbeat:
                // an operator "Reset job-channel key" clears the stale pin and our next enroll takes,
                // recovering the device with no restart. (Before, ok=true alone latched ENROLLED, so a
                // re-imaged client signed results the console rejected forever.)
                if g("ok") && g("pinned") {
                    ENROLLED.store(true, Ordering::Relaxed);
                    hbb_common::log::info!("console job-channel key enrolled");
                } else if g("ok") && !WARNED.swap(true, Ordering::Relaxed) {
                    hbb_common::log::warn!("console job-channel: signing key is not the one pinned on the console (reinstalled?); use 'Reset job-channel key' on the device to re-pin it");
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
            // Sensitive kinds arrive without params over the heartbeat — fetch them with a signed
            // request (proving we hold the pinned key) before running.
            let params = if SENSITIVE_KINDS.contains(&kind.as_str()) && params.is_none() {
                fetch_params(&url, &id, &job_id).await
            } else {
                params
            };
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
        // Param-based actions: the param is a non-sensitive identifier, sanitized before use.
        "kill" => spawn_blocking(move || kill_process(params.as_deref())).await.ok(),
        "restart-service" => spawn_blocking(move || service_action(params.as_deref(), "Restart", "restarted")).await.ok(),
        "start-service" => spawn_blocking(move || service_action(params.as_deref(), "Start", "started")).await.ok(),
        "stop-service" => spawn_blocking(move || service_action(params.as_deref(), "Stop", "stopped")).await.ok(),
        "logoff" => spawn_blocking(move || logoff_session(params.as_deref())).await.ok(),
        "script" => spawn_blocking(move || run_script(params.as_deref())).await.ok(),
        "reg-read" => spawn_blocking(move || reg_read(params.as_deref())).await.ok().flatten(),
        "reg-write" => spawn_blocking(move || reg_write(params.as_deref())).await.ok(),
        "file-pull" => spawn_blocking(move || file_pull(params.as_deref())).await.ok(),
        "file-push" => spawn_blocking(move || file_push(params.as_deref())).await.ok(),
        "deploy" => spawn_blocking(move || deploy(params.as_deref())).await.ok(),
        "ad" => spawn_blocking(move || ad_action(params.as_deref())).await.ok(),
        "wol" => spawn_blocking(move || wol(params.as_deref())).await.ok(),
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

/// Run an action command (no console window), reporting `{ok, result | error}`. The argv is built
/// from constants + already-sanitized params, never raw operator text.
#[cfg(windows)]
fn run_action(argv: &[&str], ok_label: &str) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(argv[0])
        .args(&argv[1..])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) if o.status.success() => json!({ "ok": true, "result": ok_label }),
        Ok(o) => json!({ "ok": false, "error": String::from_utf8_lossy(&o.stderr).trim().chars().take(300).collect::<String>() }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// Kill a process by PID (`taskkill /F /PID`). PID must be all-digits.
#[cfg(windows)]
fn kill_process(params: Option<&str>) -> Value {
    let pid = params.unwrap_or("").trim();
    if pid.is_empty() || pid.len() > 10 || !pid.chars().all(|c| c.is_ascii_digit()) {
        return json!({ "ok": false, "error": "kill requires a numeric PID" });
    }
    run_action(&["taskkill", "/F", "/PID", pid], "killed")
}

/// Start / Stop / Restart a Windows service by name. Name sanitized to a safe set; Stop/Restart
/// force dependent-service handling, Start does not. The `verb` is a fixed constant from `run_kind`
/// (never operator text), so the formatted command is safe.
#[cfg(windows)]
fn service_action(params: Option<&str>, verb: &str, ok_label: &str) -> Value {
    let name = params.unwrap_or("").trim();
    if name.is_empty()
        || name.len() > 256
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
    {
        return json!({ "ok": false, "error": "a valid service name is required" });
    }
    let force = if verb == "Start" { "" } else { " -Force" };
    let script = format!("{verb}-Service -Name '{name}'{force}");
    run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], ok_label)
}

/// Log off a Windows session by id (`logoff <id>`). Id must be all-digits.
#[cfg(windows)]
fn logoff_session(params: Option<&str>) -> Value {
    let sid = params.unwrap_or("").trim();
    if sid.is_empty() || sid.len() > 10 || !sid.chars().all(|c| c.is_ascii_digit()) {
        return json!({ "ok": false, "error": "logoff requires a numeric session id" });
    }
    run_action(&["logoff", sid], "logged off")
}

#[cfg(not(windows))]
fn kill_process(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
#[cfg(not(windows))]
fn service_action(_params: Option<&str>, _verb: &str, _ok_label: &str) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
#[cfg(not(windows))]
fn logoff_session(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Run an operator-supplied PowerShell script (admin-gated, params delivered over the SIGNED
/// `/params` channel — never the unauthenticated heartbeat). Captures stdout+stderr+exit and
/// char-safe-truncates the combined output to stay under the console's 64 KB result cap. Returns
/// `{ok, exit, output}` (or `{ok:false, error}` if the shell couldn't launch).
#[cfg(windows)]
fn run_script(params: Option<&str>) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = params.unwrap_or("").trim();
    if script.is_empty() {
        return json!({ "ok": false, "error": "no script provided" });
    }
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let combined: String = format!("{stdout}{stderr}").chars().take(60_000).collect();
            json!({ "ok": o.status.success(), "exit": o.status.code(), "output": combined })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}
#[cfg(not(windows))]
fn run_script(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Validate a registry path (F11): a known hive root + no characters that could break out of the
/// single-quoted PowerShell literal it's interpolated into. Conservative — rare paths with quotes
/// are rejected rather than risk injection.
#[cfg(windows)]
fn valid_reg_path(path: &str) -> bool {
    let roots = ["HKLM:\\", "HKCU:\\", "HKCR:\\", "HKU:\\", "HKCC:\\"];
    roots.iter().any(|r| path.starts_with(r))
        && path.len() <= 512
        && !path.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`'))
}

/// Read a registry key's values + immediate subkey names (F11, read-only). `params` is a PS-drive
/// path like `HKLM:\SOFTWARE\Microsoft\Windows`. Returns `{key, subkeys:[…], values:[{name,type,data}]}`;
/// each value's data is char-capped so the signed result stays under the console's 64 KB cap.
#[cfg(windows)]
fn reg_read(params: Option<&str>) -> Option<Value> {
    let path = params.unwrap_or("").trim();
    if !valid_reg_path(path) {
        return Some(json!({ "error": "invalid registry path (expected HKLM:\\, HKCU:\\, HKCR:\\, HKU:\\ or HKCC:\\ …)" }));
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = format!(
        "$ErrorActionPreference='Stop'; $k=Get-Item -LiteralPath '{path}'; \
         $vals=foreach($n in $k.GetValueNames()){{[pscustomobject]@{{name=$n;type=$k.GetValueKind($n).ToString();data=[string]($k.GetValue($n))}}}}; \
         [pscustomobject]@{{key=$k.Name;subkeys=@($k.GetSubKeyNames());values=@($vals)}}|ConvertTo-Json -Compress -Depth 4"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Some(json!({ "error": err.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect::<String>() }));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parsed: Value = serde_json::from_str(text.trim()).ok()?;
    if let Some(vals) = parsed.get_mut("values").and_then(|v| v.as_array_mut()) {
        for v in vals.iter_mut() {
            if let Some(d) = v.get("data").and_then(|x| x.as_str()) {
                if d.chars().count() > 1000 {
                    v["data"] = json!(d.chars().take(1000).collect::<String>() + "…");
                }
            }
        }
    }
    Some(parsed)
}

/// Write a registry value (F11, admin action). `params` is JSON `{path,name,type,data}` where type ∈
/// String|ExpandString|DWord|QWord|MultiString. Creates the key if missing. Numbers are validated;
/// strings are single-quote-escaped; MultiString splits on newlines. Returns `{ok, result|error}`.
#[cfg(windows)]
fn reg_write(params: Option<&str>) -> Value {
    let Some(p) = params.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return json!({ "ok": false, "error": "reg-write needs JSON {path,name,type,data}" });
    };
    let path = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    let name = p.get("name").and_then(|x| x.as_str()).unwrap_or("").trim();
    let rtype = p.get("type").and_then(|x| x.as_str()).unwrap_or("String").trim();
    let data = p.get("data").and_then(|x| x.as_str()).unwrap_or("");
    if !valid_reg_path(path) {
        return json!({ "ok": false, "error": "invalid registry path" });
    }
    if name.is_empty() || name.len() > 255 || name.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`')) {
        return json!({ "ok": false, "error": "invalid value name" });
    }
    if !["String", "ExpandString", "DWord", "QWord", "MultiString"].contains(&rtype) {
        return json!({ "ok": false, "error": "type must be String, ExpandString, DWord, QWord, or MultiString" });
    }
    let value_lit = match rtype {
        "DWord" | "QWord" => {
            let n = data.trim();
            if n.is_empty() || !n.chars().enumerate().all(|(i, c)| c.is_ascii_digit() || (i == 0 && c == '-')) {
                return json!({ "ok": false, "error": "DWord/QWord data must be an integer" });
            }
            n.to_string()
        }
        "MultiString" => {
            let items = data
                .split('\n')
                .map(|l| format!("'{}'", l.trim_end_matches('\r').replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",");
            format!("@({items})")
        }
        _ => format!("'{}'", data.replace('\'', "''")),
    };
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = format!(
        "$ErrorActionPreference='Stop'; New-Item -Path '{path}' -Force | Out-Null; \
         New-ItemProperty -LiteralPath '{path}' -Name '{name}' -PropertyType {rtype} -Value {value_lit} -Force | Out-Null; 'ok'"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) if o.status.success() => json!({ "ok": true, "result": format!("{rtype} value '{name}' written") }),
        Ok(o) => json!({ "ok": false, "error": String::from_utf8_lossy(&o.stderr).split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect::<String>() }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(not(windows))]
fn reg_read(_params: Option<&str>) -> Option<Value> {
    None
}
#[cfg(not(windows))]
fn reg_write(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Reject a path/arg that could break out of the single-quoted PowerShell literal it's interpolated
/// into, or that's empty/over-long. Quotes/newlines/backticks are banned (rare in real paths).
#[cfg(windows)]
fn safe_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`'))
}

/// Only http(s) URLs with no whitespace or quotes (so the single-quoted `Invoke-WebRequest` arg is safe).
#[cfg(windows)]
fn safe_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s.chars().any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '`'))
}

/// Pull a file off the endpoint (F14, admin). Reads via Rust `std::fs` (no shell), size-capped; returns
/// it as `text` when valid UTF-8, else base64. `{ok, path, size, truncated, encoding, content}`.
#[cfg(windows)]
fn file_pull(params: Option<&str>) -> Value {
    let path = params.unwrap_or("").trim();
    if path.is_empty() {
        return json!({ "ok": false, "error": "file-pull needs a path" });
    }
    const CAP: usize = 128 * 1024; // 128 KB raw keeps the signed result well within limits.
    match std::fs::read(path) {
        Ok(bytes) => {
            let size = bytes.len();
            let truncated = size > CAP;
            let slice = if truncated { &bytes[..CAP] } else { &bytes[..] };
            match std::str::from_utf8(slice) {
                Ok(text) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "text", "content": text }),
                Err(_) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "base64", "content": base64::encode(slice, variant()) }),
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// Push a file to the endpoint (F14, admin, sensitive). JSON `{path, url|content_b64}`: a URL is
/// downloaded to `path` via `Invoke-WebRequest`; inline `content_b64` is decoded and written (small
/// files only — the enqueue clamps params, so binaries/installers should use `url`).
#[cfg(windows)]
fn file_push(params: Option<&str>) -> Value {
    let Some(p) = params.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return json!({ "ok": false, "error": "file-push needs JSON {path, url|content_b64}" });
    };
    let path = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if !safe_path(path) {
        return json!({ "ok": false, "error": "invalid destination path" });
    }
    if let Some(url) = p.get("url").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
        if !safe_url(url) {
            return json!({ "ok": false, "error": "url must be http(s) with no spaces/quotes" });
        }
        let script = format!("$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{path}' -UseBasicParsing; 'ok'");
        return run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], &format!("downloaded to {path}"));
    }
    if let Some(b64) = p.get("content_b64").and_then(|x| x.as_str()) {
        let Ok(bytes) = base64::decode(b64, variant()) else {
            return json!({ "ok": false, "error": "content_b64 is not valid base64" });
        };
        return match std::fs::write(path, &bytes) {
            Ok(_) => json!({ "ok": true, "result": format!("wrote {} bytes to {path}", bytes.len()) }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        };
    }
    json!({ "ok": false, "error": "file-push needs either url or content_b64" })
}

/// Download an installer and run it (F13, admin, sensitive). JSON `{url, dest, args?}`: fetches `url`
/// to `dest`, then runs it (hidden, waited) with optional `args`, returning `{ok, exit, output}`. Self-
/// executing installers (`*.exe /quiet`); for MSI, push the file then use a `script` job with `msiexec`.
#[cfg(windows)]
fn deploy(params: Option<&str>) -> Value {
    let Some(p) = params.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return json!({ "ok": false, "error": "deploy needs JSON {url, dest, args?}" });
    };
    let url = p.get("url").and_then(|x| x.as_str()).unwrap_or("").trim();
    let dest = p.get("dest").and_then(|x| x.as_str()).unwrap_or("").trim();
    let args = p.get("args").and_then(|x| x.as_str()).unwrap_or("").trim();
    if !safe_url(url) {
        return json!({ "ok": false, "error": "url must be http(s) with no spaces/quotes" });
    }
    if !safe_path(dest) {
        return json!({ "ok": false, "error": "invalid dest path" });
    }
    if args.len() > 1024 || args.chars().any(|c| matches!(c, '\'' | '\n' | '\r' | '`')) {
        return json!({ "ok": false, "error": "args may not contain quotes or newlines" });
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let run_part = if args.is_empty() {
        format!("$p=Start-Process -FilePath '{dest}' -Wait -PassThru -WindowStyle Hidden; $p.ExitCode")
    } else {
        format!("$p=Start-Process -FilePath '{dest}' -ArgumentList '{args}' -Wait -PassThru -WindowStyle Hidden; $p.ExitCode")
    };
    let script = format!("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{dest}' -UseBasicParsing; {run_part}");
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let exit_code = stdout.trim().lines().last().and_then(|l| l.trim().parse::<i64>().ok());
            let combined: String = format!("{}{}", stdout, String::from_utf8_lossy(&o.stderr)).chars().take(20_000).collect();
            json!({ "ok": o.status.success(), "exit": exit_code, "output": combined })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(not(windows))]
fn file_pull(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
#[cfg(not(windows))]
fn file_push(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
#[cfg(not(windows))]
fn deploy(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Active Directory helpdesk action (F17, admin, sensitive). JSON `{op, user, password?}` where op ∈
/// unlock|enable|disable|reset, run via the `ActiveDirectory` module **under the endpoint's existing
/// rights** (works where the logged-on/computer account has delegated permission; otherwise the AD
/// error is returned). `user` is a samAccountName; the reset password rides the signed channel.
#[cfg(windows)]
fn ad_action(params: Option<&str>) -> Value {
    let Some(p) = params.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return json!({ "ok": false, "error": "ad needs JSON {op, user, password?}" });
    };
    let op = p.get("op").and_then(|x| x.as_str()).unwrap_or("").trim();

    // move-ou acts on THIS machine's own computer object (no samAccountName) — it relocates the device
    // into a different OU. Identity = the local computer DN; TargetPath = the operator-supplied OU DN.
    if op == "move-ou" {
        let target = p.get("target_ou").and_then(|x| x.as_str()).unwrap_or("").trim();
        if target.is_empty() || target.len() > 1024 || target.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`')) {
            return json!({ "ok": false, "error": "move-ou needs a target OU distinguishedName" });
        }
        let own = crate::console_ad::computer_dn();
        if own.is_empty() {
            return json!({ "ok": false, "error": "not domain-joined, or the DC is unreachable" });
        }
        if own.chars().any(|c| matches!(c, '\'' | '\n' | '\r')) {
            return json!({ "ok": false, "error": "unexpected characters in the computer DN" });
        }
        let script = format!("$ErrorActionPreference='Stop'; Import-Module ActiveDirectory -ErrorAction Stop; Move-ADObject -Identity '{own}' -TargetPath '{target}'; 'ok'");
        return run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], &format!("moved to {target}"));
    }

    let user = p.get("user").and_then(|x| x.as_str()).unwrap_or("").trim();
    if user.is_empty() || user.len() > 256 || user.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`')) {
        return json!({ "ok": false, "error": "invalid user (samAccountName)" });
    }
    let cmd = match op {
        "unlock" => format!("Unlock-ADAccount -Identity '{user}'"),
        "enable" => format!("Enable-ADAccount -Identity '{user}'"),
        "disable" => format!("Disable-ADAccount -Identity '{user}'"),
        "reset" => {
            let pw = p.get("password").and_then(|x| x.as_str()).unwrap_or("");
            if pw.is_empty() || pw.contains(['\n', '\r']) {
                return json!({ "ok": false, "error": "reset needs a password (no newlines)" });
            }
            let pw_esc = pw.replace('\'', "''");
            format!("Set-ADAccountPassword -Identity '{user}' -Reset -NewPassword (ConvertTo-SecureString '{pw_esc}' -AsPlainText -Force); Unlock-ADAccount -Identity '{user}'")
        }
        _ => return json!({ "ok": false, "error": "op must be unlock, enable, disable, reset, or move-ou" }),
    };
    let script = format!("$ErrorActionPreference='Stop'; Import-Module ActiveDirectory -ErrorAction Stop; {cmd}; 'ok'");
    run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], &format!("{op} {user}"))
}
#[cfg(not(windows))]
fn ad_action(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Wake-on-LAN magic packet (F9). `params` is the **target** MAC ("AA:BB:CC:DD:EE:FF" or bare hex; any
/// separators tolerated); this online device broadcasts the packet on its LAN to wake the sleeping
/// target. Cross-platform UDP — sent to the broadcast address on the conventional WoL ports (9 and 7).
fn wol(params: Option<&str>) -> Value {
    let raw = params.unwrap_or("").trim();
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return json!({ "ok": false, "error": "MAC must be 6 hex bytes (e.g. AA:BB:CC:DD:EE:FF)" });
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.set_broadcast(true);
            let r1 = sock.send_to(&packet, "255.255.255.255:9");
            let r2 = sock.send_to(&packet, "255.255.255.255:7");
            if r1.is_ok() || r2.is_ok() {
                json!({ "ok": true, "result": format!("magic packet sent to {raw}") })
            } else {
                json!({ "ok": false, "error": "failed to send broadcast" })
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
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

/// Fetch a sensitive job's params over a SIGNED request (the heartbeat withholds them). Signs
/// `device_id\njob_id\nts` with the pinned key, so the server serves the params (e.g. a script) only
/// to the device that actually holds the key.
async fn fetch_params(heartbeat_url: &str, device_id: &str, job_id: &str) -> Option<String> {
    let (_, sk) = keypair();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let msg = format!("{device_id}\n{job_id}\n{ts}");
    let sig = sign::sign_detached(msg.as_bytes(), &sk);
    let body = json!({ "device_id": device_id, "ts": ts, "sig": base64::encode(sig.as_ref(), variant()) }).to_string();
    let url = format!("{}/{}/params", heartbeat_url.replace("heartbeat", "client/jobs"), job_id);
    let rsp = crate::post_request(url, body, "").await.ok()?;
    serde_json::from_str::<Value>(&rsp)
        .ok()?
        .get("params")
        .and_then(|x| x.as_str())
        .map(str::to_owned)
}
