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
        if job_id.is_empty() {
            continue;
        }
        let url = heartbeat_url.clone();
        let id = id.clone();
        hbb_common::tokio::spawn(async move {
            let (status, result) = run_kind(&kind).await;
            post_result(&url, &id, &job_id, status, &result).await;
        });
    }
}

/// Execute one read-only kind → (status, result-json-or-message). Registry/SMBIOS/process work runs
/// on a blocking thread so it can't stall the async runtime.
async fn run_kind(kind: &str) -> (&'static str, String) {
    use hbb_common::tokio::task::spawn_blocking;
    let value: Option<Value> = match kind {
        "inventory" => spawn_blocking(crate::console_inventory::collect).await.ok(),
        "processes" => spawn_blocking(|| crate::console_snapshot::collect("processes")).await.ok().flatten(),
        "services" => spawn_blocking(|| crate::console_snapshot::collect("services")).await.ok().flatten(),
        _ => None,
    };
    match value {
        Some(v) => ("done", v.to_string()),
        None => ("error", format!("job kind not supported by this client: {kind}")),
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
