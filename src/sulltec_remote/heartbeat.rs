//! **The reply is a flat namespace shared by unrelated features.** Every key is removed by whoever
//! claims it, so two consumers using the same name starve one another.

use super::{jobs, update};
use hbb_common::log;
use serde_json::Value;
use std::collections::HashMap;

/// Call this after all sysinfo fields are finalized because the signature covers the complete value.
pub fn decorate_sysinfo(v: &mut Value) {
    v["version"] = serde_json::json!(crate::sulltec_remote::SULLTEC_VERSION);
    if let Some(adsig) = jobs::sign_sysinfo(v) {
        v["adsig"] = serde_json::json!(adsig);
    }
    IDENTITY.lock().unwrap().pending = Some(identity_of(v));
}

/// Sysinfo uploads once per process run, so a machine whose identity changes while it is up — a
/// laptop leaving a site's DNS suffix behind, a host whose adapters came up after the service did —
/// keeps reporting what it measured at start until something restarts it. These two say when the
/// identity the console groups on has moved since the last accepted upload.
struct Identity {
    uploaded: Option<String>,
    pending: Option<String>,
}

static IDENTITY: std::sync::Mutex<Identity> =
    std::sync::Mutex::new(Identity { uploaded: None, pending: None });

fn identity_of(v: &Value) -> String {
    ["hostname", "domain", "domain_netbios", "ou", "workgroup", "dns_suffix"]
        .iter()
        .map(|k| v.get(k).and_then(Value::as_str).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pure — the upload is what records a value, not the asking.
pub fn identity_changed(v: &Value) -> bool {
    let now = identity_of(v);
    IDENTITY.lock().unwrap().uploaded.as_deref().is_some_and(|prev| prev != now)
}

/// The console ACCEPTED the upload. Until that lands the old value stands, so a failed post is
/// re-offered rather than forgotten.
pub fn identity_uploaded() {
    let mut g = IDENTITY.lock().unwrap();
    if let Some(p) = g.pending.take() {
        g.uploaded = Some(p);
    }
}

pub fn decorate_body(v: &mut Value) {
    v["logon_pub"] = serde_json::json!(jobs::current_logon_pubkey());
    v["logon_anchor"] = serde_json::json!(jobs::baked_logon_pubkey());
}

#[derive(Default)]
pub struct FailureLog {
    consecutive: u32,
}

impl FailureLog {
    pub fn record<T>(&mut self, r: &hbb_common::ResultType<T>) {
        match r {
            Err(err) => {
                self.consecutive += 1;
                if self.consecutive == 1 || self.consecutive % 10 == 0 {
                    log::warn!(
                        "heartbeat POST failed ({} consecutive): {:?} — console requests \
                         (update checks, jobs, policy) are NOT being received; rendezvous \
                         is unaffected so this device still appears online",
                        self.consecutive,
                        err
                    );
                }
            }
            Ok(_) if self.consecutive > 0 => {
                log::info!(
                    "heartbeat recovered after {} consecutive failure(s)",
                    self.consecutive
                );
                self.consecutive = 0;
            }
            Ok(_) => {}
        }
    }
}

pub fn handle_keys(rsp: &mut HashMap<&str, Value>, url: &str, id: &str) {
    if rsp.remove("check_update").is_some() {
        update::arm_update_request();
    }

    jobs::ensure_enrolled(url, id);
    jobs::sweep_orphaned_results(url, id);
    jobs::sweep_job_temp();
    let waiting = rsp.remove("jobs_waiting").is_some();
    let unsettled = rsp.remove("jobs_unsettled").is_some();
    if waiting || unsettled {
        jobs::poll(url.to_owned(), id.to_owned());
    }

    update::service_update_request(waiting, unsettled);

    jobs::update_logon_chain(rsp.remove("logon_chain"));

    jobs::apply_policy(rsp.remove("policy_push"));
}
