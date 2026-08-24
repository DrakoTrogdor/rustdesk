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
