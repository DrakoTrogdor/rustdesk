//! **The reply is a flat namespace shared by unrelated features.** Every key is removed by whoever
//! claims it, so two consumers using the same name starve one another. Console keys must remain
//! distinct from all other response keys. The console's keys are
//! `jobs_waiting`, `jobs_unsettled`, `policy_push`, `logon_chain` and `check_update`.

use super::{jobs, update};
use hbb_common::log;
use serde_json::Value;
use std::collections::HashMap;

/// `version` is the console-aligned product version, so the console UI shows a number matching its
/// own; the RustDesk protocol version still rides the heartbeat's numeric `ver` field for hbbs
/// strategy, and the two are deliberately different numbers.
///
/// `adsig` signs the AD identity so the console can bind domain/OU/tenant to this machine's enrolled
/// key. That ingest tier is unauthenticated, so the console drops an AD report whose signature does
/// not match the pinned key — which stops anyone who merely knows the device id from spoofing its
/// tenant and grouping. It no-ops off-domain.
///
/// Call this after all sysinfo fields are finalized because the signature covers the complete value.
pub fn decorate_sysinfo(v: &mut Value) {
    v["version"] = serde_json::json!(crate::sulltec_remote::SULLTEC_VERSION);
    if let Some(adsig) = jobs::sign_sysinfo(v) {
        v["adsig"] = serde_json::json!(adsig);
    }
}

/// `logon_pub` is the logon key this device currently trusts, so the console can show whether
/// passwordless logon will actually work for it — current, stale, or no key at all.
///
/// `logon_anchor` is the anchor COMPILED INTO THIS BUILD, which is a different question. The trusted
/// key moves as the rotation chain is walked forward; the anchor never does. Chain resolution
/// restarts from the anchor every heartbeat, so the anchor — not the trusted key — decides whether a
/// device survives the chain being pruned. Without it the console can see what the fleet trusts but
/// not what it can safely prune.
pub fn decorate_body(v: &mut Value) {
    v["logon_pub"] = serde_json::json!(jobs::current_logon_pubkey());
    v["logon_anchor"] = serde_json::json!(jobs::baked_logon_pubkey());
}

/// The heartbeat is the console's only channel for `check_update`, jobs and policy, and it runs
/// over the API port — a different path from rendezvous. A client that cannot POST goes
/// unable to receive these commands while it can still appear online through rendezvous.
#[derive(Default)]
pub struct FailureLog {
    consecutive: u32,
}

impl FailureLog {
    /// First failure then every tenth, so a long outage neither floods the log nor goes silent.
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
    // An operator queued a client-update push. The backend DRAINS that request, so it arrives here
    // exactly once: a beat that cannot act on it has to hold it, or the push is lost silently.
    if rsp.remove("check_update").is_some() {
        update::arm_update_request();
    }

    // Enroll the device's Ed25519 key through TOFU. The unauthenticated heartbeat carries only the
    // `jobs_waiting` announcement; the authenticated poll returns each job with its parameters.
    // Dispatch signatures are verified before execution because request authentication proves the
    // caller to the console, not the console to the caller.
    jobs::ensure_enrolled(url, id);
    // Report any job this device finished but never managed to tell the console about. Once per
    // process, here because this is the first point at which both the URL and the id are known.
    // Needs nothing from the console, so it still settles those rows against one with no
    // `jobs_unsettled` announcement to ask with.
    jobs::sweep_orphaned_results(url, id);
    jobs::sweep_job_temp();
    // BOTH must be drained whichever fires. `jobs_unsettled` is the only route to a device with an
    // open run and nothing queued: the poll hands it nothing and asks it to settle the run instead.
    let waiting = rsp.remove("jobs_waiting").is_some();
    let unsettled = rsp.remove("jobs_unsettled").is_some();
    if waiting || unsettled {
        jobs::poll(url.to_owned(), id.to_owned());
    }

    // After both flags, because neither is in the in-flight set yet.
    update::service_update_request(waiting, unsettled);

    // Walking the chain from our baked anchor adopts the current logon key without a rebuild.
    // An ABSENT chain leaves the baked anchor in force.
    jobs::update_logon_chain(rsp.remove("logon_chain"));

    // Verified against our trusted logon key. An absent or empty policy RELEASES any locks held,
    // so this is also how a lockdown is lifted.
    jobs::apply_policy(rsp.remove("policy_push"));
}
