//! The console's half of the heartbeat response.
//!
//! Upstream's sync loop posts a heartbeat and parses the reply into a flat map. Stock servers answer
//! with a handful of keys; the SullTec console answers with those *and* its own. This module reads
//! and removes the console's keys, leaving upstream's untouched for their own arms to consume.
//!
//! It runs from inside upstream's loop because that is the only place the parsed reply exists, but
//! it needs nothing from that loop beyond three plain values — so the loop keeps one call and the
//! dispatch lives here.
//!
//! **The reply is a flat namespace shared by unrelated features.** Every key is removed by whoever
//! claims it, so two consumers that pick the same name silently starve one another — a new key must
//! be checked against every arm here *and* against upstream's. The console's keys are exactly
//! `jobs_waiting`, `policy_push`, `logon_chain` and `check_update`.

use super::{jobs, update};
use hbb_common::log;
use serde_json::Value;
use std::collections::HashMap;

/// Add the console's fields to an outgoing sysinfo upload.
///
/// `version` is the console-aligned product version, so the console UI shows a number matching its
/// own; the RustDesk protocol version still rides the heartbeat's numeric `ver` field for hbbs
/// strategy, and the two are deliberately different numbers.
///
/// `adsig` signs the AD identity so the console can bind domain/OU/tenant to this machine's enrolled
/// key. That ingest tier is unauthenticated, so the console drops an AD report whose signature does
/// not match the pinned key — which stops anyone who merely knows the device id from spoofing its
/// tenant and grouping. It no-ops off-domain.
///
/// **Call this last.** The signature covers `v` as it stands, and upstream overwrites `username` and
/// `hostname` from preset options partway down the block it is called from.
pub fn decorate_sysinfo(v: &mut Value) {
    v["version"] = serde_json::json!(crate::sulltec_remote::SULLTEC_VERSION);
    if let Some(adsig) = jobs::sign_sysinfo(v) {
        v["adsig"] = serde_json::json!(adsig);
    }
}

/// Add the console's fields to an outgoing heartbeat body.
///
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

/// Consecutive heartbeat POST failures, so the log can say what a failing beat costs.
///
/// The heartbeat is the console's only channel for `check_update`, jobs and policy, and it runs
/// over the API port — a different path from rendezvous. A client that cannot POST goes
/// completely inert while still showing ONLINE in the console, so the operator sees a device that
/// simply ignores every request. Counting it here lets the log say that out loud rather than leaving
/// it to be inferred from silence.
#[derive(Default)]
pub struct FailureLog {
    consecutive: u32,
}

impl FailureLog {
    /// Record the outcome of one heartbeat POST.
    ///
    /// Logs the first failure and then every tenth, so a long outage neither floods the log nor goes
    /// fully quiet, and logs once on recovery.
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

/// Consume the console's keys from a parsed heartbeat reply.
///
/// The namespace is flat and shared: two arms that claim the same key silently starve one another,
/// so a new key must be checked against every arm here *and* against upstream's before it ships.
pub fn handle_keys(rsp: &mut HashMap<&str, Value>, url: &str, id: &str) {
    // An operator queued a client-update push. This compares against /version/latest, so it no-ops
    // unless the console's target is actually newer.
    if rsp.remove("check_update").is_some() {
        log::info!("update check requested by server");
        update::force_check_update_now();
    }

    // The client-native job channel. Pin our Ed25519 key (once, TOFU), then POLL for our own queue
    // over a signed request.
    //
    // ⚠ **Jobs no longer ride the heartbeat, and that is deliberate.** This listener is
    // unauthenticated — the console hands a reply to whoever posts an id — so a job's params could
    // not travel on it once the backend began hosting the COMMAND TEXT. The old arrangement withheld
    // them here and made us fetch each one separately, which cost two round trips per job and a kind
    // list that had to stay in lockstep with the backend's or the params silently never arrived.
    // Proving who we are first removes the whole problem: the job and its params come together.
    //
    // The console still SIGNS the dispatch and we still verify it before running anything. Us
    // authenticating tells the console who is calling; it does not tell us the answer came from the
    // console.
    // ⚠ **Only when told.** The heartbeat still carries the ANNOUNCEMENT — one bit, `jobs_waiting` —
    // and we fetch only then. Polling every beat regardless would spend a round trip per cycle to be
    // told there is nothing, on every device in the fleet; the announcement is what the
    // unauthenticated channel can safely carry, and the payload is what it cannot.
    jobs::ensure_enrolled(url, id);
    if rsp.remove("jobs_waiting").is_some() {
        jobs::poll(url.to_owned(), id.to_owned());
    }

    // The key-pair logon rotation chain: walk it from our baked anchor and adopt the current logon
    // key with no rebuild. Absent — no rotation yet — leaves the baked anchor in force.
    jobs::update_logon_chain(rsp.remove("logon_chain"));

    // The GPO-style settings lockdown: apply and lock what the console pushed, verified against our
    // trusted logon key. An absent or empty policy releases any locks we hold.
    jobs::apply_policy(rsp.remove("policy_push"));
}
