//! **The reply is a flat namespace shared by unrelated features.** Every key is removed by whoever
//! claims it, so two consumers using the same name starve one another.

use super::{jobs, update};
use hbb_common::log;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Call this after all sysinfo fields are finalized because the signature covers the complete value.
pub fn decorate_sysinfo(v: &mut Value) {
    v["version"] = serde_json::json!(crate::sulltec_remote::SULLTEC_VERSION);
    v["rendezvous_pk"] =
        serde_json::json!(crate::encode64(hbb_common::config::Config::get_key_pair().1));
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
    let fields: Vec<Option<&str>> = ["hostname", "domain", "domain_netbios", "ou", "workgroup", "dns_suffix"]
        .iter()
        .map(|k| v.get(k).and_then(Value::as_str))
        .collect();
    serde_json::to_string(&fields).unwrap_or_default()
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

static LAG_PROBE: AtomicBool = AtomicBool::new(false);
const LAG_BUCKETS_MS: [u64; 12] = [10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000];

fn start_lag_probe() {
    if LAG_PROBE.load(Ordering::Relaxed) {
        return;
    }
    let Ok(rt) = hbb_common::tokio::runtime::Handle::try_current() else {
        return;
    };
    if !LAG_PROBE.swap(true, Ordering::Relaxed) {
        rt.spawn(lag_probe());
    }
}

async fn lag_probe() {
    use hbb_common::tokio::time::{sleep_until, Duration, Instant};
    let mut counts = [0u64; LAG_BUCKETS_MS.len() + 1];
    let mut max = Duration::ZERO;
    let mut over_2s = 0u64;
    let mut window = Instant::now();
    loop {
        let due = Instant::now() + Duration::from_secs(1);
        sleep_until(due).await;
        let late = Instant::now().saturating_duration_since(due);
        let ms = late.as_millis() as u64;
        counts[LAG_BUCKETS_MS.iter().position(|b| ms <= *b).unwrap_or(LAG_BUCKETS_MS.len())] += 1;
        max = max.max(late);
        if late > Duration::from_secs(2) {
            over_2s += 1;
        }
        if window.elapsed() < Duration::from_secs(3600) {
            continue;
        }
        let total: u64 = counts.iter().sum();
        let rank = (total * 95).div_ceil(100);
        let mut seen = 0u64;
        let bucket = counts
            .iter()
            .position(|c| {
                seen += *c;
                seen >= rank
            })
            .unwrap_or(LAG_BUCKETS_MS.len());
        let p95 = match LAG_BUCKETS_MS.get(bucket) {
            Some(b) => format!("<= {b} ms"),
            None => format!("> {} ms", LAG_BUCKETS_MS[LAG_BUCKETS_MS.len() - 1]),
        };
        let reads = super::ad::take_read_stats();
        log::info!(
            "lag probe, last hour: {total} wakes, max {} ms late, p95 {p95}, {over_2s} later than 2 s{}{reads}",
            max.as_millis(),
            if reads.is_empty() { "" } else { "; " }
        );
        counts = [0u64; LAG_BUCKETS_MS.len() + 1];
        max = Duration::ZERO;
        over_2s = 0;
        window = Instant::now();
    }
}

pub fn decorate_body(v: &mut Value) {
    start_lag_probe();
    v["version"] = serde_json::json!(crate::sulltec_remote::SULLTEC_VERSION);
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
