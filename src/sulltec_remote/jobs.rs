//! Client-native job channel. The client:
//!   1. enrolls an Ed25519 public key (trust-on-first-use) so the console can verify its results;
//!   2. receives queued jobs in the `/api/heartbeat` response (`{"jobs":[{id,kind,params}, …]}`),
//!      carrying a console signature (`jobs_sig`/`jobs_ts`) it verifies before running anything;
//!   3. runs the job natively and POSTs a **signed** result to `/api/client/jobs/{id}/result` — the
//!      signature covers `device_id\njob_id\nstatus\nresult`.
//!
//! Two signatures protect the channel:
//!   * Egress (result / sensitive-param fetch) is signed by THIS device's pinned key, so the server
//!     can authenticate what the client posts.
//!   * Ingress (the dispatch itself) is signed by the CONSOLE and verified here (`verify_jobs`)
//!     before dispatch, so a forged/unauthenticated heartbeat can't run a job. Both read-only kinds
//!     (inventory / processes / services) and action kinds (reboot, service control, script, …)
//!     dispatch through `run_job`.

// ── the builtin procedures ────────────────────────────────────────────────────────────────────
//
// One module per name `exec_builtin` dispatches, holding that procedure and the helpers only it
// uses. A helper shared by two of them stays HERE — `now_secs`, `page_within_budget`,
// `powershell_exe` and `variant` are the ones that are, and a child reaches them through
// `use super::*` because a private item is visible to its own module's descendants.
//
// ⚠ `inventory` is `pub(crate)` where the rest are private: `ad.rs` reads
// `primary_dns_suffix()` from it, which is a fact about this machine's DNS identity rather than
// about the inventory procedure, so that one name has to stay reachable from a sibling.
// The two COMMAND TYPES sit beside them for the same reason: `powershell` and `native` are what a
// hosted dispatch names instead of a builtin, and each owns the machinery only it uses — the guard
// prologue and output parsing for one, argv splitting and the run loop for the other.
mod command_argv;
mod command_powershell;

mod client_log;
mod client_logs;
mod disconnect;
mod file_pull;
mod file_push;
mod fs;
pub(crate) mod inventory;
mod perf;
mod script;
mod services;
mod wol;

use command_argv::exec_native;
use command_powershell::exec_powershell;

use client_log::client_log_pull;
use client_logs::client_logs_list;
use disconnect::disconnect_sessions;
use file_pull::file_pull;
use file_push::file_push;
use fs::fs_list;
use perf::perf;
use script::run_script;
use services::services;
use wol::wol;

use hbb_common::config::{self, Config, LocalConfig};
use hbb_common::sodiumoxide::{base64, crypto::sign};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::RwLock;

/// Name of the base64 Ed25519 ingest-signing secret (seed‖pub) used for both the machine-wide file
/// and the per-user compatibility option. Stored machine-wide (see `keypair`) so every
/// context on the box shares ONE key the console pins.
const KEY_OPT: &str = "console-job-key";
static ENROLLED: AtomicBool = AtomicBool::new(false);
/// Throttles the "key not pinned" warning to once per process (enroll retries every heartbeat).
static WARNED: AtomicBool = AtomicBool::new(false);
/// The console logon public key this device currently trusts (base64), advanced from the baked
/// anchor by walking rotation chains off the heartbeat. `None` until the first chain is seen (the
/// baked anchor is used until then). See `update_logon_chain` / `current_logon_pubkey`.
static LOGON_TRUSTED: RwLock<Option<String>> = RwLock::new(None);
/// Max rotation-chain entries we'll accept/walk off the heartbeat — a guard against an oversized
/// chain (only reachable via a compromised/MITM'd, unauthenticated heartbeat) burning verify work.
const MAX_CHAIN: usize = 256;
/// LocalConfig key persisting the adopted logon trust: `{"anchor":<baked>,"trusted":<adopted pub>}`.
/// Lets an adopted rotation survive a reboot and enforces monotonicity (no regression to an earlier,
/// possibly-revoked key); reset whenever the baked anchor changes (a fresh client build supersedes
/// any learned chain).
const LOGON_TRUST_OPT: &str = "console-logon-trust";


/// In-memory enforce floor: whether to DROP jobs whose console dispatch signature doesn't verify
/// (vs. just observe + run). Learned from each validly-signed heartbeat (the flag rides inside the
/// signed message), default observe. Kept in memory only — a backend that stops signing reverts the
/// fleet to observe (jobs keep running) instead of bricking them, and a fresh signed beat re-arms it.
static JOBS_ENFORCE: AtomicBool = AtomicBool::new(false);
/// Freshness window for a signed dispatch — mirrors the params endpoint's ±5-min anti-replay.
const JOBS_FRESH_SECS: i64 = 300;
/// LocalConfig key: persisted `job-id → {t: first-seen-ts, n: attempts}` dedup. Runs each job-id once
/// per [`JOBS_SEEN_TTL_SECS`], so a captured heartbeat can't replay a job across a client restart and
/// the backend's re-delivery-until-result can't re-run an action kind. A live id is evicted past that
/// TTL, which is what lets a job whose result never landed retry; one that has spent
/// [`JOB_MAX_ATTEMPTS`] is kept for [`JOB_POISON_TTL_SECS`] instead, because forgetting it is how the
/// retry loop restarts. Bounded at [`JOBS_SEEN_MAX`] entries.
const JOBS_SEEN_OPT: &str = "console-jobs-seen";

/// Seconds since the Unix epoch (matches the backend's `now_secs`).
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Absolute path to the system PowerShell, so a hijacked PATH can't substitute a rogue
/// `powershell.exe` for these SYSTEM-context collectors/actions. Falls back to the bare name only if
/// `%SystemRoot%` is somehow unset.
#[cfg(windows)]
pub(crate) fn powershell_exe() -> String {
    std::env::var("SystemRoot")
        .map(|r| format!("{r}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        .unwrap_or_else(|_| "powershell".to_string())
}

#[inline]
fn variant() -> base64::Variant {
    // Standard base64 + padding — matches the backend's base64 STANDARD engine.
    base64::Variant::Original
}

/// This machine's Ed25519 ingest-signing keypair, resolved once per process and memoized.
///
/// The secret is stored **machine-wide** under `%ProgramData%\<app>\` on Windows so the SYSTEM
/// service and interactive user instances sign ingest with the same key. Resolution order:
///   1. the machine-wide file (the shared key);
///   2. an existing per-user `LocalConfig` key, copied to the machine-wide file to preserve the
///      device's pinned identity;
///   3. else a freshly generated key.
/// The chosen key is mirrored back to `LocalConfig` as a fallback for a context that can't yet read
/// the file (e.g. a user instance before the service has written it). Off Windows the ingest runs in
/// a single context, so `machine_key_path` is `None` and storage remains per-user.
fn keypair() -> (sign::PublicKey, sign::SecretKey) {
    static SK_BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = SK_BYTES.get_or_init(resolve_key_bytes);
    // `resolve_key_bytes` only ever yields a valid 64-byte secret (`seed[32] ‖ pubkey[32]`), so the
    // trailing 32 bytes are the public key.
    let sk = sign::SecretKey::from_slice(bytes).expect("resolved console-job key is a valid ed25519 secret");
    let pk = sign::PublicKey::from_slice(&sk.as_ref()[32..]).expect("an ed25519 secret embeds its public key");
    (pk, sk)
}

/// Resolve the signing secret's raw bytes (machine-wide file → per-user compatibility key → freshly
/// minted), persisting it machine-wide (+ per-user fallback) as a side effect. Always valid.
fn resolve_key_bytes() -> Vec<u8> {
    let valid = |b: &Vec<u8>| sign::SecretKey::from_slice(b).is_some();
    if let Some(b) = read_machine_key_bytes().filter(valid) {
        return b;
    }
    // Adopt a valid per-user key to preserve an existing pinned identity; otherwise mint a new key.
    let bytes = local_key_bytes()
        .filter(valid)
        .unwrap_or_else(|| sign::gen_keypair().1.as_ref().to_vec());
    write_machine_key_bytes(&bytes);
    LocalConfig::set_option(KEY_OPT.to_owned(), base64::encode(&bytes, variant()));
    bytes
}

/// The per-user `LocalConfig` copy of the signing secret used as a cross-context fallback.
fn local_key_bytes() -> Option<Vec<u8>> {
    base64::decode(LocalConfig::get_option(KEY_OPT), variant()).ok().filter(|b| !b.is_empty())
}

/// Machine-wide path for the shared signing secret: `%ProgramData%\SullTecRemote\console-job-key`
/// on Windows — readable by every account on the box (the SYSTEM service writes it; user instances
/// read it). `None` off Windows, where the ingest runs single-context and `LocalConfig` suffices.
#[cfg(windows)]
fn machine_key_path() -> Option<std::path::PathBuf> {
    std::env::var_os("ProgramData")
        .map(|p| std::path::PathBuf::from(p).join(hbb_common::config::APP_NAME.read().unwrap().clone()).join(KEY_OPT))
}
#[cfg(not(windows))]
fn machine_key_path() -> Option<std::path::PathBuf> {
    None
}

fn read_machine_key_bytes() -> Option<Vec<u8>> {
    let s = std::fs::read_to_string(machine_key_path()?).ok()?;
    base64::decode(s.trim(), variant()).ok().filter(|b| !b.is_empty())
}

/// Best-effort machine-wide persist. The SYSTEM service succeeds; a plain-user instance may not be
/// able to write `%ProgramData%` — it keeps using the per-user copy until the service writes the
/// shared one, at which point the next process start picks it up.
fn write_machine_key_bytes(bytes: &[u8]) {
    let Some(path) = machine_key_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, base64::encode(bytes, variant()));
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
///
/// The heartbeat body is signed with this same scheme and key. Stock servers ignore the header; the
/// console verifies it and — only once enforcement is enabled — withholds queued jobs and pushed
/// policy from an unsigned or forged beat for a device that has signed before. Sign the exact bytes
/// that are sent: build the body string once and pass it to both.
pub fn sign_header(body: &str) -> String {
    let (_, sk) = keypair();
    format!("X-ST-Sig: {}", base64::encode(sign::sign_detached(body.as_bytes(), &sk).as_ref(), variant()))
}

// ── Key-pair logon rotation-chain trust ──────────────────────────────────────────────────────

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
    // Not yet re-derived this process (e.g. just after a reboot): fall back to the persisted floor
    // when it was adopted under our current baked anchor, so an adopted rotation survives a restart
    // until the next heartbeat re-walks the chain. A baked-anchor change discards the stale floor.
    let anchor = baked_logon_pubkey();
    if let Ok(v) = serde_json::from_str::<Value>(&LocalConfig::get_option(LOGON_TRUST_OPT)) {
        if v.get("anchor").and_then(|x| x.as_str()) == Some(anchor) {
            if let Some(t) = v.get("trusted").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                return t.to_owned();
            }
        }
    }
    anchor.to_owned()
}

/// Ask the console to sign `CONSOLE-LOGON\n{device_id}\n{challenge}` for this connection. The
/// console's PRIVATE key never leaves it. Authenticated with the operator's token; the console
/// authorizes the operator for this device, signs, audits, and returns the attached signature.
/// Returns the raw signature bytes, or empty on any failure (→ caller falls back to the password flow).
pub async fn fetch_logon_grant(console_url: &str, token: &str, device_id: &str, challenge: &str) -> Vec<u8> {
    // The device is named by the ADDRESS, so the body carries only the challenge. The console
    // resolves the id through the rows the caller can already see, which is what authorizes this.
    //
    // A 404 or any unparsable response yields an empty signature and falls back to password login.
    let url = format!(
        "{}/api/devices/key/{}/common/logon/issue",
        console_url.trim_end_matches('/'),
        device_id
    );
    let body = json!({ "challenge": challenge }).to_string();
    let header = format!("Authorization: Bearer {token}");
    match crate::post_request(url, body, &header).await {
        Ok(rsp) => serde_json::from_str::<Value>(&rsp)
            .ok()
            .and_then(|v| v.get("sig").and_then(|x| x.as_str()).map(str::to_owned))
            .and_then(|s| base64::decode(s.trim(), variant()).ok())
            .unwrap_or_default(),
        Err(e) => {
            hbb_common::log::warn!("console logon grant failed: {e}");
            Vec::new()
        }
    }
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
    // Attached sig is `sig(64)‖msg`; reject obviously-malformed / oversized blobs before verify.
    if attached.len() < 64 || attached.len() > 64 + 4096 {
        return false;
    }
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let expected = format!("CONSOLE-LOGON-ROTATE\n{new_pub_b64}");
    matches!(sign::verify(&attached, &pk), Ok(m) if m == expected.as_bytes())
}

/// Pure chain resolution (no I/O — unit-tested). Given the baked `anchor`, the advertised `entries`
/// (`{pub, sig}` each), and the persisted floor `prev` (the anchor it was derived under + the highest
/// pubkey adopted under it), return the pubkey this device should trust. Walks forward from the anchor
/// verifying each hop (capped at MAX_CHAIN, stopping at the first bad hop); NEVER regresses below a
/// floor adopted under the SAME anchor (so a replayed older chain can't roll the device back to a
/// possibly-revoked key); resets to the anchor when the baked anchor changed (a fresh client build
/// supersedes any learned chain — compromise recovery).
fn resolve_trusted(anchor: &str, entries: &[Value], prev: Option<(&str, &str)>) -> String {
    // A nested fn (not a closure) so the returned &str borrows from the argument via normal lifetime
    // elision — a `let` closure can't express that higher-ranked relationship.
    fn pub_at(e: &Value) -> Option<&str> {
        e.get("pub").and_then(|x| x.as_str())
    }
    // The floor only applies under the same baked anchor; a changed anchor discards learned history.
    let floor = prev.and_then(|(pa, pt)| (pa == anchor).then_some(pt));

    let Some(start_idx) = entries.iter().position(|e| pub_at(e) == Some(anchor)) else {
        // Anchor not in the advertised chain (stale/foreign/replayed) → keep the floor, else the anchor.
        return floor.unwrap_or(anchor).to_owned();
    };

    let mut trusted = anchor.to_owned();
    let mut trusted_idx = start_idx;
    for (off, e) in entries[start_idx + 1..].iter().take(MAX_CHAIN).enumerate() {
        let (Some(new_pub), Some(sig)) = (pub_at(e), e.get("sig").and_then(|x| x.as_str())) else {
            break;
        };
        if new_pub.is_empty() || sig.is_empty() || !verify_rotate(&trusted, new_pub, sig) {
            break; // stop at the last validated key
        }
        trusted = new_pub.to_owned();
        trusted_idx = start_idx + 1 + off;
    }

    // Monotonic floor: refuse to adopt a key earlier than one already adopted under this anchor.
    match floor {
        Some(f) => match entries.iter().position(|e| pub_at(e) == Some(f)) {
            Some(f_idx) if trusted_idx >= f_idx => trusted, // at/beyond the floor → forward progress
            _ => f.to_owned(),                              // floor absent or walk regressed → hold it
        },
        None => trusted,
    }
}

/// Adopt logon-key rotations advertised on the heartbeat (§B instant rotation). Resolves the trusted
/// key via `resolve_trusted` (forward-walk + monotonic floor + anchor reset), persists it so it
/// survives a reboot and can't be rolled back, and caches it in `LOGON_TRUSTED`. A broken / foreign /
/// oversized chain is ignored; the baked anchor stays the durable root (compromise recovery is a
/// fresh client build, which resets the floor).
pub fn update_logon_chain(chain: Option<Value>) {
    let anchor = baked_logon_pubkey();
    if anchor.is_empty() {
        return;
    }
    let Some(chain) = chain else { return };
    let Ok(entries) = serde_json::from_value::<Vec<Value>>(chain) else {
        return;
    };
    if entries.len() > MAX_CHAIN + 1 {
        hbb_common::log::warn!("console logon chain too long ({}); ignoring", entries.len());
        return;
    }

    let stored = LocalConfig::get_option(LOGON_TRUST_OPT);
    let prev: Option<(String, String)> = serde_json::from_str::<Value>(&stored).ok().and_then(|v| {
        Some((v.get("anchor")?.as_str()?.to_owned(), v.get("trusted")?.as_str()?.to_owned()))
    });
    let trusted = resolve_trusted(
        anchor,
        &entries,
        prev.as_ref().map(|(a, t)| (a.as_str(), t.as_str())),
    );

    // Persist only when (anchor, trusted) changed — avoids a disk write every heartbeat.
    if prev.as_ref().map(|(a, t)| a.as_str() != anchor || t.as_str() != trusted.as_str()).unwrap_or(true) {
        LocalConfig::set_option(
            LOGON_TRUST_OPT.to_owned(),
            json!({ "anchor": anchor, "trusted": trusted }).to_string(),
        );
    }
    if let Ok(mut g) = LOGON_TRUSTED.write() {
        if g.as_deref() != Some(trusted.as_str()) {
            hbb_common::log::info!("console logon key trusted = {trusted}");
        }
        *g = Some(trusted);
    }
}

// ── Signed update channel ─────────────────────────────────────────────────────────────────────

/// LocalConfig key: sticky signed-update enforce latch. Set when a verified client policy carries
/// `update.require_sig` truthy; kept OUTSIDE the OVERWRITE_* maps that `policy_release_all` clears,
/// so a MITM that merely drops the policy push can't downgrade enforce→observe once a device has
/// latched. Only an explicit signed `update.require_sig=0` (or a baked-enforce rebuild) reverses it.
const UPDATE_ENFORCE_LATCH_OPT: &str = "console-update-enforce-latched";
/// LocalConfig key: signed-update high-water mark (the version token of the highest build ever
/// installed). Anti-rollback floor — see the updater's verify gate.
const UPDATE_HWM_OPT: &str = "console-update-hwm";
/// Policy key (over the signed CONSOLE-POLICY channel) that arms signed-update enforce.
const UPDATE_REQUIRE_SIG_KEY: &str = "update.require_sig";

/// Verify the console's attached signature over `CONSOLE-PKG\n{version}\n{sha256_hex}\n{size}`
/// against the CURRENT trusted logon key. A rotated-*out* key is intentionally NOT accepted, so a
/// rotation revokes a compromised key; the backend re-signs hosted packages under the current key
/// on rotation. Any empty component is a hard fail. Mirrors `verify_rotate` and
/// the backend's `sign_package`.
pub fn verify_package(version: &str, sha256_hex: &str, size: u64, sig_b64: &str) -> bool {
    if version.is_empty() || sha256_hex.is_empty() || size == 0 || sig_b64.is_empty() {
        return false;
    }
    let pub_b64 = current_logon_pubkey();
    if pub_b64.is_empty() {
        return false;
    }
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(&pub_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return false;
    };
    // Attached sig is `sig(64)‖msg`; reject obviously-malformed / oversized blobs before verify.
    if attached.len() < 64 || attached.len() > 64 + 4096 {
        return false;
    }
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let expected = format!("CONSOLE-PKG\n{version}\n{sha256_hex}\n{size}");
    matches!(sign::verify(&attached, &pk), Ok(m) if m == expected.as_bytes())
}

/// Effective signed-update enforce mode = the baked floor OR the sticky policy latch. The baked
/// floor is compile-time (`ST_UPDATE_ENFORCE=1`; unset selects observe mode).
/// The latch is set by a verified `update.require_sig` policy (`apply_policy`) and persists across
/// the policy going absent.
pub fn update_sig_enforced() -> bool {
    if option_env!("ST_UPDATE_ENFORCE") == Some("1") {
        return true;
    }
    LocalConfig::get_option(UPDATE_ENFORCE_LATCH_OPT) == "1"
}

/// Signed-update high-water mark (version token) — the anti-rollback floor. Empty until seeded.
pub fn update_hwm() -> String {
    LocalConfig::get_option(UPDATE_HWM_OPT)
}

/// Raise the high-water mark to `token` when it out-ranks the stored one; never lowers it. Called
/// by the first-boot hwm hook with the running build's baked version.
pub fn advance_update_hwm(token: &str) {
    if token.is_empty() {
        return;
    }
    let cur = LocalConfig::get_option(UPDATE_HWM_OPT);
    if cur.is_empty() || crate::sulltec_remote::update::version_key(token) > crate::sulltec_remote::update::version_key(&cur) {
        LocalConfig::set_option(UPDATE_HWM_OPT.to_owned(), token.to_owned());
    }
}

/// Apply the signed `update.require_sig` policy value to the enforce latch. Truthy latches enforce
/// (sticky); an explicit falsy value un-latches, but only when enforce is NOT baked
/// (`max(enforce,0)=enforce`). An ABSENT key is not passed here at all, so it never downgrades.
fn apply_update_require_sig(value: &str) {
    let truthy = matches!(value.trim(), "1" | "true" | "yes" | "on");
    if truthy {
        LocalConfig::set_option(UPDATE_ENFORCE_LATCH_OPT.to_owned(), "1".to_owned());
    } else if option_env!("ST_UPDATE_ENFORCE") != Some("1") {
        LocalConfig::set_option(UPDATE_ENFORCE_LATCH_OPT.to_owned(), "0".to_owned());
    }
}

// ── Client policy (GPO-style settings lockdown): apply console-pushed settings, lock the chosen ones ─

/// Keys this device currently has locked via policy (forced into the OVERWRITE_* maps). Tracked so a
/// policy that drops a key — or is removed entirely — releases the lock instead of leaving it stuck.
static POLICY_LOCKED: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Release every policy-forced lock (from all three stores) — used when the heartbeat carries no/empty
/// policy for this device.
fn policy_release_all() {
    let mut locked = match POLICY_LOCKED.write() {
        Ok(g) => g,
        Err(_) => return,
    };
    if locked.is_empty() {
        return;
    }
    for map in [&*config::OVERWRITE_SETTINGS, &*config::OVERWRITE_DISPLAY_SETTINGS, &*config::OVERWRITE_LOCAL_SETTINGS] {
        if let Ok(mut m) = map.write() {
            for k in locked.iter() {
                m.remove(k);
            }
        }
    }
    hbb_common::log::info!("console policy: released {} lock(s)", locked.len());
    locked.clear();
}

/// Verify a console-signed policy blob → its `(key, value, locked)` settings. The blob is the attached
/// Ed25519 signature (`sig‖msg`) over `CONSOLE-POLICY\n{device_id}\n{settings_json}`, signed by the
/// console logon key and verified against the key this device currently trusts (the same anchor /
/// rotation chain used for key-pair logon), bound to THIS device's id so one device's policy can't be
/// replayed to another. `None` on any failure → the caller leaves current state untouched (a bad sig
/// never unlocks). Domain-separated from the logon-challenge / rotate messages by its prefix.
fn verify_policy(sig_b64: &str) -> Option<Vec<(String, String, bool)>> {
    let pk_b64 = current_logon_pubkey();
    if pk_b64.is_empty() {
        return None; // key-pair logon not provisioned for this build → no trusted signer
    }
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(&pk_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return None;
    };
    if attached.len() < 64 || attached.len() > 64 + 65536 {
        return None; // sig(64) ‖ msg; generous cap on the settings payload
    }
    let pk = sign::PublicKey::from_slice(&pk_bytes)?;
    let msg = sign::verify(&attached, &pk).ok()?;
    let msg = String::from_utf8(msg).ok()?;
    // CONSOLE-POLICY\n{device_id}\n{settings_json}
    let mut parts = msg.splitn(3, '\n');
    if parts.next() != Some("CONSOLE-POLICY") {
        return None;
    }
    if parts.next() != Some(Config::get_id().as_str()) {
        return None; // device-id-bound
    }
    let map = serde_json::from_str::<serde_json::Map<String, Value>>(parts.next()?).ok()?;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let value = v.get("value").and_then(|x| x.as_str()).unwrap_or("").to_owned();
        let locked = v.get("locked").and_then(|x| x.as_bool()).unwrap_or(false);
        out.push((k, value, locked));
    }
    Some(out)
}

/// Apply the console's client policy delivered on the heartbeat (the GPO-style settings lockdown). For
/// each setting: when `locked`, force + lock it (a runtime insert into the OVERWRITE_* maps, which wins
/// over any saved value AND greys the control in Settings, since the UI already gates on
/// `is_option_fixed`); else apply the value to the user layer (still editable). Settings live in three
/// stores — main (`Config`), Display user-defaults (`UserDefaultConfig`), and local (`LocalConfig`) —
/// each with its own OVERWRITE_* map. Since we don't know a key's store, we force/release it in ALL
/// THREE maps (an entry in a non-owning map is inert — only that map's getter reads it) and apply
/// unlocked values via all three setters. Locks dropped from the policy — or an absent/empty/invalid
/// policy — are released. Re-applied every heartbeat, so an out-of-band edit to a locked setting is
/// undone on the next beat.
pub fn apply_policy(policy: Option<Value>) {
    let sig = match policy.as_ref().and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            policy_release_all(); // no policy for this device → drop any locks we hold
            sync_policy_file(&[]); // and clear the mirror so other processes (the UI) release too
            return;
        }
    };
    let Some(mut settings) = verify_policy(sig) else {
        hbb_common::log::warn!("console policy: signature invalid; ignoring");
        return; // fail-safe: a forged/corrupt blob never changes locks
    };

    // The signed `update.require_sig` key arms the sticky signed-update enforce latch
    // (a persisted LocalConfig flag OUTSIDE the OVERWRITE maps). Handle it here and drop it from the
    // normal setting apply so it never becomes a device Config option / greyed control.
    if let Some(pos) = settings.iter().position(|(k, _, _)| k == UPDATE_REQUIRE_SIG_KEY) {
        let (_, value, _) = settings.remove(pos);
        apply_update_require_sig(&value);
    }

    let now_locked: Vec<String> = settings.iter().filter(|(_, _, l)| *l).map(|(k, _, _)| k.clone()).collect();
    let prev_locked: Vec<String> = POLICY_LOCKED.read().map(|g| g.clone()).unwrap_or_default();

    // Force locked keys (and release unlocked / no-longer-listed ones) in each store's OVERWRITE map.
    // Done per-map (acquire-write-drop), and BEFORE any set_option below — set_option re-reads
    // OVERWRITE_SETTINGS, which would deadlock if we still held that lock.
    apply_overwrite(&config::OVERWRITE_SETTINGS, &settings, &prev_locked, &now_locked);
    apply_overwrite(&config::OVERWRITE_DISPLAY_SETTINGS, &settings, &prev_locked, &now_locked);
    apply_overwrite(&config::OVERWRITE_LOCAL_SETTINGS, &settings, &prev_locked, &now_locked);
    if let Ok(mut g) = POLICY_LOCKED.write() {
        *g = now_locked;
    }

    // Unlocked: apply the value to the user layer of each store (the owning store sticks; the rest inert).
    for (k, value, locked) in &settings {
        if !*locked {
            Config::set_option(k.clone(), value.clone());
            LocalConfig::set_option(k.clone(), value.clone());
            config::UserDefaultConfig::load().set(k.clone(), value.clone());
        }
    }

    // Mirror the locked set to disk so the OTHER processes — chiefly the Flutter Settings UI, whose
    // `is_option_fixed` reads its own (otherwise empty) OVERWRITE_* maps — can grey the locked
    // controls. The heartbeat that authors the policy only runs in the `--server` process, so without
    // this the value is forced but the control never disables. See `load_persisted_policy`.
    let locked_kv: Vec<(String, String)> = settings
        .iter()
        .filter(|(_, _, l)| *l)
        .map(|(k, v, _)| (k.clone(), v.clone()))
        .collect();
    sync_policy_file(&locked_kv);
}

/// Force (locked) or release (unlocked / no-longer-listed) the given policy keys in ONE OVERWRITE_* map.
fn apply_overwrite(
    map: &std::sync::RwLock<std::collections::HashMap<String, String>>,
    settings: &[(String, String, bool)],
    prev_locked: &[String],
    now_locked: &[String],
) {
    let Ok(mut m) = map.write() else { return };
    for (k, value, locked) in settings {
        if *locked {
            m.insert(k.clone(), value.clone());
        } else {
            m.remove(k);
        }
    }
    for k in prev_locked {
        if !now_locked.contains(k) {
            m.remove(k);
        }
    }
}

// ── Cross-process lock visibility (greying) ──────────────────────────────────────────────────────
// `apply_policy` runs in the rendezvous-mediator (`--server`) process. The Flutter Settings UI runs
// in the MAIN process and greys a control via `is_option_fixed`, which reads THAT process's own
// OVERWRITE_* maps — and those maps are per-process. So the lock the server applied is invisible to
// the UI: the value is still forced (the server enforces it + syncs the value over IPC) but the
// control never disables. To make the lock visible everywhere, the server mirrors the locked set to
// a small file in the config dir; every process loads it into its OWN OVERWRITE_* maps at startup,
// and the UI re-loads it on its periodic IPC tick so a policy change greys live without a restart.
// (Relies on the portable, user-context server sharing the config dir with the UI; a SYSTEM-service
// install would not share it — there enforcement still holds, only the grey would be missing.)
// The file is authored only by the verified heartbeat path; a tampered/deleted file can at most
// grey/un-grey the LOCAL UI — the server still enforces the signed policy and rejects IPC saves of
// locked keys, so nothing functional is gained by editing it.

fn policy_file_path() -> std::path::PathBuf {
    // The file must be reachable by BOTH its writer and its reader, which on a SERVICE install are
    // DIFFERENT Windows accounts: `apply_policy` runs in the heartbeat = the `--server` process,
    // which a service install runs as SYSTEM/LocalService, while `load_persisted_policy` runs in the
    // user-session Flutter UI. `Config::path()` resolves PER-IDENTITY (SYSTEM →
    // `…\ServiceProfiles\LocalService\…` via `patch()`, user → `%APPDATA%`), so it can't bridge that
    // gap — the UI never sees the SYSTEM-written file and the controls never grey. Use a shared
    // location instead: `C:\ProgramData` grants `Users:(OI)(CI)(RX)` (a SYSTEM-written file there is
    // readable by the UI) and `Users:(CI)(WD,AD)` (a user-context/portable server can create it too).
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_owned());
        let mut p = std::path::PathBuf::from(base);
        p.push(config::APP_NAME.read().unwrap().clone());
        let _ = std::fs::create_dir_all(&p);
        p.push("console-policy.json");
        p
    }
    #[cfg(not(windows))]
    {
        Config::path("console-policy.json")
    }
}

/// mtime (secs; 0 = missing) of the policy file at the last `load_persisted_policy`, so the UI's
/// periodic reload is a cheap stat until the file actually changes.
static PERSISTED_MTIME: AtomicI64 = AtomicI64::new(i64::MIN);
/// The locked `(key, value)` set last written to the file — lets the server skip rewriting it (and
/// thus every UI re-reading it) when a heartbeat re-delivers an unchanged policy.
static LAST_PERSISTED: RwLock<Vec<(String, String)>> = RwLock::new(Vec::new());
/// Bumped whenever THIS process's policy locks change (a file reload gets past the mtime gate). The
/// Flutter Settings page polls it via the `#policy-rev` synthetic option key and rebuilds its
/// kept-alive tabs so locked controls grey out live, with no client restart.
static POLICY_VERSION: AtomicI64 = AtomicI64::new(0);

/// Current client-policy revision for this process (see `POLICY_VERSION`). Read by the Settings UI
/// through the `#policy-rev` magic key in `ui_interface::get_option`.
pub fn policy_version() -> i64 {
    POLICY_VERSION.load(Ordering::Relaxed)
}

/// Mirror the currently-locked `(key, value)` settings to the policy file (atomic temp+rename). Skips
/// the write when nothing changed AND the file is still present (so a locally-deleted file self-heals
/// within one heartbeat). An empty set removes the file (full release).
fn sync_policy_file(locked: &[(String, String)]) {
    let path = policy_file_path();
    let unchanged = LAST_PERSISTED
        .read()
        .map(|l| l.as_slice() == locked)
        .unwrap_or(false);
    if unchanged && (locked.is_empty() || path.exists()) {
        return;
    }
    if locked.is_empty() {
        let _ = std::fs::remove_file(&path);
    } else if let Ok(body) =
        serde_json::to_vec(&locked.iter().map(|(k, v)| json!({ "k": k, "v": v })).collect::<Vec<_>>())
    {
        let tmp = policy_file_path().with_extension("json.tmp");
        if std::fs::write(&tmp, &body).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
    if let Ok(mut g) = LAST_PERSISTED.write() {
        *g = locked.to_vec();
    }
}

/// Load the mirrored policy locks into THIS process's OVERWRITE_* maps so the Settings UI greys the
/// locked controls (and the value is forced) here too. Reconciles against `POLICY_LOCKED`: keys
/// dropped from the file since the last load are released. mtime-gated, so it's a cheap stat when
/// nothing changed. Called at startup in every process and on the UI's periodic IPC tick — the file
/// is always in lock-step with `apply_policy`, so reusing `POLICY_LOCKED` here can't fight it even
/// when both run in one process (the portable in-thread server).
pub fn load_persisted_policy() {
    let path = policy_file_path();
    let meta = std::fs::metadata(&path).ok();
    let mtime = meta
        .as_ref()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if PERSISTED_MTIME.swap(mtime, Ordering::Relaxed) == mtime {
        return; // unchanged since last load (also covers the steady "no file" case: 0 == 0)
    }
    let raw = if meta.is_some() { std::fs::read(&path).ok() } else { None };
    if meta.is_some() && raw.is_none() {
        // Transient read failure on an existing file — retry next tick rather than wrongly releasing.
        PERSISTED_MTIME.store(i64::MIN, Ordering::Relaxed);
        return;
    }
    let now: Vec<(String, String)> = raw
        .and_then(|b| serde_json::from_slice::<Vec<Value>>(&b).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| {
            Some((
                e.get("k")?.as_str()?.to_owned(),
                e.get("v").and_then(|x| x.as_str()).unwrap_or("").to_owned(),
            ))
        })
        .collect();
    let now_keys: Vec<String> = now.iter().map(|(k, _)| k.clone()).collect();
    let settings: Vec<(String, String, bool)> =
        now.into_iter().map(|(k, v)| (k, v, true)).collect();
    let prev_keys = POLICY_LOCKED.read().map(|g| g.clone()).unwrap_or_default();
    apply_overwrite(&config::OVERWRITE_SETTINGS, &settings, &prev_keys, &now_keys);
    apply_overwrite(&config::OVERWRITE_DISPLAY_SETTINGS, &settings, &prev_keys, &now_keys);
    apply_overwrite(&config::OVERWRITE_LOCAL_SETTINGS, &settings, &prev_keys, &now_keys);
    if let Ok(mut g) = POLICY_LOCKED.write() {
        *g = now_keys;
    }
    // The file changed (we got past the mtime gate), so the policy locks just shifted — bump the
    // revision so the Settings UI rebuilds its kept-alive tabs and re-evaluates `is_option_fixed`.
    POLICY_VERSION.fetch_add(1, Ordering::Relaxed);
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
                // Stop enrolling only once this key is pinned. If another key is pinned, retry each
                // heartbeat so an operator reset can recover the device without a restart.
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

/// Verdict from verifying the console's job-dispatch signature.
enum JobsVerdict {
    /// Signature verified, fresh, device-bound, and matching the wire jobs. Carries the operator's
    /// enforce flag (learned) and the authentic job list to run.
    Valid { enforce: bool, jobs: Vec<Value> },
    /// A signature was present but didn't verify / was stale / didn't match the wire jobs.
    Invalid,
    /// No signature on this heartbeat (a backend that isn't signing yet, or a stock server).
    Absent,
}

/// Run the jobs the heartbeat delivered, each on its own task, posting a signed result — but only
/// after verifying the console's dispatch signature. In *enforce* mode an unverified dispatch is
/// dropped; in *observe* mode (the default, and what a not-yet-signing backend yields) it runs but
/// is logged. The enforce flag is learned from validly-signed beats. Each job-id runs once within
/// the freshness window (replay + re-delivery dedup).
/// Ask the console for this device's queued jobs over a signed request and run the returned jobs.
/// Params arrive with each authenticated job, including hosted commands and unsealed secrets.
/// The console signs the dispatch, [`run`] verifies it, and `JOBS_ENFORCE` determines whether an
/// unverifiable dispatch may run.
pub fn poll(heartbeat_url: String, id: String) {
    hbb_common::tokio::spawn(async move {
        let Some(mut rsp) = fetch_jobs(&heartbeat_url, &id).await else { return };
        let Some(items) = rsp.get_mut("items").map(Value::take) else { return };
        run(
            heartbeat_url,
            id,
            items,
            rsp.get("jobs_sig").cloned(),
            rsp.get("jobs_ts").cloned(),
        );
    });
}

/// The signed read of our own queue — the device's pinned key
/// over a fresh timestamp — with its own domain string so a signature captured for one request can
/// never be replayed as the other.
async fn fetch_jobs(heartbeat_url: &str, device_id: &str) -> Option<Value> {
    let (_, sk) = keypair();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let msg = format!("CONSOLE-DEVICE-JOBS\n{device_id}\n{ts}");
    let sig = sign::sign_detached(msg.as_bytes(), &sk);
    let body = json!({ "device_id": device_id, "ts": ts, "sig": base64::encode(sig.as_ref(), variant()) })
        .to_string();
    let url = format!("{}/api/device/jobs/list", origin_of(heartbeat_url));
    // The response carries every queued job's params; a `file-push` or `deploy`
    // payload is the bulk case — so this takes the data timeout rather than the control one.
    let rsp = crate::post_request_timeout(url, body, "", crate::sulltec_remote::http::API_TIMEOUT_DATA)
        .await
        .ok()?;
    serde_json::from_str::<Value>(&rsp).ok()
}

/// Return the heartbeat URL's scheme and host so sibling endpoints do not depend on its path.
fn origin_of(heartbeat_url: &str) -> String {
    match heartbeat_url.find("/api/") {
        Some(i) => heartbeat_url[..i].to_owned(),
        None => heartbeat_url.trim_end_matches('/').to_owned(),
    }
}

pub fn run(heartbeat_url: String, id: String, jobs: Value, jobs_sig: Option<Value>, jobs_ts: Option<Value>) {
    let Ok(wire_jobs) = serde_json::from_value::<Vec<Value>>(jobs) else {
        return;
    };
    if wire_jobs.is_empty() {
        return;
    }
    let run_jobs: Vec<Value> = match verify_jobs(&wire_jobs, jobs_sig.as_ref(), jobs_ts.as_ref()) {
        JobsVerdict::Valid { enforce, jobs } => {
            JOBS_ENFORCE.store(enforce, Ordering::Relaxed);
            jobs // the authentic (signed) copy
        }
        JobsVerdict::Invalid => {
            if JOBS_ENFORCE.load(Ordering::Relaxed) {
                hbb_common::log::warn!("console jobs: dropping {} job(s) — dispatch signature didn't verify (enforce on)", wire_jobs.len());
                return;
            }
            hbb_common::log::warn!("console jobs: dispatch signature didn't verify; running anyway (observe — enable enforcement once the fleet is signed)");
            wire_jobs
        }
        JobsVerdict::Absent => {
            if JOBS_ENFORCE.load(Ordering::Relaxed) {
                hbb_common::log::info!("console jobs: dropping {} unsigned job(s) (enforce on)", wire_jobs.len());
                return;
            }
            wire_jobs // observe / not-yet-signing backend: today's behavior
        }
    };
    for job in run_jobs {
        let job_id = job.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        // The operation this job IS — the console's address for it plus the verb. Diagnostic only:
        // what actually runs comes from the params, which carry the executor and the command.
        // Absent for a compatibility kind-name dispatch, which has no verb to name.
        let op = job.get("op").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let params = job.get("params").and_then(|x| x.as_str()).map(str::to_owned);
        if job_id.is_empty() {
            continue;
        }
        // ORDER MATTERS. In-flight first: it answers "is this running right now", and a job that is
        // still working must not have a retry counted against it. Reversed, anything legitimately
        // slower than the 300 s window would burn its attempts while running fine and be abandoned
        // mid-run. The guard is released by the `continue` below if the seen-check then declines.
        let Some(in_flight) = in_flight_acquire(&job_id) else {
            continue;
        };
        // Replay defence, re-delivery dedup, and the attempt cap that stops a job which kills the
        // client from being relaunched forever.
        if !mark_job_seen(&job_id) {
            continue;
        }
        // The only trace a job leaves before it runs. A job that kills the client never reaches the
        // result path, so without this the last thing in the log is unrelated to what was running.
        // Emitted after the guards so it records runs that actually START, not ones deduped away.
        // Id and OPERATION only — params can carry a registry path, a file path or credentials
        // merged in at delivery, and this log gets pulled off devices.
        match op.is_empty() {
            true => hbb_common::log::info!("console job {job_id} starting"),
            false => hbb_common::log::info!("console job {job_id} starting ({op})"),
        }
        let url = heartbeat_url.clone();
        let id = id.clone();
        hbb_common::tokio::spawn(async move {
            let _in_flight = in_flight;
            // Params arrive WITH the job. The queue read is authenticated, so there is nothing to
            // withhold and no second fetch to make: the console unseals any secret and merges any
            // application secret into the same response that hands the job over.
            let (status, result) = run_job(params).await;
            post_result(&url, &id, &job_id, status, &result).await;
        });
    }
}

/// Verify a console-signed job dispatch (mirrors `verify_policy`). The attached Ed25519 signature
/// (`sig‖msg`) covers `CONSOLE-JOBS\n{device_id}\n{ts}\n{enforce}\n{jobs_json}`, signed by the console
/// logon key and verified against the key this device currently trusts — bound to THIS device's id +
/// a fresh ts (anti-replay), with `enforce` carried inside so a forged beat can't flip it. The signed
/// jobs must equal the wire jobs (order-independent `Value` equality), so the signature gates exactly
/// what runs. `Absent` when no signature is present, which selects observe mode.
fn verify_jobs(wire_jobs: &[Value], sig: Option<&Value>, ts: Option<&Value>) -> JobsVerdict {
    let sig_b64 = match sig.and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return JobsVerdict::Absent,
    };
    let pk_b64 = current_logon_pubkey();
    if pk_b64.is_empty() {
        return JobsVerdict::Invalid; // a sig was sent but this build has no trusted signer
    }
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(&pk_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return JobsVerdict::Invalid;
    };
    if attached.len() < 64 || attached.len() > 64 + 256 * 1024 {
        return JobsVerdict::Invalid; // sig(64) ‖ msg; generous cap on the jobs payload
    }
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return JobsVerdict::Invalid;
    };
    let Ok(msg) = sign::verify(&attached, &pk) else {
        return JobsVerdict::Invalid;
    };
    let Ok(msg) = String::from_utf8(msg) else {
        return JobsVerdict::Invalid;
    };
    // CONSOLE-JOBS\n{device_id}\n{ts}\n{enforce}\n{jobs_json}
    let mut parts = msg.splitn(5, '\n');
    if parts.next() != Some("CONSOLE-JOBS") {
        return JobsVerdict::Invalid;
    }
    if parts.next() != Some(Config::get_id().as_str()) {
        return JobsVerdict::Invalid; // device-id-bound
    }
    let Some(signed_ts) = parts.next().and_then(|s| s.parse::<i64>().ok()) else {
        return JobsVerdict::Invalid;
    };
    let enforce = parts.next() == Some("1");
    let Some(jobs_json) = parts.next() else {
        return JobsVerdict::Invalid;
    };
    // Freshness (anti-replay) on the signed ts; cross-check the advertised ts matches.
    if (now_secs() - signed_ts).abs() > JOBS_FRESH_SECS {
        return JobsVerdict::Invalid;
    }
    if let Some(adv) = ts.and_then(|v| v.as_i64()) {
        if adv != signed_ts {
            return JobsVerdict::Invalid;
        }
    }
    // The signed jobs must match what's on the wire (order-independent Value equality), so the
    // signature actually authorizes exactly the jobs we're about to run.
    let Ok(signed_jobs) = serde_json::from_str::<Vec<Value>>(jobs_json) else {
        return JobsVerdict::Invalid;
    };
    if signed_jobs != *wire_jobs {
        return JobsVerdict::Invalid;
    }
    JobsVerdict::Valid { enforce, jobs: signed_jobs }
}

/// Write panics to the log before the process dies.
///
/// Release builds set `panic = 'abort'`; a Windows service has no stderr, so the panic message must
/// be logged before the process aborts.
///
/// The default hook still runs afterwards, so nothing changes about the abort itself.
pub fn install_panic_logger() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".into());
        // `payload_as_str` is not stable here; the two concrete types cover every practical panic.
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_owned());
        let thread = std::thread::current().name().unwrap_or("unnamed").to_owned();
        hbb_common::log::error!("PANIC on thread '{thread}' at {loc}: {msg}");
        previous(info);
    }));
}

/// Job ids whose run is executing in THIS process right now.
///
/// `Vec` rather than `HashSet`: `HashSet::new()` is not const, and `once_cell::Lazy` is not available
/// here — once_cell is an optional dependency gated on `unix-file-copy-paste`, so it is absent from
/// the Windows build. Only a handful of ids are ever in flight, so the linear scan is free.
static JOBS_IN_FLIGHT: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Owns a job id for the length of its run. Acquired in [`run`] and **moved into** the spawned
/// future, so the insert and the obligation to release are the same object — constructing it inside
/// the future instead would leak the id for the life of the process if that future were ever dropped
/// before its first poll, leaving the job permanently un-runnable with nothing logged.
///
/// Released on normal completion and on cancellation after the first poll. NOT on panic (release
/// builds set `panic = 'abort'`) and not at process exit (the heartbeat runtime is never dropped) —
/// but both of those end the process, which clears the set anyway.
struct InFlight(String);

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut ids = JOBS_IN_FLIGHT.write().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = ids.iter().position(|x| *x == self.0) {
            ids.swap_remove(i);
        }
    }
}

/// Claim `job_id` for this process, or `None` if a run already owns it.
///
/// This is what stops a long job being relaunched underneath itself. [`mark_job_seen`] cannot: its
/// window is 300 s, which is shorter than the legitimate runtime of a good many kinds, and the
/// backend re-sends every queued row on every heartbeat until a result settles it.
///
/// ⚠ It guarantees at most one CONCURRENT run per id per process lifetime — NOT at-most-once. The id
/// is released when the run ends, not when the backend settles the row, and the set is in-memory so a
/// restart clears it. Re-entry after either is still possible, which is why the destructive Duplicati
/// path carries its own guard at the point of danger rather than relying on this.
fn in_flight_acquire(job_id: &str) -> Option<InFlight> {
    let mut ids = JOBS_IN_FLIGHT.write().unwrap_or_else(|e| e.into_inner());
    if ids.iter().any(|x| x == job_id) {
        return None;
    }
    ids.push(job_id.to_owned());
    Some(InFlight(job_id.to_owned()))
}

/// How long a job id stays remembered after a run that never reported.
///
/// This is independent of [`JOBS_FRESH_SECS`], the dispatch-signature anti-replay window that mirrors
/// the backend's ±300-second check.
const JOBS_SEEN_TTL_SECS: i64 = 300;

/// How many times this device will start the same job id when no result ever lands.
///
/// The backend re-delivers a job until a result settles it. A job that terminates the client cannot
/// send a result, so this cap prevents an indefinite relaunch loop across restarts.
const JOB_MAX_ATTEMPTS: i64 = 3;

/// How long an abandoned job id is remembered. Long, deliberately: forgetting it is precisely how the
/// loop restarts, so this must outlive any plausible run of re-deliveries.
const JOB_POISON_TTL_SECS: i64 = 7 * 24 * 3600;

/// Bound on the remembered set, so a device that is handed thousands of jobs cannot grow this without
/// limit. Oldest entries go first.
const JOBS_SEEN_MAX: usize = 256;

/// `(first_seen_ts, attempts)` for a stored entry. A bare timestamp is accepted as a compatibility
/// form so an existing map remains valid.
fn seen_entry(v: &Value) -> Option<(i64, i64)> {
    if let Some(t) = v.as_i64() {
        return Some((t, 1));
    }
    let t = v.get("t")?.as_i64()?;
    Some((t, v.get("n").and_then(|x| x.as_i64()).unwrap_or(1)))
}

/// Record an attempt at `job_id`, returning true if it should run now.
///
/// Three outcomes: unseen → run; seen within the window → skip (ordinary re-delivery dedup); seen but
/// aged out → this is a retry, so count it and run until [`JOB_MAX_ATTEMPTS`] is spent, then never
/// again. Persisted in LocalConfig, so the count survives the abort it exists to bound.
///
/// ⚠ Callers MUST take the in-flight guard first. A job legitimately running longer than the window
/// would otherwise have its attempts counted while it is still working, and be abandoned mid-run.
fn mark_job_seen(job_id: &str) -> bool {
    let now = now_secs();
    let mut map: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    // Abandoned ids use the longer poison window so eviction cannot restart the retry loop.
    map.retain(|_, v| match seen_entry(v) {
        Some((t, n)) => {
            let ttl = if n >= JOB_MAX_ATTEMPTS { JOB_POISON_TTL_SECS } else { JOBS_SEEN_TTL_SECS };
            (now - t).abs() <= ttl
        }
        None => false,
    });
    let run = match map.get(job_id).and_then(seen_entry) {
        None => {
            map.insert(job_id.to_owned(), json!({ "t": now, "n": 1 }));
            true
        }
        Some((_, n)) if n >= JOB_MAX_ATTEMPTS => false,
        Some((t, _)) if (now - t).abs() <= JOBS_SEEN_TTL_SECS => false,
        Some((_, n)) => {
            let n = n + 1;
            if n >= JOB_MAX_ATTEMPTS {
                hbb_common::log::warn!(
                    "console job {job_id}: attempt {n} of {JOB_MAX_ATTEMPTS} and no result has ever \
                     reached the console. After this one the job is ABANDONED on this device — if it \
                     is killing the client, that is what stops the loop. The console still shows it \
                     queued until its own expiry settles it."
                );
            }
            map.insert(job_id.to_owned(), json!({ "t": now, "n": n }));
            n <= JOB_MAX_ATTEMPTS
        }
    };
    if map.len() > JOBS_SEEN_MAX {
        let mut by_age: Vec<(String, i64)> = map
            .iter()
            .map(|(k, v)| (k.clone(), seen_entry(v).map(|(t, _)| t).unwrap_or(0)))
            .collect();
        by_age.sort_by_key(|(_, t)| *t);
        for (k, _) in by_age.into_iter().take(map.len() - JOBS_SEEN_MAX) {
            map.remove(&k);
        }
    }
    LocalConfig::set_option(JOBS_SEEN_OPT.to_owned(), Value::Object(map).to_string());
    run
}



async fn run_job(params: Option<String>) -> (&'static str, String) {
    use hbb_common::tokio::task::spawn_blocking;
    // ⚠ **THE CLIENT RUNS WHAT THE DISPATCH BRINGS WITH IT, and nothing else.** An ask carrying an
    // `exec` names its own command and runs through [`keyset_exec`]; one carrying none is refused,
    // because the backend has not hosted that ask yet — and answering it from a compiled-in arm
    // would make an unhosted ask indistinguishable from a hosted one on both sides at once.
    if keyset_requested(params.as_deref()) {
        let value = spawn_blocking(move || keyset_exec(params.as_deref())).await.ok().flatten();
        return job_answer(value);
    }
    (
        "error",
        "this job carried no command to run: the client runs what the dispatch brings with it, so \
         an ask arriving without one has not been hosted by the backend yet"
            .to_string(),
    )
}

/// What a job REPORTS, given whatever its collector produced.
///
/// `Some(Value::Null)` is grouped with `None` deliberately: a collector that yields JSON `null`
/// has produced no data, and reporting it as `("done", "null")` puts `result: null` on the wire
/// beside `status:"done"` with no error — indistinguishable from a collector that ran and had
/// nothing to say. [`ps_json`] now stops that at the source; this is the backstop for any path
/// that does not go through it, because the failure is silent and fleet-wide when it happens.
///
/// Shared by the hosted path and compiled-in procedures so a hosted
/// collector that answered nothing must reach the console as the same failure, not as a silence.
///
/// **It names no kind, and does not need one.** The result is stored against the job that produced
/// it, and the console addresses that job by its own operation. The wording retains "produced no
/// result" as the documented failure phrase.
fn job_answer(value: Option<Value>) -> (&'static str, String) {
    match value {
        Some(v) if !v.is_null() => ("done", v.to_string()),
        _ => (
            "error",
            "the job produced no result (the command failed, or this client cannot run it)"
                .to_string(),
        ),
    }
}

/// A JSON number, or a numeric string. The `/api/diag` route delivers a filter body whose values may
/// arrive as strings, so a param that means "a number" has to accept both spellings or it silently
/// stops filtering.
#[cfg(windows)]
fn as_i64_loose(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}





// ── Diagnostic deep-read collectors — read-only, optionally filtered ─────────────────────────────
//
// Each collector invokes OS query APIs or built-in Windows tools per job, never a resident `.ps1`.
// They take the same
// `params: Option<&str>` a JSON filter body arrives in (mirroring `eventlog`), filter AT THE SOURCE so
// the signed result stays under the console's result cap (`store::MAX_JOB_RESULT`, **256 KiB**), and
// never mutate device state regardless of params. Off Windows each returns `None` / a "Windows-only"
// marker like the other Windows collectors.
//
// The source-side budgets below are conservative against the 256 KiB result cap. Going over is loud:
// an over-cap result
// is not clipped, it is REPLACED wholesale with `{ok:false, store_truncated:true, chars, limit}` and
// forced to `status:"error"` (`crates/backend/src/client_api.rs`), so a partial body can never be read
// as a complete one.


























/// The row cap for `services`, and the ordering it cuts against.
///
/// `services` has a row cap and marker because its bare `Vec<Value>` has no pagination envelope.
/// The backend replaces an over-cap result wholesale rather than dropping only its tail.
///
/// The 3000-row cap bounds implausibly large service sets; the backend byte cap remains the primary
/// size bound.
const SERVICE_CAP: usize = 3000;

/// Alphabetical by display name, which is what the console's table shows and what an operator scans.
const SERVICE_ORDER: &str = "display asc";






/// Read a NUL-terminated wide string into a `String` (empty on null pointer).
#[cfg(windows)]
unsafe fn pwstr(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
}

#[cfg(test)]
mod service_cap_tests {
    use super::services::cap_rows;
    use super::SERVICE_ORDER;
    use serde_json::{json, Value};

    /// The service collector declares a cut using the shared marker shape before reaching the
    /// backend's 256 KiB cap. The marker contains no field used by the console's Start/Stop buttons;
    /// `name` contains its explanatory text.
    #[test]
    fn services_declares_its_cut_in_the_shared_marker_shape() {
        let svc = |i: usize| json!({ "name": format!("svc{i}"), "display": format!("Service {i}"), "state": "running", "start": "auto" });
        let under: Vec<Value> = (0..10usize).map(svc).collect();
        assert_eq!(cap_rows(under.clone(), 3000, SERVICE_ORDER, "services", "last-alphabetically").len(), 10, "under the cap, untouched");
        assert!(cap_rows(under, 3000, SERVICE_ORDER, "services", "last-alphabetically").iter().all(|r| r.get("truncated").is_none()));

        let over: Vec<Value> = (0..25usize).map(svc).collect();
        let out = cap_rows(over, 10, SERVICE_ORDER, "services", "last-alphabetically");
        assert_eq!(out.len(), 11, "10 rows + one marker");
        let m = out.last().expect("marker");
        assert_eq!(m["truncated"], json!(true));
        assert_eq!(m["total"], json!(25), "the TRUE count, not what was returned");
        assert_eq!(m["returned"], json!(10));
        assert_eq!(m["order"].as_str(), Some(SERVICE_ORDER));
        assert!(m["name"].as_str().unwrap_or_default().contains("15 last-alphabetically"), "say WHICH rows went: {}", m["name"]);
        // Marker hygiene: nothing here may look like a real service to the action buttons.
        assert!(m.get("display").is_none() && m.get("state").is_none() && m.get("start").is_none(), "{m}");
    }
}

// ── Server-role deep-read collectors ────────────────────────────────────────────────────────────
// Each is read-only, gated by the console on the device's `roles` fingerprint, and follows the
// PowerShell/ADSI/WMI one-liner → `ps_rows_guarded` → `paginate` collector shape.







// ── RDS session-history collectors (role `rdsh`) ──────────────────────────────────────────────────
//
// These collectors read session events directly and filter them at the source.
//
// Event schema and filtering facts:
//   * 4624 `Properties` indices 5/6/8 = TargetUserName / TargetDomainName / LogonType (18 = IpAddress,
//     11 = WorkstationName). 4625 shifts: 5/6 user+domain, 7 Status, 9 SubStatus, 10 LogonType, 19 IP.
//   * The noise to drop is machine accounts (`*$`), `SYSTEM`, and the `DWM-*` / `UMFD-*` pseudo-users
//     the desktop-window and font-driver hosts generate on every session.
//   * Security events are level 0 (`LogAlways`), so the `Level` key is OMITTED — a level filter of any
//     positive value silently matches nothing here.
//   * Results come back newest-first, so a row cap drops the OLDEST part of the window, not the
//     newest. `row_cap_hit` says so rather than leaving the caller to assume a complete window.



/// Run a PowerShell one-liner that emits `ConvertTo-Json` and return its rows **always as a JSON
/// array** — like `ps_json` but normalizing the bare-object case (`ConvertTo-Json` emits an object,
/// not a 1-element array, for a single row) and a null/empty result to `[]`. For the list-shaped diag
/// collectors that want an array back without the per-field char-cap `ps_json_array` applies. Empty
/// off Windows.
#[cfg(windows)]
// ── Duplicati backup integration ──────────────────────────────────────────────────────────────
// Read + operate the endpoint's local Duplicati backup service through its official automation CLI,
// `Duplicati.CommandLine.ServerUtil.exe`. The Duplicati service and this client both run as
// LocalSystem, so ServerUtil — pointed at the service's datafolder (discovered from the service's
// registry ImagePath) — reads the server database directly and authenticates locally with NO
// password. `--json` gives machine-readable output we pass through. Reads: list-backups, status +
// health. Actions: run / pause / resume. Repair, compact, and verify use the server REST API below.







// ── Duplicati Server REST API actions ─────────────────────────────────────────────────────────
// repair / recreate / verify / compact / vacuum go through the local Duplicati Server API (:8200) —
// the server owns the DB and runs the op in-process (web-UI parity), so no passphrase-on-disk and no
// DB-lock conflict. Auth: ServerUtil mints a long-lived bearer via `issue-forever-token` (which does
// the datafolder→signin-JWT→`auth/signin` flow internally); we cache it and send `Authorization:
// Bearer`. The mint requires the operator to have enabled `--webservice-enable-forever-token` on the
// service once; until then these actions return an actionable error.























// ── Duplicati datafolder ACL check / secure ───────────────────────────────────────────────────
// Duplicati 2.3.0.107 requires exact data-folder permissions unless
// `--allow-insecure-datafolder` is set. The read-only compliance check and L2 corrective action use
// `ConfigureTool secure-datafolder` when available and otherwise set the ACL directly. Principals
// are matched by SID so this works on non-English Windows.





















// ── Failed reads must not look like empty ones ────────────────────────────────────────────────────
//
// A collector that runs its cmdlets under `$ErrorActionPreference='SilentlyContinue'` and then
// null-coerces (`@($fwd.IPAddress)` → `[]`, `[bool]$fwd.UseRootHint` → `false`) cannot tell a *failed
// read* from an *absent setting*, and the zeroed shape reads as a configuration verdict. A read must
// therefore produce its answer or explicitly report failure.





/// Read a child pipe to EOF on its own thread. Both streams must drain while the exit is being polled —
/// a full pipe buffer blocks the child, and a child that never exits is the case being bounded.
#[cfg(windows)]
fn drain_pipe<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}


/// Whether a bounded run finished or hit its ceiling. [`ps_capture`] flattens the two into one failed
/// `Output`, which is right for a compiled-in collector — the ceiling is an "it will never end" guard,
/// not a budget, so there is nothing useful to say beyond that it failed. A backend-hosted collector
/// carries a chosen `timeout_s`, and there the distinction IS the answer: exceeding a number somebody
/// picked says the run was delivered, ran, and outlasted an expectation.
#[cfg(windows)]
enum PsRun {
    Done(std::process::Output),
    TimedOut,
}


/// How a native argv run ended. The sibling of [`PsRun`], carrying the exit CODE rather than a
/// `Output`: a native action's whole result is "did it work", so the code is the answer instead of
/// something to inspect the output for.
#[cfg(windows)]
enum NativeRun {
    Done { code: i32, stdout: String, stderr: String },
    TimedOut,
}





/// Rows from a [`PS_GUARD`] script, or the collector error to return in their place. A distinct type
/// rather than a `Value`, because the list collectors feed their rows straight into `paginate` — and
/// an error object there would `unwrap_or_default()` into an empty page, re-hiding the failure the
/// guard exists to surface. This way the compiler asks every call site what it does with a failure.
#[cfg(windows)]
enum GuardedRows {
    Rows(Vec<Value>),
    Failed(Value),
}





/// Soft byte budget for one paginated diag page, leaving headroom for the wrapper object + pagination
/// metadata.
///
/// The 48 KiB budget leaves substantial headroom under the 256 KiB result cap, where an over-cap
/// result is replaced wholesale with a failure notice. A recursive `fs` read is the collector here
/// that reaches it.
#[cfg(windows)]
const PAGE_BUDGET: usize = 48 * 1024;

/// Take items until either `limit` or [`PAGE_BUDGET`] is reached — the one place the byte budget is
/// applied, so every paging shape (offset, cursor, keyset) cuts at the same size for the same reason.
///
/// ⚠ At least one item always lands. A row wider than the whole budget would otherwise produce an
/// empty page forever: the caller advances past nothing, asks again, and the collector never finishes.
/// One oversized row through is the lesser failure, because the result cap above still clips it.
#[cfg(windows)]
fn page_within_budget<'a>(items: impl Iterator<Item = &'a Value>, limit: usize) -> Vec<Value> {
    let mut page: Vec<Value> = Vec::new();
    let mut used = 0usize;
    for item in items.take(limit) {
        let sz = serde_json::to_string(item).map(|s| s.len() + 1).unwrap_or(0);
        if !page.is_empty() && used + sz > PAGE_BUDGET {
            break;
        }
        used += sz;
        page.push(item.clone());
    }
    page
}



/// The in-band failure a backend-hosted collector returns. The job still reports `done`: it WAS
/// delivered and DID produce an answer, and `status:"error"` means there is no result to read at all.
/// A page that cannot be produced is this, never an empty `items` — an absence and an emptiness are
/// different answers.
#[cfg(windows)]
fn keyset_error(why: &str) -> Value {
    json!({ "ok": false, "error": why })
}

/// Whether a job's params ask for the backend-hosted form rather than the compiled-in collector.
///
/// The discriminator is `exec`, and deliberately nothing else. Params without an executor use the
/// compiled-in collector; the hosted path is selected explicitly by the side that owns the command.
fn keyset_requested(params: Option<&str>) -> bool {
    params
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|p| p.get("exec").and_then(|x| x.as_str()).map(|e| !e.trim().is_empty()))
        .unwrap_or(false)
}

/// The environment variable a hosted command reads its ask out of. See [`ps_capture_within`].
#[cfg(windows)]
const JOB_PARAMS_ENV: &str = "SULLTEC_JOB_PARAMS";

/// The wire fields the executor reads FOR ITSELF, and therefore the ones a command never sees.
///
/// ⚠ Kept in lockstep with the backend's `HOSTED_WIRE_FIELDS`. A field one half reserves and the
/// other does not is either a wire control a script can read as though it were a selector, or a
/// selector the script is never handed.
#[cfg(windows)]
const HOSTED_WIRE_FIELDS: &[&str] = &["exec", "command", "key", "limit", "timeout_s", "after"];

/// What the dispatch ASKED FOR, with the executor's own wire fields taken out — the JSON a hosted
/// command receives as `$Params`.
#[cfg(windows)]
fn hosted_ask(p: &Value) -> String {
    let mut o = p.as_object().cloned().unwrap_or_default();
    for f in HOSTED_WIRE_FIELDS {
        o.remove(*f);
    }
    Value::Object(o).to_string()
}

/// The whole answer to a BOUNDED ask, in one result.
///
/// ⚠ **No cursor, no `more` and no page size, and every absence is deliberate.** A bounded ask is
/// one row or a handful — a member's detail read, not a sweep — so there is nothing to resume from
/// and a caller must not be handed an envelope shaped like one that needs paging. The distinction is
/// the backend's to make and it makes it by sending no `key`: an ask with nothing to sort or hash by
/// is an ask that is complete when it answers.
///
/// ⚠ **The byte budget still applies, and when it bites the answer SAYS SO.** A result that will not
/// fit is not made to fit by being sent, and a short set reported as the whole one is the confident
/// wrong answer this whole module exists to prevent — so a cut answer carries `truncated` and the
/// total it was cut from. Reaching it means the ask was not bounded in practice: narrow it.
#[cfg(windows)]
fn bounded_answer(rows: Vec<Value>, collected_at: i64) -> Value {
    let total = rows.len();
    let items = page_within_budget(rows.iter(), usize::MAX);
    let count = items.len();
    let mut out = json!({
        "ok": true,
        "items": items,
        "count": count,
        "collected_at": collected_at,
    });
    if count < total {
        out["truncated"] = json!(true);
        out["total"] = json!(total);
    }
    out
}

/// A key value as the wire renders it: a number in decimal with no padding, a string as itself.
/// Anything else is not an identity — it can be neither sorted on nor resumed from.
#[cfg(windows)]
fn key_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Run a backend-supplied command through the named executor and return its rows — one keyset PAGE
/// of them for a cycle, the whole answer for a bounded ask.
///
/// The wire contract is `docs/SPEC-keyset-collector-wire.md` in the console repo; neither side may
/// deviate without changing it first.
#[cfg(windows)]
fn keyset_exec(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let exec = p.get("exec").and_then(|x| x.as_str()).unwrap_or("").trim();
    let command = p.get("command").and_then(|x| x.as_str()).unwrap_or("");
    let key = p.get("key").and_then(|x| x.as_str()).unwrap_or("").trim();
    if command.trim().is_empty() {
        return Some(keyset_error("a backend-hosted collector needs a command to run"));
    }
    // `after` is a cursor this device minted on an earlier page, so it arrives as the string that page
    // rendered. A backend reading its own `last` back may spell it as a number; both are accepted
    // rather than failing a cycle over a JSON type.
    let after = p.get("after").and_then(key_text);
    // No `limit` means the byte budget alone governs the page. Zero or negative is not a page size.
    let limit = p
        .get("limit")
        .and_then(as_i64_loose)
        .filter(|n| *n > 0)
        .map(|n| n as usize)
        .unwrap_or(usize::MAX);
    // ⚠ **The KEY is what tells a cycle from a bounded ask, and its absence is a declaration.** A
    // key is what a set is sorted, hashed and resumed by; an ask that names none is one row or a
    // handful, complete when it answers, and wrapping it in a page envelope would hand the caller a
    // cursor for a set with no second page. A cursor or a page size WITHOUT a key is the one
    // combination that means neither, and it is refused rather than silently read as either.
    let paged = !key.is_empty();
    if !paged && (after.is_some() || p.get("limit").is_some()) {
        return Some(keyset_error(
            "a paged collector needs the key field that identifies a row; an ask with a cursor or a \
             page limit and no key is neither a cycle nor a bounded read",
        ));
    }
    // The backend decides how long its own command may take; the client's ceiling stays a CEILING, so
    // a bad declaration cannot talk a device into outrunning the guard that exists to stop a run which
    // is never going to end. Absent, the compiled-in collectors' ceiling applies unchanged.
    let timeout_s = p
        .get("timeout_s")
        .and_then(as_i64_loose)
        .filter(|n| *n > 0)
        .map(|n| (n as u64).min(PS_RUN_CEILING_SECS))
        .unwrap_or(PS_RUN_CEILING_SECS);
    // Stamped when the command starts. A set assembled from N pages is N stamped moments, not one, and
    // a reader comparing two rows has to know which moment each came from.
    let collected_at = now_secs();
    let ask = hosted_ask(&p);

    // ⚠ **The builtin executor returns EARLY, before any of the row machinery.** The other two
    // executors produce rows that get paged or bounded; a builtin produces its own complete answer —
    // `{ok, …}` — because the procedure IS the client's, and re-wrapping it would change a shape the
    // console has always read. Everything below this line is about rows and does not apply.
    if exec == "builtin" {
        return Some(exec_builtin(command, &ask));
    }
    let rows = match exec {
        "powershell" => exec_powershell(command, timeout_s, &ask),
        // This executor is a method rather than a collector: run the backend-supplied argv and
        // report its outcome.
        "native" => exec_native(command, timeout_s, &ask),
        // An executor this client does not have is a REFUSAL. Returning an empty page instead would
        // read as "this machine has nothing", which is the failure the whole guard layer exists for.
        other => Err(keyset_error(&format!("this client has no '{other}' executor"))),
    };
    Some(match rows {
        Err(e) => e,
        Ok(rows) => match paged {
            true => keyset_page(rows, key, after.as_deref(), limit, collected_at),
            false => bounded_answer(rows, collected_at),
        },
    })
}




/// Split a hosted command into argv elements, honouring double quotes.
///
/// ⚠ **Whitespace alone cannot express an argument that contains a space**, and `shutdown /c "…"` is
/// the case that proves it: a plain split turns one comment into seven arguments. Quotes group, and
/// are not themselves passed on — `"a b"` is one element `a b`.
///
/// A `${name}` token is substituted whole, AFTER splitting, so a value containing a space stays one
/// argument and can never introduce another. That is the property the whole argv form exists for:
/// there is no shell, so nothing re-parses what a substitution produced.
#[cfg(windows)]
fn split_argv(command: &str, bound: &Value) -> Result<Vec<String>, Value> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has = false;
    for ch in command.chars() {
        match ch {
            '"' => { quoted = !quoted; has = true; }
            c if c.is_whitespace() && !quoted => {
                if has { out.push(std::mem::take(&mut cur)); has = false; }
            }
            c => { cur.push(c); has = true; }
        }
    }
    if quoted {
        return Err(keyset_error("the hosted command has an unclosed quote"));
    }
    if has { out.push(cur); }
    let mut argv = Vec::with_capacity(out.len());
    for tok in out {
        match tok.strip_prefix("${").and_then(|t| t.strip_suffix('}')) {
            Some(name) => match bound.get(name) {
                Some(Value::String(v)) => argv.push(v.clone()),
                Some(Value::Number(n)) => argv.push(n.to_string()),
                _ => {
                    return Err(keyset_error(&format!(
                        "the hosted command needs '{name}', and the dispatch carried no single                          value for it — running with the argument dropped would be a different                          command from the one that was sent"
                    )))
                }
            },
            None if tok.contains("${") => {
                return Err(keyset_error(&format!(
                    "'{tok}': a substitution must be a whole argument, not part of one"
                )))
            }
            None => argv.push(tok),
        }
    }
    Ok(argv)
}

/// The `builtin` executor: invoke a procedure COMPILED INTO THIS CLIENT, named by the backend.
///
/// This is `run_job`'s match, reached through the same dispatch as the other executors. Seven procedures
/// place here — the agent's own state (`disconnect`, `client-log`, `inventory`), a raw socket
/// (`wol`), byte movement that has to be fast (`file-pull`, `file-push`), and `script`, which is
/// PowerShell text but not a PowerShell invocation. Everything else the backend sends as a script or
/// argv. The verb names the procedure to invoke.
///
/// **The caller's params reach the procedure unchanged**, which is what lets these functions keep
/// their existing signatures. A bare scalar the backend wrapped as `{"ask": …}` is unwrapped back to
/// the scalar; an object ask is handed over as its own JSON. So `wol` still receives a MAC string and
/// `file-push` still receives `{path, content_b64}`.
///
/// **`${name}` substitutes from the ask, exactly as [`exec_native`] does**, for a declaration that
/// wants to name its argument explicitly. Absent, the reconstructed ask is passed — which is the
/// ordinary case, and the reason the seven functions did not have to change.
#[cfg(windows)]
fn exec_builtin(command: &str, ask: &str) -> Value {
    let bound: Value = serde_json::from_str(ask).unwrap_or(Value::Null);
    let argv = match split_argv(command, &bound) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let Some((name, args)) = argv.split_first() else {
        return keyset_error("the hosted procedure is empty");
    };
    // An explicit `${…}` argument wins; otherwise the caller's own params are reconstructed. The
    // unwrap matters: `hosted_params` names a NON-OBJECT ask `ask` so it cannot be dropped on the
    // wire, and a procedure expecting a bare MAC or a bare path must not receive that wrapper.
    let params: Option<String> = match args.first() {
        Some(a) => Some(a.clone()),
        None => match bound.get("ask") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => Some(other.to_string()),
            None if bound.is_object() && bound.as_object().is_some_and(|o| !o.is_empty()) => {
                Some(bound.to_string())
            }
            _ => None,
        },
    };
    let p = params.as_deref();
    match name.as_str() {
        "disconnect" => disconnect_sessions(),
        "wol" => wol(p),
        "file-pull" => file_pull(p),
        "file-push" => file_push(p),
        "script" => run_script(p),
        "client-log" => client_log_pull(p),
        "client-logs" => client_logs_list(),
        "inventory" => inventory::collect(),
        // Native bodies are dispatched by procedure name. Refusals name the first element of the
        // builtin command; `job_answer` names nothing because the caller already identifies the job.
        "perf" => perf(p).unwrap_or_else(|| keyset_error(
            "the 'perf' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "fs" => fs_list(p).unwrap_or_else(|| keyset_error(
            "the 'fs' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "services" => services(),
        // A name this client does not implement is a REFUSAL. Answering an empty result would read
        // as "the machine had nothing", which is the failure the whole guard layer exists for.
        other => keyset_error(&format!("this client has no '{other}' procedure")),
    }
}


/// Sort the whole set, describe it, and cut one page out of it.
#[cfg(windows)]
fn keyset_page(rows: Vec<Value>, key: &str, after: Option<&str>, limit: usize, collected_at: i64) -> Value {
    use hbb_common::sha2::{Digest, Sha256};
    let mut keyed: Vec<(String, Option<i128>, Value)> = Vec::with_capacity(rows.len());
    for row in rows {
        // A row with no key cannot be paged past — `after` would either skip it or return it forever.
        // Dropping it would lose it silently, which is the one outcome worse than failing the page.
        let Some(text) = row.get(key).and_then(key_text) else {
            return keyset_error(&format!("a row has no '{key}' to identify it by"));
        };
        let num = text.trim().parse::<i128>().ok();
        keyed.push((text, num, row));
    }
    // ⚠ The wire renders a key as a STRING, and a lexical sort puts pid 10 ahead of pid 9 — after
    // which `after:"9"` skips every pid from 10 to 99. So the ordering is decided ONCE for the set:
    // numeric when every key parses as an integer, lexical otherwise. Per-comparison fallback is not
    // even a total order on a mixed set, and any sort that disagrees with the cursor comparison loses
    // rows at the seam. An empty set is lexical; there is nothing to infer an ordering from.
    let numeric = !keyed.is_empty() && keyed.iter().all(|(_, n, _)| n.is_some());
    match numeric {
        true => keyed.sort_by_key(|(_, n, _)| n.unwrap_or(i128::MIN)),
        false => keyed.sort_by(|a, b| a.0.cmp(&b.0)),
    }
    // ⚠ Duplicate keys are not papered over, because the executor cannot: `after` is exclusive, so a
    // second row sharing a key is skipped along with the first. That is a bug in the command — the
    // field it declared is not an identity — and inventing a tiebreak here would bury it under a set
    // that quietly loses one row per collision.
    let total = keyed.len();
    // Keys only, never row content. A process list's CPU and memory are MEANT to move between pages;
    // hashing them would report drift on every cycle and restart it forever, chasing readings that are
    // supposed to change. This answers "is this the same set of things", which is the only question a
    // seam can be corrupted by.
    let mut h = Sha256::new();
    for (i, (text, _, _)) in keyed.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(text.as_bytes());
    }
    let set_hash = format!("{:x}", h.finalize());
    // The cursor is compared the way the sort ordered, against the same rendering `last` uses — so a
    // `last` fed back as `after` always resumes exactly at the row it named.
    let after_num = match (numeric, after) {
        (true, Some(a)) => match a.trim().parse::<i128>() {
            Ok(n) => Some(n),
            // Only reachable when the cursor did not come from a `last` this collector emitted.
            Err(_) => return keyset_error(&format!("the cursor '{a}' is not a key this set sorts by")),
        },
        _ => None,
    };
    let keep = |text: &str, num: Option<i128>| match (after, after_num) {
        (None, _) => true,
        (Some(_), Some(a)) => num.is_some_and(|n| n > a),
        (Some(a), None) => text > a,
    };
    let rest: Vec<&(String, Option<i128>, Value)> = keyed.iter().filter(|t| keep(&t.0, t.1)).collect();
    let page = page_within_budget(rest.iter().map(|t| &t.2), limit);
    // ⚠ `more` is whether rows remain after the last one emitted — NOT `count == limit`. The byte
    // budget can cut a page short of its limit, and a backend inferring completion from the count
    // would stop mid-set and record it as complete.
    let count = page.len();
    let more = rest.len() > count;
    let last = count.checked_sub(1).map(|i| rest[i].0.clone());
    let mut out = json!({
        "ok": true,
        "items": page,
        "count": count,
        "more": more,
        "total": total,
        "set_hash": set_hash,
        "collected_at": collected_at,
    });
    if let Some(last) = last {
        out["last"] = json!(last);
    }
    out
}

#[cfg(not(windows))]
fn keyset_exec(_params: Option<&str>) -> Option<Value> {
    None
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
    // Job results carry collector output up to `store::MAX_JOB_RESULT` (256 KiB), so they use the bulk
    // transport budget rather than the heartbeat budget.
    // `Ok` is NOT success. `post_request_timeout` collapses (status, text) to the text, so a 401, a
    // 404 and a 409 all arrive here as `Ok("")` — indistinguishable from a stored result, and every
    // one of them was logged as "result posted" while the row stayed queued and the job was run
    // again 300 s later. The console answers a settled row with an explicit marker; anything else is
    // a refusal. Same shape the snapshot path already uses for `SNAPSHOT_UPDATED`.
    match crate::post_request_timeout(url, body, "", crate::sulltec_remote::http::API_TIMEOUT_DATA).await {
        Ok(rsp) if rsp.trim() == "JOB_SETTLED" => {
            hbb_common::log::info!("console job {job_id} result posted ({status})")
        }
        Ok(rsp) => hbb_common::log::error!(
            "console job {job_id} result REFUSED by the console ({status}) — the job is still open \
             and will be retried. Response: {:?}",
            rsp.chars().take(200).collect::<String>()
        ),
        Err(e) => hbb_common::log::error!("console job {job_id} result post failed: {e}"),
    }
}


#[cfg(test)]
mod logon_chain_tests {
    use super::{resolve_trusted, variant};
    use hbb_common::sodiumoxide::{base64, crypto::sign};
    use serde_json::{json, Value};

    fn kp() -> (String, sign::SecretKey) {
        let (pk, sk) = sign::gen_keypair();
        (base64::encode(pk.as_ref(), variant()), sk)
    }
    // Attached sig over `CONSOLE-LOGON-ROTATE\n{new_pub}` by `sk` — what the backend's rotate emits.
    fn hop(sk: &sign::SecretKey, new_pub: &str) -> String {
        let msg = format!("CONSOLE-LOGON-ROTATE\n{new_pub}");
        // sign::sign returns Vec<u8> (the attached blob); pass it directly — `Vec::as_ref` is
        // ambiguous (AsRef<[u8]> vs AsRef<Vec<u8>>), unlike production's `Signature` newtype.
        base64::encode(sign::sign(msg.as_bytes(), sk), variant())
    }
    fn e(p: &str, s: &str) -> Value {
        json!({ "pub": p, "sig": s })
    }

    #[test]
    fn walk_floor_and_anchor_reset() {
        let (g, g_sk) = kp(); // genesis
        let (k1, k1_sk) = kp();
        let (k2, _k2_sk) = kp();
        let s1 = hop(&g_sk, &k1); // genesis signs k1
        let s2 = hop(&k1_sk, &k2); // k1 signs k2
        let full = vec![e(&g, ""), e(&k1, &s1), e(&k2, &s2)];

        // forward walk, no floor → reaches k2
        assert_eq!(resolve_trusted(&g, &full, None), k2);
        // floor at k1 (same anchor) → still forward to k2
        assert_eq!(resolve_trusted(&g, &full, Some((g.as_str(), k1.as_str()))), k2);

        // REPLAY of a shorter chain [genesis,k1] while floor is k2 → must NOT regress (hold k2)
        let replay = vec![e(&g, ""), e(&k1, &s1)];
        assert_eq!(resolve_trusted(&g, &replay, Some((g.as_str(), k2.as_str()))), k2);

        // baked anchor changed since the floor was stored → discard floor, walk from the new anchor
        assert_eq!(resolve_trusted(&g, &full, Some(("OTHER-ANCHOR", k2.as_str()))), k2);

        // a hop with the WRONG signature (k2 "signed" by genesis, not k1) stops the walk at k1
        let bad = hop(&g_sk, &k2);
        let broken = vec![e(&g, ""), e(&k1, &s1), e(&k2, &bad)];
        assert_eq!(resolve_trusted(&g, &broken, None), k1);

        // anchor absent from the chain, no floor → keep the baked anchor
        assert_eq!(resolve_trusted("UNSEEN", &full, None), "UNSEEN");
    }
}

#[cfg(test)]
mod package_verify_tests {
    // `verify_package` accepts signatures under the current trusted logon key and rejects tampered
    // tuples, empty components, and signatures from any other key. Verifying only against the
    // current key preserves key revocation.
    use super::{variant, verify_package, LOGON_TRUSTED};
    use hbb_common::sodiumoxide::{base64, crypto::sign};

    fn sign_pkg(sk: &sign::SecretKey, version: &str, sha: &str, size: u64) -> String {
        let msg = format!("CONSOLE-PKG\n{version}\n{sha}\n{size}");
        base64::encode(sign::sign(msg.as_bytes(), sk), variant())
    }

    #[test]
    fn verify_package_accepts_current_key_and_rejects_others() {
        let (pk, sk) = sign::gen_keypair();
        let pub_b64 = base64::encode(pk.as_ref(), variant());
        *LOGON_TRUSTED.write().unwrap() = Some(pub_b64);

        let version = "0.26.0+003.20260722-000000.abc";
        let sha = "a".repeat(64);
        let size = 1234u64;
        let sig = sign_pkg(&sk, version, &sha, size);

        // The correct tuple under the current key verifies.
        assert!(verify_package(version, &sha, size, &sig));
        // Tampered version / sha / size fail.
        assert!(!verify_package("0.27.0", &sha, size, &sig));
        assert!(!verify_package(version, &"b".repeat(64), size, &sig));
        assert!(!verify_package(version, &sha, size + 1, &sig));
        // Any empty component is a hard verify-fail.
        assert!(!verify_package("", &sha, size, &sig));
        assert!(!verify_package(version, "", size, &sig));
        assert!(!verify_package(version, &sha, 0, &sig));
        assert!(!verify_package(version, &sha, size, ""));
        // A signature under a DIFFERENT key (rotated-out / attacker) is refused.
        let (_pk2, sk2) = sign::gen_keypair();
        let sig2 = sign_pkg(&sk2, version, &sha, size);
        assert!(!verify_package(version, &sha, size, &sig2));

        *LOGON_TRUSTED.write().unwrap() = None;
    }
}








#[cfg(test)]
mod script_lint_tests {
    //! A source lint for PowerShell comments inside continued Rust string literals.
    //!
    //! The collector scripts are built as ONE LINE: every line of the Rust literal ends with `\`,
    //! which removes the newline. A PowerShell `#` comment runs to the next newline — so a comment
    //! written with that trailing continuation swallows the entire rest of the script, and the
    //! collector dies with "Missing closing '}'" at runtime. Write the comment without the trailing
    //! backslash so a real newline survives.

    #[test]
    fn no_powershell_comment_swallows_its_script() {
        let src = include_str!("jobs.rs");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                let e = l.trim_end();
                // A PowerShell comment inside a script literal, continued into the next line.
                //
                // The trailing `\` is Rust's line-continuation: it removes the newline, so whatever
                // follows lands INSIDE the comment. Unless the string supplies one itself — `…\n\`
                // ends the comment explicitly and is the normal way to lay out a multi-line script
                // literal here. Only a BARE `\` is the bug, and treating both alike would ban the
                // safe form everywhere it is already correctly used.
                t.starts_with("# ") && e.ends_with('\\') && !e.ends_with("\\n\\")
            })
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "PowerShell comment(s) ending in a line-continuation — the comment will swallow the rest \
             of the one-line script. Drop the trailing backslash so the newline survives:\n{offenders:#?}"
        );

        // Pin the distinction between a bare continuation and a string-supplied newline.
        let flags = |l: &str| {
            let (t, e) = (l.trim_start(), l.trim_end());
            t.starts_with("# ") && e.ends_with('\\') && !e.ends_with("\\n\\")
        };
        assert!(flags(r"         # this swallows the next line\"), "a bare trailing continuation MUST be flagged");
        assert!(!flags(r"         # this is fine\n\"), "an explicit \\n before the continuation is safe and must NOT be flagged");
    }
}

/// The destination counters must come from `BackendStatistics`, and nothing else.

#[cfg(all(test, windows))]
mod ps_json_null_tests {
    use super::ps_json_or_none;
    use serde_json::json;

    /// JSON `null` is NO DATA. `ConvertTo-Json` renders `$null` as the literal `null`, serde parses
    /// it to `Some(Value::Null)`, and that slips past every `unwrap_or_else(|| error)` a caller
    /// wrote — those fire only on `None`. On the wire it becomes `result: null` beside
    /// `status:"done"` with no error, incorrectly reporting that the collector found nothing.
    #[test]
    fn json_null_is_not_a_value() {
        assert_eq!(ps_json_or_none(json!(null)), None);
    }

    /// Everything else passes through — including the shapes that LOOK empty but are real answers.
    /// An empty object or array is a collector that ran and found nothing, which is data.
    #[test]
    fn every_other_shape_survives() {
        for v in [json!({}), json!([]), json!({"ok": false, "error": "x"}), json!(0), json!(false), json!("")] {
            assert_eq!(ps_json_or_none(v.clone()), Some(v.clone()), "{v} must not be swallowed");
        }
    }
}


/// The two gpresult parsers live in PowerShell, so what is pinned here is the SHAPE of the guard —
/// that both of them skip the `Filtering:` annotation rather than filing it as a denied GPO.




#[cfg(test)]
#[cfg(windows)]
mod main_log_tests {
    use super::client_log::main_log;

    fn stage(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("stmainlog_{tag}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).ok();
        dir
    }

    /// A top-level compatibility log with the newest mtime must not outrank the service's own log.
    #[test]
    fn the_service_log_wins_over_a_newer_top_level_relic() {
        let dir = stage("relic");
        std::fs::create_dir_all(dir.join("server")).ok();
        std::fs::write(dir.join("server").join("SullTecRemote_rCURRENT.log"), b"current").ok();
        std::fs::write(dir.join("sulltec-remote_rCURRENT.log"), b"june relic").ok();
        let got = main_log(&dir).expect("a log");
        assert_eq!(got.parent().and_then(|p| p.file_name()), Some("server".as_ref()));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The top-level compatibility location resolves when no server-subdirectory log exists.
    #[test]
    fn a_top_level_log_is_still_found_when_there_is_no_server_dir() {
        let dir = stage("legacy");
        std::fs::write(dir.join("sulltec-remote_rCURRENT.log"), b"old layout").ok();
        assert_eq!(main_log(&dir).and_then(|p| p.file_name().map(|f| f.to_owned())),
                   Some("sulltec-remote_rCURRENT.log".into()));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Neither a server dir nor a top-level log: rather than report nothing, fall through to
    /// whatever component HAS logged. Returning None here would read as "this client has no logs".
    #[test]
    fn some_other_component_is_better_than_nothing() {
        let dir = stage("fallback");
        std::fs::create_dir_all(dir.join("update")).ok();
        std::fs::write(dir.join("update").join("sulltecremote_rCURRENT.log"), b"update").ok();
        assert_eq!(main_log(&dir).and_then(|p| p.parent().and_then(|q| q.file_name()).map(|f| f.to_owned())),
                   Some("update".into()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_log_dir_yields_none() {
        let dir = stage("empty");
        assert!(main_log(&dir).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(all(test, windows))]
mod keyset_wire_tests {
    //! Keyset-envelope wire-contract tests. The backend stops on `more`, resumes on `last`, and uses
    //! `set_hash` to detect set changes; these tests keep those properties independent of executors.
    use super::{bounded_answer, key_text, keyset_exec, keyset_page, keyset_requested, PAGE_BUDGET};
    use serde_json::{json, Value};

    fn rows(pids: &[i64]) -> Vec<Value> {
        pids.iter().map(|p| json!({ "pid": p, "name": format!("p{p}") })).collect()
    }
    fn keys(page: &Value) -> Vec<i64> {
        page["items"].as_array().expect("items").iter().map(|r| r["pid"].as_i64().expect("pid")).collect()
    }

    /// Rendered as strings, "10" sorts before "9", so a
    /// lexical sort followed by `after:"9"` skips every pid from 10 to 99 — a hole in the middle of the
    /// set rather than a visible failure.
    #[test]
    fn a_numeric_key_sorts_and_resumes_numerically() {
        let page = keyset_page(rows(&[10, 9, 100, 2]), "pid", None, 10, 0);
        assert_eq!(keys(&page), vec![2, 9, 10, 100], "sorted numerically: {page}");
        assert_eq!(page["last"], json!("100"), "last is the final key, rendered: {page}");
        let after_9 = keyset_page(rows(&[10, 9, 100, 2]), "pid", Some("9"), 10, 0);
        assert_eq!(keys(&after_9), vec![10, 100], "after is exclusive AND numeric: {after_9}");
    }

    /// A set whose keys are not numeric orders lexically — the fallback has to exist for service names,
    /// thumbprints and rule ids, and it has to be the SAME order the cursor compares in.
    #[test]
    fn a_text_key_sorts_and_resumes_lexically() {
        let set: Vec<Value> = ["spooler", "audiosrv", "bits"].iter().map(|n| json!({ "name": n })).collect();
        let page = keyset_page(set.clone(), "name", None, 10, 0);
        let got: Vec<&str> =
            page["items"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert_eq!(got, vec!["audiosrv", "bits", "spooler"], "{page}");
        let next = keyset_page(set, "name", Some("bits"), 10, 0);
        assert_eq!(next["count"], json!(1), "{next}");
        assert_eq!(next["items"][0]["name"], json!("spooler"), "{next}");
    }

    /// `more` is "rows remain after `last`", not "the page filled its limit". The byte budget can cut a
    /// page short, and a backend reading `count < limit` as completion would stop mid-set and record it
    /// as complete.
    #[test]
    fn more_survives_a_page_the_byte_budget_cut_short() {
        let wide: Vec<Value> = (1..=200).map(|p| json!({ "pid": p, "blob": "x".repeat(2000) })).collect();
        let page = keyset_page(wide, "pid", None, 200, 0);
        let count = page["count"].as_u64().expect("count");
        assert!(count < 200, "the budget must have cut this page short: {count}");
        assert!(count > 0, "a budget-cut page still carries rows");
        assert_eq!(page["more"], json!(true), "rows remain, so more is true even though count < limit");
        assert_eq!(page["total"], json!(200), "total is the WHOLE set, not the page");
        assert!(serde_json::to_string(&page["items"]).unwrap().len() < PAGE_BUDGET + 4096);
    }

    /// The seam. Feeding `last` back as `after` must lose nothing and repeat nothing — the failure
    /// keyset paging exists to prevent, and the one an offset cursor cannot avoid.
    #[test]
    fn paging_the_whole_set_by_last_loses_and_repeats_nothing() {
        let all: Vec<i64> = (1..=25).collect();
        let mut seen: Vec<i64> = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = keyset_page(rows(&all), "pid", after.as_deref(), 7, 0);
            seen.extend(keys(&page));
            if page["more"] != json!(true) {
                break;
            }
            after = Some(page["last"].as_str().expect("more implies last").to_owned());
        }
        assert_eq!(seen, all, "every row exactly once, in key order");
    }

    /// The hash answers "is this the same set of things", never "is this the same state of things".
    /// Hashing row content would make a process list drift on every cycle and restart it forever,
    /// chasing a CPU percentage that is MEANT to move.
    #[test]
    fn the_set_hash_covers_keys_only() {
        let a = keyset_page(vec![json!({ "pid": 1, "cpu": 11 }), json!({ "pid": 2, "cpu": 4 })], "pid", None, 10, 0);
        let b = keyset_page(vec![json!({ "pid": 1, "cpu": 93 }), json!({ "pid": 2, "cpu": 0 })], "pid", None, 10, 0);
        assert_eq!(a["set_hash"], b["set_hash"], "same membership, moved readings — same hash");
        let c = keyset_page(vec![json!({ "pid": 1, "cpu": 11 }), json!({ "pid": 3, "cpu": 4 })], "pid", None, 10, 0);
        assert_ne!(a["set_hash"], c["set_hash"], "membership changed — the hash must say so");
        let h = a["set_hash"].as_str().expect("set_hash");
        assert_eq!(h.len(), 64, "sha-256, lowercase hex: {h}");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{h}");
    }

    /// A page that cannot be produced is `ok:false`, never an empty `items` — an absence and an
    /// emptiness are different answers, and a row with no identity cannot be paged past at all.
    #[test]
    fn a_row_without_the_key_fails_the_page_rather_than_vanishing() {
        let page = keyset_page(vec![json!({ "pid": 1 }), json!({ "name": "orphan" })], "pid", None, 10, 0);
        assert_eq!(page["ok"], json!(false), "{page}");
        assert!(page["error"].as_str().is_some_and(|e| e.contains("pid")), "and it names the key: {page}");
    }

    /// An empty command result is a real answer: a complete set of nothing, not a failure.
    #[test]
    fn an_empty_set_is_ok_and_complete() {
        let page = keyset_page(Vec::new(), "pid", None, 10, 0);
        assert_eq!(page["ok"], json!(true), "{page}");
        assert_eq!(page["count"], json!(0), "{page}");
        assert_eq!(page["total"], json!(0), "{page}");
        assert_eq!(page["more"], json!(false), "{page}");
        assert!(page.get("last").is_none(), "nothing to resume from: {page}");
    }

    /// `exec` is the only discriminator; params without it use the compiled-in collector.
    #[test]
    fn only_a_non_empty_exec_selects_the_hosted_path() {
        assert!(!keyset_requested(None));
        assert!(!keyset_requested(Some("{}")));
        assert!(!keyset_requested(Some(r#"{"limit":500}"#)), "the old params must still fall through");
        assert!(!keyset_requested(Some(r#"{"exec":"  "}"#)));
        assert!(!keyset_requested(Some("not json")));
        assert!(keyset_requested(Some(r#"{"exec":"powershell","command":"x","key":"pid"}"#)));
    }

    /// An executor this client does not have refuses out loud — the field exists precisely so `cmd`,
    /// `wmi` and `registry` can arrive on the wire before the arm that runs them does.
    #[test]
    fn an_unknown_executor_and_a_missing_param_both_refuse() {
        let v = keyset_exec(Some(r#"{"exec":"wmi","command":"select * from x","key":"id"}"#)).expect("a result");
        assert_eq!(v["ok"], json!(false), "{v}");
        assert!(v["error"].as_str().is_some_and(|e| e.contains("wmi")), "{v}");
        let no_cmd = keyset_exec(Some(r#"{"exec":"powershell","key":"pid"}"#)).expect("a result");
        assert_eq!(no_cmd["ok"], json!(false), "{no_cmd}");
        // A cursor or a page size with no key is neither a cycle nor a bounded read. Refused rather
        // than resolved either way: guessing "cycle" pages a set with nothing to sort it by, and
        // guessing "bounded" answers the first result to an ask that was told to resume.
        for contradiction in [
            r#"{"exec":"powershell","command":"x","after":"9"}"#,
            r#"{"exec":"powershell","command":"x","limit":10}"#,
        ] {
            let v = keyset_exec(Some(contradiction)).expect("a result");
            assert_eq!(v["ok"], json!(false), "{v}");
            assert!(v["error"].as_str().is_some_and(|e| e.contains("key")), "{v}");
        }
    }

    /// A BOUNDED ask answers whole, and nothing in its envelope invites a caller to page it.
    ///
    /// ⚠ The property `{pid}` rests on: a member's detail read is one row with no continuation, so a
    /// `more`/`last` pair here would send a caller looking for a second page that will never exist —
    /// and a `set_hash` would invite a drift comparison against a set of one.
    #[test]
    fn a_bounded_ask_answers_whole_and_offers_no_continuation() {
        let page = bounded_answer(rows(&[900]), 1234);
        assert_eq!(page["ok"], json!(true), "{page}");
        assert_eq!(keys(&page), vec![900], "{page}");
        assert_eq!(page["count"], json!(1), "{page}");
        assert_eq!(page["collected_at"], json!(1234), "{page}");
        for absent in ["more", "last", "set_hash", "total", "truncated"] {
            assert!(page.get(absent).is_none(), "a bounded answer states no `{absent}`: {page}");
        }
        // ⚠ And the byte budget, which still applies, is DECLARED when it bites — a short answer
        // reported as the whole one is the failure the envelope exists to make impossible.
        let wide: Vec<Value> =
            (1..=200).map(|p| json!({ "pid": p, "blob": "x".repeat(2000) })).collect();
        let cut = bounded_answer(wide, 0);
        assert_eq!(cut["truncated"], json!(true), "{cut}");
        assert_eq!(cut["total"], json!(200), "{cut}");
        assert!(cut["count"].as_u64().is_some_and(|n| n > 0 && n < 200), "{cut}");
    }

    /// The cursor and the sort share one rendering, which is what lets `last` be fed straight back.
    #[test]
    fn a_key_renders_the_way_the_cursor_spells_it() {
        assert_eq!(key_text(&json!(1234)), Some("1234".to_owned()));
        assert_eq!(key_text(&json!("spooler")), Some("spooler".to_owned()));
        assert_eq!(key_text(&json!(null)), None, "null is not an identity");
        assert_eq!(key_text(&json!([1])), None, "nor is a list");
    }
}

/// Run a PowerShell script that emits `ConvertTo-Json` and return the parsed value **as-is** (object
/// OR array) — for the object-shaped read models (Defender status, Windows-update lists) that
/// `ps_json_array` would wrongly flatten. The caller bounds size at collection time (e.g.
/// `Select-Object -First N`). `None` off-Windows or on any launch/parse failure.
///
/// ⚠ **`None` here means the read FAILED — a caller must never let it reach the wire.** This runner
/// is unguarded, so it cannot distinguish a script that died from one that legitimately produced
/// nothing; either way the output is unparseable, and a collector that returns bare `None` sends
/// `result: null` beside `status:"done"` with no error. Convert it with
/// `.or_else(|| Some(json!({ "ok": false, "error": … })))` or use
/// [`ps_json_guarded`] / [`ps_rows_guarded`], which carry the guard and do this for you.
#[cfg(windows)]
pub(crate) fn ps_json(script: &str) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let v: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).ok()?;
    ps_json_or_none(v)
}

#[cfg(not(windows))]
pub(crate) fn ps_json(_script: &str) -> Option<Value> {
    None
}

/// A parsed PowerShell result, unless it is JSON `null` — in which case the read produced NO DATA and
/// must be reported as a failure, not as a value.
///
/// `ConvertTo-Json` renders `$null` as the literal `null`, which `serde_json` parses happily into
/// `Some(Value::Null)`. That slips past every `unwrap_or_else(|| error)` a caller wrote — those only
/// fire on `None` — and lands on the wire as `result: null` beside `status:"done"` with no error,
/// incorrectly presenting missing data as success.
///
/// Collapsing it to `None` here means the existing failure substitution in every caller starts
/// working for this case too, rather than each one needing its own null check.
#[cfg(windows)]
fn ps_json_or_none(v: Value) -> Option<Value> {
    match v.is_null() {
        true => None,
        false => Some(v),
    }
}

/// `service-name (lowercase) → start type` from `HKLM\SYSTEM\CurrentControlSet\Services`.
/// The SCM enumeration gives live state but not the configured start type; the registry
/// has it without a per-service SCM query.
#[cfg(windows)]
pub(crate) fn service_start_types() -> std::collections::HashMap<String, String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let mut map = std::collections::HashMap::new();
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ)
    else {
        return map;
    };
    for name in root.enum_keys().flatten() {
        if let Ok(svc) = root.open_subkey_with_flags(&name, KEY_READ) {
            // `Start`: 0 boot, 1 system, 2 auto, 3 manual (demand), 4 disabled.
            if let Ok(start) = svc.get_value::<u32, _>("Start") {
                let delayed = svc.get_value::<u32, _>("DelayedAutostart").unwrap_or(0) == 1;
                // A start TRIGGER is the other thing .NET's ServiceStartMode cannot express. Windows
                // starts such a service on demand and lets it idle back to Stopped, so an automatic
                // service sitting Stopped is its designed state, not a failure. Presence of the
                // subkey is the signal; its contents
                // (which trigger) do not change the conclusion.
                let triggered = svc.open_subkey_with_flags("TriggerInfo", KEY_READ).is_ok();
                let label = match (start, delayed, triggered) {
                    (0, _, _) => "boot",
                    (1, _, _) => "system",
                    (2, true, true) => "automatic (delayed, trigger start)",
                    (2, true, false) => "automatic (delayed)",
                    (2, false, true) => "automatic (trigger start)",
                    (2, false, false) => "automatic",
                    (3, _, _) => "manual",
                    (4, _, _) => "disabled",
                    _ => "",
                };
                if !label.is_empty() {
                    map.insert(name.to_lowercase(), label.to_owned());
                }
            }
        }
    }
    map
}

/// Wall-clock ceiling on a hosted run.
///
/// Despite its `PS_` prefix, this limits both hosted executors and the timeout clamp in this file.
///
/// **Not a budget.** It is deliberately far above anything legitimate, so reaching it means the run
/// is never going to end rather than merely slow. An hour remains well inside the console's 24-hour
/// expiry, so the device reports the timeout before the job expires.
///
/// What it buys is the difference between a job that reports a failure and one that holds its
/// in-flight slot, a blocking thread and a child process for the life of the process. It is NOT a
/// per-kind timeout, and the runner behind action kinds is
/// deliberately left unbounded, because `update-install` drives `IUpdateInstaller.Install()`
/// synchronously and its runtime is set by the machine's patch backlog.
const PS_RUN_CEILING_SECS: u64 = 3600;

/// How long to wait for the output pipes after the child has already exited. Normally instant — the
/// readers drain concurrently and EOF arrives with the exit — so this only ever elapses when a
/// descendant inherited a pipe and is still holding it. ⚠ Shared: `run_argv_within` drains on the
/// same grace period, which is the other half of why this is not in `command_powershell`.
const PS_DRAIN_GRACE_SECS: u64 = 30;
