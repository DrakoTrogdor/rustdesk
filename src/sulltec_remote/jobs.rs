//! Client-native job channel (EXTENSION-PLAN D). The patched client:
//!   1. enrolls an Ed25519 public key (trust-on-first-use) so the console can verify its results;
//!   2. receives queued jobs in the `/api/heartbeat` response (`{"jobs":[{id,kind,params}, …]}`),
//!      carrying a console signature (`jobs_sig`/`jobs_ts`) it verifies before running anything;
//!   3. runs the job natively and POSTs a **signed** result to `/api/client/jobs/{id}/result` — the
//!      signature covers `device_id\njob_id\nstatus\nresult`.
//!
//! Two signatures, both anchored on the console logon key:
//!   * Egress (result / sensitive-param fetch) is signed by THIS device's pinned key, so the server
//!     trusts what the client posts — replacing the retired `CONSOLE_AGENT_TOKEN` + `jobs.ps1` path.
//!   * Ingress (the dispatch itself) is signed by the CONSOLE and verified here (`verify_jobs`)
//!     before dispatch, so a forged/unauthenticated heartbeat can't run a job. Both read-only kinds
//!     (inventory / processes / services) and action kinds (reboot, service control, script, …)
//!     dispatch through `run_job`; the action kinds rode unverified before this signature gate.

use hbb_common::config::{self, Config, LocalConfig};
use hbb_common::sodiumoxide::{base64, crypto::sign};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::RwLock;

/// Name of the base64 Ed25519 ingest-signing secret (seed‖pub) — used both as the machine-wide file
/// name and the legacy per-user `LocalConfig` option. Stored machine-wide (see `keypair`) so every
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
/// The secret is stored **machine-wide** (a file under `%ProgramData%\<app>\` on Windows) rather than
/// in per-user `LocalConfig`, so every context on the box — the SYSTEM service AND any interactive
/// user instance — signs ingest with the SAME key. With a per-user key each context had its own and
/// the console (trust-on-first-use) pinned one then rejected the rest forever ("key doesn't match the
/// pinned one" churn until an operator reset the device key). Resolution order:
///   1. the machine-wide file (the shared key);
///   2. else an existing per-user `LocalConfig` key — **migrated** into the machine-wide file, so a
///      device that was already enrolled keeps its pinned identity (no fleet-wide re-pin/reset);
///   3. else a freshly generated key.
/// The chosen key is mirrored back to `LocalConfig` as a fallback for a context that can't yet read
/// the file (e.g. a user instance before the service has written it). Off Windows the ingest runs in
/// a single context, so `machine_key_path` is `None` and this stays per-user (unchanged behaviour).
fn keypair() -> (sign::PublicKey, sign::SecretKey) {
    static SK_BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = SK_BYTES.get_or_init(resolve_key_bytes);
    // `resolve_key_bytes` only ever yields a valid 64-byte secret (`seed[32] ‖ pubkey[32]`), so the
    // trailing 32 bytes are the public key.
    let sk = sign::SecretKey::from_slice(bytes).expect("resolved console-job key is a valid ed25519 secret");
    let pk = sign::PublicKey::from_slice(&sk.as_ref()[32..]).expect("an ed25519 secret embeds its public key");
    (pk, sk)
}

/// Resolve the signing secret's raw bytes (machine-wide file → migrated per-user key → freshly
/// minted), persisting it machine-wide (+ per-user fallback) as a side effect. Always valid.
fn resolve_key_bytes() -> Vec<u8> {
    let valid = |b: &Vec<u8>| sign::SecretKey::from_slice(b).is_some();
    if let Some(b) = read_machine_key_bytes().filter(valid) {
        return b;
    }
    // No shared key yet: adopt the existing per-user key (migration — keeps an already-pinned device
    // pinned) when valid, else mint a fresh one.
    let bytes = local_key_bytes()
        .filter(valid)
        .unwrap_or_else(|| sign::gen_keypair().1.as_ref().to_vec());
    write_machine_key_bytes(&bytes);
    LocalConfig::set_option(KEY_OPT.to_owned(), base64::encode(&bytes, variant()));
    bytes
}

/// The per-user `LocalConfig` copy of the signing secret (legacy / cross-context fallback location).
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

/// D1-d: ask the console to sign `CONSOLE-LOGON\n{device_id}\n{challenge}` for this connection — the
/// console's PRIVATE key never leaves it. Authenticated with the operator's token; the console
/// authorizes the operator for this device, signs, audits, and returns the attached signature.
/// Returns the raw signature bytes, or empty on any failure (→ caller falls back to the password flow).
pub async fn fetch_logon_grant(console_url: &str, token: &str, device_id: &str, challenge: &str) -> Vec<u8> {
    // The device is named by the ADDRESS, so the body carries only the challenge. The console
    // resolves the id through the rows the caller can already see, which is what authorizes this.
    //
    // ⚠ A console older than this address answers 404, and `post_request` hands any status back as
    // `Ok`, so the parse below yields an empty signature and the connection falls through to the
    // password flow. That is the same degradation as any other grant failure — quiet, and not a
    // broken connect — but it is the reason the predecessor is still mounted rather than withdrawn.
    let url = format!(
        "{}/api/devices/{}/common/logon/issue",
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

// ── Signed update channel (H6) ────────────────────────────────────────────────────────────────
// See docs/plans_completed/PLAN-H6-signed-update-channel.md.

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
/// rotation revokes a compromised key (the backend re-signs hosted packages under the current key
/// on rotation — see the plan §7). Any empty component is a hard fail. Mirrors `verify_rotate` and
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
/// floor is compile-time (`ST_UPDATE_ENFORCE=1` in a future enforce build; unset = observe here).
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

    // SullTec (H6): the signed `update.require_sig` key arms the sticky signed-update enforce latch
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
/// Ask the console for this device's queued jobs, over a SIGNED request, and run what comes back.
///
/// ⚠ **The params arrive WITH the job, which is the whole point of polling.** Jobs used to be handed
/// down on the heartbeat — an unauthenticated listener — so anything a caller must not see had to be
/// withheld and fetched afterwards per job. Once the backend began hosting the command text that
/// meant every job cost two round trips and depended on a kind list kept in step across two
/// repositories; a kind missing from ours meant we ran with no params at all, and the failure looked
/// like a malformed request rather than a delivery problem. Proving who we are first removes both.
///
/// [`run`] is unchanged beneath this: the console still signs the dispatch, we still verify it, and
/// `JOBS_ENFORCE` still decides what an unverifiable one means.
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
    // Data plane: the RESPONSE now carries every queued job's params — a `file-push` or `deploy`
    // payload is the bulk case — so this takes the data timeout rather than the control one.
    let rsp = crate::post_request_timeout(url, body, "", crate::sulltec_remote::http::API_TIMEOUT_DATA)
        .await
        .ok()?;
    serde_json::from_str::<Value>(&rsp).ok()
}

/// The scheme+host of the heartbeat URL, so a sibling endpoint can be addressed without assuming
/// where in the path `heartbeat` sits. The retired params fetch did this by string-replacing
/// `heartbeat`, which only works while the two share a prefix — they no longer do.
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
        // Absent for a dispatch minted by a legacy kind-name surface, which has no verb to name.
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
/// what runs. `Absent` when no signature rode the beat (old/stock backend → observe).
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
/// Release builds set `panic = 'abort'`, so a panic goes to stderr and aborts — and a Windows service
/// has no stderr, so the message is simply lost. All that reaches anyone is a WER entry with
/// exception `0xc0000409` and a fault offset that always resolves to `__rust_abort`, because every
/// panic funnels through the same address. That is how a collector that panicked on one machine went
/// a full day undiagnosed: the client aborted every ~40 s and never once said why.
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
/// Split from [`JOBS_FRESH_SECS`], which is the dispatch-signature anti-replay window and must keep
/// mirroring the backend's ±300 s check. One constant was serving both, so neither could be tuned.
const JOBS_SEEN_TTL_SECS: i64 = 300;

/// How many times this device will start the same job id when no result ever lands.
///
/// The backend re-delivers a job until a result settles it, and a job that KILLS the client can never
/// send one — so without a cap the two mechanisms form a loop that survives every restart. That is
/// not hypothetical: a `reg-read` of `HKLM:\SOFTWARE\Classes\Interface` panicked this client, and
/// because `panic = 'abort'` takes the process with it, the job stayed queued and was relaunched
/// roughly every 40 s for a day, making the machine unusable for remote sessions.
const JOB_MAX_ATTEMPTS: i64 = 3;

/// How long an abandoned job id is remembered. Long, deliberately: forgetting it is precisely how the
/// loop restarts, so this must outlive any plausible run of re-deliveries.
const JOB_POISON_TTL_SECS: i64 = 7 * 24 * 3600;

/// Bound on the remembered set, so a device that is handed thousands of jobs cannot grow this without
/// limit. Oldest entries go first.
const JOBS_SEEN_MAX: usize = 256;

/// `(first_seen_ts, attempts)` for a stored entry. Accepts the legacy bare-timestamp form so an
/// existing client's map survives the upgrade instead of being silently discarded.
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
    // Abandoned ids are kept far longer than live ones — evicting them on the short window would let
    // the loop resume, which is the whole failure being fixed.
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
/// Shared by the hosted path and the compiled-in match rather than written at each: a hosted
/// collector that answered nothing must reach the console as the same failure, not as a silence.
///
/// **It names no kind, and does not need one.** The result is stored against the job that produced
/// it, and the console addresses that job by its own operation — so a kind spelled into the text
/// identified nothing the reader did not already have, while being one more place the dying
/// vocabulary had to be carried. The wording keeps "produced no result", which is the phrase the
/// console's own documentation points callers at.
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





// ── Diagnostic deep-read collectors (PLAN §2.5) — read-only, optionally filtered ──────────────────
//
// Each is a native fork-client collector invoking OS query APIs / built-in Windows tools per-job (the
// established READONLY-collector approach — never a resident `.ps1`). They take the same
// `params: Option<&str>` a JSON filter body arrives in (mirroring `eventlog`), filter AT THE SOURCE so
// the signed result stays under the console's result cap (`store::MAX_JOB_RESULT`, **256 KiB**), and
// never mutate device state regardless of params. Off Windows each returns `None` / a "Windows-only"
// marker like the other Windows collectors.
//
// ⚠ The source-side budgets below were sized against 64 KiB — the figure the result cap shared with
// `MAX_JOB_PARAMS` before it was raised — so they are CONSERVATIVE against the real cap, not tuned to
// it. Treat headroom as available rather than spent. Going over is loud either way: an over-cap result
// is not clipped, it is REPLACED wholesale with `{ok:false, store_truncated:true, chars, limit}` and
// forced to `status:"error"` (`crates/backend/src/client_api.rs`), so a partial body can never be read
// as a complete one.






/// Row builders every hosted script gets in its prologue ([`exec_powershell`]). `Add-S` / `Add-N` /
/// `Add-D` add a key ONLY when the
/// source had a value: a property PowerShell or WMI returned nothing for is OMITTED, never rendered as
/// `""`, so a caller can tell "no value" from a value that is genuinely empty.
///
/// `Add-D` normalizes a date to one sortable spelling instead of the host's locale format, and drops
/// anything before 2000 — that is not a date, it is a SENTINEL. Task Scheduler reports a task that has
/// never run as `1999-11-30`, and other Windows APIs use `1899-12-30` or the FILETIME epoch; each of
/// them serializes as a perfectly plausible timestamp, and "this task last ran in 1999" is exactly the
/// confident-but-wrong answer this file exists to stop. Absent is the honest rendering of never.
#[cfg(windows)]
const PS_ADD_FNS: &str = "function Add-S { param($H,[string]$K,$V) \
if ($null -ne $V) { $s=[string]$V; if ($s.Trim() -ne '') { $H[$K]=$s } } }; \
function Add-N { param($H,[string]$K,$V) \
if ($null -ne $V) { $n=$V -as [long]; if ($null -ne $n) { $H[$K]=$n } } }; \
function Add-D { param($H,[string]$K,$V) \
if ($null -ne $V) { try { $d=[datetime]$V; if ($d -ge [datetime]'2000-01-01') { $H[$K]=$d.ToString('yyyy-MM-dd HH:mm:ss') } } catch { } } }; \
function Add-B { param($H,[string]$K,$V) \
if ($null -ne $V) { $H[$K]=[bool]$V } }; ";



/// A short CPU / memory / disk performance sample with the top processes by CPU and by memory
/// (read-only). Native `sysinfo` (already a client dep) so there's no PowerShell launch: a two-pass
/// refresh makes CPU% a real delta. `params` JSON `{top_n:N}` (default 10, max 50) sets how many top
/// processes to return per dimension. Returns
/// `{cpu_pct, mem_total_mb, mem_used_mb, mem_pct, top_cpu:[…], top_mem:[…]}`.
fn perf(params: Option<&str>) -> Option<Value> {
    use hbb_common::sysinfo::{System, MINIMUM_CPU_UPDATE_INTERVAL};
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let top_n = p.get("top_n").and_then(|x| x.as_u64()).unwrap_or(10).clamp(1, 50) as usize;

    let mut sys = System::new();
    // First pass seeds per-process + global CPU counters; the second pass (after the minimum
    // interval) turns them into usable percentages.
    sys.refresh_cpu();
    sys.refresh_processes();
    sys.refresh_memory();
    std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu();
    sys.refresh_processes();

    let ncpu = num_cpus::get().max(1) as f32;
    // Global CPU utilisation (the same idiom sulltec_remote::inventory uses).
    let cpu_pct = (sys.global_cpu_info().cpu_usage() as f64 * 10.0).round() / 10.0;
    let mem_total = sys.total_memory();
    let mem_used = sys.used_memory();
    let to_mb = |b: u64| (b as f64 / 1024.0 / 1024.0 * 10.0).round() / 10.0;
    let mem_pct = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    // Build the per-process rows once, then sort two ways.
    let procs: Vec<(u32, String, f32, f64)> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            (
                pid.as_u32(),
                p.name().to_owned(),
                ((p.cpu_usage() / ncpu) * 10.0).round() / 10.0,
                (p.memory() as f64 / 1024.0 / 1024.0 * 10.0).round() / 10.0,
            )
        })
        .collect();

    let mut by_cpu = procs.clone();
    by_cpu.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    by_cpu.truncate(top_n);
    let mut by_mem = procs;
    by_mem.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
    by_mem.truncate(top_n);
    let row = |(pid, name, cpu, mem): &(u32, String, f32, f64)| {
        json!({ "pid": pid, "name": name, "cpu": cpu, "mem_mb": mem })
    };

    Some(json!({
        "cpu_pct": cpu_pct,
        "mem_total_mb": to_mb(mem_total),
        "mem_used_mb": to_mb(mem_used),
        "mem_pct": mem_pct,
        "top_cpu": by_cpu.iter().map(row).collect::<Vec<_>>(),
        "top_mem": by_mem.iter().map(row).collect::<Vec<_>>(),
    }))
}



/// `true` if `name` matches a simple `*`/`?` glob (case-insensitive) — `*` any run, `?` one char.
/// Used by `fs_list` for in-collector name filtering without pulling in the `glob` crate.
#[cfg(windows)]
fn glob_match(pat: &str, name: &str) -> bool {
    // Classic two-pointer wildcard match with backtracking on `*`.
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let s: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// An `fs` result that is NOT a listing — a missing path, a refused one, or one that could not be
/// opened or walked. Carries `ok:false` alongside `{path, error}` so [`is_collector_error`] recognizes
/// it; see [`wmi_error`] for why the flag lives in the body while the dispatch `status` stays `done`.
/// `path` is echoed on every arm (including the denylist refusal) so one shape answers "which read
/// failed, and why" without the caller re-deriving it from the request.
#[cfg(windows)]
fn fs_error(path: &str, why: impl Into<String>) -> Value {
    json!({ "ok": false, "path": path, "error": why.into() })
}

/// Filesystem listing at a specified root (read-only). CONTENT-ADJACENT: returns directory entries
/// (name/path/size/modified/attrs/is_reparse_point) and, with `hash`, the SHA-256 of matched files —
/// but NOT file *contents* in this pass (a `read` (contents) mode is a TODO; the console admin-gates
/// this collector).
/// `params` JSON `{path (required root), recurse:bool, depth:N, glob:"*.log", min_size:bytes,
/// modified_since:"yyyy-MM-dd"|days, hidden:bool, hash:bool}`. Walks with `std::fs` (no shell), capped at
/// 1000 entries; the SAM/SECURITY/LSA/DPAPI-equivalent denylist below blocks credential-store paths even
/// though the client runs as SYSTEM. Returns `{path, recurse, row_cap_hit, unreadable_dirs, entries:{…page…}}`.
///
/// **A path that is not there, or cannot be opened, is an error — never an empty listing.** `fs` is
/// the collector most often used to establish that something is *absent* ("no Dropbox in that
/// profile", "nothing changed under that tree"), so a typo, a since-renamed folder and an unreadable
/// root all used to come back byte-identical to a real but empty directory. Not-found, not-a-directory
/// and access-denied each return [`fs_error`]'s `{ok:false, path, error}` — and a subdirectory that
/// cannot be read mid-walk is counted in `unreadable_dirs` rather than silently skipped, so a
/// partially-readable tree returns what it read AND says it is partial.
#[cfg(windows)]
fn fs_list(params: Option<&str>) -> Option<Value> {
    use hbb_common::sha2::{Digest, Sha256};
    const CAP: usize = 1000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let root = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if root.is_empty() {
        return Some(fs_error(root, "fs needs a path (root)"));
    }
    // Sensitive-store denylist: the client is LocalSystem, so refuse the credential stores outright —
    // "read-only" must never become "credential-dump". Compared case-insensitively on a normalized path.
    let norm = root.replace('/', "\\").to_lowercase();
    const DENY: &[&str] = &[
        "\\windows\\system32\\config",         // SAM / SECURITY / SYSTEM hives + RegBack
        "\\windows\\ntds",                      // AD DIT (ntds.dit) on a DC
        "\\microsoft\\protect",                 // DPAPI master keys (…\AppData\Roaming\Microsoft\Protect, …\System32\Microsoft\Protect)
        "\\microsoft\\credentials",             // DPAPI credential blobs
        "\\microsoft\\crypto",                  // private-key containers
    ];
    if DENY.iter().any(|d| norm.contains(d)) {
        return Some(fs_error(root, "path is in the sensitive-store denylist (SAM/SECURITY/NTDS/DPAPI); refused"));
    }
    // Does the root exist, and is it a directory we can open? Answered BEFORE the walk, because the
    // walk's only failure mode is "returned no entries" — which is also its most useful success.
    match std::fs::metadata(root) {
        Ok(m) if !m.is_dir() => {
            return Some(fs_error(root, "path exists but is not a directory; fs lists directories"));
        }
        Ok(_) => {}
        Err(e) => {
            // Kind first, OS text as the fallback: an unformatted drive, a disconnected UNC share and
            // a not-ready removable volume are none of them "not found", and the OS says so better
            // than a guess would.
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "path not found".to_owned(),
                std::io::ErrorKind::PermissionDenied => "access denied reading the path".to_owned(),
                _ => format!("path could not be opened: {e}"),
            };
            return Some(fs_error(root, reason));
        }
    }
    let recurse = p.get("recurse").and_then(|x| x.as_bool()).unwrap_or(false);
    let max_depth = p.get("depth").and_then(|x| x.as_u64()).map(|d| d as usize).unwrap_or(if recurse { 8 } else { 1 }).min(32);
    let glob = p.get("glob").and_then(|x| x.as_str()).filter(|s| !s.is_empty());
    let min_size = p.get("min_size").and_then(|x| x.as_u64()).unwrap_or(0);
    let want_hidden = p.get("hidden").and_then(|x| x.as_bool()).unwrap_or(false);
    let want_hash = p.get("hash").and_then(|x| x.as_bool()).unwrap_or(false);
    // modified_since → a SystemTime floor (integer = N days back; string = a date).
    use chrono::TimeZone; // for Local.from_local_datetime
    let since: Option<std::time::SystemTime> = match p.get("modified_since") {
        Some(Value::Number(n)) => n
            .as_i64()
            .map(|d| std::time::SystemTime::now() - std::time::Duration::from_secs((d.max(0) as u64) * 86400)),
        Some(Value::String(s)) => chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
            .map(std::time::SystemTime::from),
        _ => None,
    };

    let fmt_time = |t: std::time::SystemTime| {
        chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M:%S").to_string()
    };
    let mut entries: Vec<Value> = Vec::new();
    let mut truncated = false;
    let mut unreadable_dirs = 0usize;
    // Counting past the materialization cap.
    //
    // `entries.total` is the page family's word for "how many rows this envelope is paging over", and
    // once CAP is hit that is exactly CAP — a constant wearing the shape of a count. Measured on a DC:
    // `C:/Windows/System32` reported total:1000, which is the cap, against a directory holding
    // thousands. Anything extrapolated from it is a floor presented as a fact, and the client-audit
    // skill is instructed to report `total` in preference to the page size, so the understatement
    // propagates into audit reports.
    //
    // So the walk no longer STOPS at CAP — it stops MATERIALIZING and keeps counting, which costs a
    // stat per entry and no allocation. Both bounds below exist because a count that never ends is
    // worse than a count that admits it stopped: `count_stopped` distinguishes "this is the real total"
    // from "at least this many", and `matched_total` is null rather than a floor whenever we bailed.
    const COUNT_SCAN_CAP: usize = 200_000;
    let count_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut matched = 0usize;
    let mut examined = 0usize;
    let mut count_stopped = false;
    // Iterative DFS with an explicit (path, depth) stack so a deep tree can't blow the call stack.
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(std::path::PathBuf::from(root), 1)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // The ROOT failing is the whole answer failing (the `metadata` probe above can succeed on
            // a directory the walk still cannot enumerate), so it reports rather than returning the
            // empty listing that started this. A SUBDIRECTORY failing — an ACL'd or EFS subtree — is
            // counted: dropping the rest of the tree over one denied branch would be the opposite lie.
            Err(e) if depth == 1 => {
                return Some(fs_error(root, format!("path could not be listed: {e}")));
            }
            Err(_) => {
                unreadable_dirs += 1;
                continue;
            }
        };
        for ent in rd.flatten() {
            // FIRST statement in the loop, deliberately: it must bound entries the filters below
            // `continue` past as well, or a huge directory of non-matching files costs the full walk
            // with nothing to show for it. Checking the clock every entry is cheap next to the stat.
            examined += 1;
            if examined > COUNT_SCAN_CAP || (examined % 4096 == 0 && std::time::Instant::now() > count_deadline) {
                count_stopped = true;
                break 'walk;
            }
            let path = ent.path();
            let Ok(meta) = ent.metadata() else { continue };
            let is_dir = meta.is_dir();
            let name = ent.file_name().to_string_lossy().into_owned();
            // Hidden filter (Windows FILE_ATTRIBUTE_HIDDEN bit) — skip hidden unless asked.
            let attrs = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes()
            };
            let is_hidden = attrs & 0x2 != 0; // FILE_ATTRIBUTE_HIDDEN
            // A reparse point stands in for a tree that may not be here: on an RDS host with User
            // Profile Disks each `C:\Users\<name>` is one, and the profile's contents exist only while
            // its VHDX is mounted — so the walk succeeds and returns a short, plausible, wrong answer.
            // Flagging it lets a caller tell a virtual tree from a real one.
            let is_reparse_point = attrs & 0x400 != 0; // FILE_ATTRIBUTE_REPARSE_POINT
            // Skip hidden entries (and don't descend into hidden dirs) unless hidden was requested.
            if is_hidden && !want_hidden {
                continue;
            }
            // Apply file-only filters (glob/min_size/modified_since) to FILES; dirs are always listed
            // (they're the navigation aid) but still subject to the name glob when one is given.
            let modified = meta.modified().ok();
            let passes_glob = glob.map_or(true, |g| glob_match(g, &name));
            let passes_size = is_dir || meta.len() >= min_size;
            let passes_since = since.map_or(true, |fl| modified.map_or(false, |m| m >= fl));
            if passes_glob && passes_size && passes_since {
                matched += 1;
                // Past the cap we count but no longer build — and skip the hash, which is the only
                // genuinely expensive step here (a 64 MB read per matched file).
                if truncated {
                    // Still descend, below, so the count covers the whole tree.
                    if is_dir && recurse && depth < max_depth && !is_reparse_point {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                let mut e = json!({
                    "name": name,
                    "path": path.to_string_lossy(),
                    "is_dir": is_dir,
                    "size": if is_dir { 0 } else { meta.len() },
                    "modified": modified.map(fmt_time).unwrap_or_default(),
                    "attrs": attrs,
                    "is_reparse_point": is_reparse_point,
                });
                // SHA-256 of matched FILES on request (size-capped at 64 MB to bound the read).
                if want_hash && !is_dir && meta.len() <= 64 * 1024 * 1024 {
                    if let Ok(bytes) = std::fs::read(&path) {
                        let mut h = Sha256::new();
                        h.update(&bytes);
                        e["sha256"] = json!(format!("{:x}", h.finalize()));
                    }
                }
                entries.push(e);
                if entries.len() >= CAP {
                    // Stop MATERIALIZING, not walking. The old `break 'walk` here is what made
                    // `entries.total` report the cap as though it were the count.
                    truncated = true;
                }
            }
            // Descend into subdirectories (honouring recurse + depth; hidden dirs already skipped
            // above). A reparse point is LISTED but never followed: Windows ships self-referential
            // junctions (`…\ProgramData\Application Data` → `…\ProgramData` and the per-user
            // equivalent), so following them revisits the same tree and inflates every count with
            // duplicate rows. `is_reparse_point` on the entry is how a caller sees the link is there.
            if is_dir && recurse && depth < max_depth && !is_reparse_point {
                stack.push((path, depth + 1));
            }
        }
    }
    // `row_cap_hit` NOT `truncated` — see the note in `wmi_query`: the page envelope has its own
    // `truncated` and the store cap a third, so the CAP-hit flag is named for what it is.
    Some(json!({
        "path": root,
        "recurse": recurse,
        "row_cap_hit": truncated,
        // Subdirectories the walk could not enumerate. Non-zero means the listing is short of the
        // tree by an unknown amount, which no other field in this envelope can say.
        // ⚠ This now counts through the COUNTING phase too, so on a capped listing it reports the whole
        // walked tree's denied subtrees rather than only those met before the cap. Strictly more
        // complete, but the number is larger than a pre-0.63.0 client would have reported.
        "unreadable_dirs": unreadable_dirs,
        // How many entries MATCHED the filters across the whole walk, not just the ones materialized.
        // `entries.total` keeps the page family's meaning (the rows this envelope pages over) and is
        // still the cap once `row_cap_hit`; these two say what that number cannot:
        //   matched_at_least — always real, always a floor you can trust
        //   matched_total    — the true count, or NULL if a bound stopped the count early. Never a
        //                      floor dressed as a total: a caller that reads it gets the answer or
        //                      gets nothing, which is the only way "unknown" survives arithmetic.
        "matched_at_least": matched,
        "matched_total": if count_stopped { Value::Null } else { json!(matched) },
        // The count gave up (scan cap or time budget). Distinct from `row_cap_hit`, which is only
        // about how many rows were built.
        "count_stopped": count_stopped,
        "entries": paginate(entries, params, CAP),
        // NOTE: file `read` (contents) is intentionally NOT implemented in this pass — listing + hash only.
    }))
}
#[cfg(not(windows))]
fn fs_list(_params: Option<&str>) -> Option<Value> {
    None
}











/// Logged-on / terminal-server sessions on the box (read-only) — the GENERAL diag view (distinct from
/// the in-session RDS switcher). Parses `quser` (the built-in `query user`), which lists every
/// interactive + RDP session with its state + idle + logon time. No params (an empty params object is
/// accepted + ignored). Returns `[{user,session,id,state,idle,logon_time}, …]`. `quser` exits non-zero
/// with "No User exists for *" when nobody is logged on — that's an empty list, not an error.
#[cfg(windows)]
fn sessions() -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // `quser` is the canonical built-in (a thin wrapper over WTS APIs); its columns are fixed-width.
    let out = std::process::Command::new("quser")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Header line + one row per session. The leading column may carry a '>' marker for the current
    // session; SESSIONNAME is blank for a disconnected session. Parse positionally from the right so a
    // username with spaces (rare) or a blank session name doesn't misalign the trailing fixed columns.
    let mut rows: Vec<Value> = Vec::new();
    let mut capped = false;
    for line in text.lines().skip(1) {
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        // The user name is the first token (drop a leading '>' current-session marker).
        let line_no_marker = trimmed.trim_start();
        let line_no_marker = line_no_marker.strip_prefix('>').unwrap_or(line_no_marker);
        let fields: Vec<&str> = line_no_marker.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        // Trailing fields are stable: … ID STATE IDLE LOGON-DATE LOGON-TIME (logon time = last 2 tokens).
        // A disconnected session omits SESSIONNAME, so field count varies (6 connected / 5 disconnected).
        let n = fields.len();
        let (user, session, id, state, idle, logon_time) = if n >= 6 {
            (
                fields[0].to_string(),
                fields[1].to_string(),
                fields[2].to_string(),
                fields[3].to_string(),
                fields[4].to_string(),
                format!("{} {}", fields[n - 2], fields[n - 1]),
            )
        } else if n == 5 {
            // Disconnected: user, id, state, idle, logon-date/time collapsed — session name blank.
            (
                fields[0].to_string(),
                String::new(),
                fields[1].to_string(),
                fields[2].to_string(),
                fields[3].to_string(),
                fields[4].to_string(),
            )
        } else {
            continue;
        };
        rows.push(json!({
            "user": user,
            "session": session,
            "id": id,
            "state": state,
            "idle": idle,
            "logon_time": logon_time,
        }));
        if rows.len() >= 200 {
            capped = true;
            break;
        }
    }
    // Say so when the tail was dropped: a silently clipped list reads as a complete one.
    let mut out = json!({ "total": rows.len(), "count": rows.len(), "truncated": capped, "items": rows });
    if capped {
        out["next_offset"] = json!(200);
    }
    Some(out)
}
#[cfg(not(windows))]
fn sessions() -> Option<Value> {
    None
}

/// The row cap for `services`, and the ordering it cuts against.
///
/// `services` was the last genuinely ungoverned collector: a bare `Vec<Value>` with no cap, no marker
/// and no envelope, which grew until it tripped the backend's 256 KiB stored-result cap — and an
/// over-cap result is REPLACED WHOLESALE, so the failure was losing the entire service list rather
/// than its tail. Measured on this fleet: ~296 services against a cliff around 2,264.
///
/// 3000 sits above the cliff deliberately. The row cap is not the size bound — the byte cliff is — so
/// the point of this number is to bound ROWS on a host with an implausible service count while never
/// binding on a real one. The declaration is the feature; the number is just where it starts.
const SERVICE_CAP: usize = 3000;

/// Alphabetical by display name, which is what the console's table shows and what an operator scans.
const SERVICE_ORDER: &str = "display asc";

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
fn cap_rows(mut list: Vec<Value>, cap: usize, order: &str, noun: &str, lost: &str) -> Vec<Value> {
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

/// Win32 services as `[{name, display, state, start}, …]`, by display name. Empty on
/// non-Windows. `state` is live (from the SCM); `start` is the configured start type
/// (from the registry).
fn services() -> Value {
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
fn enum_services_wmi() -> Vec<(String, String, String)> {
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

/// Bulk-enumerate Win32 services → `(name, display, state)`. One SCM call (two-pass for
/// sizing). Empty on any failure (e.g. SCM access denied when not running as a service).
#[cfg(windows)]
fn enum_services() -> Vec<(String, String, String)> {
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
                // service sitting Stopped is its designed state, not a failure — `gpsvc` is the one
                // that flapped an alert this way. Presence of the subkey is the signal; its contents
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
    use super::{cap_rows, SERVICE_ORDER};
    use serde_json::{json, Value};

    /// `services` was the last ungoverned collector — a bare Vec that grew until it tripped the
    /// backend's 256 KiB cap, where an over-cap result is REPLACED WHOLESALE. It must now declare a cut
    /// in the shared marker shape, and the marker must carry no field the console's Start/Stop
    /// buttons key off. (`name` holds the prose, which is exactly what those buttons gate on — hence the
    /// console-side marker predicate shipped alongside this.)
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

// ── Server-role deep-read collectors (docs/PLAN-role-collectors.md). Each is read-only, gated
// CONSOLE-SIDE on the device's `roles` fingerprint (the fork just serves the data). All follow the
// existing collector shape: a PowerShell/ADSI/WMI one-liner → `ps_rows_guarded` → `paginate`. ──







// ── RDS session-history collectors (role `rdsh`) ──────────────────────────────────────────────────
//
// Answering "who logged on to this session host today" used to take eight hand-windowed `wmi` queries
// plus client-side noise filtering. These read the same events directly, filtered at the source.
//
// Method facts baked in here rather than rediscovered:
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
// health. Actions: run / pause / resume. (Repair/compact/verify live only in the standalone
// CommandLine.exe and need the backup's target URL + passphrase — a separate follow-up.)







// ── Duplicati Server REST API actions (Phase 2b) ──────────────────────────────────────────────
// repair / recreate / verify / compact / vacuum go through the local Duplicati Server API (:8200) —
// the server owns the DB and runs the op in-process (web-UI parity), so no passphrase-on-disk and no
// DB-lock conflict. Auth: ServerUtil mints a long-lived bearer via `issue-forever-token` (which does
// the datafolder→signin-JWT→`auth/signin` flow internally); we cache it and send `Authorization:
// Bearer`. The mint requires the operator to have enabled `--webservice-enable-forever-token` on the
// service once; until then these actions return an actionable error.
// NOTE: this token + HTTP layer is NOT exercised by the Rust build/tests — validate on a box (against a
// throwaway backup) before first real use.























// ── Duplicati datafolder ACL check / secure ───────────────────────────────────────────────────
// Duplicati 2.3.0.107 makes the data folder permissions a HARD requirement: the server refuses to use
// a folder whose permissions aren't exactly as expected (opt-out only via --allow-insecure-datafolder).
// A box with a custom datafolder + inherited/lax ACLs will simply stop backing up on upgrade, so we
// expose a read-only compliance check and an L2 corrective action. 2.3 ships
// `ConfigureTool secure-datafolder`; it does NOT exist in 2.2.x, so the fix falls back to setting the
// ACL directly. Principals are matched by **SID**, not name, so this works on non-English Windows.





















// ── Failed reads must not look like empty ones ────────────────────────────────────────────────────
//
// A collector that runs its cmdlets under `$ErrorActionPreference='SilentlyContinue'` and then
// null-coerces (`@($fwd.IPAddress)` → `[]`, `[bool]$fwd.UseRootHint` → `false`) cannot tell a *failed
// read* from an *absent setting* — and the zeroed shape it emits reads as a configuration verdict. A
// DNS server whose cmdlets were failing reported "no forwarders, root hints off" that way, and an
// audit recorded it as a real finding. So a read either produces its answer or says it failed; it
// never produces a plausible answer it did not obtain.

/// Prologue for a collector script that must not report a failed read as an empty one. Defines
/// `Stop-OnError`, which inspects the errors raised since the last checkpoint and — if any are real —
/// writes the first message to stderr and exits 1, which the guarded runners below turn into a
/// collector `{ok:false,error}`. Call it directly after each read, **before** anything derived from
/// that read is used; a read that legitimately returned nothing leaves `$Error` empty and passes.
///
/// `-Ignore` takes `FullyQualifiedErrorId` prefixes, for the cmdlets that raise an error to mean
/// "nothing matched". Matching on the id rather than the message text is what makes this work on a
/// non-English host. `-ErrorAction SilentlyContinue` stays on the reads themselves: a multi-target
/// query has to survive one target failing, and `$Error` still records what did.
///
/// ⚠ A read that is deliberately **best-effort** must be followed by `$Error.Clear()`, not merely
/// wrapped in `try/catch`: PowerShell records a caught exception in `$Error` regardless, so the next
/// `Stop-OnError` would otherwise fail the collector over an optional read that was allowed to fail.
#[cfg(windows)]
const PS_GUARD: &str = "$ErrorActionPreference='SilentlyContinue'; $Error.Clear(); \
function Stop-OnError { param([string]$What='',[string[]]$Ignore=@()) \
$real=@($Error | Where-Object { $i=[string]$_.FullyQualifiedErrorId; \
-not (@($Ignore | Where-Object { $i -like ($_ + '*') }).Count) }); \
if ($real.Count -gt 0) { $m=[string]$real[0].Exception.Message; if ($What) { $m=$What + ': ' + $m }; \
[Console]::Error.WriteLine($m); exit 1 }; $Error.Clear() }; ";

/// Wall-clock ceiling on a read-only collector's PowerShell run.
///
/// **Not a budget.** It is deliberately far above anything legitimate so that reaching it means the run
/// is never going to end, not that it is slow: every kind behind [`ps_capture`] is a metadata read, and
/// the slowest ever measured are `firewall` at 143.8 s before it was rewritten and `features` on a
/// client SKU at over two minutes. An hour is roughly twenty-five times that, and it sits well inside
/// the console's own 24 h expiry, so the device still answers first.
///
/// What it buys is the difference between a job that reports a failure and one that holds its in-flight
/// slot, a blocking thread and a PowerShell process for the life of the process. It is NOT a per-kind
/// timeout — no per-kind measurement exists, and the runner behind the ACTION kinds is deliberately
/// left unbounded, because `update-install` drives `IUpdateInstaller.Install()` synchronously and its
/// runtime is set by the machine's patch backlog.
#[cfg(windows)]
const PS_RUN_CEILING_SECS: u64 = 3600;

/// How long to wait for the output pipes after the child has already exited. Normally instant — the
/// readers drain concurrently and EOF arrives with the exit — so this only ever elapses when a
/// descendant inherited a pipe and is still holding it.
#[cfg(windows)]
const PS_DRAIN_GRACE_SECS: u64 = 30;

/// The result a run that could not be finished reports: a failure status, the reason on stderr, and
/// deliberately NO stdout — see [`ps_capture`].
#[cfg(windows)]
fn ps_run_unfinished(why: &str) -> std::process::Output {
    use std::os::windows::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(1),
        stdout: Vec::new(),
        stderr: format!(
            "the PowerShell run did not complete: {why}. Whatever it had written is discarded rather \
             than reported as the answer"
        )
        .into_bytes(),
    }
}

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

/// [`ps_capture`] with the wall-clock ceiling supplied by the caller.
#[cfg(windows)]
fn ps_capture_within(script: &str, ceiling_secs: u64, ask: Option<&str>) -> Option<PsRun> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new(powershell_exe());
    cmd.args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // ⚠ The ask travels in the ENVIRONMENT, never in the script text. A backend-hosted command has
    // to be able to select the row the address named, and the only two ways to give it a value are
    // to paste the value into the code or to hand it over as data. Pasting is how a selector becomes
    // a command, and no amount of escaping makes that a property of the design rather than of the
    // escaper. This way the command compares against a variable it did not author.
    if let Some(ask) = ask {
        cmd.env(JOB_PARAMS_ENV, ask);
    }
    let mut child = cmd.spawn().ok()?;
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ceiling_secs);
    let mut nap = std::time::Duration::from_millis(2);
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            // A handle we cannot ask about will not be waited on either — treat it as the timeout case.
            Err(_) => break None,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(std::time::Duration::from_millis(250));
    };
    let Some(status) = finished else {
        let _ = child.kill();
        hbb_common::log::error!("a collector's PowerShell run passed {ceiling_secs}s and was terminated");
        return Some(PsRun::TimedOut);
    };
    // The child is gone, so the pipes are at EOF and the readers have finished — unless a descendant
    // inherited one and is still alive, in which case the read never ends. That is a FAILED run rather
    // than a timed-out one: the command itself finished, and a caller told to expect `timed_out` for a
    // command that outlasted its budget would be told the wrong thing.
    let grace = std::time::Duration::from_secs(PS_DRAIN_GRACE_SECS);
    match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(stdout), Ok(stderr)) => Some(PsRun::Done(std::process::Output { status, stdout, stderr })),
        _ => Some(PsRun::Done(ps_run_unfinished(
            "a descendant kept its output pipe open after the process exited",
        ))),
    }
}

/// How a native argv run ended. The sibling of [`PsRun`], carrying the exit CODE rather than a
/// `Output`: a native action's whole result is "did it work", so the code is the answer instead of
/// something to inspect the output for.
#[cfg(windows)]
enum NativeRun {
    Done { code: i32, stdout: String, stderr: String },
    TimedOut,
}

/// Spawn one program with its arguments, under the same wall-clock ceiling PowerShell runs under.
///
/// ⚠ **`args` is a LIST and is never joined into a string.** `std::process::Command` passes it to the
/// process API as separate elements, so nothing a substituted value contains can turn into a second
/// argument, a redirect or a command separator. This is why a hosted native command needs no escaping
/// rule and no allow-list on the values it carries — a pid's all-digits check is there because
/// `taskkill` is picky about its argument, not because the spawn was unsafe.
///
/// ⚠ **No environment ask.** The PowerShell executor hands its ask over in `SULLTEC_JOB_PARAMS`
/// because its input is a LANGUAGE and pasting a value into code is how a selector becomes a command.
/// An argv has no such hazard, so the values are already substituted by the time they get here and
/// there is nothing to bind.
///
/// The wait loop is [`ps_capture_within`]'s, deliberately: one timeout discipline for both
/// executors, so a hosted command's budget means the same thing whichever one runs it.
#[cfg(windows)]
fn run_argv_within(program: &str, args: &[String], ceiling_secs: u64) -> Option<NativeRun> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().ok()?;
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ceiling_secs);
    let mut nap = std::time::Duration::from_millis(2);
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            // A handle we cannot ask about will not be waited on either — treat it as the timeout case.
            Err(_) => break None,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(std::time::Duration::from_millis(250));
    };
    let Some(status) = finished else {
        let _ = child.kill();
        hbb_common::log::error!("a hosted '{program}' run passed {ceiling_secs}s and was terminated");
        return Some(NativeRun::TimedOut);
    };
    let grace = std::time::Duration::from_secs(PS_DRAIN_GRACE_SECS);
    let (stdout, stderr) = match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(o), Ok(e)) => (o, e),
        // A descendant inherited a pipe and outlived its parent. The command itself FINISHED, so
        // reporting a timeout would say the wrong thing; the exit status is still true.
        _ => (Vec::new(), b"a descendant kept its output pipe open after the process exited".to_vec()),
    };
    Some(NativeRun::Done {
        // ⚠ A process killed by a signal has no code. `-1` rather than `0`, because the one thing
        // this must never do is report a run it cannot describe as a success.
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// The collector error for a [`PS_GUARD`] script that failed a read, or `None` when the run is
/// trustworthy. Output on stdout wins: a multi-target read that got rows from one target and an error
/// from another still returns the rows, exactly as the event-log collector does. Empty stdout with a
/// clean exit is a genuine empty result and is left alone — reporting *that* as a failure would train
/// operators to ignore the collector, which is the same lie in the other direction.
#[cfg(windows)]
fn guard_failure(out: &std::process::Output, what: &str) -> Option<Value> {
    if !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
        return None;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.trim();
    if err.is_empty() && out.status.success() {
        return None;
    }
    let detail: String = match err.is_empty() {
        true => format!("exited {}", out.status.code().unwrap_or(-1)),
        false => err.chars().take(2000).collect(),
    };
    Some(json!({ "ok": false, "error": format!("{what} failed: {detail}") }))
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


/// The row-reading half of [`ps_rows_guarded`], separated so a run captured under a caller-supplied
/// ceiling reads its output through the SAME parse. Split rather than copied: a second reader is how
/// the two paths drift into disagreeing about what an unparseable line means.
#[cfg(windows)]
fn ps_rows_of(out: &std::process::Output, what: &str) -> GuardedRows {
    if let Some(e) = guard_failure(out, what) {
        return GuardedRows::Failed(e);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    // Nothing on stdout, having already cleared the failure check above — a genuine empty result.
    if text.is_empty() {
        return GuardedRows::Rows(Vec::new());
    }
    match serde_json::from_str(text) {
        Ok(Value::Array(a)) => GuardedRows::Rows(a),
        Ok(v @ Value::Object(_)) => GuardedRows::Rows(vec![v]), // ConvertTo-Json emits a bare object for one row
        Ok(Value::Null) => GuardedRows::Rows(Vec::new()),
        Ok(other) => GuardedRows::Rows(vec![other]),
        // Output that won't parse is a failure, not an empty list: the script wrote *something*, so
        // whatever it wrote is the closest thing to a reason available.
        Err(e) => GuardedRows::Failed(json!({ "ok": false, "error": format!("{what} returned unreadable output: {e}") })),
    }
}



/// Soft byte budget for one paginated diag page, leaving headroom for the wrapper object + pagination
/// metadata.
///
/// ⚠ 48 KiB was chosen against a 64 KiB result cap (~16 KiB of headroom). The cap is now **256 KiB**
/// (`store::MAX_JOB_RESULT`), so this budget is conservative by roughly fourfold — every paginated
/// collector is returning far smaller pages, and therefore far more of them, than the cap requires.
/// **MEASURED 2026-07-30 across the fleet, and it STAYS at 48 KiB.** The budget fires on exactly one
/// collector in practice (`firewall`: page 1 = 50,361 B on one DC, 50,482 B on the other, so 2-3 pages)
/// plus `fs`. Raising it buys a saved page fetch and costs headroom against the 256 KiB cliff — where an
/// over-cap result is **replaced wholesale** with a failure notice rather than clipped, so the whole
/// answer is lost. `fs` recursive already extrapolates to ~221 KiB, 86% of that cap. A budget-governed
/// collector is safe at *any* size precisely because this clips it first; the real exposure is the
/// collectors that have NO budget. Fix those rather than raising this.
///
/// ⚠ **This paragraph used to name that set wrongly, and the error outlived several sweeps.** It said
/// `services`, `processes` and `ad-users`/`-computers`/`-groups` were ungoverned and that `ad-users`
/// broke at ~610 users. Re-read against the code: the three `ad-*` collectors all end in
/// `paginate_cursor(items, params, 300)` and are budgeted by this very constant, and `processes` is
/// bounded by [`cap_processes`]. **`services` is the only genuinely ungoverned collector** — a bare
/// unbounded `Vec<Value>`, no cap, no marker, no envelope. A wrong claim in a doc comment is worse than
/// no claim: this one sat three functions above the calls that disprove it, and a fleet measurement was
/// derived from it for a cliff that does not exist. Verify against the call site, not against this.
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

/// Paginate + size-cap a JSON item list for a diag result: apply the optional `{offset, limit}` from
/// `params`, then include items only while the serialized page stays under [`PAGE_BUDGET`] — so a large
/// collection (firewall rules, installed programs, drivers, …) can never SILENTLY overflow the result
/// cap. Returns `{total, offset, count, truncated, next_offset?, items:[…]}`; a caller reads the whole
/// set by re-requesting with `offset = next_offset` until `truncated` is false.
#[cfg(windows)]
fn paginate(items: Vec<Value>, params: Option<&str>, default_limit: usize) -> Value {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let total = items.len();
    let offset = p.get("offset").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let limit = p
        .get("limit")
        .and_then(|x| x.as_u64())
        .map(|n| (n as usize).max(1))
        .unwrap_or(default_limit);
    let page = page_within_budget(items.iter().skip(offset), limit);
    let end = offset + page.len();
    let mut out = json!({
        "total": total,
        "offset": offset,
        "count": page.len(),
        "truncated": end < total,
        "items": page,
    });
    if end < total {
        out["next_offset"] = json!(end);
    }
    out
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
/// The discriminator is `exec`, and deliberately nothing else: a backend that has not been updated
/// sends the params it always sent, they carry no executor, and the compiled-in collector still
/// answers. The new path is opt-in from the side that owns the command, so neither half has to be
/// rolled forward before the other can move.
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
/// Dispatch is on `exec` alone, and the sorting/hashing/paging below is executor-independent — so
/// `cmd`, `wmi` and `registry` become new arms here rather than a new wire contract.
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
        // ⚠ The second executor, and it is a METHOD rather than a collector: "run this argv and tell
        // me how it went". What is run is the backend's to state — `kill` and `logoff` used to be
        // argv lists compiled in here, and only their location changed.
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

/// The prologue every hosted PowerShell command runs behind — the executor's own dialect.
///
/// `$Params` is the ask: the dispatch's narrowing params, minus the fields the executor reserves.
/// Bound from the environment rather than pasted into the script, so a selector is a VALUE the
/// command compares against and can never be code (see [`ps_capture_within`]). It is `$null` for a
/// command that was sent none, which is the shape a script tests with `$null -ne`.
///
/// The variable is cleared once read: a descendant this command starts inherits the environment,
/// and there is no reason for the ask to travel any further than the script that asked for it.
#[cfg(windows)]
const PS_PARAMS_BIND: &str = "$Params=$null; \
if($env:SULLTEC_JOB_PARAMS){ $Params=ConvertFrom-Json $env:SULLTEC_JOB_PARAMS }; \
$env:SULLTEC_JOB_PARAMS=$null; $Error.Clear(); ";

/// The `native` executor: spawn one program with its arguments, and report how it went.
///
/// ⚠ **An ARGV, never a shell string, and that is the whole security property.** The text is split on
/// whitespace into argument elements and handed to the process API as a list, so nothing reparses
/// it: there is no shell to interpret `&`, `|`, `>`, quotes or globs, and a substituted value cannot
/// become a second argument no matter what it contains. The PowerShell executor beside this one has
/// to bind its ask through an environment variable precisely because its input IS a language; this
/// one has no language to escape into.
///
/// **`${name}` takes one value from the ask, and must be a WHOLE element.** `taskkill /F /PID ${pid}`
/// is four arguments, the fourth being the pid as sent. A token embedded in a larger element is
/// REFUSED rather than substituted — such a value would still be a single argument, so this is about
/// keeping the rule one sentence long rather than about closing a hole.
///
/// **A missing or empty value is a refusal, not an empty argument.** `taskkill /F /PID` with the pid
/// silently dropped is a different command from the one the backend authored, and one of the shapes
/// it could take is "kill nothing and exit 0".
///
/// **Spawning an argv list is what a process kill and a session logoff always did here.** What
/// changes is only that the list is now the backend's to state. Starting, stopping and restarting a
/// service are genuinely PowerShell on this device and go through the executor above instead.
#[cfg(windows)]
fn exec_native(command: &str, timeout_s: u64, ask: &str) -> Result<Vec<Value>, Value> {
    let bound: Value = serde_json::from_str(ask).unwrap_or(Value::Null);
    let argv = split_argv(command, &bound)?;
    let Some((program, args)) = argv.split_first() else {
        return Err(keyset_error("the hosted command is empty"));
    };
    match run_argv_within(program, args, timeout_s) {
        None => Err(keyset_error(&format!("'{program}' could not be started"))),
        // Same reasoning as the PowerShell executor's: a result rather than a silence, because a job
        // in its timeout and a job never picked up read identically to the console otherwise.
        Some(NativeRun::TimedOut) => Err(json!({
            "ok": false,
            "error": format!("'{program}' timed out after {timeout_s}s"),
            "timed_out": true,
        })),
        // ⚠ A non-zero exit is a FAILED JOB, not a row saying so. The fork's `run_action` reported a
        // fixed label — "killed" — whatever the exit code was, so a `taskkill` that found no such
        // process answered exactly like one that ended it. That is the single worst shape an action
        // result can have: it reads as done.
        Some(NativeRun::Done { code, stdout, stderr }) if code != 0 => Err(json!({
            "ok": false,
            "error": format!(
                "'{program}' exited {code}: {}",
                first_line(&stderr).or_else(|| first_line(&stdout)).unwrap_or_default()
            ),
            "exit_code": code,
        })),
        Some(NativeRun::Done { code, stdout, .. }) => Ok(vec![json!({
            "exit_code": code,
            "output": stdout.trim(),
        })]),
    }
}

/// The first non-empty line of a program's output — enough to say WHY it failed without carrying a
/// screenful of untrusted device text onto an error path.
#[cfg(windows)]
fn first_line(s: &str) -> Option<String> {
    s.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.chars().take(256).collect())
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
/// ⚠ **This is `run_job`'s match, reached the way the other executors are.** Seven procedures earn a
/// place here — the agent's own state (`disconnect`, `client-log`, `inventory`), a raw socket
/// (`wol`), byte movement that has to be fast (`file-pull`, `file-push`), and `script`, which is
/// PowerShell text but not a PowerShell invocation. Everything else the backend sends as a script or
/// an argv. What changed is not where the code lives, it is that the VERB now says which procedure
/// it invokes instead of a job-kind string being looked up in a table the endpoint could not see.
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
        "inventory" => crate::sulltec_remote::inventory::collect(),
        // Native bodies the backend dispatches by procedure name; each body is the compiled
        // collector unchanged. These refusals NAME THE PROCEDURE, and that is not the dying job
        // vocabulary: the name is the first element of the builtin command the backend sent, so it
        // is the one identifier this layer genuinely owns. `job_answer` names nothing, because on
        // that path there is nothing it could name that the caller does not already hold.
        "perf" => perf(p).unwrap_or_else(|| keyset_error(
            "the 'perf' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "fs" => fs_list(p).unwrap_or_else(|| keyset_error(
            "the 'fs' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "sessions" => sessions().unwrap_or_else(|| keyset_error(
            "the 'sessions' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "services" => services(),
        // A name this client does not implement is a REFUSAL. Answering an empty result would read
        // as "the machine had nothing", which is the failure the whole guard layer exists for.
        other => keyset_error(&format!("this client has no '{other}' procedure")),
    }
}

/// The `powershell` executor: run the backend's command under [`PS_GUARD`] with a hard ceiling.
///
/// The prologue is the one every compiled-in collector gets — [`PS_GUARD`] so a hosted command can
/// call `Stop-OnError` and have a failed read reported as a failure rather than as an empty set, and
/// [`PS_ADD_FNS`] so it can project a row the way the compiled-in collectors do, omitting a field
/// the source had no value for instead of rendering it as an empty string. A hosted command that had
/// to carry its own copies of those would be shipping the client's dialect over the wire on every
/// single dispatch.
#[cfg(windows)]
fn exec_powershell(command: &str, timeout_s: u64, ask: &str) -> Result<Vec<Value>, Value> {
    let script = format!("{PS_GUARD}{PS_ADD_FNS}{PS_PARAMS_BIND}{command}");
    match ps_capture_within(&script, timeout_s, Some(ask)) {
        None => Err(keyset_error("the collector command failed: PowerShell could not be started")),
        // ⚠ A RESULT, never a silence. A job sitting in its timeout and a job that was never picked up
        // both read `queued` to the console. This says three things a silence cannot: it was
        // delivered, it ran, and it outlasted a budget somebody chose — which is what makes the
        // timeout a probe of the machine rather than only a guardrail.
        Some(PsRun::TimedOut) => Err(json!({
            "ok": false,
            "error": format!("timed out after {timeout_s}s"),
            "timed_out": true,
        })),
        Some(PsRun::Done(out)) => match ps_rows_of(&out, "the collector command") {
            GuardedRows::Rows(rows) => Ok(rows),
            GuardedRows::Failed(e) => Err(e),
        },
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

/// Run a PowerShell script that emits `ConvertTo-Json` and return the parsed value **as-is** (object
/// OR array) — for the object-shaped read models (Defender status, Windows-update lists) that
/// `ps_json_array` would wrongly flatten. The caller bounds size at collection time (e.g.
/// `Select-Object -First N`). `None` off-Windows or on any launch/parse failure.
///
/// ⚠ **`None` here means the read FAILED — a caller must never let it reach the wire.** This runner
/// is unguarded, so it cannot distinguish a script that died from one that legitimately produced
/// nothing; either way the output is unparseable, and a collector that returns the bare `None` sends
/// `result: null` beside `status:"done"` with no error, which reads as "ran, found nothing". Ten
/// collectors did exactly that until 2026-07-31, found by running `duplicati-status` against a live
/// host. Convert it — `.or_else(|| Some(json!({ "ok": false, "error": … })))` — or use
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

/// A parsed PowerShell result, unless it is JSON `null` — in which case the read produced NO DATA and
/// must be reported as a failure, not as a value.
///
/// `ConvertTo-Json` renders `$null` as the literal `null`, which `serde_json` parses happily into
/// `Some(Value::Null)`. That slips past every `unwrap_or_else(|| error)` a caller wrote — those only
/// fire on `None` — and lands on the wire as `result: null` beside `status:"done"` with no error,
/// which is the same "ran and found nothing" lie the `None` arm was fixed for in 2026-07-31. Measured
/// 2026-08-02: an `idrac-power` dispatch returned exactly that while an authenticated Redfish read a
/// minute earlier showed two healthy PSUs drawing 203 W, and the immediate retry returned the full
/// payload — so it is intermittent, and it presents as success.
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
#[cfg(not(windows))]
pub(crate) fn ps_json(_script: &str) -> Option<Value> {
    None
}

/// Force-disconnect (S6): close every active incoming session (remote control / file transfer /
/// view camera / terminal). Port-forward tunnels can't be reached this way; they're reported as
/// skipped so the operator isn't told they were closed.
fn disconnect_sessions() -> Value {
    let (closed, skipped_port_forward, peers) =
        crate::sulltec_remote::connection::close_all_authed_conns();
    json!({
        "ok": true,
        "closed": closed,
        "peers": peers,
        "skipped_port_forward": skipped_port_forward,
    })
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

/// Decode bytes written by PowerShell's `*>` redirect, honouring the BOM. `powershell_exe()` is
/// Windows PowerShell 5.1, whose redirect operators default to **UTF-16LE with a `FF FE` BOM** — not
/// UTF-8. `0xFF` is invalid UTF-8, so `read_to_string` on such a file always `Err`s; paired with
/// `unwrap_or_default()` that silently turned EVERY script job's output into an empty string. Decode
/// by BOM instead, and fall back to a lossy UTF-8 read (bare UTF-8 is what `pwsh` 6+ would write, if
/// this ever stops hard-coding 5.1).
#[cfg(windows)]
fn decode_ps_bytes(bytes: &[u8]) -> String {
    let utf16 = |b: &[u8], le: bool| -> String {
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Read + decode a PowerShell-written output file. A MISSING file means the script wrote nothing (or
/// never ran) → `Ok("")`; any other read failure is returned as `Err` so the caller can SAY so rather
/// than pass an empty string off as "the script printed nothing". That distinction matters: `ok`/`exit`
/// come from the PowerShell process, which exits 0 whatever the script did, so `output` is the only
/// evidence a job actually did its work.
#[cfg(windows)]
fn read_ps_output(path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(decode_ps_bytes(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Run an operator-supplied PowerShell script (admin-gated, params delivered over the SIGNED
/// `/params` channel — never the unauthenticated heartbeat). Captures stdout+stderr+exit and
/// char-safe-truncates the combined output (60,000 chars — sized against a 64 KiB result cap, and so
/// conservative against the real 256 KiB `store::MAX_JOB_RESULT` even after JSON escaping). Returns
/// `{ok, exit, output}` (or `{ok:false, error}` if the shell couldn't launch).
#[cfg(windows)]
fn run_script(params: Option<&str>) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let raw = params.unwrap_or("").trim();
    if raw.is_empty() {
        return json!({ "ok": false, "error": "no script provided" });
    }
    // Params are either a bare script (the default — runs in THIS process's own context, unchanged)
    // or a JSON envelope `{script, run_as, username, password}` selecting an optional run-as identity.
    // The envelope only ever arrives over the SIGNED `/params` channel (script is a sensitive kind),
    // so a credential inside it never rides the unauthenticated heartbeat.
    let (script, run_as, username, password) = parse_script_params(raw);
    if run_as == "user" || run_as == "credential" {
        return run_script_as(&script, &run_as, &username, &password);
    }
    // Default: PowerShell in the client's own (service / SYSTEM) context. Run the script from a temp
    // `.ps1` via `-File` rather than inline `-Command`: the inline path pushes the whole script through
    // Rust arg-escaping → PowerShell → the native tool, which mangles quoting and could echo / parse-fail
    // scripts that call native commands (`auditpol`, `reg`, …). A file sidesteps all command-line escaping,
    // and the child's stdout/stderr — including the native command's — is captured normally.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::path::Path::new(r"C:\Windows\Temp").join(format!("sulltec-job-{}-{}", std::process::id(), nonce));
    if std::fs::create_dir_all(&dir).is_err() {
        return json!({ "ok": false, "error": "failed to create job temp dir" });
    }
    let ps1 = dir.join("job.ps1");
    if std::fs::write(&ps1, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": "failed to write script" });
    }
    // Invoke the file via the call operator and redirect ALL PowerShell streams (`*>`) — including a
    // native command's stdout (auditpol/reg/etc.) — to a file we read back. A bare `-File` leaves an
    // unassigned native command writing to the host, which the session-0 service context doesn't capture
    // on the stdout pipe (it came back as just the echoed command line). This is the same file-capture
    // the run-as path uses. Both paths are quote-free temp paths, single-quoted so Rust arg-escaping
    // can't mangle them.
    let out_file = dir.join("out.txt");
    let invoke = format!("& '{}' *> '{}'", ps1.display(), out_file.display());
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &invoke])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    // `captured` = the script's own output (all streams, redirected to the file, BOM-decoded); `o.stderr`
    // only catches a failure to launch PowerShell itself.
    let captured = read_ps_output(&out_file);
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) => {
            let ps_err = String::from_utf8_lossy(&o.stderr);
            // Surface a read failure rather than flattening it to "" — an empty `output` must mean the
            // script printed nothing, never "we lost what it printed".
            let (captured, read_err) = match captured {
                Ok(s) => (s, String::new()),
                Err(e) => (String::new(), format!("[console: the script ran but its captured output could not be read: {e}]")),
            };
            let combined: String = format!("{captured}{ps_err}{read_err}").chars().take(60_000).collect();
            json!({ "ok": o.status.success(), "exit": o.status.code(), "output": combined })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// Split a remote-script param into `(script, run_as, username, password)`. A bare string (the legacy
/// shape) is the script itself with `run_as = "system"`; a `{ "script": … }` JSON object carries the
/// optional run-as fields.
#[cfg(windows)]
fn parse_script_params(raw: &str) -> (String, String, String, String) {
    if raw.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(script) = v.get("script").and_then(|x| x.as_str()) {
                let f = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let run_as = v.get("run_as").and_then(|x| x.as_str()).unwrap_or("system").to_string();
                return (script.to_string(), run_as, f("username"), f("password"));
            }
        }
    }
    (raw.to_string(), "system".to_string(), String::new(), String::new())
}

/// Run a script under a DIFFERENT identity than the service: `"user"` = the active console user
/// (CreateProcessAsUser via `run_exe_in_session`), `"credential"` = a supplied account
/// (CreateProcessWithLogonW). Both launchers are fire-and-forget (no waitable child), so we run a
/// wrapper that redirects every PowerShell stream to a temp file and always drops a `done.flag`, then
/// poll for the flag. Temp script + output live in `C:\Windows\Temp\sulltec-job-…` (writable by the
/// target identity) and are deleted afterward; the password is passed only to the Win32 logon API,
/// never to disk.
#[cfg(windows)]
fn run_script_as(script: &str, mode: &str, username: &str, password: &str) -> Value {
    if mode == "credential" && (username.is_empty() || password.is_empty()) {
        return json!({ "ok": false, "error": "run-as credential needs a username and password" });
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::path::Path::new(r"C:\Windows\Temp").join(format!("sulltec-job-{}-{}", std::process::id(), nonce));
    if std::fs::create_dir_all(&dir).is_err() {
        return json!({ "ok": false, "error": "failed to create job temp dir" });
    }
    let inner = dir.join("inner.ps1");
    let wrapper = dir.join("wrapper.ps1");
    let out = dir.join("out.txt");
    let flag = dir.join("done.flag");
    if std::fs::write(&inner, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": "failed to write script" });
    }
    // `*>` captures all six PowerShell streams; `finally` guarantees the flag even if the script throws.
    let wrapper_ps = format!(
        "$ErrorActionPreference='Continue'\r\ntry {{ & '{inner}' *> '{out}' }} catch {{ \"$_\" | Out-File -LiteralPath '{out}' -Append }} finally {{ Set-Content -LiteralPath '{flag}' -Value 'done' }}\r\n",
        inner = inner.display(),
        out = out.display(),
        flag = flag.display(),
    );
    if std::fs::write(&wrapper, wrapper_ps.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": "failed to write wrapper" });
    }
    let ps = powershell_exe();
    let wrapper_str = wrapper.display().to_string();
    let launch = if mode == "credential" {
        let arg = format!("-ExecutionPolicy Bypass -NoProfile -File \"{wrapper_str}\"");
        crate::platform::create_process_with_logon(username, password, &ps, &arg)
    } else {
        let session = crate::platform::get_current_session_id(false);
        crate::platform::run_exe_in_session(
            &ps,
            vec!["-ExecutionPolicy", "Bypass", "-NoProfile", "-File", wrapper_str.as_str()],
            session,
            false,
        )
        .map(|_| ())
    };
    if let Err(e) = launch {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": format!("launch failed ({mode}): {e}") });
    }
    // Poll for completion (10-minute cap) — the launchers gave us no handle to wait on.
    let deadline = now_secs() + 600;
    while now_secs() < deadline && !flag.exists() {
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    let done = flag.exists();
    // Same BOM-decode as the SYSTEM path: the wrapper redirects with `*>`, so 5.1 writes UTF-16LE.
    let output: String = read_ps_output(&out)
        .unwrap_or_else(|e| format!("[console: the script's captured output could not be read: {e}]"))
        .chars()
        .take(60_000)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    if done {
        json!({ "ok": true, "output": output, "run_as": mode })
    } else {
        json!({ "ok": false, "error": "timed out after 10 minutes", "output": output, "run_as": mode })
    }
}
#[cfg(not(windows))]
fn run_script(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}





/// Extract a scalar collector param that may arrive as a **bare string** (the console UI sends it raw)
/// OR **wrapped in a JSON object** by the `/api/diag` route (which serializes its request body). Returns
/// the first matching field for an object, the string for a JSON string, else the raw input. This is
/// what fixes the collectors that expected a raw scalar (`reg-read` = a path, `file-pull` = a path) but
/// were handed a JSON body over the API.
///
/// Several keys are accepted for the same value because callers reasonably spell it differently — a
/// path arrives as `path` from one surface and `file` from another, and reading only the first name
/// silently drops the value rather than failing, which is far harder to notice.
#[cfg(windows)]
fn json_field_or_raw(raw: &str, keys: &[&str]) -> String {
    let raw = raw.trim();
    if raw.starts_with('{') || raw.starts_with('"') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(o) = v.as_object() {
                return keys
                    .iter()
                    .find_map(|k| o.get(*k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()))
                    .unwrap_or("")
                    .to_string();
            }
            if let Some(s) = v.as_str() {
                return s.trim().to_string();
            }
        }
    }
    raw.to_string()
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
///
/// Intentionally reads an ARBITRARY path (an operator pulls a log from anywhere), so — unlike
/// `file_push` — it must NOT be constrained to a write-root via `safe_path`; that would break
/// the feature. Its authorization is the signed job channel (R2): once dispatch-signature enforcement
/// is on, only the console can request a pull. Until then (observe) the `CAP` size limit bounds any one
/// read. Don't bolt a path allow-list on here without making it operator-configurable.
#[cfg(windows)]
fn file_pull(params: Option<&str>) -> Value {
    // A bare path (console UI) or a `{"path":…}` / `{"file":…}` body (/api/diag). Without the unwrap the
    // JSON text itself was passed to `read`, which failed with a filename-syntax error naming the body.
    let path_owned = json_field_or_raw(params.unwrap_or(""), &["path", "file"]);
    let path = path_owned.trim();
    if path.is_empty() {
        return json!({ "ok": false, "error": "file-pull needs a path" });
    }
    const CAP: usize = 128 * 1024; // 128 KB raw keeps the signed result well within limits.
    // The read is bounded BEFORE it allocates. `std::fs::read` sizes its buffer from the file — and
    // grows it without limit when the size hint is 0, as on a device path — so a pull of a pagefile,
    // a VHDX or `\\.\PhysicalDrive0` allocated proportionally to the target, and an allocation failure
    // aborts the process rather than failing the job. CAP+1 is read so a file of exactly CAP is still
    // reported untruncated, as before.
    use std::io::Read;
    let read = std::fs::File::open(path).and_then(|f| {
        let file_size = f.metadata()?.len();
        let mut buf: Vec<u8> = Vec::new();
        f.take(CAP as u64 + 1).read_to_end(&mut buf)?;
        Ok((file_size, buf))
    });
    match read {
        Ok((file_size, mut bytes)) => {
            let truncated = bytes.len() > CAP;
            if truncated {
                bytes.truncate(CAP);
            }
            // The file's own size, so the caller learns how much it did NOT get. A device path can
            // report 0 there, so never understate it below what was actually read.
            let size = file_size.max(bytes.len() as u64);
            match std::str::from_utf8(&bytes) {
                Ok(text) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "text", "content": text }),
                Err(_) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "base64", "content": base64::encode(&bytes, variant()) }),
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// Newest `*.log` under `dir` (and one level of per-component subdirs flexi_logger may create),
/// by modified time. `None` if the dir is absent or holds no log.
#[cfg(windows)]
fn newest_log(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dirs = vec![dir.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path());
            }
        }
    }
    let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("log") {
                continue;
            }
            if let Some(m) = e.metadata().ok().and_then(|md| md.modified().ok()) {
                if best.as_ref().map_or(true, |(bm, _)| m > *bm) {
                    best = Some((m, p));
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// The MAIN service log — where the service writes its heartbeat, job-channel and updater-*check*
/// activity, and so the right default when an operator asks for "the log" without naming one.
///
/// That lives in the `server` subdirectory. It is looked up there FIRST, and only then does this
/// fall back to a top-level `*.log` and finally to `newest_log` (anywhere).
///
/// The order used to be the other way round, and it silently rotted. Top-level was preferred to keep
/// short-lived subprocess logs (`update`, `check-hwcodec-config`, …) from winning on mtime — sound
/// when the client wrote its service log at the top level. It no longer does: every component logs
/// into its own subdirectory, so nothing writes a top-level log any more, and the only files still
/// matching are relics left by the pre-subdirectory layout. The default therefore returned a log
/// frozen months earlier — plausible-looking, correctly formatted, and describing a client that no
/// longer exists. That is worse than an error, because nothing about it announces itself as stale.
///
/// The gate was on "does a top-level log exist" when the question is "which log is the service
/// writing NOW". Preferring `server` answers the second one directly.
#[cfg(windows)]
fn main_log(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    newest_log_in(&dir.join("server"))
        .or_else(|| newest_log_in(dir))
        .or_else(|| newest_log(dir))
}

/// Newest `*.log` directly inside `dir` — no recursion, so a caller can ask about one component
/// without a subdirectory's shorter-lived logs outvoting it on mtime.
#[cfg(windows)]
fn newest_log_in(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("log"))
        .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()).map(|m| (m, e.path())))
        .max_by_key(|(m, _)| *m)
        .map(|(_, p)| p)
}

/// List the client's available log files (`name` relative to the log dir, `size`, local `modified`),
/// newest first — so an operator can see what's there + which is freshest, then fetch a specific one
/// via `client-log` with that `name`. No content; read-only.
#[cfg(windows)]
fn client_logs_list() -> Value {
    let dir = Config::log_path();
    let mut dirs = vec![dir.clone()];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path());
            }
        }
    }
    let mut out: Vec<(i64, Value)> = vec![];
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("log") {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            let modified = meta.modified().ok();
            let mtime = modified
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let modified_str = modified
                .map(|m| chrono::DateTime::<chrono::Local>::from(m).format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            // rel path under the log dir (the `name` selector for client-log), forward-slashed.
            let name = p.strip_prefix(&dir).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            out.push((mtime, json!({ "name": name, "size": meta.len(), "modified": modified_str })));
        }
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    Value::Array(out.into_iter().map(|(_, v)| v).collect())
}

/// Pull the TAIL of one of this client's run logs — written under `Config::log_path()` (machine-wide
/// `%ProgramData%\SullTecRemote\log` for a service install), where the updater + this job channel log
/// their errors, so "didn't update / job failed" is diagnosable from the console without RDP. With no
/// `params` it returns the **main service log**; pass a `name` from `client-logs` to fetch a specific
/// one (confined to the log dir — no traversal). Same `file_pull` shape over the last `CAP` bytes.
///
/// `params` reaches us two ways and BOTH are accepted: the console UI right-click passes a **bare name**
/// (`job_enqueue_h` sends `Option<String>` verbatim), while the REST `/api/diag` path serializes the
/// whole request body to the params string — so `{"name":"foo.log"}` (or `{}` for "no filter", which the
/// MCP bridge sends) arrives as JSON. A real log name always ends in `.log` and never parses as JSON, so
/// the bare form still falls through untouched; a JSON object supplies the name via `name`/`file`/`log`,
/// and an empty/nameless object (or `null`) means "main log".
#[cfg(windows)]
fn client_log_pull(params: Option<&str>) -> Value {
    const CAP: usize = 128 * 1024;
    let dir = Config::log_path();
    let want: Option<String> = params.map(str::trim).filter(|s| !s.is_empty()).and_then(|raw| {
        match serde_json::from_str::<Value>(raw) {
            // JSON object (REST body): the name is under `name` (what `client-logs` emits), or
            // `file`/`log` as aliases. `{}` / a nameless object → None → main log.
            Ok(Value::Object(map)) => ["name", "file", "log"]
                .iter()
                .find_map(|k| map.get(*k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()))
                .map(|s| s.to_string()),
            // A JSON string body (`"foo.log"`) — use it directly.
            Ok(Value::String(s)) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            // `null` / number / bool / array carry no name → main log.
            Ok(_) => None,
            // Not JSON → the bare-name form from the console UI; use verbatim.
            Err(_) => Some(raw.to_string()),
        }
    });
    let path = match want.as_deref() {
        Some(name) => {
            // A specific file from the list — confine to the log dir via canonicalized prefix check.
            let candidate = dir.join(name.replace('/', "\\"));
            match candidate.canonicalize().ok().zip(dir.canonicalize().ok()) {
                Some((cp, cdir)) if cp.starts_with(&cdir) && cp.is_file() => cp,
                _ => return json!({ "ok": false, "error": format!("no such log: {name}") }),
            }
        }
        None => match main_log(&dir) {
            Some(p) => p,
            None => return json!({ "ok": false, "error": format!("no .log under {}", dir.display()) }),
        },
    };
    // Seek to the tail rather than reading the log in and slicing it: a log left unrotated (or a path
    // that resolved to something much larger than a log) would otherwise allocate its whole length,
    // and an allocation failure aborts the process rather than failing the job.
    use std::io::{Read, Seek, SeekFrom};
    let read = std::fs::File::open(&path).and_then(|mut f| {
        let file_size = f.metadata()?.len();
        if file_size > CAP as u64 {
            f.seek(SeekFrom::Start(file_size - CAP as u64))?;
        }
        let mut buf: Vec<u8> = Vec::new();
        f.take(CAP as u64).read_to_end(&mut buf)?;
        Ok((file_size, buf))
    });
    match read {
        Ok((size, bytes)) => {
            let truncated = size > CAP as u64;
            // We hold the LAST CAP bytes (recent activity) — drop the leading partial line + lossily
            // decode (a run log is always UTF-8 text, so no base64 fallback needed).
            let mut slice: &[u8] = &bytes;
            if truncated {
                if let Some(nl) = slice.iter().position(|&b| b == b'\n') {
                    slice = &slice[nl + 1..];
                }
            }
            let text = String::from_utf8_lossy(slice);
            json!({ "ok": true, "path": path.display().to_string(), "size": size, "truncated": truncated, "encoding": "text", "content": text.as_ref() })
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
        let ps = powershell_exe();
        return run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &script], &format!("downloaded to {path}"));
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

#[cfg(not(windows))]
fn file_pull(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
#[cfg(not(windows))]
fn file_push(_params: Option<&str>) -> Value {
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
    // Data plane: a job result carries collector output (capped at 256 KiB — `store::MAX_JOB_RESULT`),
    // but that cap is the only reason the old 12 s total budget held — any collector that outgrows it
    // inherits exactly the failure the updater hit. ⚠ The budget was set when the cap read 64 KiB, so
    // a result four times that size now fits the STORE while the transport budget behind it has never
    // been re-measured. Bulk budget, not the heartbeat's.
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
    // SullTec (H6): the fork side of the CONSOLE-PKG seam — `verify_package` must accept a signature
    // under the CURRENT trusted logon key and reject a tampered tuple, an empty component, and a
    // signature under any OTHER (rotated-out / attacker) key (revocation is preserved by verifying
    // against the current key only).
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
    //! A source lint for one specific footgun that has already cost a release.
    //!
    //! The collector scripts are built as ONE LINE: every line of the Rust literal ends with `\`,
    //! which removes the newline. A PowerShell `#` comment runs to the next newline — so a comment
    //! written with that trailing continuation swallows the entire rest of the script, and the
    //! collector dies with "Missing closing '}'" at RUNTIME, on a device, where it costs a release to
    //! find. Write the comment WITHOUT the trailing backslash so a real newline survives.

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

        // Pin the distinction the filter turns on. Without these, "simplifying" it back to a bare
        // ends_with('\\') looks harmless — the suite stays green — and the cost shows up as a
        // collector failing on a device, which is how this class of bug got here in the first place.
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
    /// `status:"done"` with no error, which is the "ran and found nothing" lie. Measured on
    /// `idrac-power` 2026-08-02 against a host with two healthy PSUs drawing 203 W.
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
    use super::*;

    fn stage(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("stmainlog_{tag}"));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).ok();
        dir
    }

    /// The regression. A pre-subdirectory relic sits at the top level and is written LAST here, so
    /// it also has the newest mtime - the strongest form of the trap, since the old ordering would
    /// have picked it on both counts. The service's own log must still win.
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

    /// An install predating the subdirectory layout still resolves - the fallback is why the fix is
    /// a reorder rather than a replacement.
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
    //! The keyset envelope, pinned against the wire contract the backend half is built to. Every claim
    //! here is one the backend RELIES on: it stops on `more`, resumes on `last`, and decides a set moved
    //! from `set_hash`. Breaking one of these corrupts an assembled set rather than failing a page,
    //! which is why they are pinned apart from the executor that feeds them.
    use super::{bounded_answer, key_text, keyset_exec, keyset_page, keyset_requested, PAGE_BUDGET};
    use serde_json::{json, Value};

    fn rows(pids: &[i64]) -> Vec<Value> {
        pids.iter().map(|p| json!({ "pid": p, "name": format!("p{p}") })).collect()
    }
    fn keys(page: &Value) -> Vec<i64> {
        page["items"].as_array().expect("items").iter().map(|r| r["pid"].as_i64().expect("pid")).collect()
    }

    /// The regression the ordering rule exists for. Rendered as strings, "10" sorts before "9", so a
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

    /// `exec` is the ONLY discriminator, so a backend that has not been updated keeps reaching the
    /// compiled-in collector. Anything looser here would make the hosted path silently mandatory.
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
