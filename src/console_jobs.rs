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
//!     dispatch through `run_kind`; the action kinds rode unverified before this signature gate.

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

/// Kinds whose params the server withholds from the heartbeat; we fetch them with a signed request.
/// (Remote scripts; file pushes — content/path; software deploys — url/dest; AD ops — reset password.)
const SENSITIVE_KINDS: &[&str] = &[
    "script", "file-push", "deploy", "ad",
    // Duplicati API kinds: the console merges this device's sealed Duplicati token into the params at
    // delivery, so they MUST come down the signed fetch rather than the heartbeat. Keep in lockstep
    // with the backend's SENSITIVE_JOB_KINDS / DUPLICATI_TOKEN_KINDS.
    "duplicati-repair", "duplicati-recreate", "duplicati-verify", "duplicati-compact",
    "duplicati-vacuum", "duplicati-browse", "duplicati-log", "duplicati-target-check",
    // iDRAC reads carry the management USERNAME + PASSWORD in their params — the one credential in
    // this list that is a reusable human-style login rather than a scoped machine token, so it must
    // never ride the unauthenticated heartbeat.
    "idrac-storage", "idrac-health", "idrac-sel", "idrac-thermal", "idrac-power",
    "idrac-memory", "idrac-cpu", "idrac-nic", "idrac-firmware", "idrac-jobs",
    "idrac-network", "idrac-accounts", "idrac-services", "idrac-boot", "idrac-licenses",
];

/// In-memory enforce floor: whether to DROP jobs whose console dispatch signature doesn't verify
/// (vs. just observe + run). Learned from each validly-signed heartbeat (the flag rides inside the
/// signed message), default observe. Kept in memory only — a backend that stops signing reverts the
/// fleet to observe (jobs keep running) instead of bricking them, and a fresh signed beat re-arms it.
static JOBS_ENFORCE: AtomicBool = AtomicBool::new(false);
/// Freshness window for a signed dispatch — mirrors the params endpoint's ±5-min anti-replay.
const JOBS_FRESH_SECS: i64 = 300;
/// LocalConfig key: persisted job-id → first-seen-ts dedup. Runs each job-id once within the window,
/// so a captured heartbeat can't replay a job across a client restart and the backend's
/// re-delivery-until-result can't re-run an action kind. Evicted past the window (bounded; lets a
/// job whose result never landed eventually retry).
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

/// Machine-wide path for the shared signing secret: `%ProgramData%\<app_dir_name>\console-job-key`
/// on Windows — readable by every account on the box (the SYSTEM service writes it; user instances
/// read it). `None` off Windows, where the ingest runs single-context and `LocalConfig` suffices.
#[cfg(windows)]
fn machine_key_path() -> Option<std::path::PathBuf> {
    std::env::var_os("ProgramData")
        .map(|p| std::path::PathBuf::from(p).join(hbb_common::config::app_dir_name()).join(KEY_OPT))
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
    let url = format!("{}/api/console/logon-grant", console_url.trim_end_matches('/'));
    let body = json!({ "device_id": device_id, "challenge": challenge }).to_string();
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
    if cur.is_empty() || crate::common::version_key(token) > crate::common::version_key(&cur) {
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
        p.push(config::app_dir_name());
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
        let kind = job.get("kind").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let params = job.get("params").and_then(|x| x.as_str()).map(str::to_owned);
        if job_id.is_empty() {
            continue;
        }
        // Run each job-id once within the freshness window — defeats replay across a restart and the
        // backend's re-delivery-until-result (which would otherwise re-run an action kind).
        if !mark_job_seen(&job_id) {
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

/// Record a job-id as seen, returning true if it's new (should run). Persists a bounded
/// `{job_id: first_seen_ts}` map in LocalConfig, evicting ids older than the freshness window so the
/// set stays small and an aged id can eventually re-run if its result never landed.
fn mark_job_seen(job_id: &str) -> bool {
    let now = now_secs();
    let mut map: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    map.retain(|_, v| v.as_i64().map(|t| (now - t).abs() <= JOBS_FRESH_SECS).unwrap_or(false));
    let fresh = !map.contains_key(job_id);
    if fresh {
        map.insert(job_id.to_owned(), json!(now));
    }
    LocalConfig::set_option(JOBS_SEEN_OPT.to_owned(), Value::Object(map).to_string());
    fresh
}

/// Execute one read-only kind → (status, result-json-or-message). Registry/SMBIOS/process work runs
/// on a blocking thread so it can't stall the async runtime.
async fn run_kind(kind: &str, params: Option<String>) -> (&'static str, String) {
    use hbb_common::tokio::task::spawn_blocking;
    let value: Option<Value> = match kind {
        "inventory" => spawn_blocking(crate::console_inventory::collect).await.ok(),
        "processes" => spawn_blocking(|| crate::console_snapshot::collect("processes")).await.ok().flatten(),
        "services" => spawn_blocking(|| crate::console_snapshot::collect("services")).await.ok().flatten(),
        "defender" => spawn_blocking(|| crate::console_snapshot::collect("defender")).await.ok().flatten(),
        "winupdate" => spawn_blocking(|| crate::console_snapshot::collect("winupdate")).await.ok().flatten(),
        "eventlog" => spawn_blocking(move || eventlog(params.as_deref())).await.ok().flatten(),
        "schtasks" => spawn_blocking(move || ps_json_array(
            "Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Sort-Object TaskPath,TaskName | ConvertTo-Json -Compress",
            400, params.as_deref(), "schtasks",
        )).await.ok().flatten(),
        "startup" => spawn_blocking(move || ps_json_array(
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress",
            200, params.as_deref(), "startup",
        )).await.ok().flatten(),
        "netconn" => spawn_blocking(move || ps_json_array(
            "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress",
            300, params.as_deref(), "netconn",
        )).await.ok().flatten(),
        "pnp" => spawn_blocking(move || ps_json_array(
            "Get-PnpDevice | Select-Object FriendlyName,Class,Status,InstanceId | Sort-Object Class,FriendlyName | ConvertTo-Json -Compress",
            600, params.as_deref(), "pnp",
        )).await.ok().flatten(),
        // Read-only diagnostic deep-read collectors (PLAN §2.5). Each takes an optional JSON filter
        // body and returns a structured, source-filtered result; no state change regardless of params.
        "firewall" => spawn_blocking(move || firewall(params.as_deref())).await.ok().flatten(),
        "firewall-rule" => spawn_blocking(move || firewall_rule(params.as_deref())).await.ok().flatten(),
        "system" => spawn_blocking(|| system_info()).await.ok().flatten(),
        "disks" => spawn_blocking(|| disks()).await.ok().flatten(),
        "localusers" => spawn_blocking(move || localusers(params.as_deref())).await.ok().flatten(),
        "perf" => spawn_blocking(move || perf(params.as_deref())).await.ok().flatten(),
        "reliability" => spawn_blocking(move || reliability(params.as_deref())).await.ok().flatten(),
        "certs" => spawn_blocking(move || certs(params.as_deref())).await.ok().flatten(),
        "adpolicy" => spawn_blocking(|| adpolicy()).await.ok().flatten(),
        // Detailed Resultant-Set-of-Policy deep-read (computer + logged-on users). Content-bearing
        // (exposes security posture + resolved settings) → admin-gated CONSOLE-SIDE like fs/wmi.
        "rsop" => spawn_blocking(move || rsop(params.as_deref())).await.ok().flatten(),
        // Content-bearing: `fs` returns file listings (+ optional hash) and `wmi` returns raw WQL rows;
        // both are admin-gated CONSOLE-SIDE (the fork doesn't gate — it just serves the read-only data).
        "fs" => spawn_blocking(move || fs_list(params.as_deref())).await.ok().flatten(),
        "wmi" => spawn_blocking(move || wmi_query(params.as_deref())).await.ok().flatten(),
        // More read-only diagnostic collectors (PLAN §2.5). `programs` / `drivers` / `sessions` /
        // `printers` are metadata; `env` exposes variable values (admin-gated CONSOLE-SIDE like fs/wmi).
        "programs" => spawn_blocking(move || programs(params.as_deref())).await.ok().flatten(),
        "drivers" => spawn_blocking(move || drivers(params.as_deref())).await.ok().flatten(),
        "sessions" => spawn_blocking(|| sessions()).await.ok().flatten(),
        "printers" => spawn_blocking(move || printers(params.as_deref())).await.ok().flatten(),
        "env" => spawn_blocking(move || env_vars(params.as_deref())).await.ok().flatten(),
        // Server-role deep-read collectors (docs/PLAN-role-collectors.md); console-side role-gated.
        "shares" => spawn_blocking(move || shares(params.as_deref())).await.ok().flatten(),
        "print-queues" => spawn_blocking(move || print_queues(params.as_deref())).await.ok().flatten(),
        "dns-zones" => spawn_blocking(move || dns_zones(params.as_deref())).await.ok().flatten(),
        "dns-records" => spawn_blocking(move || dns_records(params.as_deref())).await.ok().flatten(),
        "dhcp-scopes" => spawn_blocking(move || dhcp_scopes(params.as_deref())).await.ok().flatten(),
        "dhcp-leases" => spawn_blocking(move || dhcp_leases(params.as_deref())).await.ok().flatten(),
        "ad-users" => spawn_blocking(move || ad_users(params.as_deref())).await.ok().flatten(),
        "ad-groups" => spawn_blocking(move || ad_groups(params.as_deref())).await.ok().flatten(),
        "ad-computers" => spawn_blocking(move || ad_computers(params.as_deref())).await.ok().flatten(),
        "ad-ous" => spawn_blocking(move || ad_ous(params.as_deref())).await.ok().flatten(),
        "gpo-list" => spawn_blocking(move || gpo_list(params.as_deref())).await.ok().flatten(),
        "gpo-report" => spawn_blocking(move || gpo_report(params.as_deref())).await.ok().flatten(),
        "hyperv-vms" => spawn_blocking(move || hyperv_vms(params.as_deref())).await.ok().flatten(),
        "rds-sessions" => spawn_blocking(move || rds_sessions(params.as_deref())).await.ok().flatten(),
        // Optional role collectors (docs/PLAN-role-collectors.md §11 "later").
        "dns-health" => spawn_blocking(move || dns_health(params.as_deref())).await.ok().flatten(),
        "dhcp-options" => spawn_blocking(move || dhcp_options(params.as_deref())).await.ok().flatten(),
        "share-sessions" => spawn_blocking(move || share_sessions(params.as_deref())).await.ok().flatten(),
        "print-jobs" => spawn_blocking(move || print_jobs(params.as_deref())).await.ok().flatten(),
        "hyperv-vm" => spawn_blocking(move || hyperv_vm(params.as_deref())).await.ok().flatten(),
        "hyperv-switches" => spawn_blocking(move || hyperv_switches(params.as_deref())).await.ok().flatten(),
        "hyperv-host" => spawn_blocking(move || hyperv_host(params.as_deref())).await.ok().flatten(),
        "rds-config" => spawn_blocking(move || rds_config(params.as_deref())).await.ok().flatten(),
        // Audit-gap server-health collectors. `dcdiag`/`ldaps-check` are console-side role-gated (addc);
        // the rest run on any Windows box. Each returns a single object; a failed read is an explicit
        // `{error}`/`{ok:false}`, never a healthy-looking empty shape.
        "activation" => spawn_blocking(move || activation(params.as_deref())).await.ok().flatten(),
        "vss-health" => spawn_blocking(move || vss_health(params.as_deref())).await.ok().flatten(),
        "backup-state" => spawn_blocking(move || backup_state(params.as_deref())).await.ok().flatten(),
        "dcdiag" => spawn_blocking(move || dcdiag(params.as_deref())).await.ok().flatten(),
        "timesync" => spawn_blocking(move || timesync(params.as_deref())).await.ok().flatten(),
        "ldaps-check" => spawn_blocking(move || ldaps_check(params.as_deref())).await.ok().flatten(),
        "wu-servicing" => spawn_blocking(move || wu_servicing(params.as_deref())).await.ok().flatten(),
        "device-guard" => spawn_blocking(move || device_guard(params.as_deref())).await.ok().flatten(),
        // Duplicati backup reads — operate the endpoint's local Duplicati service via ServerUtil (see
        // the Duplicati block below). Content-bearing (target URLs may embed secrets) → admin-gated
        // console-side.
        "duplicati-backups" => spawn_blocking(|| duplicati_backups()).await.ok().flatten(),
        "duplicati-status" => spawn_blocking(|| duplicati_status()).await.ok().flatten(),
        "duplicati-vss-test" => spawn_blocking(move || duplicati_vss_test(params.as_deref())).await.ok().flatten(),
        "duplicati-browse" => spawn_blocking(move || duplicati_browse(params.as_deref())).await.ok().flatten(),
        "duplicati-log" => spawn_blocking(move || duplicati_log(params.as_deref())).await.ok().flatten(),
        "duplicati-target-check" => spawn_blocking(move || duplicati_target_check(params.as_deref())).await.ok().flatten(),
        "duplicati-datafolder-check" => spawn_blocking(move || duplicati_datafolder_check(params.as_deref())).await.ok().flatten(),
        "idrac-storage" => spawn_blocking(move || idrac_storage(params.as_deref())).await.ok().flatten(),
        "idrac-health" => spawn_blocking(move || idrac_health(params.as_deref())).await.ok().flatten(),
        "idrac-sel" => spawn_blocking(move || idrac_sel(params.as_deref())).await.ok().flatten(),
        "idrac-thermal" => spawn_blocking(move || idrac_thermal(params.as_deref())).await.ok().flatten(),
        "idrac-power" => spawn_blocking(move || idrac_power(params.as_deref())).await.ok().flatten(),
        "idrac-memory" => spawn_blocking(move || idrac_memory(params.as_deref())).await.ok().flatten(),
        "idrac-cpu" => spawn_blocking(move || idrac_cpu(params.as_deref())).await.ok().flatten(),
        "idrac-nic" => spawn_blocking(move || idrac_nic(params.as_deref())).await.ok().flatten(),
        "idrac-firmware" => spawn_blocking(move || idrac_firmware(params.as_deref())).await.ok().flatten(),
        "idrac-jobs" => spawn_blocking(move || idrac_jobs(params.as_deref())).await.ok().flatten(),
        "idrac-network" => spawn_blocking(move || idrac_network(params.as_deref())).await.ok().flatten(),
        "idrac-accounts" => spawn_blocking(move || idrac_accounts(params.as_deref())).await.ok().flatten(),
        "idrac-services" => spawn_blocking(move || idrac_services(params.as_deref())).await.ok().flatten(),
        "idrac-boot" => spawn_blocking(move || idrac_boot(params.as_deref())).await.ok().flatten(),
        "idrac-licenses" => spawn_blocking(move || idrac_licenses(params.as_deref())).await.ok().flatten(),
        // Action kinds (admin-only, console-confirmed). A short delay lets the signed result post
        // before the OS goes down.
        "reboot" => spawn_blocking(|| power_action("/r")).await.ok(),
        "shutdown" => spawn_blocking(|| power_action("/s")).await.ok(),
        // Force-disconnect (S6): close every active incoming session. In-process channel sends —
        // no blocking work, so no spawn_blocking.
        "disconnect" => Some(disconnect_sessions()),
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
        "client-log" => spawn_blocking(move || client_log_pull(params.as_deref())).await.ok(),
        "client-logs" => spawn_blocking(|| client_logs_list()).await.ok(),
        "file-push" => spawn_blocking(move || file_push(params.as_deref())).await.ok(),
        "deploy" => spawn_blocking(move || deploy(params.as_deref())).await.ok(),
        "ad" => spawn_blocking(move || ad_action(params.as_deref())).await.ok(),
        "wol" => spawn_blocking(move || wol(params.as_deref())).await.ok(),
        "defender-scan" => spawn_blocking(move || defender_scan(params.as_deref())).await.ok(),
        "defender-update-sigs" => spawn_blocking(|| defender_update_sigs()).await.ok(),
        "win-update-install" => spawn_blocking(move || win_update_install(params.as_deref())).await.ok(),
        // Duplicati backup actions (operate the local Duplicati service via ServerUtil).
        "duplicati-run" => spawn_blocking(move || duplicati_run(params.as_deref())).await.ok(),
        "duplicati-pause" => spawn_blocking(move || duplicati_pause(params.as_deref())).await.ok(),
        "duplicati-resume" => spawn_blocking(|| duplicati_resume()).await.ok(),
        // Duplicati Server-API maintenance actions (Phase 2b).
        "duplicati-repair" => spawn_blocking(move || duplicati_repair(params.as_deref())).await.ok(),
        "duplicati-recreate" => spawn_blocking(move || duplicati_recreate(params.as_deref())).await.ok(),
        "duplicati-verify" => spawn_blocking(move || duplicati_verify(params.as_deref())).await.ok(),
        "duplicati-compact" => spawn_blocking(move || duplicati_compact(params.as_deref())).await.ok(),
        "duplicati-vacuum" => spawn_blocking(move || duplicati_vacuum(params.as_deref())).await.ok(),
        "duplicati-datafolder-secure" => spawn_blocking(move || duplicati_datafolder_secure(params.as_deref())).await.ok(),
        "duplicati-forever-token-enable" => spawn_blocking(move || duplicati_forever_token_enable(params.as_deref())).await.ok(),
        "duplicati-token-issue" => spawn_blocking(move || duplicati_token_issue(params.as_deref())).await.ok(),
        _ => None,
    };
    match value {
        Some(v) => ("done", v.to_string()),
        None => ("error", format!("the '{kind}' job produced no result (unsupported on this client/OS, or the collector failed)")),
    }
}

/// A JSON number, or a numeric string. The `/api/diag` route delivers a filter body whose values may
/// arrive as strings, so a param that means "a number" has to accept both spellings or it silently
/// stops filtering.
#[cfg(windows)]
fn as_i64_loose(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}

/// Read an int-list filter param in any of the shapes a caller reasonably writes: `4624`, `"4624"`,
/// `"21,23,24"`, or `[21,23,24]`. Non-numeric entries are dropped rather than failing the whole query.
#[cfg(windows)]
fn int_list(v: Option<&Value>) -> Vec<i64> {
    let mut out: Vec<i64> = match v {
        Some(Value::Array(a)) => a.iter().filter_map(as_i64_loose).collect(),
        Some(Value::String(s)) => s.split(',').filter_map(|t| t.trim().parse::<i64>().ok()).collect(),
        Some(other) => as_i64_loose(other).into_iter().collect(),
        None => Vec::new(),
    };
    out.sort_unstable();
    out.dedup();
    out
}

/// Read a string-list filter param (`"a"`, `"a,b"`, `["a","b"]`) and return each entry single-quoted
/// for interpolation into a PowerShell literal, embedded quotes stripped.
#[cfg(windows)]
fn str_list(v: Option<&Value>) -> Vec<String> {
    let quote = |s: &str| format!("'{}'", s.trim().replace('\'', ""));
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).filter(|s| !s.trim().is_empty()).map(quote).collect(),
        Some(Value::String(s)) => s.split(',').filter(|t| !t.trim().is_empty()).map(quote).collect(),
        _ => Vec::new(),
    }
}

/// Build the `Level` / `Id` / `ProviderName` keys of an `eventlog` `-FilterHashtable`, each prefixed
/// with `"; "` so they append to `LogName`. A param the caller omitted produces no key at all —
/// notably `Level`, whose absence returns every severity **including 0 (LogAlways)**, which is what
/// Security audit events are written at and what no list built from a positive default can reach.
///
/// `level` has two spellings on purpose. A scalar keeps the cumulative meaning it always had
/// (`3` ⇒ `@(1,2,3)`), so a caller that pinned one still gets exactly the rows it got before; a list
/// (`[0,4]`) means those levels and no others, which is the only way to express "audit events" or
/// "informational only". A scalar therefore cannot reach 0 — it clamps to 1 — and callers are told so.
#[cfg(windows)]
fn eventlog_filter_clauses(p: &Value) -> String {
    let ps_list = |v: &[i64]| v.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let mut out = String::new();

    let level = p.get("level").filter(|v| !v.is_null());
    let as_list = matches!(level, Some(Value::Array(_))) || matches!(level, Some(Value::String(s)) if s.contains(','));
    match level {
        None => {}
        Some(v) if as_list => {
            let mut lv: Vec<i64> = int_list(Some(v)).into_iter().map(|n| n.clamp(0, 5)).collect();
            lv.sort_unstable();
            lv.dedup();
            if !lv.is_empty() {
                out.push_str(&format!("; Level=@({})", ps_list(&lv)));
            }
        }
        Some(v) => {
            if let Some(n) = as_i64_loose(v) {
                let lv: Vec<i64> = (1..=n.clamp(1, 5)).collect();
                out.push_str(&format!("; Level=@({})", ps_list(&lv)));
            }
        }
    }

    // Filtering by id and provider in the hashtable rather than client-side turns "the four RDS
    // session events" into one bounded query instead of 200 rows fetched and mostly discarded.
    let ids = int_list(p.get("id").or_else(|| p.get("event_id")));
    if !ids.is_empty() {
        out.push_str(&format!("; Id=@({})", ps_list(&ids)));
    }
    let providers = str_list(p.get("provider"));
    if !providers.is_empty() {
        out.push_str(&format!("; ProviderName=@({})", providers.join(",")));
    }
    out
}

/// Recent Windows event-log entries via PowerShell `Get-WinEvent` — System + Application, every
/// severity, newest first, paginated so a page of long messages can't overflow the console's result
/// cap. Optional `params` JSON `{log:"System,Application", level:3|[0,4], id:4624|[21,23], provider:"…",
/// since:"yyyy-MM-dd"|days-int, max:60, offset:0, limit:60}` narrows it (`level` scalar = cumulative
/// max severity, 1 crit … 5 verbose; `level` list = exactly those levels, the only way to ask for 0
/// (LogAlways) and therefore for Security audit events; `since` bounds the window — integer OR an
/// all-digit string = N days back, any other string = a date literal, omitted = newest `max` with no
/// lower bound). Returns a `{total,offset,count,truncated,next_offset?,items}` envelope when the filter
/// matched — with `items: []` when it genuinely matched nothing, including a **cleared or quiet log**,
/// which is the normal state for a low-traffic host and NOT an error — but `{ok:false,error}` when the
/// query itself failed OR a requested channel could not be read. Those are NOT the same: neither may be
/// reported as the other, so an empty page never hides a blow-up and a failure never hides an empty log.
/// Empty off-Windows.
#[cfg(windows)]
fn eventlog(params: Option<&str>) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let logs = p.get("log").and_then(|x| x.as_str()).unwrap_or("System,Application");
    // Row cap. `max` is the documented name; accept the legacy `count` too. Default 60, max 200.
    let max = p.get("max").or_else(|| p.get("count")).and_then(|x| x.as_i64()).unwrap_or(60).clamp(1, 200);
    // `since` bounds the window (mirrors `reliability`): an integer = that many days back, a string = a
    // date/datetime literal (sanitized to date chars). Omitted = newest `max` with no lower bound.
    let days_clause = |d: i64| format!("; StartTime=(Get-Date).AddDays(-{})", d.clamp(1, 3650));
    let start_clause = match p.get("since") {
        Some(Value::Number(n)) => days_clause(n.as_i64().unwrap_or(1)),
        // An all-digit STRING is a day-count, NOT a date. `{"since":"7"}` is the natural JSON shape and
        // is what the /api/diag route delivers, but it used to fall into the date branch below and build
        // `StartTime=[datetime]'7'` — which throws while the -FilterHashtable argument is being
        // constructed, so Get-WinEvent's -ErrorAction never applies: the statement died, stdout came back
        // empty, and the empty-stdout shortcut reported the blow-up as a clean `[]`.
        Some(Value::String(s)) if !s.trim().is_empty() && s.trim().chars().all(|c| c.is_ascii_digit()) => {
            days_clause(s.trim().parse::<i64>().unwrap_or(1))
        }
        Some(Value::String(s)) => {
            let safe: String = s.chars().filter(|c| c.is_ascii_digit() || matches!(c, '-' | '/' | ':' | ' ' | 'T')).take(32).collect();
            if safe.is_empty() { String::new() } else { format!("; StartTime=[datetime]'{safe}'") }
        }
        _ => String::new(),
    };
    // Sanitize the log names (single-quoted, strip embedded quotes).
    let log_arr = logs
        .split(',')
        .map(|l| format!("'{}'", l.trim().replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",");
    let narrowing = eventlog_filter_clauses(&p);
    // `Get-WinEvent` does NOT return an empty set when nothing matches — it raises
    // "No events were found that match the specified selection criteria" and the host exits 1. Left
    // alone, that lands in the failure branch below, so a *cleared or quiet* log is indistinguishable
    // from a broken one (hit live on a host whose System log had simply been cleared: every query
    // shape failed identically, which read as a damaged box). So the script classifies its own
    // outcome and normalizes the exit code:
    //   rows found            → JSON on stdout, exit 0
    //   nothing matched       → empty stdout,   exit 0  ⇒ the valid-empty branch
    //   any other failure     → message on stderr, exit 1 ⇒ the error branch
    // Matched on `FullyQualifiedErrorId` (a stable identifier) rather than the message text, so it
    // survives a non-English host. `-ErrorAction SilentlyContinue` is deliberately KEPT rather than
    // moving to a try/catch on `-ErrorAction Stop`: a multi-log query raises per-log, and Stop would
    // abort the whole query when one of several logs is empty — discarding the other log's real rows.
    // Inspecting `$Error` after the fact preserves those partial results.
    //
    // The empty path needs one more discrimination before it can be trusted. Through
    // `-FilterHashtable`, a channel the process may not READ raises `NoMatchingEventsFound` — the same
    // id a genuinely empty match raises — so the two are indistinguishable at that point. Re-reading
    // each log through `-LogName` separates them: an unreadable channel raises an access failure there,
    // a quiet one still raises only `NoMatchingEventsFound`. One extra one-row read per log, on the
    // empty path only.
    let script = format!(
        "$Error.Clear(); \
         $logs = @({log_arr}); \
         $rows = Get-WinEvent -FilterHashtable @{{LogName=$logs{narrowing}{start_clause}}} -MaxEvents {max} -ErrorAction SilentlyContinue | \
         Select-Object @{{n='time';e={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}},@{{n='log';e={{$_.LogName}}}},@{{n='id';e={{$_.Id}}}},@{{n='level';e={{$_.LevelDisplayName}}}},@{{n='provider';e={{$_.ProviderName}}}},@{{n='message';e={{$_.Message}}}}; \
         if ($rows) {{ $rows | ConvertTo-Json -Compress -Depth 3 }} \
         else {{ \
           $real = @($Error | Where-Object {{ $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }}); \
           if ($real.Count -gt 0) {{ [Console]::Error.WriteLine($real[0].Exception.Message); exit 1 }}; \
           foreach ($n in $logs) {{ \
             try {{ $null = Get-WinEvent -LogName $n -MaxEvents 1 -ErrorAction Stop }} \
             catch {{ \
               if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ \
                 [Console]::Error.WriteLine(('{{0}}: {{1}}' -f $n, $_.Exception.Message)); exit 1 \
               }} \
             }} \
           }} \
         }}; \
         exit 0"
    );
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let trimmed = text.trim();
    // A filter matching nothing (e.g. a tight `since` window, or a log that was simply cleared) yields
    // empty stdout — that's a valid empty result, not a failure. Return an empty page rather than
    // erroring the whole job. But empty stdout ALSO means "the script blew up", and reporting THAT as
    // an empty page reads as "the log is clean" — the worst possible lie for an audit. The script above
    // normalizes the two onto the exit code (no-match ⇒ 0, real failure or unreadable channel ⇒ 1 +
    // stderr), so this branch can trust it and return the collector error shape (`{ok:false,error}`, as
    // `gpo-list` and friends do). Both directions matter: a quiet log reported as failure trains
    // operators to ignore the collector.
    if trimmed.is_empty() {
        let err_text = String::from_utf8_lossy(&out.stderr);
        let err_text = err_text.trim();
        if !err_text.is_empty() || !out.status.success() {
            let detail: String = if err_text.is_empty() {
                format!("Get-WinEvent exited {}", out.status.code().unwrap_or(-1))
            } else {
                err_text.chars().take(2000).collect()
            };
            return Some(json!({ "ok": false, "error": format!("event-log query failed: {detail}") }));
        }
        return Some(paginate(Vec::new(), params, max as usize));
    }
    let parsed: Value = serde_json::from_str(trimmed).ok()?;
    let rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v], // ConvertTo-Json emits a bare object for a single row
        _ => return Some(paginate(Vec::new(), params, max as usize)),
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
    // 200 rows of 400-char messages clears the store cap on its own, so the page is byte-budgeted like
    // every other list collector. The default page is the whole fetched set — `max` still bounds the
    // read — so a caller that passes no `limit` sees what it always did, just wrapped.
    Some(paginate(entries, params, max as usize))
}
#[cfg(not(windows))]
fn eventlog(_params: Option<&str>) -> Option<Value> {
    None
}

// ── Diagnostic deep-read collectors (PLAN §2.5) — read-only, optionally filtered ──────────────────
//
// Each is a native fork-client collector invoking OS query APIs / built-in Windows tools per-job (the
// established READONLY-collector approach — never a resident `.ps1`). They take the same
// `params: Option<&str>` a JSON filter body arrives in (mirroring `eventlog`), filter AT THE SOURCE so
// the signed result stays under the console's 64 KB cap, and never mutate device state regardless of
// params. Off Windows each returns `None` / a "Windows-only" marker like the other Windows collectors.

/// Windows Firewall rules (read-only). `params` JSON filters at the source
/// (`{direction:"Inbound"|"Outbound", action:"Allow"|"Block", enabled:true|false,
///   profile:"Domain"|"Private"|"Public", name:"glob*"}`) plus `{offset,limit}` pagination. Returns
/// `{profiles:[…on/off summary…], rules:{total,offset,count,truncated,next_offset?,items:[{name,display,
/// direction,action,enabled,profile,protocol,local_port,program}, …]}}` — the `profiles` summary is
/// always whole; the rules list is paginated + byte-capped (`paginate`) so it never overflows the result
/// cap. Uses the `NetSecurity` module (`Get-NetFirewallRule` joined with its port/application filters).
#[cfg(windows)]
fn firewall(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    // Build server-side `Where-Object` clauses from the optional filter. Each value is sanitized to a
    // safe set (alphanumerics + a few glob/path chars) before being interpolated into the single-
    // quoted PS literal, so a filter value can't break out of the script.
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?' | '\\' | ':' | '/'))
            .take(256)
            .collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(d) = p.get("direction").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Direction -eq '{}'", safe(d)));
    }
    if let Some(a) = p.get("action").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Action -eq '{}'", safe(a)));
    }
    if let Some(e) = p.get("enabled").and_then(|x| x.as_bool()) {
        clauses.push(format!("$_.Enabled -eq '{}'", if e { "True" } else { "False" }));
    }
    if let Some(n) = p.get("name").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.DisplayName -like '{}'", safe(n)));
    }
    // Profile is a flag string ("Domain, Private, …"); match a substring.
    if let Some(pr) = p.get("profile").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Profile -like '*{}*'", safe(pr)));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" | Where-Object {{ {} }}", clauses.join(" -and "))
    };
    // Port/program live on separate filter objects; resolve them per-rule. Pull up to 2000 rules as a
    // safety bound; the small per-profile on/off summary is always returned in full, and the rules list
    // is paginated + size-capped below so a firewall with hundreds of rules can't overflow the result cap.
    let script = format!(
        "{PS_GUARD}\
         $pr=@(Get-NetFirewallProfile); Stop-OnError 'firewall profiles'; \
         $rl=@(Get-NetFirewallRule{where_clause} | Select-Object -First 2000); Stop-OnError 'firewall rules'; \
         $profiles=@($pr | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.Name; enabled=[bool]$_.Enabled }} }}); \
         $rules=@($rl | ForEach-Object {{ \
           $pf=$_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; \
           $af=$_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue; \
           [pscustomobject]@{{ name=[string]$_.Name; display=[string]$_.DisplayName; direction=[string]$_.Direction; action=[string]$_.Action; enabled=[string]$_.Enabled; profile=[string]$_.Profile; protocol=[string]$pf.Protocol; local_port=([string]($pf.LocalPort -join ',')); program=[string]$af.Program }} \
         }}); \
         [pscustomobject]@{{ profiles=$profiles; rules=$rules }} | ConvertTo-Json -Depth 4 -Compress"
    );
    let raw = ps_json_guarded(&script, "firewall")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let profiles = raw.get("profiles").cloned().unwrap_or_else(|| json!([]));
    let rules = raw.get("rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    // `profiles` (the on/off summary) is small + always whole; `rules` is paginated (offset/limit) + byte-capped.
    Some(json!({ "profiles": profiles, "rules": paginate(rules, params, 150) }))
}
#[cfg(not(windows))]
fn firewall(_params: Option<&str>) -> Option<Value> {
    None
}

/// Windows Firewall rule DEEP-READ (read-only) — the drill-down companion to [`firewall`]. Given a
/// narrowing selector it returns EVERY filter object Windows exposes for each matched rule: address
/// scope (`local_address`/`remote_address`), local/remote ports, program, service, interface +
/// interface-type, and the IPsec/security filter (authentication/encryption/remote user+machine) —
/// the detail the list-oriented `firewall` collector omits. `params` REQUIRES at least one of
/// `name`/`id`/`port`, so it can never dump full detail for the whole rule set:
/// `{name:"glob*" (DisplayName), id:"rule-id substring", port:"3389" (Local OR Remote),
/// direction:"Inbound"|"Outbound", action:"Allow"|"Block", enabled:true|false,
/// profile:"Domain|Private|Public"}` plus `{offset,limit}`. Pair `port` with `direction`/`action`
/// to keep it fast. Returns the standard paginated envelope
/// `{total,offset,count,truncated,next_offset?,items:[…full per-rule detail…]}`; byte-capped.
#[cfg(windows)]
fn firewall_rule(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    // Same sanitizer as `firewall`: constrain each interpolated filter value to a safe glob/path set.
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?' | '\\' | ':' | '/'))
            .take(256)
            .collect()
    };
    let name = p.get("name").and_then(|x| x.as_str()).map(|s| safe(s)).filter(|s| !s.is_empty());
    let id = p.get("id").and_then(|x| x.as_str()).map(|s| safe(s)).filter(|s| !s.is_empty());
    let port = p
        .get("port")
        .and_then(|x| x.as_str().map(str::to_string).or_else(|| x.as_u64().map(|n| n.to_string())))
        .map(|s| safe(&s))
        .filter(|s| !s.is_empty());
    // Require a narrowing selector — a full-detail dump of every rule is never allowed.
    if name.is_none() && id.is_none() && port.is_none() {
        return Some(json!({ "error": "specify at least one of: name (DisplayName glob), id (rule id substring), or port" }));
    }
    let mut clauses: Vec<String> = Vec::new();
    if let Some(d) = p.get("direction").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Direction -eq '{}'", safe(d)));
    }
    if let Some(a) = p.get("action").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Action -eq '{}'", safe(a)));
    }
    if let Some(e) = p.get("enabled").and_then(|x| x.as_bool()) {
        clauses.push(format!("$_.Enabled -eq '{}'", if e { "True" } else { "False" }));
    }
    if let Some(ref n) = name {
        clauses.push(format!("$_.DisplayName -like '{n}'"));
    }
    if let Some(ref i) = id {
        clauses.push(format!("$_.Name -like '*{i}*'"));
    }
    if let Some(pr) = p.get("profile").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Profile -like '*{}*'", safe(pr)));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" | Where-Object {{ {} }}", clauses.join(" -and "))
    };
    // Optional in-script port gate: keep a rule only if its port filter lists the port (Local or Remote).
    let port_gate = match &port {
        Some(pt) => format!("if (-not ($pf -and (($pf.LocalPort -contains '{pt}') -or ($pf.RemotePort -contains '{pt}')))) {{ return }}; "),
        None => String::new(),
    };
    // Join every NetSecurity filter object per rule. `-First 400` bounds the per-rule join work; the
    // final list is paginated + byte-capped so a wide-detail result can't overflow the signed cap.
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-NetFirewallRule{where_clause} | Select-Object -First 400); Stop-OnError 'firewall rules'; \
         @($src | ForEach-Object {{ \
           $pf=$_ | Get-NetFirewallPortFilter; \
           {port_gate}\
           $af=$_ | Get-NetFirewallAddressFilter; \
           $ap=$_ | Get-NetFirewallApplicationFilter; \
           $sv=$_ | Get-NetFirewallServiceFilter; \
           $ia=$_ | Get-NetFirewallInterfaceFilter; \
           $it=$_ | Get-NetFirewallInterfaceTypeFilter; \
           $se=$_ | Get-NetFirewallSecurityFilter; \
           [pscustomobject]@{{ \
             id=[string]$_.Name; display=[string]$_.DisplayName; description=[string]$_.Description; group=[string]$_.DisplayGroup; \
             enabled=[string]$_.Enabled; direction=[string]$_.Direction; action=[string]$_.Action; profile=[string]$_.Profile; \
             edge_traversal=[string]$_.EdgeTraversalPolicy; policy_store_source=[string]$_.PolicyStoreSource; policy_store_source_type=[string]$_.PolicyStoreSourceType; \
             primary_status=[string]$_.PrimaryStatus; status=[string]$_.Status; owner=[string]$_.Owner; \
             protocol=[string]$pf.Protocol; local_port=([string]($pf.LocalPort -join ',')); remote_port=([string]($pf.RemotePort -join ',')); icmp_type=([string]($pf.IcmpType -join ',')); dynamic_target=[string]$pf.DynamicTarget; \
             local_address=([string]($af.LocalAddress -join ',')); remote_address=([string]($af.RemoteAddress -join ',')); \
             program=[string]$ap.Program; package=[string]$ap.Package; service=[string]$sv.Service; \
             interface_alias=([string]($ia.InterfaceAlias -join ',')); interface_type=([string]$it.InterfaceType); \
             authentication=[string]$se.Authentication; encryption=[string]$se.Encryption; override_block_rules=[string]$se.OverrideBlockRules; \
             local_user=[string]$se.LocalUser; remote_user=[string]$se.RemoteUser; remote_machine=[string]$se.RemoteMachine \
           }} \
         }}) | ConvertTo-Json -Depth 4 -Compress"
    );
    let items = match ps_rows_guarded(&script, "firewall-rule") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 40))
}
#[cfg(not(windows))]
fn firewall_rule(_params: Option<&str>) -> Option<Value> {
    None
}

/// System identity + firmware/security posture (read-only). One PowerShell pass: make/model/serial
/// (Win32_ComputerSystem/BIOS), BIOS/UEFI mode + Secure Boot state, TPM presence/ready, RAM/CPU,
/// last-boot + uptime, and a pending-reboot flag (CBS / Windows-Update / pending file-rename). Returns
/// a single object; takes no filter (it's already a small fixed shape).
#[cfg(windows)]
fn system_info() -> Option<Value> {
    const SCRIPT: &str = r#"
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
$cpu = @(Get-CimInstance Win32_Processor)[0]
Stop-OnError 'system inventory'
# UEFI vs legacy BIOS: SecureBoot cmdlets only work on UEFI; their failure implies legacy.
$secureboot = $null; $firmware = 'BIOS'
try { $secureboot = [bool](Confirm-SecureBootUEFI); $firmware = 'UEFI' } catch { $secureboot = $null }
# TPM presence/readiness via the TPM WMI class (no admin-only Get-Tpm dependency).
$tpm_present = $false; $tpm_ready = $false; $tpm_version = ''
try {
  $t = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -Class Win32_Tpm -ErrorAction Stop
  if ($t) { $tpm_present = $true; $tpm_ready = [bool]$t.IsActivated_InitialValue -and [bool]$t.IsEnabled_InitialValue; $tpm_version = [string]$t.SpecVersion }
} catch {}
$lastboot = $os.LastBootUpTime
$uptime_hours = if ($lastboot) { [math]::Round(((Get-Date) - $lastboot).TotalHours,1) } else { -1 }
# Pending-reboot: CBS RebootPending, WU RebootRequired, or a queued PendingFileRenameOperations.
$pending = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }
$pfr = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfr) { $pending = $true }
[PSCustomObject]@{
  manufacturer = [string]$cs.Manufacturer
  model = [string]$cs.Model
  serial = [string]$bios.SerialNumber
  bios_version = ([string]($bios.SMBIOSBIOSVersion))
  bios_release = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { '' }
  firmware = $firmware
  secure_boot = $secureboot
  tpm_present = $tpm_present
  tpm_ready = $tpm_ready
  tpm_version = $tpm_version
  cpu = [string]$cpu.Name
  cpu_cores = [int]$cpu.NumberOfCores
  cpu_logical = [int]$cs.NumberOfLogicalProcessors
  ram_gb = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
  os_caption = [string]$os.Caption
  os_version = [string]$os.Version
  last_boot = if ($lastboot) { $lastboot.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
  uptime_hours = $uptime_hours
  pending_reboot = $pending
} | ConvertTo-Json -Depth 3 -Compress
"#;
    ps_json_guarded(&format!("{PS_GUARD}{SCRIPT}"), "system-info")
}
#[cfg(not(windows))]
fn system_info() -> Option<Value> {
    None
}

/// Disks + volumes (read-only): physical disks (SMART health), partition layout, and per-volume free
/// space + BitLocker protection state. One PowerShell pass returning
/// `{disks:[{number,model,serial,size_gb,health,bus}], volumes:[{letter,label,fs,size_gb,free_gb,
///   free_pct,bitlocker}]}`. No filter (small fixed shape).
#[cfg(windows)]
fn disks() -> Option<Value> {
    const SCRIPT: &str = r#"
$src = @(Get-Disk)
Stop-OnError 'disks'
$disks = @($src | ForEach-Object {
  [PSCustomObject]@{
    number = [int]$_.Number
    model = [string]$_.FriendlyName
    serial = [string]$_.SerialNumber
    size_gb = [math]::Round($_.Size/1GB,1)
    health = [string]$_.HealthStatus
    bus = [string]$_.BusType
    partition_style = [string]$_.PartitionStyle
  }
})
# BitLocker per mount point (may be unavailable on Home SKUs / without the module → empty map).
# Deliberately best-effort: a host without the cmdlet still has readable volumes. Catching the
# exception is NOT enough to make it best-effort — PowerShell records a caught error in $Error
# anyway, so without clearing it the next Stop-OnError would fail the whole collector over a
# BitLocker cmdlet nobody asked about.
$bl = @{}
try { Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { $bl[[string]$_.MountPoint] = [string]$_.ProtectionStatus } } catch {}
$Error.Clear()
$vsrc = @(Get-Volume | Where-Object { $_.DriveLetter })
Stop-OnError 'volumes'
$volumes = @($vsrc | ForEach-Object {
  $mp = "$($_.DriveLetter):"
  [PSCustomObject]@{
    letter = [string]$_.DriveLetter
    label = [string]$_.FileSystemLabel
    fs = [string]$_.FileSystem
    size_gb = [math]::Round($_.Size/1GB,1)
    free_gb = [math]::Round($_.SizeRemaining/1GB,1)
    free_pct = if ($_.Size -gt 0) { [math]::Round(($_.SizeRemaining/$_.Size)*100,1) } else { 0 }
    bitlocker = if ($bl.ContainsKey($mp)) { $bl[$mp] } else { 'Unknown' }
  }
})
[PSCustomObject]@{ disks=$disks; volumes=$volumes } | ConvertTo-Json -Depth 4 -Compress
"#;
    ps_json_guarded(&format!("{PS_GUARD}{SCRIPT}"), "disks")
}
#[cfg(not(windows))]
fn disks() -> Option<Value> {
    None
}

/// Local user accounts + Administrators-group membership (read-only). `params` JSON
/// `{name:"glob*", enabled:true|false}` filters at the source. Returns
/// `[{name,enabled,is_admin,last_logon,password_expires,password_last_set,description}, …]`. Uses the
/// `Microsoft.PowerShell.LocalAccounts` module; admin membership resolved by SID match against the
/// well-known local Administrators group (`Get-LocalGroupMember`, falling back to CIM `Win32_GroupUser`).
/// **`is_admin` is `null`, not `false`, when membership could not be resolved** — treat null as unknown.
#[cfg(windows)]
fn localusers(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?'))
            .take(256)
            .collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(n) = p.get("name").and_then(|x| x.as_str()) {
        clauses.push(format!("$_.Name -like '{}'", safe(n)));
    }
    if let Some(e) = p.get("enabled").and_then(|x| x.as_bool()) {
        clauses.push(format!("$_.Enabled -eq ${}", if e { "true" } else { "false" }));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" | Where-Object {{ {} }}", clauses.join(" -and "))
    };
    // Admin membership: `Get-LocalGroupMember` FIRST, but it is known to fail outright (not per-member)
    // when the group holds an unresolvable/orphaned SID. That failure used to be swallowed by a bare
    // `catch {}`, leaving `$admins` empty so `is_admin` came back **false for every account, including a
    // real administrator** — a false negative that silently understates privilege. Fall back to CIM
    // (`Win32_GroupUser`, scoped `LocalAccount=True` so a domain box doesn't enumerate domain groups),
    // and if BOTH fail emit `is_admin = null` — "couldn't determine", which a consumer can tell apart
    // from a determined `false`. Never guess `false`.
    let script = format!(
        "{PS_GUARD}\
         $admins=@(); $resolved=$false; \
         try {{ $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {{ [string]$_.SID }}); $resolved=$true }} catch {{}}; \
         if(-not $resolved){{ try {{ \
           $g=Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=True' -ErrorAction Stop | Where-Object {{ $_.SID -eq 'S-1-5-32-544' }}; \
           $admins=@(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser -ErrorAction Stop | ForEach-Object {{ [string]$_.SID }}); \
           $resolved=$true \
         }} catch {{}} }}; \
         $Error.Clear(); $src=@(Get-LocalUser{where_clause}); Stop-OnError 'local accounts'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; enabled=[bool]$_.Enabled; \
             is_admin=$(if($resolved){{ [bool]($admins -contains [string]$_.SID) }} else {{ $null }}); \
             last_logon=if($_.LastLogon){{$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}}else{{''}}; \
             password_expires=if($_.PasswordExpires){{$_.PasswordExpires.ToString('yyyy-MM-dd')}}else{{'never'}}; \
             password_last_set=if($_.PasswordLastSet){{$_.PasswordLastSet.ToString('yyyy-MM-dd')}}else{{''}}; \
             description=[string]$_.Description }} \
         }}) | ConvertTo-Json -Depth 3 -Compress"
    );
    match ps_rows_guarded(&script, "localusers") {
        GuardedRows::Failed(e) => Some(e),
        GuardedRows::Rows(v) => Some(Value::Array(v)),
    }
}
#[cfg(not(windows))]
fn localusers(_params: Option<&str>) -> Option<Value> {
    None
}

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
    // Global CPU utilisation (the same idiom console_inventory uses).
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

/// Reliability / crash history (read-only): WER application-crash records (Application-log event 1000,
/// `Windows Error Reporting` 1001), unexpected-shutdown + bugcheck (BSOD) System-log events (Kernel-Power
/// 41, EventLog 6008, BugCheck 1001), and the list of crash minidumps under `%SystemRoot%\Minidump`.
/// `params` JSON `{since:"yyyy-MM-dd"|days-int, max:N}` — `since` bounds the event window (an integer is
/// "that many days back", a string is parsed as a date; default 14 days), `max` caps each event list
/// (default 60, max 200). One PowerShell pass → `{crashes:[…], shutdowns:[…], minidumps:[…]}`.
#[cfg(windows)]
fn reliability(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let max = p.get("max").and_then(|x| x.as_i64()).unwrap_or(60).clamp(1, 200);
    // `since`: an integer = N days back; a string = a date literal (sanitized to date chars). Default 14d.
    let start_expr = match p.get("since") {
        Some(Value::Number(n)) => {
            let days = n.as_i64().unwrap_or(14).clamp(1, 3650);
            format!("(Get-Date).AddDays(-{days})")
        }
        Some(Value::String(s)) => {
            let safe: String = s.chars().filter(|c| c.is_ascii_digit() || matches!(c, '-' | '/' | ':' | ' ' | 'T')).take(32).collect();
            if safe.is_empty() { "(Get-Date).AddDays(-14)".to_owned() } else { format!("[datetime]'{safe}'") }
        }
        _ => "(Get-Date).AddDays(-14)".to_owned(),
    };
    let script = format!(
        r#"{PS_GUARD}
$start = {start_expr}
$max = {max}
$fmt = {{ param($e) [pscustomobject]@{{ time=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); log=[string]$e.LogName; id=[int]$e.Id; level=[string]$e.LevelDisplayName; provider=[string]$e.ProviderName; message=(($e.Message -split "`n")[0]) }} }}
$crashes = @(Get-WinEvent -FilterHashtable @{{ LogName='Application'; ProviderName=@('Application Error','Windows Error Reporting','Application Hang'); StartTime=$start }} -MaxEvents $max -ErrorAction SilentlyContinue | ForEach-Object {{ & $fmt $_ }})
$shutdowns = @(Get-WinEvent -FilterHashtable @{{ LogName='System'; Id=@(41,1001,6008,6005,6006); StartTime=$start }} -MaxEvents $max -ErrorAction SilentlyContinue | ForEach-Object {{ & $fmt $_ }})
Stop-OnError 'reliability events' -Ignore 'NoMatchingEventsFound'
$dmpdir = Join-Path $env:SystemRoot 'Minidump'
$minidumps = @()
if (Test-Path $dmpdir) {{ $minidumps = @(Get-ChildItem -LiteralPath $dmpdir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First $max | ForEach-Object {{ [pscustomobject]@{{ name=$_.Name; size=[int64]$_.Length; modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }} }}) }}
[pscustomobject]@{{ crashes=$crashes; shutdowns=$shutdowns; minidumps=$minidumps }} | ConvertTo-Json -Depth 4 -Compress
"#
    );
    // Collapse + cap the per-event message so the combined result stays under the console's result cap.
    let v = ps_json_guarded(&script, "reliability")?;
    if is_collector_error(&v) {
        return Some(v);
    }
    let mut v = v;
    for key in ["crashes", "shutdowns"] {
        if let Some(arr) = v.get_mut(key).and_then(|x| x.as_array_mut()) {
            for r in arr.iter_mut() {
                if let Some(m) = r.get("message").and_then(|x| x.as_str()) {
                    let collapsed: String = m.split_whitespace().collect::<Vec<_>>().join(" ");
                    let trimmed: String = collapsed.chars().take(300).collect();
                    let trimmed = if trimmed.chars().count() < collapsed.chars().count() { format!("{trimmed}…") } else { trimmed };
                    r["message"] = json!(trimmed);
                }
            }
        }
    }
    Some(v)
}
#[cfg(not(windows))]
fn reliability(_params: Option<&str>) -> Option<Value> {
    None
}

/// Machine-store certificates (read-only). Walks `Cert:\LocalMachine\<store>` and reports
/// subject/issuer/thumbprint/serial + NotBefore/NotAfter, flagging each as expired / expiring (within
/// `expiring_days`, default 30) / ok. `params` JSON `{store:"My"|"Root"|…, expiring_days:N,
/// expiring_only:bool}` — `store` limits to one store (default: all common machine stores), `expiring_only`
/// returns only the expired+expiring set. Reads at most 800 certs and returns `{expiring_days,
/// certs:{total,offset,count,truncated,next_offset?,items}}` — paginated + byte-capped — or
/// `{ok:false,error}` when the store could not be read, which must never read as "nothing deployed".
#[cfg(windows)]
fn certs(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let days = p.get("expiring_days").and_then(|x| x.as_i64()).unwrap_or(30).clamp(0, 3650);
    let expiring_only = p.get("expiring_only").and_then(|x| x.as_bool()).unwrap_or(false);
    // Store name → a safe segment (store names are simple identifiers); empty/invalid ⇒ all stores.
    let store = p.get("store").and_then(|x| x.as_str()).map(|s| {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')).take(64).collect::<String>()
    }).filter(|s| !s.is_empty());
    let path = match &store {
        Some(s) => format!("Cert:\\LocalMachine\\{s}"),
        None => "Cert:\\LocalMachine".to_owned(),
    };
    let filter = if expiring_only { " | Where-Object { $_.status -ne 'ok' }" } else { "" };
    let script = format!(
        r#"{PS_GUARD}
$now = Get-Date
$soon = $now.AddDays({days})
$src = @(Get-ChildItem -Path '{path}' -Recurse | Where-Object {{ $_.PSIsContainer -eq $false -and $_.Thumbprint }} | Select-Object -First 800)
Stop-OnError 'certificate store'
@($src | ForEach-Object {{
  $status = if ($_.NotAfter -lt $now) {{ 'expired' }} elseif ($_.NotAfter -le $soon) {{ 'expiring' }} else {{ 'ok' }}
  [pscustomobject]@{{
    store=($_.PSParentPath -replace '.*LocalMachine\\','')
    subject=[string]$_.Subject
    issuer=[string]$_.Issuer
    thumbprint=[string]$_.Thumbprint
    serial=[string]$_.SerialNumber
    not_before=if($_.NotBefore){{$_.NotBefore.ToString('yyyy-MM-dd')}}else{{''}}
    not_after=if($_.NotAfter){{$_.NotAfter.ToString('yyyy-MM-dd')}}else{{''}}
    days_left=[int][math]::Floor(($_.NotAfter - $now).TotalDays)
    has_private_key=[bool]$_.HasPrivateKey
    status=$status
  }}
}}){filter} | ConvertTo-Json -Depth 3 -Compress
"#
    );
    let items = match ps_rows_guarded(&script, "certs") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(json!({ "expiring_days": days, "certs": paginate(items, params, 200) }))
}
#[cfg(not(windows))]
fn certs(_params: Option<&str>) -> Option<Value> {
    None
}

/// Domain / Group-Policy posture (read-only). One PowerShell pass: domain membership + DC + site,
/// secure-channel health (`Test-ComputerSecureChannel`), this computer's OU (its DN), the applied +
/// denied GPOs and last refresh (parsed from `gpresult /r` — RSoP without admin), and the w32tm time-sync
/// offset vs. the configured source. No params. Returns a single object
/// `{domain, dc, secure_channel, computer_dn, ou, gpresult:{computer_applied,computer_denied,user_applied,
///   last_refresh}, time:{source, offset_seconds}}`.
#[cfg(windows)]
fn adpolicy() -> Option<Value> {
    const SCRIPT: &str = r#"
$cs = Get-CimInstance Win32_ComputerSystem
Stop-OnError 'computer system'
$domain = if ($cs.PartOfDomain) { [string]$cs.Domain } else { '' }
$dc = ''; $site = ''
try { $dc = [string](nltest /dsgetdc:$domain 2>$null | Select-String 'DC:' | ForEach-Object { ($_ -split '\\\\')[-1].Trim() } | Select-Object -First 1) } catch {}
$secure = $null
if ($cs.PartOfDomain) { try { $secure = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $secure = $false } }
$cdn = ''
try {
  $s = New-Object System.DirectoryServices.DirectorySearcher
  $s.Filter = "(&(objectClass=computer)(cn=$env:COMPUTERNAME))"
  $r = $s.FindOne(); if ($r) { $cdn = [string]$r.Properties['distinguishedname'][0] }
} catch {}
$ou = ''
if ($cdn) { $ou = (($cdn -split ',' | Where-Object { $_ -match '^OU=' } | ForEach-Object { ($_ -replace '^OU=','') }) -join '/') }
# gpresult /r → applied + denied GPOs + last refresh (RSoP summary; no admin needed for the user/computer the caller can read)
$capplied=@(); $cdenied=@(); $uapplied=@(); $refresh=''
try {
  $g = gpresult /r /scope:computer 2>$null
  $section=''
  foreach ($ln in $g) {
    $t = $ln.Trim()
    if ($t -match 'Last time Group Policy was applied:\s*(.+)$') { $refresh = $matches[1].Trim() }
    elseif ($t -match '^Applied Group Policy Objects') { $section='applied'; continue }
    elseif ($t -match '(not applied because|were not applied because|Denied)') { $section='denied'; continue }
    elseif ($t -match '^(The (computer|user) is|The following|Group Policy was|Security Group|Resultant)') { $section='' }
    elseif ($t -and $section -eq 'applied' -and $t -notmatch '^-+$' -and $t -ne 'N/A') { $capplied += $t }
    elseif ($t -and $section -eq 'denied' -and $t -notmatch '^-+$' -and $t -ne 'N/A' -and $t -notmatch ':\s*$') { $cdenied += $t }
  }
} catch {}
# w32tm offset vs configured source (the "/" line of monitor; fall back to stripchart parse)
$tsource=''; $toffset=$null
try {
  $st = w32tm /query /status 2>$null
  $src = ($st | Select-String 'Source:'); if ($src) { $tsource = ($src -split ':',2)[1].Trim() }
  $strip = w32tm /stripchart /computer:$tsource /samples:1 /dataonly 2>$null
  $m = ($strip | Select-String ',\s*([+-]?\d+\.?\d*)s'); if ($m) { $toffset = [double]$m.Matches[0].Groups[1].Value }
} catch {}
[pscustomobject]@{
  domain=$domain
  part_of_domain=[bool]$cs.PartOfDomain
  dc=$dc
  secure_channel=$secure
  computer_dn=$cdn
  ou=$ou
  gpresult=[pscustomobject]@{ computer_applied=$capplied; computer_denied=$cdenied; user_applied=$uapplied; last_refresh=$refresh }
  time=[pscustomobject]@{ source=$tsource; offset_seconds=$toffset }
} | ConvertTo-Json -Depth 4 -Compress
"#;
    ps_json_guarded(&format!("{PS_GUARD}{SCRIPT}"), "adpolicy")
}
#[cfg(not(windows))]
fn adpolicy() -> Option<Value> {
    None
}

/// The RSoP deep-read PowerShell (computer + logged-on users). Placeholders (`@INCLUDE_SETTINGS@`,
/// `@USER_FILTER@`, `@MAX_USERS@`) are substituted by [`rsop_core`] — a `.replace()` rather than a
/// `format!` so the script's many `{}` hashtable braces don't need escaping. Read-only throughout:
/// `gpresult /r` (applied/denied GPOs + last-refresh, per scope), `secedit /export` (security posture:
/// account/lockout, audit, key security options), the `GroupPolicy/Operational` log (processing
/// errors/warnings, last 24 h), and — only when settings are requested — `gpresult /x` parsed for the
/// resolved Administrative-Template policy settings. Emits ONE compact object (see [`rsop`]).
#[cfg(windows)]
const RSOP_SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
$includeSettings = @INCLUDE_SETTINGS@
$userFilter = '@USER_FILTER@'
$maxUsers = @MAX_USERS@

$cs = Get-CimInstance Win32_ComputerSystem
$partOfDomain = [bool]$cs.PartOfDomain
$domain = if ($partOfDomain) { [string]$cs.Domain } else { '' }

function Parse-Gpresult($lines) {
  $applied=@(); $denied=@(); $refresh=''
  $section=''
  foreach ($ln in $lines) {
    $t = ([string]$ln).Trim()
    if ($t -match 'Group Policy was applied:\s*(.+)$') { $refresh = $matches[1].Trim() }
    elseif ($t -match '^Applied Group Policy Objects') { $section='applied'; continue }
    elseif ($t -match 'not applied because') { $section='denied'; continue }
    elseif ($t -match '^(The following|Security Group|Resultant|The user|The computer|Group Policy)') { $section='' }
    elseif ($t -and $section -eq 'applied' -and $t -notmatch '^-+$' -and $t -ne 'N/A') { $applied += $t }
    elseif ($t -and $section -eq 'denied' -and $t -notmatch '^-+$' -and $t -ne 'N/A' -and $t -notmatch ':\s*$') { $denied += $t }
  }
  [pscustomobject]@{ applied=$applied; denied=$denied; refresh=$refresh }
}
function Age-Hours($s) { if (-not $s) { return -1 } $s = ($s -replace ' at ',' ').Trim(); try { [int]((New-TimeSpan -Start ([datetime]::Parse($s)) -End (Get-Date)).TotalHours) } catch { -1 } }
function RegVal($h,$k){ if($h){$v=$h[$k]; if($v){($v -split ',')[-1]}else{''}}else{''} }

$lb = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name UserPolicyMode -EA SilentlyContinue).UserPolicyMode
$loopback = switch ([int]$lb) { 1 {'Merge'} 2 {'Replace'} default {'NotConfigured'} }

$cg = @(gpresult /r /scope:computer 2>$null)
$cp = Parse-Gpresult $cg

# GP processing errors/warnings (last 24 h). Windows logs several BENIGN events in this log at
# Error/Warning severity: 6314 ("bandwidth estimation failed - assuming fast link", every refresh) and
# the "Completed <ext> Extension Processing in N ms" timing markers (4016/5016/6016/7016) — a real CSE
# failure logs its OWN distinct event (1085/1096/1112/...), so excluding these avoids a health false-
# positive on every domain box. Pull extra then filter, so genuine errors behind the noise still surface.
$benignGp = @(6314,4016,5016,6016,7016)
$gpErrors=@()
try {
  $gpErrors = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-GroupPolicy/Operational'; Level=2,3; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 -EA SilentlyContinue | Where-Object { $benignGp -notcontains [int]$_.Id } | Select-Object -First 20 | ForEach-Object {
    $m = (([string]$_.Message) -replace '\s+',' ').Trim()
    [pscustomobject]@{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id=[int]$_.Id; level=$(if($_.Level -eq 2){'Error'}else{'Warning'}); message=$m.Substring(0,[Math]::Min(200,$m.Length)) }
  })
} catch {}

# Effective audit policy, read from the ADVANCED (subcategory) policy via auditpol.
#
# The legacy source for this block was secedit's `[Event Audit]` INI section — the BASIC audit
# categories. Once a box uses the advanced subcategory policy (SCENoApplyLegacyAuditPolicy=1, which
# is every modern Windows Server BY DEFAULT), that section reads 0 across the board while the
# effective policy is substantially on. So a fully-audited host reported as entirely unconfigured:
# proven on a server where 8 subcategories were confirmed Success/Failure by `auditpol /get` yet a
# fresh rsop still returned all-zeros, and it produced a real overstated "no security telemetry"
# audit finding. Same false-negative-in-the-safe-looking-direction class as the other collector bugs.
#
# Categories are selected by GUID, not name — stable and identical on a non-English host. Values keep
# the legacy 0-3 encoding (0 none, 1 success, 2 failure, 3 both) so existing consumers are unchanged.
# $null means "could not determine", which is deliberately NOT 0: an undetermined category must never
# render as "unaudited", because that is the exact false negative this fix exists to remove.
function Get-AuditCat($guid){
  try {
    $lines = @(auditpol /get /category:"$guid" /r 2>$null | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -lt 2) { return $null }
    $v = 0; $known = $false
    foreach($r in @($lines | ConvertFrom-Csv)){
      # By COLUMN INDEX (4 = "Inclusion Setting"), since the CSV header is localized too.
      $props = @($r.PSObject.Properties)
      if ($props.Count -lt 5) { continue }
      $s = [string]$props[4].Value
      if (-not $s) { continue }
      # The setting VALUES are localized as well; an unrecognized one leaves the category
      # undetermined rather than silently contributing a 0.
      if ($s -match 'No Auditing') { $known = $true; continue }
      if ($s -match 'Success') { $v = $v -bor 1; $known = $true }
      if ($s -match 'Failure') { $v = $v -bor 2; $known = $true }
    }
    if (-not $known) { return $null }
    return $v
  } catch { return $null }
}
$auditCats = [ordered]@{
  account_logon = '{69979850-797A-11D9-BED3-505054503030}'
  logon         = '{69979849-797A-11D9-BED3-505054503030}'
  object_access = '{6997984A-797A-11D9-BED3-505054503030}'
  privilege_use = '{6997984B-797A-11D9-BED3-505054503030}'
  policy_change = '{6997984D-797A-11D9-BED3-505054503030}'
}
$auditEff=@{}; $auditOk=$false
foreach($k in @($auditCats.Keys)){
  $val = Get-AuditCat $auditCats[$k]
  $auditEff[$k] = $val
  if ($null -ne $val) { $auditOk = $true }
}

$security=$null
try {
  $inf = Join-Path $env:TEMP ('st_sec_'+$PID+'.inf')
  secedit /export /cfg $inf /quiet | Out-Null
  $ini=@{}; $s=''
  foreach($ln in Get-Content $inf){
    if($ln -match '^\[(.+)\]'){ $s=$matches[1]; $ini[$s]=@{}; continue }
    if($s -and $ln -match '^(.+?)=(.*)$'){ $ini[$s][$matches[1].Trim()]=$matches[2].Trim() }
  }
  Remove-Item $inf -Force -EA SilentlyContinue
  $sa=$ini['System Access']; $ea=$ini['Event Audit']; $rv=$ini['Registry Values']
  $security=[pscustomobject]@{
    account=[pscustomobject]@{
      min_password_length=[int]$sa['MinimumPasswordLength']
      password_complexity=([int]$sa['PasswordComplexity'] -eq 1)
      max_password_age=[int]$sa['MaximumPasswordAge']
      lockout_threshold=[int]$sa['LockoutBadCount']
      lockout_duration=[int]$sa['LockoutDuration']
      clear_text_password=([int]$sa['ClearTextPassword'] -eq 1)
    }
    # Effective (advanced) policy when auditpol answered; the legacy basic categories only as a
    # fallback for a box too old to have them — reported in `audit_source` so a consumer can tell
    # which it is looking at rather than having to guess.
    audit=[pscustomobject]@{
      logon=$(if($auditOk){$auditEff['logon']}else{[int]$ea['AuditLogonEvents']})
      account_logon=$(if($auditOk){$auditEff['account_logon']}else{[int]$ea['AuditAccountLogon']})
      policy_change=$(if($auditOk){$auditEff['policy_change']}else{[int]$ea['AuditPolicyChange']})
      privilege_use=$(if($auditOk){$auditEff['privilege_use']}else{[int]$ea['AuditPrivilegeUse']})
      object_access=$(if($auditOk){$auditEff['object_access']}else{[int]$ea['AuditObjectAccess']})
    }
    audit_source=$(if($auditOk){'auditpol'}else{'secedit-legacy'})
    options=[pscustomobject]@{
      smb_signing_required=((RegVal $rv 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature') -eq '1')
      lsa_runasppl=([int]((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -EA SilentlyContinue).RunAsPPL) -ne 0)
      restrict_anonymous=((RegVal $rv 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous') -eq '1')
      no_lm_hash=((RegVal $rv 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLmHash') -eq '1')
      uac_enabled=((RegVal $rv 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA') -eq '1')
    }
  }
} catch {}

$targets=@()
if ($userFilter) { $targets=@($userFilter) }
else {
  try {
    $ids = @(Get-CimInstance Win32_LogonSession -EA SilentlyContinue | Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } | ForEach-Object { [string]$_.LogonId })
    $set=[ordered]@{}
    foreach($lu in Get-CimInstance Win32_LoggedOnUser -EA SilentlyContinue){
      $lid = [string]$lu.Dependent.LogonId
      if ($ids -notcontains $lid) { continue }
      $d=[string]$lu.Antecedent.Domain; $n=[string]$lu.Antecedent.Name
      if (-not $n -or $n -match '\$$') { continue }
      # DWM-N / UMFD-N are the Desktop Window Manager + font-driver virtual accounts; they log on
      # interactively under the COMPUTER's netbios "domain", so the domain denylist below misses them.
      if ($n -match '^(DWM|UMFD)-\d+$') { continue }
      if ($n -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE')) { continue }
      if ($d -in @('NT AUTHORITY','Window Manager','Font Driver Host','')) { continue }
      $key = "$d\$n"
      if (-not $set.Contains($key)) { $set[$key]=$true }
    }
    $targets=@($set.Keys | Select-Object -First $maxUsers)
  } catch {}
}

$users=@()
foreach($u in $targets){
  $ug = @(gpresult /r /scope:user /user "$u" 2>$null)
  $upp = Parse-Gpresult $ug
  $users += [pscustomobject]@{
    user=$u
    last_refresh=$upp.refresh
    refresh_age_hours=(Age-Hours $upp.refresh)
    applied_gpos=@($upp.applied | Select-Object -First 20)
    denied_gpos=@($upp.denied | Select-Object -First 20)
  }
}

$settings_raw=@()
if ($includeSettings) {
  function Extract-Settings($xmlPath,$scopeLabel){
    $out=@()
    if (Test-Path $xmlPath) {
      try {
        [xml]$x = Get-Content $xmlPath -Raw
        foreach($pol in $x.SelectNodes("//*[local-name()='Policy']")){
          $nm=$pol.SelectSingleNode("*[local-name()='Name']").InnerText
          if(-not $nm){continue}
          $stt=$pol.SelectSingleNode("*[local-name()='State']").InnerText
          $cat=$pol.SelectSingleNode("*[local-name()='Category']").InnerText
          $out += [pscustomobject]@{ scope=$scopeLabel; name=$nm; state=$stt; category=$cat }
        }
      } catch {}
      Remove-Item $xmlPath -Force -EA SilentlyContinue
    }
    $out
  }
  $cx = Join-Path $env:TEMP ('st_rsop_c_'+$PID+'.xml')
  gpresult /f /x $cx /scope:computer 2>$null | Out-Null
  $settings_raw += Extract-Settings $cx 'computer'
  $ui=0
  foreach($u in $targets){
    if($ui -ge 3){break}
    $ux = Join-Path $env:TEMP ('st_rsop_u'+$ui+'_'+$PID+'.xml')
    gpresult /f /x $ux /scope:user /user "$u" 2>$null | Out-Null
    $settings_raw += Extract-Settings $ux ('user:'+$u)
    $ui++
  }
  $settings_raw = @($settings_raw | Select-Object -First 3000)
}

[pscustomobject]@{
  part_of_domain=$partOfDomain
  domain=$domain
  loopback=$loopback
  computer=[pscustomobject]@{
    last_refresh=$cp.refresh
    refresh_age_hours=(Age-Hours $cp.refresh)
    applied_gpos=@($cp.applied | Select-Object -First 50)
    denied_gpos=@($cp.denied | Select-Object -First 50)
  }
  users=$users
  errors=$gpErrors
  error_count=$gpErrors.Count
  security=$security
  settings_raw=$settings_raw
} | ConvertTo-Json -Depth 6 -Compress
"#;

/// Run the RSoP deep-read (shared by the on-demand `rsop` collector and the periodic `policy`
/// snapshot). `include_settings` adds the resolved Administrative-Template settings (slower —
/// `gpresult /x` per scope); `user_filter` targets ONE `DOMAIN\user` instead of enumerating the
/// logged-on set; `max_users` caps that enumeration. Returns the parsed object (`None` on failure).
#[cfg(windows)]
pub(crate) fn rsop_core(include_settings: bool, user_filter: Option<&str>, max_users: usize) -> Option<Value> {
    // Sanitize the optional DOMAIN\user target before interpolating it into the single-quoted PS literal.
    let safe_user: String = user_filter
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '\\' | '@' | '$'))
        .take(128)
        .collect();
    let script = RSOP_SCRIPT
        .replace("@INCLUDE_SETTINGS@", if include_settings { "$true" } else { "$false" })
        .replace("@USER_FILTER@", &safe_user)
        .replace("@MAX_USERS@", &max_users.to_string());
    ps_json(&script)
}
#[cfg(not(windows))]
pub(crate) fn rsop_core(_include_settings: bool, _user_filter: Option<&str>, _max_users: usize) -> Option<Value> {
    None
}

/// Detailed Resultant Set of Policy (read-only) — the deep-read companion to `adpolicy`'s summary.
/// The client service runs as LocalSystem (elevated), so it resolves BOTH computer scope and each
/// logged-on interactive/RDP user's scope. Two complementary modes via the optional filter body:
///   * default (`{}`) — the *posture* view: per-scope applied/denied GPOs, last-refresh + age,
///     loopback mode, the `GroupPolicy/Operational` errors (last 24 h), and the machine security
///     posture (`secedit`: account/lockout, audit, key security options);
///   * `{"settings":true}` — the *drill-in*: the resolved Administrative-Template settings
///     (`{scope,name,state,category}`) as a PAGINATED list (`{offset,limit}`, byte-capped), with the
///     verbose GPO/errors/security context trimmed so a page always fits the signed-result cap.
/// `{"user":"DOMAIN\\name"}` targets one user instead of all logged-on. Object-shaped; the health
/// engine consumes a compact reduction of the same data via the `policy` snapshot.
#[cfg(windows)]
fn rsop(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let include_settings = p.get("settings").and_then(|x| x.as_bool()).unwrap_or(false);
    let user_filter = p.get("user").and_then(|x| x.as_str());
    let mut v = rsop_core(include_settings, user_filter, 10)?;
    // The core always emits the flat `settings_raw`. In settings mode, paginate it (and trim the
    // verbose posture fields so one page + context stays under the ~64 KB signed cap); otherwise drop it.
    let raw = v.as_object_mut().and_then(|o| o.remove("settings_raw"));
    if include_settings {
        let items = match raw {
            Some(Value::Array(a)) => a,
            _ => Vec::new(),
        };
        if let Some(o) = v.as_object_mut() {
            if let Some(c) = o.get_mut("computer").and_then(|c| c.as_object_mut()) {
                c.remove("applied_gpos");
                c.remove("denied_gpos");
            }
            if let Some(us) = o.get_mut("users").and_then(|u| u.as_array_mut()) {
                for u in us.iter_mut() {
                    if let Some(uo) = u.as_object_mut() {
                        uo.remove("applied_gpos");
                        uo.remove("denied_gpos");
                    }
                }
            }
            o.remove("errors");
            o.remove("security");
            o.insert("settings".to_string(), paginate(items, params, 250));
        }
    }
    Some(v)
}
#[cfg(not(windows))]
fn rsop(_params: Option<&str>) -> Option<Value> {
    None
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

/// Filesystem listing at a specified root (read-only). CONTENT-ADJACENT: returns directory entries
/// (name/path/size/modified/attrs) and, with `hash`, the SHA-256 of matched files — but NOT file
/// *contents* in this pass (a `read` (contents) mode is a TODO; the console admin-gates this collector).
/// `params` JSON `{path (required root), recurse:bool, depth:N, glob:"*.log", min_size:bytes,
/// modified_since:"yyyy-MM-dd"|days, hidden:bool, hash:bool}`. Walks with `std::fs` (no shell), capped at
/// 1000 entries; the SAM/SECURITY/LSA/DPAPI-equivalent denylist below blocks credential-store paths even
/// though the client runs as SYSTEM. Returns `{path, recurse, truncated, count, entries:[…]}`.
#[cfg(windows)]
fn fs_list(params: Option<&str>) -> Option<Value> {
    use hbb_common::sha2::{Digest, Sha256};
    const CAP: usize = 1000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let root = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if root.is_empty() {
        return Some(json!({ "error": "fs needs a path (root)" }));
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
        return Some(json!({ "error": "path is in the sensitive-store denylist (SAM/SECURITY/NTDS/DPAPI); refused" }));
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
    // Iterative DFS with an explicit (path, depth) stack so a deep tree can't blow the call stack.
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(std::path::PathBuf::from(root), 1)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
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
                let mut e = json!({
                    "name": name,
                    "path": path.to_string_lossy(),
                    "is_dir": is_dir,
                    "size": if is_dir { 0 } else { meta.len() },
                    "modified": modified.map(fmt_time).unwrap_or_default(),
                    "attrs": attrs,
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
                    truncated = true;
                    break 'walk;
                }
            }
            // Descend into subdirectories (honouring recurse + depth; hidden dirs already skipped above).
            if is_dir && recurse && depth < max_depth {
                stack.push((path, depth + 1));
            }
        }
    }
    Some(json!({
        "path": root,
        "recurse": recurse,
        "truncated": truncated,
        "count": entries.len(),
        "entries": entries,
        // NOTE: file `read` (contents) is intentionally NOT implemented in this pass — listing + hash only.
    }))
}
#[cfg(not(windows))]
fn fs_list(_params: Option<&str>) -> Option<Value> {
    None
}

/// Generic read-only WQL `SELECT` (the LLM escape hatch). CONTENT-BEARING (admin-gated console-side).
/// `params` JSON `{namespace:"root\\cimv2", query:"SELECT … FROM …", max:N}`. SELECT-ONLY by construction:
/// the query must start with `SELECT` and must NOT contain method-call / write tokens
/// (`__`-class refs, `ExecMethod`, `Put`, `Delete`, `Create`, `;`), else an error result is returned and
/// nothing runs. Rows capped (default 200, max 1000). Returns `{namespace, query, truncated, count, rows:[…]}`.
#[cfg(windows)]
fn wmi_query(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let ns_raw = p.get("namespace").and_then(|x| x.as_str()).unwrap_or("root\\cimv2").trim();
    let query = p.get("query").and_then(|x| x.as_str()).unwrap_or("").trim();
    let max = p.get("max").and_then(|x| x.as_i64()).unwrap_or(200).clamp(1, 1000);
    if query.is_empty() {
        return Some(json!({ "error": "wmi needs a WQL query" }));
    }
    // SELECT-only gate. Reject anything that isn't a plain SELECT, any statement separator, and any
    // write/method token (case-insensitive) — so this read-only escape hatch can never mutate.
    let upper = query.to_uppercase();
    if !upper.trim_start().starts_with("SELECT") {
        return Some(json!({ "error": "wmi is SELECT-only (query must start with SELECT)" }));
    }
    // Disallowed substrings: method invocation / instance writes / class-method refs / chaining.
    const FORBIDDEN: &[&str] = &["__", "EXECMETHOD", "EXECNOTIFICATION", " PUT", "PUTINSTANCE", "DELETEINSTANCE", "CREATEINSTANCE", "INVOKE", "SPAWNINSTANCE", ";"];
    if FORBIDDEN.iter().any(|f| upper.contains(f)) || query.contains(';') {
        return Some(json!({ "error": "wmi query contains a disallowed token (method call / write / chaining); SELECT-only" }));
    }
    // Namespace → a safe value (alnum + the WMI path separators); the query → single-quote-escaped for
    // the PS literal. Both interpolate into a Get-CimInstance -Query call, which itself only READS.
    let ns: String = ns_raw.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '\\' | '/' | '_' | '-')).take(128).collect();
    let ns = if ns.is_empty() { "root\\cimv2".to_owned() } else { ns };
    let q_esc = query.replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop'; try {{ \
           @(Get-CimInstance -Namespace '{ns}' -Query '{q_esc}' -ErrorAction Stop | Select-Object -First {max} | \
             ForEach-Object {{ $o=$_; $h=[ordered]@{{}}; $o.CimInstanceProperties | Where-Object {{ $_.Name -notmatch '^Cim' }} | ForEach-Object {{ $h[$_.Name]=[string]$_.Value }}; [pscustomobject]$h }}) | \
           ConvertTo-Json -Depth 3 -Compress \
         }} catch {{ [pscustomobject]@{{ error=[string]$_.Exception.Message }} | ConvertTo-Json -Compress }}"
    );
    let parsed = ps_json(&script)?;
    // A bare {error:…} object surfaced from the catch → pass it through as an error result.
    if parsed.get("error").is_some() && !parsed.is_array() {
        return Some(json!({ "namespace": ns, "query": query, "error": parsed.get("error").and_then(|x| x.as_str()).unwrap_or("query failed") }));
    }
    let mut rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v],
        _ => Vec::new(),
    };
    let truncated = rows.len() as i64 >= max;
    // Char-cap any over-long string value so a wide row can't blow the 64 KB result cap.
    for r in rows.iter_mut() {
        if let Some(obj) = r.as_object_mut() {
            for (_k, val) in obj.iter_mut() {
                if let Some(s) = val.as_str() {
                    if s.chars().count() > 500 {
                        *val = json!(s.chars().take(500).collect::<String>() + "…");
                    }
                }
            }
        }
    }
    Some(json!({ "namespace": ns, "query": query, "truncated": truncated, "count": rows.len(), "rows": rows }))
}
#[cfg(not(windows))]
fn wmi_query(_params: Option<&str>) -> Option<Value> {
    None
}

/// Installed software (read-only). Enumerates the three Uninstall registry views — HKLM 64-bit, HKLM
/// WOW6432Node (32-bit installs on a 64-bit OS), and HKCU (per-user installs) — NOT `Win32_Product`
/// (notoriously slow + triggers an MSI self-repair on every row). `params` JSON `{name_filter,
/// publisher_filter}` are case-insensitive substrings applied AT THE SOURCE. Returns
/// `[{name,version,publisher,install_date,scope}, …]`, capped at 1000 entries. Skips entries with no
/// DisplayName and the update/patch rows (SystemComponent=1 / a parent) the way Add-Remove Programs does.
#[cfg(windows)]
fn programs(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    // Substring filters → single-quoted PS `-like '*…*'` literals; sanitize to a safe set so the value
    // can't break out of the literal (mirrors the firewall/localusers source-filter approach).
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '+' | '&' | ',' | '*' | '?'))
            .take(256)
            .collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(n) = p.get("name_filter").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.name -like '*{}*'", safe(n)));
    }
    if let Some(pub_f) = p.get("publisher_filter").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.publisher -like '*{}*'", safe(pub_f)));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" | Where-Object {{ {} }}", clauses.join(" -and "))
    };
    // Three Uninstall views, each tagged with its scope; skip rows without a DisplayName and the
    // SystemComponent-hidden patch/update rows. `Get-ItemProperty` only READS the registry.
    let script = format!(
        "{PS_GUARD}\
         $roots=@( \
           @{{ p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s='machine' }}, \
           @{{ p='HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s='machine-wow64' }}, \
           @{{ p='HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s='user' }} \
         ); \
         $src=@($roots | ForEach-Object {{ $scope=$_.s; Get-ItemProperty -Path $_.p | \
           Where-Object {{ $_.DisplayName -and -not ($_.SystemComponent -eq 1) }} | ForEach-Object {{ \
             [pscustomobject]@{{ name=[string]$_.DisplayName; version=[string]$_.DisplayVersion; publisher=[string]$_.Publisher; install_date=[string]$_.InstallDate; scope=$scope }} \
           }} }}); \
         Stop-OnError 'uninstall registry' -Ignore 'PathNotFound','ItemNotFound'; \
         @($src){where_clause} | Sort-Object name | Select-Object -First 1000 | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "programs") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 250))
}
#[cfg(not(windows))]
fn programs(_params: Option<&str>) -> Option<Value> {
    None
}

/// Installed device drivers (read-only) via `Win32_PnPSignedDriver` (the same CIM source `driverquery
/// /v` reports from, but already JSON-shaped). `params` JSON `{filter}` is a case-insensitive substring
/// matched against the device name OR provider, applied at the source; plus `{offset,limit}` pagination.
/// Returns the paginated shape `{total,offset,count,truncated,next_offset?,items:[{device,version,
/// provider,date,class,signed,inf}, …]}` (byte-capped per page; the source list is sorted by device).
#[cfg(windows)]
fn drivers(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '*' | '?' | ','))
            .take(256)
            .collect()
    };
    // One substring matched against device name OR provider (a single `-like` over both fields).
    let where_clause = match p.get("filter").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        Some(f) => {
            let f = safe(f);
            format!(" | Where-Object {{ $_.device -like '*{f}*' -or $_.provider -like '*{f}*' }}")
        }
        None => String::new(),
    };
    // DriverDate is a CIM datetime; format it to yyyy-MM-dd when present. `IsSigned` → bool.
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-CimInstance Win32_PnPSignedDriver | Where-Object {{ $_.DeviceName }}); Stop-OnError 'driver inventory'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ device=[string]$_.DeviceName; version=[string]$_.DriverVersion; provider=[string]$_.DriverProviderName; \
             date=if($_.DriverDate){{([datetime]$_.DriverDate).ToString('yyyy-MM-dd')}}else{{''}}; class=[string]$_.DeviceClass; \
             signed=[bool]$_.IsSigned; inf=[string]$_.InfName }} \
         }}){where_clause} | Sort-Object device -Unique | Select-Object -First 1000 | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "drivers") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 250))
}
#[cfg(not(windows))]
fn drivers(_params: Option<&str>) -> Option<Value> {
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

/// Installed printers (read-only) via the `PrintManagement` module (`Get-Printer`). `params` JSON
/// `{filter}` is a case-insensitive substring over the printer name, applied at the source. Returns
/// `[{name,driver,port,shared,share_name,status,default,type}, …]`, capped at 500 entries. The default
/// printer is resolved separately (Win32_Printer.Default) and flagged per row.
#[cfg(windows)]
fn printers(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '*' | '?' | '\\' | ',' | '#'))
            .take(256)
            .collect()
    };
    let where_clause = match p.get("filter").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        Some(f) => format!(" | Where-Object {{ $_.name -like '*{}*' }}", safe(f)),
        None => String::new(),
    };
    // Get-Printer for the inventory + status; Win32_Printer for the Default flag (no Get-Printer prop).
    let script = format!(
        "{PS_GUARD}\
         $def=@{{}}; Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue | ForEach-Object {{ if($_.Default){{ $def[[string]$_.Name]=$true }} }}; \
         $Error.Clear(); \
         $src=@(Get-Printer); Stop-OnError 'printers'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; driver=[string]$_.DriverName; port=[string]$_.PortName; \
             shared=[bool]$_.Shared; share_name=[string]$_.ShareName; status=[string]$_.PrinterStatus; \
             type=[string]$_.Type; default=[bool]($def.ContainsKey([string]$_.Name)) }} \
         }}){where_clause} | Sort-Object name | Select-Object -First 500 | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "printers") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn printers(_params: Option<&str>) -> Option<Value> {
    None
}

// ── Server-role deep-read collectors (docs/PLAN-role-collectors.md). Each is read-only, gated
// CONSOLE-SIDE on the device's `roles` fingerprint (the fork just serves the data). All follow the
// existing collector shape: a PowerShell/ADSI/WMI one-liner → `ps_rows_guarded` → `paginate`. ──

/// A share is admin/special (hidden by default) per §7.1: OS `Special` flag, a non-`FileSystemDirectory`
/// share type, or a well-known system-share name. Everything else is a *user* share. Shared inline into
/// the PS scripts that need the classification.
#[cfg(windows)]
const SHARE_SYS_NAMES_PS: &str = "@('SYSVOL','NETLOGON','PRINT$','FAX$','CertEnroll')";

/// File-server shares (role `fileserver`) — SMB shares with the §7.1 admin/user classification and
/// per-share ACLs. `params` `{name:"glob", include_admin:"bool (default false)", acl:"bool (default
/// false)", limit, offset}`. Default hides admin/special shares and returns only `ace_count`; `acl:true`
/// adds the full ACE list (the inline-field gate — output shape otherwise unchanged). Paginated.
#[cfg(windows)]
fn shares(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let include_admin = p.get("include_admin").and_then(|x| x.as_bool()).unwrap_or(false);
    let want_acl = p.get("acl").and_then(|x| x.as_bool()).unwrap_or(false);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '$' | '*' | '?')).take(128).collect()
    };
    let name_filter = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|f| format!(" | Where-Object {{ $_.Name -like '*{}*' }}", safe(f)))
        .unwrap_or_default();
    let acl_field = if want_acl {
        "acl=@($aces | ForEach-Object { [pscustomobject]@{ account=[string]$_.AccountName; rights=[string]$_.AccessRight; allow=($_.AccessControlType -eq 'Allow') } });"
    } else {
        ""
    };
    let script = format!(
        "{PS_GUARD}$sys={SHARE_SYS_NAMES_PS}; \
         $src=@(Get-SmbShare{name_filter}); Stop-OnError 'shares'; \
         @($src | ForEach-Object {{ \
           $sp=[bool]$_.Special; $st=[string]$_.ShareType; \
           $admin=($sp -or ($st -ne 'FileSystemDirectory') -or ($sys -contains $_.Name)); \
           $aces=@(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue); \
           [pscustomobject]@{{ name=[string]$_.Name; path=[string]$_.Path; description=[string]$_.Description; \
             share_type=$st; scope_name=[string]$_.ScopeName; admin=$admin; special_flag=$sp; \
             ace_count=$aces.Count; {acl_field} caching=[string]$_.CachingMode; \
             encrypt_data=[bool]$_.EncryptData; current_users=[int]$_.CurrentUsers }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 4 -Compress"
    );
    let items: Vec<Value> = match ps_rows_guarded(&script, "shares") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    }
    .into_iter()
    .filter(|it| include_admin || !it.get("admin").and_then(|a| a.as_bool()).unwrap_or(false))
    .collect();
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn shares(_params: Option<&str>) -> Option<Value> {
    None
}

/// Print-server queues (role `print`) — the server view via `PrintManagement` (`Get-Printer`), distinct
/// from the metadata `printers` collector. §8.1: a printer is "shared" iff `Shared=$true`. `params`
/// `{name:"glob", shared_only:"bool (default true)", health:"any|error|paused|ok (default any)", limit,
/// offset}`. `health` is a coarse filter over the raw `status`. Paginated.
#[cfg(windows)]
fn print_queues(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let shared_only = p.get("shared_only").and_then(|x| x.as_bool()).unwrap_or(true);
    let health = p.get("health").and_then(|x| x.as_str()).unwrap_or("any").to_lowercase();
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '*' | '?' | '\\' | ',' | '#')).take(256).collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if shared_only {
        clauses.push("$_.Shared".into());
    }
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.Name -like '*{}*'", safe(n)));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" | Where-Object {{ {} }}", clauses.join(" -and "))
    };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-Printer{where_clause}); Stop-OnError 'print queues'; \
         @($src | ForEach-Object {{ \
           $st=[string]$_.PrinterStatus; \
           [pscustomobject]@{{ name=[string]$_.Name; shared=[bool]$_.Shared; share_name=[string]$_.ShareName; \
             driver=[string]$_.DriverName; port=[string]$_.PortName; status=$st; \
             jobs_queued=@(Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue).Count; \
             published_ad=[bool]$_.Published; comment=[string]$_.Comment; location=[string]$_.Location }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    let items: Vec<Value> = match ps_rows_guarded(&script, "print-queues") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    }
    .into_iter()
    .filter(|it| {
        let st = it.get("status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
        match health.as_str() {
            "error" => st.contains("error") || st.contains("offline") || st.contains("jam") || st.contains("paper"),
            "paused" => st.contains("paused"),
            "ok" => !(st.contains("error") || st.contains("offline") || st.contains("jam") || st.contains("paper") || st.contains("paused")),
            _ => true,
        }
    })
    .collect();
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn print_queues(_params: Option<&str>) -> Option<Value> {
    None
}

/// DNS zones (role `dns`) via the `DnsServer` module (`Get-DnsServerZone`). `params` `{name:"glob",
/// type:"primary|secondary|stub|forwarder", ds_integrated:"bool", limit, offset}`. `record_count` is
/// intentionally omitted from the list (counting every zone's records would make a zone list O(records));
/// use `dns-records` for a zone's contents. Paginated.
#[cfg(windows)]
fn dns_zones(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.ZoneName -like '*{}*'", safe(n)));
    }
    if let Some(t) = p.get("type").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.ZoneType -eq '{}'", safe(t)));
    }
    if let Some(dsi) = p.get("ds_integrated").and_then(|x| x.as_bool()) {
        clauses.push(format!("$_.IsDsIntegrated -eq ${}", dsi));
    }
    let where_clause = if clauses.is_empty() { String::new() } else { format!(" | Where-Object {{ {} }}", clauses.join(" -and ")) };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-DnsServerZone{where_clause}); Stop-OnError 'zones'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ zone=[string]$_.ZoneName; type=[string]$_.ZoneType; \
             ds_integrated=[bool]$_.IsDsIntegrated; dynamic_update=[string]$_.DynamicUpdate; \
             replication_scope=[string]$_.ReplicationScope; is_reverse=[bool]$_.IsReverseLookupZone; \
             is_signed=[bool]$_.IsSigned }} \
         }}) | Sort-Object zone | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "dns-zones") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn dns_zones(_params: Option<&str>) -> Option<Value> {
    None
}

/// DNS records within one zone (role `dns`) via `Get-DnsServerResourceRecord`. `params` `{zone:"str
/// (required)", name:"glob", rrtype:"A|AAAA|CNAME|MX|SRV|PTR|TXT|NS|...", limit, offset}`. `zone` is
/// required so this never dumps a whole server in one shot. Paginated.
#[cfg(windows)]
fn dns_records(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let zone = match p.get("zone").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty()) {
        Some(z) => z,
        None => return Some(json!({ "ok": false, "error": "dns-records requires a zone" })),
    };
    let rrtype = p.get("rrtype").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty());
    let type_arg = rrtype.map(|t| format!(" -RRType {t}")).unwrap_or_default();
    let name_filter = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|n| format!(" | Where-Object {{ $_.HostName -like '*{}*' }}", safe(n)))
        .unwrap_or_default();
    // RecordData shape varies per type; stringify the most common properties into `data`.
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-DnsServerResourceRecord -ZoneName '{zone}'{type_arg}{name_filter}); Stop-OnError 'records'; \
         @($src | ForEach-Object {{ \
           $d=$_.RecordData; \
           $v=@($d.IPv4Address,$d.IPv6Address,$d.HostNameAlias,$d.NameServer,$d.DomainName,$d.PtrDomainName,$d.MailExchange,$d.PrimaryServer,$d.DescriptiveText,$d.StringData,$d.Text) | Where-Object {{ $_ }} | Select-Object -First 1; \
           [pscustomobject]@{{ name=[string]$_.HostName; type=[string]$_.RecordType; \
             ttl=[string]$_.TimeToLive; data=[string]$v }} \
         }}) | Sort-Object name,type | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "dns-records") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 300))
}
#[cfg(not(windows))]
fn dns_records(_params: Option<&str>) -> Option<Value> {
    None
}

/// DHCP scopes (role `dhcp`) via the `DhcpServer` module (`Get-DhcpServerv4Scope` +
/// `Get-DhcpServerv4ScopeStatistics`). `params` `{name:"glob", state:"active|inactive", limit, offset}`.
/// Paginated.
#[cfg(windows)]
fn dhcp_scopes(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.Name -like '*{}*'", safe(n)));
    }
    if let Some(st) = p.get("state").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.State -eq '{}'", safe(st)));
    }
    let where_clause = if clauses.is_empty() { String::new() } else { format!(" | Where-Object {{ {} }}", clauses.join(" -and ")) };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-DhcpServerv4Scope{where_clause}); Stop-OnError 'scopes'; \
         @($src | ForEach-Object {{ \
           $s=Get-DhcpServerv4ScopeStatistics -ScopeId $_.ScopeId; \
           $f=Get-DhcpServerv4Failover -ScopeId $_.ScopeId; \
           [pscustomobject]@{{ scope_id=[string]$_.ScopeId; name=[string]$_.Name; state=[string]$_.State; \
             start_range=[string]$_.StartRange; end_range=[string]$_.EndRange; subnet_mask=[string]$_.SubnetMask; \
             lease_duration=[string]$_.LeaseDuration; \
             pct_in_use=$(if ($null -ne $s) {{ [double]$s.PercentageInUse }} else {{ $null }}); \
             free=$(if ($null -ne $s) {{ [int]$s.Free }} else {{ $null }}); \
             in_use=$(if ($null -ne $s) {{ [int]$s.InUse }} else {{ $null }}); \
             reserved=$(if ($null -ne $s) {{ [int]$s.Reserved }} else {{ $null }}); \
             failover_relationship=[string]$f.Name }} \
         }}) | Sort-Object scope_id | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "dhcp-scopes") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn dhcp_scopes(_params: Option<&str>) -> Option<Value> {
    None
}

/// DHCP leases within one scope (role `dhcp`) via `Get-DhcpServerv4Lease`. `params` `{scope_id:"str
/// (required)", state:"active|expired|...", address:"glob", limit, offset}`. `scope_id` required (same
/// anti-dump reasoning as `dns-records`). Paginated.
#[cfg(windows)]
fn dhcp_leases(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let scope = match p.get("scope_id").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Some(json!({ "ok": false, "error": "dhcp-leases requires a scope_id" })),
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(st) = p.get("state").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.AddressState -like '*{}*'", safe(st)));
    }
    if let Some(a) = p.get("address").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.IPAddress -like '*{}*'", safe(a)));
    }
    let where_clause = if clauses.is_empty() { String::new() } else { format!(" | Where-Object {{ {} }}", clauses.join(" -and ")) };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-DhcpServerv4Lease -ScopeId '{scope}'{where_clause}); Stop-OnError 'leases'; \
         @($src | ForEach-Object {{ \
           $ty='dhcp'; if($_.AddressState -like '*Reservation*'){{ $ty='reservation' }}; \
           [pscustomobject]@{{ ip=[string]$_.IPAddress; mac=[string]$_.ClientId; hostname=[string]$_.HostName; \
             state=[string]$_.AddressState; lease_expiry=[string]$_.LeaseExpiryTime; type=$ty }} \
         }}) | Sort-Object ip | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "dhcp-leases") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 300))
}
#[cfg(not(windows))]
fn dhcp_leases(_params: Option<&str>) -> Option<Value> {
    None
}

/// Sanitize a value for interpolation into an LDAP filter / ADSI expression: keep the glob-relevant and
/// name-safe characters, drop anything that could break out of the filter literal. `*` is kept (globs).
#[cfg(windows)]
fn ldap_safe(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ' | '*' | '@' | '=' | ',' | '$'))
        .take(400)
        .collect()
}

/// The AD structure collectors (role `addc`) share one ADSI search shell: bind a search root (`ou` DN or
/// the default naming context), run a paged `DirectorySearcher`, project rows, and cursor-paginate. Returns
/// `filter` is the LDAP filter, `props`/`project` the property loads + the `[pscustomobject]` body, `ou`
/// the optional search-base DN. Returns rows or the collector error — a bind or search failure is not
/// an empty directory, and every consumer paginates this output, where a failure would otherwise
/// flatten into a zero-row page.
#[cfg(windows)]
fn adsi_search(ou: Option<&str>, filter: &str, props: &[&str], project: &str, extra_where: &str) -> GuardedRows {
    let root_expr = match ou.map(ldap_safe).filter(|s| !s.is_empty()) {
        Some(dn) => format!("[adsi]('LDAP://{dn}')"),
        None => "[adsi]''".to_string(),
    };
    let loads = props.iter().map(|p| format!("'{p}'")).collect::<Vec<_>>().join(",");
    let script = format!(
        "{PS_GUARD}\
         $root={root_expr}; \
         $ds=New-Object System.DirectoryServices.DirectorySearcher($root,'{filter}'); \
         $ds.PageSize=1000; \
         foreach($pp in @({loads})){{ [void]$ds.PropertiesToLoad.Add($pp) }}; \
         function Fts($v){{ if($v -and $v -gt 0 -and $v -lt 9223372036854775807){{ [datetime]::FromFileTimeUtc([int64]$v).ToString('yyyy-MM-dd HH:mm:ss') }} else {{ '' }} }}; \
         function P($x,$n){{ if($x[$n].Count -gt 0){{ [string]$x[$n][0] }} else {{ '' }} }}; \
         function OUOF($dn){{ if($dn -match '^(?:[^,]+,)(.*)$'){{ $Matches[1] }} else {{ '' }} }}; \
         $found=@($ds.FindAll()); Stop-OnError 'directory search'; \
         @($found | ForEach-Object {{ $x=$_.Properties; {project} }}){extra_where} | ConvertTo-Json -Depth 3 -Compress"
    );
    ps_rows_guarded(&script, "directory search")
}

/// AD users (role `addc`). Hardened filter `(&(objectCategory=person)(objectClass=user)(!(objectClass=
/// computer)))` — `objectClass=user` alone also matches computers (they subclass user) and
/// `objectCategory=person` alone also matches contacts, so both terms plus the exclusion are needed.
/// `params` `{name:"glob (sam/display)", enabled:"bool", stale_days:"int", ou:"DN searchBase", limit,
/// cursor}`. Secrets are never requested. Cursor-paginated. `stale_days` uses `lastLogonTimestamp`
/// (replicated with ~9–14 day jitter — see the plan; meaningful only for N ≫ 14).
#[cfg(windows)]
fn ad_users(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let mut filter = String::from("(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))");
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).map(ldap_safe).filter(|s| !s.is_empty()) {
        filter.push_str(&format!("(|(samAccountName=*{n}*)(displayName=*{n}*))"));
    }
    if let Some(en) = p.get("enabled").and_then(|x| x.as_bool()) {
        // userAccountControl bit 2 = ACCOUNTDISABLE (LDAP_MATCHING_RULE_BIT_AND).
        filter.push_str(if en { "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" } else { "(userAccountControl:1.2.840.113556.1.4.803:=2)" });
    }
    filter.push(')');
    // stale_days → filter on lastLogonTimestamp older than N days (done in PS against a filetime threshold).
    // Guard the cast: `_llt` is '' for an account that never logged on — `[int64]''` would throw.
    let extra_where = match p.get("stale_days").and_then(|x| x.as_i64()).filter(|n| *n > 0) {
        Some(n) => format!(" | Where-Object {{ $s=[string]$_.'_llt'; $t=if($s){{[int64]$s}}else{{0}}; $t -gt 0 -and $t -lt ((Get-Date).AddDays(-{n}).ToFileTimeUtc()) }}"),
        None => String::new(),
    };
    let project = "$dn=P $x 'distinguishedname'; $uac=0; if($x['useraccountcontrol'].Count){ $uac=[int]$x['useraccountcontrol'][0] }; \
        $nm=(P $x 'displayname'); if(-not $nm){ $nm=(P $x 'cn') }; \
        [pscustomobject]@{ sam=(P $x 'samaccountname'); name=$nm; upn=(P $x 'userprincipalname'); \
          enabled=(-not ($uac -band 2)); locked=(($x['lockouttime'].Count -gt 0) -and ([int64]$x['lockouttime'][0] -gt 0)); \
          pwd_last_set=(Fts (P $x 'pwdlastset')); last_logon=(Fts (P $x 'lastlogontimestamp')); \
          expires=(Fts (P $x 'accountexpires')); description=(P $x 'description'); ou=(OUOF $dn); dn=$dn; \
          groups_count=$x['memberof'].Count; _llt=(P $x 'lastlogontimestamp') }";
    let props = ["samaccountname", "cn", "displayname", "userprincipalname", "useraccountcontrol", "lockouttime", "pwdlastset", "lastlogontimestamp", "accountexpires", "description", "distinguishedname", "memberof"];
    let ou = p.get("ou").and_then(|x| x.as_str());
    let mut items = match adsi_search(ou, &filter, &props, project, &extra_where) {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    // Drop the internal sort/stale helper field before returning.
    for it in &mut items {
        if let Some(o) = it.as_object_mut() {
            o.remove("_llt");
        }
    }
    Some(paginate_cursor(items, params, 300))
}
#[cfg(not(windows))]
fn ad_users(_params: Option<&str>) -> Option<Value> {
    None
}

/// AD groups (role `addc`). `params` `{name:"glob", scope:"global|domainlocal|universal",
/// type:"security|distribution", members_of:"group DN (nested)", members:"bool (default false —
/// drill-down)", limit, cursor}`. `members:true` switches to the paginated membership of ONE group
/// (requires the query to resolve to exactly one, else a distinct error); that drill-down uses stateless
/// `offset`, not the cursor. Default list is cursor-paginated with `member_count` only.
#[cfg(windows)]
fn ad_groups(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let members = p.get("members").and_then(|x| x.as_bool()).unwrap_or(false);
    // groupType bit flags: 0x80000000 = security-enabled; scope bits 0x2 global, 0x4 domainlocal, 0x8 universal.
    let mut filter = String::from("(&(objectCategory=group)");
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).map(ldap_safe).filter(|s| !s.is_empty()) {
        filter.push_str(&format!("(|(samAccountName=*{n}*)(cn=*{n}*))"));
    }
    if let Some(mo) = p.get("members_of").and_then(|x| x.as_str()).map(ldap_safe).filter(|s| !s.is_empty()) {
        filter.push_str(&format!("(memberOf:1.2.840.113556.1.4.1941:={mo})"));
    }
    match p.get("scope").and_then(|x| x.as_str()) {
        Some("global") => filter.push_str("(groupType:1.2.840.113556.1.4.803:=2)"),
        Some("domainlocal") => filter.push_str("(groupType:1.2.840.113556.1.4.803:=4)"),
        Some("universal") => filter.push_str("(groupType:1.2.840.113556.1.4.803:=8)"),
        _ => {}
    }
    match p.get("type").and_then(|x| x.as_str()) {
        Some("security") => filter.push_str("(groupType:1.2.840.113556.1.4.803:=2147483648)"),
        Some("distribution") => filter.push_str("(!(groupType:1.2.840.113556.1.4.803:=2147483648))"),
        _ => {}
    }
    filter.push(')');
    let props = ["samaccountname", "cn", "grouptype", "description", "distinguishedname", "managedby", "member"];

    if members {
        // Drill-down: resolve to exactly one group, then page its members with stateless `offset`.
        let project = "[pscustomobject]@{ dn=(P $x 'distinguishedname'); member=@($x['member']) }";
        let groups = match adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, project, "") {
            GuardedRows::Failed(e) => return Some(e),
            GuardedRows::Rows(v) => v,
        };
        if groups.is_empty() {
            return Some(json!({ "ok": false, "error": "members:true matched no group" }));
        }
        if groups.len() > 1 {
            return Some(json!({ "ok": false, "error": "members:true matched multiple groups; narrow to one" }));
        }
        // Enumerate the one group's member DNs → {sam,name,type}.
        let member_dns = groups[0].get("member").and_then(|m| m.as_array()).cloned().unwrap_or_default();
        let list = member_dns.iter().filter_map(|d| d.as_str()).map(ldap_safe).collect::<Vec<_>>();
        if list.is_empty() {
            return Some(paginate(Vec::new(), params, 300));
        }
        let ors = list.iter().map(|d| format!("(distinguishedName={d})")).collect::<String>();
        let mfilter = format!("(|{ors})");
        let mproject = "$ty='user'; if($x['objectclass'] -contains 'group'){ $ty='group' }elseif($x['objectclass'] -contains 'computer'){ $ty='computer' }; \
            [pscustomobject]@{ sam=(P $x 'samaccountname'); name=(P $x 'displayname'); type=$ty }";
        let mprops = ["samaccountname", "displayname", "objectclass", "samaccounttype"];
        let items = match adsi_search(None, &mfilter, &mprops, mproject, "") {
            GuardedRows::Failed(e) => return Some(e),
            GuardedRows::Rows(v) => v,
        };
        return Some(paginate(items, params, 300));
    }

    let project = "$gt=0; if($x['grouptype'].Count){ $gt=[int64]$x['grouptype'][0] }; \
        $scope=''; if($gt -band 8){ $scope='universal' }elseif($gt -band 4){ $scope='domainlocal' }elseif($gt -band 2){ $scope='global' }; \
        $ty='distribution'; if($gt -band 2147483648){ $ty='security' }; \
        [pscustomobject]@{ name=(P $x 'cn'); sam=(P $x 'samaccountname'); scope=$scope; type=$ty; \
          description=(P $x 'description'); member_count=$x['member'].Count; \
          dn=(P $x 'distinguishedname'); managed_by=(P $x 'managedby') }";
    let items = match adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, project, "") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate_cursor(items, params, 300))
}
#[cfg(not(windows))]
fn ad_groups(_params: Option<&str>) -> Option<Value> {
    None
}

/// AD computers (role `addc`). `params` `{name:"glob", enabled:"bool", os:"glob (operatingSystem)",
/// stale_days:"int (same lastLogonTimestamp caveat as ad-users)", ou:"DN searchBase", limit, cursor}`.
/// Cursor-paginated.
#[cfg(windows)]
fn ad_computers(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let mut filter = String::from("(&(objectCategory=computer)");
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).map(ldap_safe).filter(|s| !s.is_empty()) {
        filter.push_str(&format!("(name=*{n}*)"));
    }
    if let Some(os) = p.get("os").and_then(|x| x.as_str()).map(ldap_safe).filter(|s| !s.is_empty()) {
        filter.push_str(&format!("(operatingSystem=*{os}*)"));
    }
    if let Some(en) = p.get("enabled").and_then(|x| x.as_bool()) {
        filter.push_str(if en { "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" } else { "(userAccountControl:1.2.840.113556.1.4.803:=2)" });
    }
    filter.push(')');
    let extra_where = match p.get("stale_days").and_then(|x| x.as_i64()).filter(|n| *n > 0) {
        Some(n) => format!(" | Where-Object {{ $s=[string]$_.'_llt'; $t=if($s){{[int64]$s}}else{{0}}; $t -gt 0 -and $t -lt ((Get-Date).AddDays(-{n}).ToFileTimeUtc()) }}"),
        None => String::new(),
    };
    let project = "$dn=P $x 'distinguishedname'; $uac=0; if($x['useraccountcontrol'].Count){ $uac=[int]$x['useraccountcontrol'][0] }; \
        [pscustomobject]@{ name=(P $x 'name'); dns_host=(P $x 'dnshostname'); os=(P $x 'operatingsystem'); \
          os_version=(P $x 'operatingsystemversion'); enabled=(-not ($uac -band 2)); \
          last_logon=(Fts (P $x 'lastlogontimestamp')); pwd_last_set=(Fts (P $x 'pwdlastset')); \
          ou=(OUOF $dn); dn=$dn; _llt=(P $x 'lastlogontimestamp') }";
    let props = ["name", "dnshostname", "operatingsystem", "operatingsystemversion", "useraccountcontrol", "lastlogontimestamp", "pwdlastset", "distinguishedname"];
    let mut items = match adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, project, &extra_where) {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    for it in &mut items {
        if let Some(o) = it.as_object_mut() {
            o.remove("_llt");
        }
    }
    Some(paginate_cursor(items, params, 300))
}
#[cfg(not(windows))]
fn ad_computers(_params: Option<&str>) -> Option<Value> {
    None
}

/// AD OU tree (role `addc`). `params` `{under:"DN (subtree root; default domain root)", depth:"int",
/// limit, offset}`. Reads `gPLink`/`gPOptions` per OU so the operator sees which GPOs link where — the
/// domain-side wiring `rsop` can't show. Stateless `paginate()` (the tree is bounded).
#[cfg(windows)]
fn ad_ous(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let filter = "(objectCategory=organizationalUnit)".to_string();
    // gPLink is a concatenation of [LDAP://<gpo-dn>;<flags>] segments; parse to {name,enforced,enabled}.
    let project = "$dn=P $x 'distinguishedname'; $gpl=P $x 'gplink'; \
        $links=@(); foreach($m in [regex]::Matches($gpl,'\\[LDAP://([^;]+);(\\d+)\\]')){ \
          $f=[int]$m.Groups[2].Value; $g=$m.Groups[1].Value; $nm=''; if($g -match '\\{[^}]+\\}'){ $nm=$Matches[0] }; \
          $links+=[pscustomobject]@{ name=$nm; enforced=[bool]($f -band 2); enabled=(-not ($f -band 1)) } }; \
        [pscustomobject]@{ name=(P $x 'name'); dn=$dn; parent_dn=(OUOF $dn); description=(P $x 'description'); \
          gplinks=$links; child_ou_count=0; blocks_inheritance=([int]((P $x 'gpoptions')) -band 1) }";
    let props = ["name", "distinguishedname", "description", "gplink", "gpoptions"];
    let items = match adsi_search(p.get("under").and_then(|x| x.as_str()), &filter, &props, project, "") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 300))
}
#[cfg(not(windows))]
fn ad_ous(_params: Option<&str>) -> Option<Value> {
    None
}

/// All GPOs in the domain (role `gpo`) via `Get-GPO -All` (GroupPolicy module). `params` `{name:"glob",
/// limit, offset}`. `links` (which OUs link the GPO) is omitted from the list — computing it per-GPO
/// would make the list O(report); use `ad-ous` `gplinks` for the linkage view. If the module is absent,
/// returns the runtime sentinel. Paginated.
#[cfg(windows)]
fn gpo_list(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let name_filter = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|n| format!(" | Where-Object {{ $_.DisplayName -like '*{}*' }}", safe(n)))
        .unwrap_or_default();
    let script = format!(
        "{PS_GUARD}\
         if(-not (Get-Module -ListAvailable -Name GroupPolicy)){{ '{{\"ok\":false,\"error\":\"GroupPolicy module not available\"}}' }} else {{ \
         $src=@(Get-GPO -All{name_filter}); Stop-OnError 'GPOs'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.DisplayName; id=[string]$_.Id; status=[string]$_.GpoStatus; \
             created=[string]$_.CreationTime; modified=[string]$_.ModificationTime; \
             computer_ver=[string]$_.Computer.DSVersion; user_ver=[string]$_.User.DSVersion; \
             wmi_filter=[string]$_.WmiFilter.Name; links=@() }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress }}"
    );
    // Single PS run: a `{ok:false}` sentinel object passes through; an array/object paginates.
    match ps_json_guarded(&script, "gpo-list") {
        Some(v @ Value::Object(_)) if v.get("ok").is_some() => Some(v),
        Some(Value::Array(a)) => Some(paginate(a, params, 200)),
        Some(v @ Value::Object(_)) => Some(paginate(vec![v], params, 200)),
        _ => Some(paginate(Vec::new(), params, 200)),
    }
}
#[cfg(not(windows))]
fn gpo_list(_params: Option<&str>) -> Option<Value> {
    None
}

/// One GPO's resolved settings (role `gpo`) via `Get-GPOReport -ReportType Xml`, flattened to
/// `{scope,category,setting,state,value}` rows (namespace-agnostic XPath over `Policy` nodes; scope from
/// the enclosing Computer/User section). `params` `{gpo:"guid or exact name (required)", section:"computer|
/// user|both (default both)", limit, offset}`. Paginated.
#[cfg(windows)]
fn gpo_report(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '{' | '}')).take(128).collect()
    };
    let gpo = match p.get("gpo").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty()) {
        Some(g) => g,
        None => return Some(json!({ "ok": false, "error": "gpo-report requires gpo (guid or exact name)" })),
    };
    let section = p.get("section").and_then(|x| x.as_str()).unwrap_or("both");
    let section_where = match section {
        "computer" => " | Where-Object { $_.scope -eq 'Computer' }",
        "user" => " | Where-Object { $_.scope -eq 'User' }",
        _ => "",
    };
    // Resolve by GUID (36-hex ± braces) or exact display name.
    let is_guid = gpo.trim_matches(|c| c == '{' || c == '}').len() == 36;
    let resolve = if is_guid {
        format!("Get-GPO -Guid '{gpo}' -ErrorAction SilentlyContinue")
    } else {
        format!("Get-GPO -Name '{gpo}' -ErrorAction SilentlyContinue")
    };
    // Admin-template `//Policy` rows PLUS the Security-extension content (SecurityOptions / Account /
    // AuditSetting) — a GPO's actual security settings, otherwise invisible in the report. If the
    // report loads but only the security XPath is empty, the admin-template rows still return.
    let script = format!(
        "{PS_GUARD}\
         if(-not (Get-Module -ListAvailable -Name GroupPolicy)){{ '{{\"ok\":false,\"error\":\"GroupPolicy module not available\"}}' }} else {{ \
         $g={resolve}; Stop-OnError 'GPO lookup' -Ignore 'GpoWithIdNotFound','GpoWithNameNotFound'; \
         if(-not $g){{ '{{\"ok\":false,\"error\":\"no such GPO\"}}' }} else {{ \
         [xml]$r=Get-GPOReport -Guid $g.Id -ReportType Xml; Stop-OnError 'GPO report'; \
         $pol=@($r.SelectNodes('//*[local-name()=\"Policy\"]') | ForEach-Object {{ \
           $nm=$_.SelectSingleNode('*[local-name()=\"Name\"]'); $st=$_.SelectSingleNode('*[local-name()=\"State\"]'); \
           $ct=$_.SelectSingleNode('*[local-name()=\"Category\"]'); \
           $anc=$_.SelectSingleNode('ancestor::*[local-name()=\"User\" or local-name()=\"Computer\"]'); \
           [pscustomobject]@{{ scope=$(if($anc){{$anc.LocalName}}else{{''}}); category=[string]$ct.InnerText; \
             setting=[string]$nm.InnerText; state=[string]$st.InnerText; value='' }} \
         }}); \
         $sec=@($r.SelectNodes('//*[local-name()=\"SecurityOptions\" or local-name()=\"Account\" or local-name()=\"AuditSetting\"]') | ForEach-Object {{ \
           $anc=$_.SelectSingleNode('ancestor::*[local-name()=\"User\" or local-name()=\"Computer\"]'); \
           $ky=$_.SelectSingleNode('*[local-name()=\"KeyName\" or local-name()=\"Name\" or local-name()=\"SubcategoryName\"]'); \
           $vl=$_.SelectSingleNode('*[local-name()=\"SettingNumber\" or local-name()=\"SettingBoolean\" or local-name()=\"SettingString\" or local-name()=\"SettingValue\"]'); \
           if($ky){{ [pscustomobject]@{{ scope=$(if($anc){{$anc.LocalName}}else{{''}}); category=('Security/'+$_.LocalName); \
             setting=[string]$ky.InnerText; state=''; value=$(if($vl){{[string]$vl.InnerText}}else{{''}}) }} }} \
         }}); \
         @($pol + $sec){section_where} | ConvertTo-Json -Depth 3 -Compress }} }}"
    );
    match ps_json_guarded(&script, "gpo-report") {
        Some(v @ Value::Object(_)) if v.get("ok").is_some() => Some(v),
        Some(Value::Array(a)) => Some(paginate(a, params, 250)),
        Some(v @ Value::Object(_)) => Some(paginate(vec![v], params, 250)),
        _ => Some(paginate(Vec::new(), params, 250)),
    }
}
#[cfg(not(windows))]
fn gpo_report(_params: Option<&str>) -> Option<Value> {
    None
}

/// Hyper-V VMs (role `hyperv`) via `Get-VM` (Hyper-V module). `params` `{name:"glob",
/// state:"running|off|paused|saved", limit, offset}`. Paginated.
#[cfg(windows)]
fn hyperv_vms(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let mut clauses: Vec<String> = Vec::new();
    if let Some(n) = p.get("name").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.Name -like '*{}*'", safe(n)));
    }
    if let Some(st) = p.get("state").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        clauses.push(format!("$_.State -eq '{}'", safe(st)));
    }
    let where_clause = if clauses.is_empty() { String::new() } else { format!(" | Where-Object {{ {} }}", clauses.join(" -and ")) };
    // `checkpoint_count` MUST come from `Get-VMSnapshot`, not `$_.Checkpoints`: a `Get-VM` object has no
    // `Checkpoints` property, so that read is `$null`, and PowerShell's `@($null)` is a ONE-element array
    // holding null — `.Count` was therefore hard-coded `1` for every VM, forever, whatever its real
    // checkpoint state. Don't "simplify" this back to a property read.
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-VM{where_clause}); Stop-OnError 'virtual machines'; \
         @($src | ForEach-Object {{ \
           $isvc=[string]$_.IntegrationServicesState; if(-not $isvc){{ $isvc=[string]$_.IntegrationServicesVersion }}; \
           [pscustomobject]@{{ name=[string]$_.Name; state=[string]$_.State; uptime=[string]$_.Uptime; \
             cpu_usage=[int]$_.CPUUsage; assigned_mem_mb=[int64]($_.MemoryAssigned/1MB); \
             demand_mem_mb=[int64]($_.MemoryDemand/1MB); gen=[int]$_.Generation; version=[string]$_.Version; \
             integration_svcs=$isvc; replication_state=[string]$_.ReplicationState; \
             checkpoint_count=@(Get-VMSnapshot -VM $_ -ErrorAction SilentlyContinue).Count }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "hyperv-vms") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn hyperv_vms(_params: Option<&str>) -> Option<Value> {
    None
}

/// RDS sessions (role `rdsh`) — richer than the metadata `sessions` collector. Prefers
/// `Get-RDUserSession` (deployment/farm context); falls back to `quser` parsing on a standalone session
/// host. `params` `{state:"active|disconnected", user:"glob", limit, offset}`. Paginated.
#[cfg(windows)]
fn rds_sessions(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?' | '\\')).take(128).collect()
    };
    let name_glob = p.get("user").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty());
    let state = p.get("state").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty());
    // Try the deployment cmdlet; on failure fall back to `quser` (fixed-width columns).
    let script = format!(
        "{PS_GUARD}\
         $rows=@(); \
         $rd=@(Get-RDUserSession -ErrorAction SilentlyContinue); \
         if($rd.Count -gt 0){{ $rows=$rd | ForEach-Object {{ [pscustomobject]@{{ user=[string]$_.UserName; \
           session_id=[string]$_.UnifiedSessionId; state=[string]$_.SessionState; collection=[string]$_.CollectionName; \
           host=[string]$_.HostServer; client_name=[string]$_.ClientName; client_ip=''; idle_time=''; \
           logon_time=[string]$_.CreateTime }} }} }} \
         else {{ $rows=@(quser 2>$null | Select-Object -Skip 1 | ForEach-Object {{ \
           $ln=$_ -replace '^>',' '; $u=$ln.Substring(1,22).Trim(); $sn=$ln.Substring(23,18).Trim(); \
           $idp=$ln.Substring(41,4).Trim(); $stt=$ln.Substring(45,8).Trim(); $idl=$ln.Substring(53,11).Trim(); $lt=$ln.Substring(64).Trim(); \
           [pscustomobject]@{{ user=$u; session_id=$idp; state=$stt; collection=''; host=''; client_name=$sn; \
             client_ip=''; idle_time=$idl; logon_time=$lt }} }}) }}; \
         if(@($rows).Count -eq 0){{ Stop-OnError 'sessions' }}; \
         @($rows) | ConvertTo-Json -Depth 3 -Compress"
    );
    // Two paths are tried in turn, so the deployment cmdlet failing on a standalone host is expected and
    // survivable — the check is deferred to the end and only fires when NEITHER produced a session. A
    // host with no one logged on leaves no error behind, so it still reports an honest empty list.
    let mut items = match ps_rows_guarded(&script, "rds-sessions") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    if let Some(g) = name_glob {
        let g = g.trim_matches('*').to_lowercase();
        items.retain(|it| it.get("user").and_then(|u| u.as_str()).map(|u| u.to_lowercase().contains(&g)).unwrap_or(false));
    }
    if let Some(st) = state {
        let st = st.to_lowercase();
        items.retain(|it| it.get("state").and_then(|s| s.as_str()).map(|s| s.to_lowercase().contains(&st)).unwrap_or(false));
    }
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn rds_sessions(_params: Option<&str>) -> Option<Value> {
    None
}

/// DNS server resolver posture (role `dns`, optional) — forwarders, root-hints use, scavenging, listen
/// addresses. Single object (no pagination). No params. A read that fails returns `{ok:false,error}`;
/// a read that succeeds but has nothing to report emits `null` for that field, so an empty
/// `forwarders` list means the server really has none rather than that the query never ran.
#[cfg(windows)]
fn dns_health(_params: Option<&str>) -> Option<Value> {
    // `Get-DnsServerSetting` is used for listen addresses instead of the heavy full-config `Get-DnsServer`
    // (which times out / fails on a live server).
    let script = format!(
        "{PS_GUARD}\
         $fwd=Get-DnsServerForwarder; Stop-OnError 'forwarders'; \
         $sc=Get-DnsServerScavenging; Stop-OnError 'scavenging'; \
         $set=Get-DnsServerSetting; Stop-OnError 'server settings'; \
         [pscustomobject]@{{ \
           forwarders=$(if ($null -ne $fwd) {{ @($fwd.IPAddress | ForEach-Object {{ [string]$_ }}) }} else {{ $null }}); \
           use_root_hints=$(if ($null -ne $fwd) {{ [bool]$fwd.UseRootHint }} else {{ $null }}); \
           scavenging_enabled=$(if ($null -ne $sc) {{ [bool]$sc.ScavengingState }} else {{ $null }}); \
           scavenging_interval=$(if ($null -ne $sc) {{ [string]$sc.ScavengingInterval }} else {{ $null }}); \
           listen_addresses=$(if ($null -ne $set) {{ @($set.ListeningIpAddress | ForEach-Object {{ [string]$_ }}) }} else {{ $null }}) }} \
         | ConvertTo-Json -Depth 4 -Compress"
    );
    ps_json_guarded(&script, "dns-health")
}
#[cfg(not(windows))]
fn dns_health(_params: Option<&str>) -> Option<Value> {
    None
}

/// DHCP options (role `dhcp`, optional) — server- or scope-level option values. `params`
/// `{scope_id:"optional (omit → server-level)", limit, offset}`. Paginated.
#[cfg(windows)]
fn dhcp_options(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')).take(64).collect()
    };
    let (arg, scope_label) = match p.get("scope_id").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty()) {
        Some(s) => (format!(" -ScopeId '{s}'"), s),
        None => (String::new(), "server".to_string()),
    };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-DhcpServerv4OptionValue{arg}); Stop-OnError 'options'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ option_id=[int]$_.OptionId; name=[string]$_.Name; \
             value=[string]($_.Value -join ', '); scope='{scope_label}' }} \
         }}) | Sort-Object option_id | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "dhcp-options") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn dhcp_options(_params: Option<&str>) -> Option<Value> {
    None
}

/// Live SMB sessions on a file server (role `fileserver`, optional) via `Get-SmbSession`. `params`
/// `{client:"glob (ip or user)", limit, offset}`. Paginated.
#[cfg(windows)]
fn share_sessions(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '\\' | '*' | '?')).take(128).collect()
    };
    let where_clause = p
        .get("client")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|c| format!(" | Where-Object {{ $_.ClientComputerName -like '*{0}*' -or $_.ClientUserName -like '*{0}*' }}", safe(c)))
        .unwrap_or_default();
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-SmbSession{where_clause}); Stop-OnError 'SMB sessions'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ client_ip=[string]$_.ClientComputerName; client_user=[string]$_.ClientUserName; \
             num_open_files=[int]$_.NumOpens; session_time=[string]$_.SecondsExists }} \
         }}) | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "share-sessions") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 300))
}
#[cfg(not(windows))]
fn share_sessions(_params: Option<&str>) -> Option<Value> {
    None
}

/// Print jobs in one queue (role `print`, optional) via `Get-PrintJob`, for triaging a stuck queue.
/// `params` `{name:"str (required — the queue's name from print-queues)", limit, offset}`. Paginated.
#[cfg(windows)]
fn print_jobs(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '\\' | ',' | '#')).take(256).collect()
    };
    let queue = match p.get("name").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty()) {
        Some(q) => q,
        None => return Some(json!({ "ok": false, "error": "print-jobs requires name (the queue)" })),
    };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-PrintJob -PrinterName '{queue}'); Stop-OnError 'print jobs'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ id=[int]$_.Id; document=[string]$_.DocumentName; owner=[string]$_.UserName; \
             status=[string]$_.JobStatus; pages=[int]$_.PagesPrinted; size=[int64]$_.Size; \
             submitted=[string]$_.SubmittedTime }} \
         }}) | Sort-Object id | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "print-jobs") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn print_jobs(_params: Option<&str>) -> Option<Value> {
    None
}

/// Deep-read one Hyper-V VM (role `hyperv`, optional). `params` `{name:"str (required — exact VM name)"}`.
/// Single object with disks/nics/checkpoints. `disks[].used` is only read for dynamic VHDX (cheap
/// `Get-VHD`); it's omitted otherwise.
#[cfg(windows)]
fn hyperv_vm(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')')).take(128).collect()
    };
    let name = match p.get("name").and_then(|x| x.as_str()).map(safe).filter(|s| !s.is_empty()) {
        Some(n) => n,
        None => return Some(json!({ "ok": false, "error": "hyperv-vm requires name (exact VM name)" })),
    };
    let script = format!(
        "{PS_GUARD}\
         $vm=Get-VM -Name '{name}'; Stop-OnError 'virtual machine' -Ignore 'InvalidParameter','ObjectNotFound'; \
         if(-not $vm){{ '{{\"ok\":false,\"error\":\"no such VM\"}}' }} else {{ \
         $disks=@(Get-VMHardDiskDrive -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {{ \
           $vhd=Get-VHD -Path $_.Path -ErrorAction SilentlyContinue; \
           [pscustomobject]@{{ path=[string]$_.Path; size=[int64]($vhd.Size/1GB); used=[int64]($vhd.FileSize/1GB); \
             type=[string]$vhd.VhdType; ctrl=[string]$_.ControllerType }} }}); \
         $nics=@(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {{ \
           [pscustomobject]@{{ switch=[string]$_.SwitchName; vlan=''; mac=[string]$_.MacAddress; \
             ip=@($_.IPAddresses) -join ', ' }} }}); \
         $chk=@(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; created=[string]$_.CreationTime; parent=[string]$_.ParentSnapshotName }} }}); \
         [pscustomobject]@{{ name=[string]$vm.Name; state=[string]$vm.State; cpus=[int]$vm.ProcessorCount; \
           dynamic_mem=[pscustomobject]@{{ min=[int64]($vm.MemoryMinimum/1MB); max=[int64]($vm.MemoryMaximum/1MB); \
             startup=[int64]($vm.MemoryStartup/1MB) }}; disks=$disks; nics=$nics; checkpoints=$chk }} \
         | ConvertTo-Json -Depth 5 -Compress }}"
    );
    ps_json_guarded(&script, "hyperv-vm")
}
#[cfg(not(windows))]
fn hyperv_vm(_params: Option<&str>) -> Option<Value> {
    None
}

/// Hyper-V virtual switches (role `hyperv`, optional) via `Get-VMSwitch`. `params` `{name:"glob
/// (optional)"}`. Small unpaginated array (bare list, no envelope — see the plan notation note).
#[cfg(windows)]
fn hyperv_switches(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let where_clause = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|n| format!(" | Where-Object {{ $_.Name -like '*{}*' }}", safe(n)))
        .unwrap_or_default();
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-VMSwitch{where_clause}); Stop-OnError 'virtual switches'; \
         @($src | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; type=[string]$_.SwitchType; \
             net_adapter=[string]$_.NetAdapterInterfaceDescription; allow_mgmt_os=[bool]$_.AllowManagementOS; vlan='' }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    // Small bounded list → return the bare array directly (no pagination envelope).
    match ps_rows_guarded(&script, "hyperv-switches") {
        GuardedRows::Failed(e) => Some(e),
        GuardedRows::Rows(v) => Some(Value::Array(v)),
    }
}
#[cfg(not(windows))]
fn hyperv_switches(_params: Option<&str>) -> Option<Value> {
    None
}

/// Hyper-V host capacity (role `hyperv`, optional) via `Get-VMHost` + a VM state roll-up. Single object.
#[cfg(windows)]
fn hyperv_host(_params: Option<&str>) -> Option<Value> {
    let script = format!(
        "{PS_GUARD}\
         $h=Get-VMHost; Stop-OnError 'Hyper-V host'; \
         $vms=@(Get-VM); Stop-OnError 'virtual machines'; \
         $byState=@{{}}; $vms | Group-Object State | ForEach-Object {{ $byState[[string]$_.Name]=$_.Count }}; \
         [pscustomobject]@{{ logical_processors=[int]$h.LogicalProcessorCount; \
           total_memory_gb=[int64]($h.MemoryCapacity/1GB); vm_count=$vms.Count; \
           vm_count_by_state=[pscustomobject]$byState; default_vm_path=[string]$h.VirtualMachinePath; \
           default_vhd_path=[string]$h.VirtualHardDiskPath; \
           live_migration=[bool]$h.VirtualMachineMigrationEnabled }} \
         | ConvertTo-Json -Depth 4 -Compress"
    );
    ps_json_guarded(&script, "hyperv-host")
}
#[cfg(not(windows))]
fn hyperv_host(_params: Option<&str>) -> Option<Value> {
    None
}

/// RDS session-host posture (role `rdsh`, optional). Best-effort: the RDS deployment cmdlets need a
/// connection broker, so on a standalone host this reads what's locally available (Terminal Server
/// settings via CIM + registry). Single object.
#[cfg(windows)]
fn rds_config(_params: Option<&str>) -> Option<Value> {
    // The Terminal Services CIM read is the load-bearing one and is checked; the deployment cmdlets
    // below it are expected to fail on a standalone host, so they stay best-effort. Fields this
    // collector does not yet gather are `null` — an empty string there would read as "not configured".
    let script = format!(
        "{PS_GUARD}\
         $ts=Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TerminalServiceSetting; \
         Stop-OnError 'terminal-server settings'; \
         $cal=Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TSLicenseKeyPack -ErrorAction SilentlyContinue | Select-Object -First 1; \
         $col=@(Get-RDSessionCollection -ErrorAction SilentlyContinue); \
         [pscustomobject]@{{ collection=$(if($col.Count -gt 0){{ [string]($col.CollectionName -join ', ') }} else {{ $null }}); \
           max_sessions=$null; per_user_or_per_device_cal=$(if($cal){{ [string]$cal.TypeAndModel }} else {{ $null }}); \
           drain_mode=[int]$ts.SessionBrokerDrainMode; connection_broker=$null; gateway=$null; \
           server_mode=[int]$ts.TerminalServerMode; published_apps=$null }} \
         | ConvertTo-Json -Depth 4 -Compress"
    );
    ps_json_guarded(&script, "rds-config")
}
#[cfg(not(windows))]
fn rds_config(_params: Option<&str>) -> Option<Value> {
    None
}

/// Windows activation / licensing state — `SoftwareLicensingProduct` (the licensed OS product with a
/// partial product key) plus the `sppsvc` service state. Single object, no params. A missing product
/// record is an abnormal state and returns `{ok:false,error}`, not a healthy-looking empty shape.
#[cfg(windows)]
fn activation(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
try {
  $flt = "PartialProductKey IS NOT NULL AND ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f'"
  $p = Get-CimInstance SoftwareLicensingProduct -Filter $flt | Select-Object -First 1
  if (-not $p) { throw 'no licensed Windows product with a partial product key found' }
  $statusMap = @{ 0='Unlicensed'; 1='Licensed'; 2='OOB grace'; 3='OOT grace'; 4='Non-genuine grace'; 5='Notification'; 6='Extended grace' }
  $svc = Get-Service sppsvc -ErrorAction SilentlyContinue
  [ordered]@{
    product                 = $p.Name
    status                  = $statusMap[[int]$p.LicenseStatus]
    status_code             = [int]$p.LicenseStatus
    channel                 = $p.ProductKeyChannel
    grace_minutes_remaining = [int]$p.GracePeriodRemaining
    sppsvc                  = if ($svc) { [string]$svc.Status } else { 'absent' }
  } | ConvertTo-Json -Depth 4 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn activation(_params: Option<&str>) -> Option<Value> {
    None
}

/// VSS writer health via `vssadmin list writers`. Single object `{total, system_writer_present,
/// unhealthy[]}`; `{all:true}` adds the full `writers` array. A failed System Writer is a
/// backup-integrity signal. en-US output assumed. Native output flattened so a stderr line can't trip
/// the `Stop` preference mid-parse.
#[cfg(windows)]
fn vss_health(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let all_lit = if p.get("all").and_then(|x| x.as_bool()).unwrap_or(false) { "$true" } else { "$false" };
    let script = format!("$ALL={all_lit};\n") + r#"$ErrorActionPreference='Stop'
function Invoke-Native { param([scriptblock]$Cmd) & { $ErrorActionPreference='Continue'; (& $Cmd) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $raw = Invoke-Native { vssadmin list writers }
  if ($LASTEXITCODE -ne 0) { throw "vssadmin exit $LASTEXITCODE : $($raw.Trim())" }
  $writers = foreach ($b in ($raw -split 'Writer name:' | Select-Object -Skip 1)) {
    [ordered]@{
      name       = ($b -split "'")[1]
      state      = if ($b -match 'State:\s*\[\d+\]\s*(.+)') { $Matches[1].Trim() } else { 'unknown' }
      last_error = if ($b -match 'Last error:\s*(.+)')      { $Matches[1].Trim() } else { 'unknown' }
    }
  }
  $writers = @($writers)
  $r = [ordered]@{
    total                 = $writers.Count
    system_writer_present = [bool]($writers | Where-Object { $_.name -eq 'System Writer' })
    unhealthy             = @($writers | Where-Object { $_.state -ne 'Stable' -or $_.last_error -ne 'No error' })
  }
  if ($ALL) { $r.writers = @($writers) }
  $r | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#;
    ps_json(&script)
}
#[cfg(not(windows))]
fn vss_health(_params: Option<&str>) -> Option<Value> {
    None
}

/// Windows Server Backup posture — `wbengine` state, `wbadmin get versions` count/latest, and
/// `Get-WBPolicy` presence + system-state flag. Single object, no params. `wbadmin` exits nonzero when
/// there simply are no backups; that is data (`wbadmin_exit` surfaced), not an error. A missing WSB
/// feature reports `policy:"unavailable:…"` in place of the two policy fields.
#[cfg(windows)]
fn backup_state(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
function Invoke-Native { param([scriptblock]$Cmd) & { $ErrorActionPreference='Continue'; (& $Cmd) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $r = [ordered]@{}
  $svc = Get-Service wbengine -ErrorAction SilentlyContinue
  $r.wbengine = if ($svc) { [string]$svc.Status } else { 'absent' }
  $ver = Invoke-Native { wbadmin get versions }
  $r.wbadmin_exit = $LASTEXITCODE
  $ids = @([regex]::Matches($ver, 'Version identifier:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
  if ($r.wbadmin_exit -ne 0 -and $ids.Count -eq 0 -and $ver -notmatch 'No backup') {
    $tail = @(($ver.Trim() -split "`r?`n") | Where-Object { $_.Trim() })[-1]
    throw "wbadmin exit $($r.wbadmin_exit) : $tail"
  }
  $r.backup_count   = $ids.Count
  $r.latest_version = if ($ids.Count) { $ids[-1] } else { $null }
  try {
    $pol = Get-WBPolicy -ErrorAction Stop
    $r.scheduled              = [bool]$pol
    $r.system_state_in_policy = if ($pol) { [bool]$pol.SystemState } else { $false }
  } catch { $r.policy = "unavailable: $($_.Exception.Message)" }
  $r | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn backup_state(_params: Option<&str>) -> Option<Value> {
    None
}

/// DC health summary (role `addc`) — `dcdiag /q` failure lines plus a passive `_ldap`/`_kerberos`
/// SRV-registration check (`Resolve-DnsName`, never dcdiag's dynamic-update-path probe). Single object,
/// no params. `quiet_output_empty` is a benign-warning-sensitive signal, not a "passed" verdict.
/// `dcdiag` can take tens of seconds — callers should allow a generous wait.
#[cfg(windows)]
fn dcdiag(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
function Invoke-Native { param([scriptblock]$Cmd) & { $ErrorActionPreference='Continue'; (& $Cmd) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $dom = (Get-CimInstance Win32_ComputerSystem).Domain
  $raw = Invoke-Native { dcdiag /q }
  $errLines = @(($raw.Trim() -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 40)
  $srv = [ordered]@{}
  foreach ($rec in "_ldap._tcp.dc._msdcs.$dom", "_kerberos._tcp.dc._msdcs.$dom") {
    try {
      $targets = @(Resolve-DnsName -Type SRV -Name $rec -ErrorAction Stop |
                   Where-Object { $_.QueryType -eq 'SRV' } | ForEach-Object { $_.NameTarget })
      $srv[$rec] = [ordered]@{ target_count = $targets.Count; self_registered = [bool]($targets -like "$env:COMPUTERNAME.*") }
    } catch { $srv[$rec] = @{ error = $_.Exception.Message } }
  }
  [ordered]@{
    quiet_output_empty = [string]::IsNullOrWhiteSpace($raw.Trim())
    errors             = $errLines
    srv_records        = $srv
  } | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn dcdiag(_params: Option<&str>) -> Option<Value> {
    None
}

/// Time-sync chain — `w32tm /query /source|/status|/configuration`, each degraded individually
/// (`*_error` fields), plus an unconditional `W32Time` registry + service fallback that answers "where
/// is time configured to come from" even when `w32tm` RPC is denied under the SYSTEM job context.
/// Single object, no params. en-US output assumed.
#[cfg(windows)]
fn timesync(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
function Invoke-Native { param([scriptblock]$Cmd) & { $ErrorActionPreference='Continue'; (& $Cmd) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $r = [ordered]@{}
  $source = (Invoke-Native { w32tm /query /source }).Trim()
  if ($LASTEXITCODE -eq 0) {
    $r.source         = $source
    $r.vm_ic_provider = ($source -like '*VM IC*')
  } else { $r.source_error = "w32tm /source exit $LASTEXITCODE : $source" }
  $statusRaw = Invoke-Native { w32tm /query /status /verbose }
  if ($LASTEXITCODE -eq 0) {
    $r.stratum      = if ($statusRaw -match 'Stratum:\s*(\d+)')                  { [int]$Matches[1] }   else { $null }
    $r.phase_offset = if ($statusRaw -match 'Phase Offset:\s*(\S+)')             { $Matches[1] }        else { $null }
    $r.last_sync    = if ($statusRaw -match 'Last Successful Sync Time:\s*(.+)') { $Matches[1].Trim() } else { $null }
  } else { $r.status_error = "w32tm /status exit $LASTEXITCODE : $($statusRaw.Trim())" }
  $cfgRaw = Invoke-Native { w32tm /query /configuration }
  if ($LASTEXITCODE -eq 0) {
    $r.type       = if ($cfgRaw -match 'Type:\s*(\S+)')      { $Matches[1] }        else { $null }
    $r.ntp_server = if ($cfgRaw -match 'NtpServer:\s*(.+)')  { $Matches[1].Trim() } else { $null }
  } else { $r.config_error = "w32tm /configuration exit $LASTEXITCODE : $($cfgRaw.Trim())" }
  try {
    $p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $r.reg_type       = $p.Type
    $r.reg_ntp_server = $p.NtpServer
  } catch { $r.reg_error = $_.Exception.Message }
  $svc = Get-Service W32Time -ErrorAction SilentlyContinue
  $r.w32time_service = if ($svc) { [string]$svc.Status } else { 'absent' }
  $r | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn timesync(_params: Option<&str>) -> Option<Value> {
    None
}

/// LDAPS posture (role `addc`) — a local loopback TLS handshake on 636 plus a `LocalMachine\My`
/// server-auth candidate-cert inventory. Single object `{probe, candidate_certs:{count, certs[]}}`,
/// no params. A refused/timed-out connect is the finding (`handshake:"refused"|"timeout"`), not an
/// error. Bounded connect (5 s) and stream (10 s) timeouts so a hung listener can't wedge the thread.
#[cfg(windows)]
fn ldaps_check(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
try {
  $probe = [ordered]@{}
  $tcp = New-Object Net.Sockets.TcpClient
  try {
    $iar = $tcp.BeginConnect('localhost', 636, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(5000)) { $probe.handshake = 'timeout' }
    else {
      try { $tcp.EndConnect($iar) } catch { $probe.handshake = 'refused'; $probe.detail = $_.Exception.Message }
      if (-not $probe.handshake) {
        $stream = $tcp.GetStream(); $stream.ReadTimeout = 10000; $stream.WriteTimeout = 10000
        $ssl = New-Object Net.Security.SslStream($stream, $false, { param($s, $c, $ch, $e) $true })
        try {
          $ssl.AuthenticateAsClient($env:COMPUTERNAME)
          $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
          $probe.handshake = 'ok'; $probe.protocol = [string]$ssl.SslProtocol
          $probe.cert_subject = $cert.Subject; $probe.cert_expires = $cert.NotAfter.ToString('yyyy-MM-dd')
        } catch { $probe.handshake = 'tls_failed'; $probe.detail = $_.Exception.Message } finally { $ssl.Dispose() }
      }
    }
  } finally { $tcp.Dispose() }
  $all = @(Get-ChildItem Cert:\LocalMachine\My)
  $certs = @($all | Select-Object -First 50 | ForEach-Object {
    $eku = @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
    [ordered]@{
      subject     = $_.Subject
      not_after   = $_.NotAfter.ToString('yyyy-MM-dd')
      server_auth = ($eku.Count -eq 0 -or $eku -contains '1.3.6.1.5.5.7.3.1')
      has_private = $_.HasPrivateKey
    }
  })
  [ordered]@{ probe = $probe; candidate_certs = [ordered]@{ count = $all.Count; certs = $certs } } | ConvertTo-Json -Depth 6 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn ldaps_check(_params: Option<&str>) -> Option<Value> {
    None
}

/// Windows Update servicing health — pending-reboot markers, `DISM /CheckHealth` component-store
/// verdict (read-only; never `/ScanHealth` or `/RestoreHealth`), WU COM last-search/last-install, and
/// recent hotfixes. Single object, no params. The four sub-reads degrade independently so a COM
/// failure can't discard the registry facts already collected. en-US output assumed.
#[cfg(windows)]
fn wu_servicing(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
function Invoke-Native { param([scriptblock]$Cmd) & { $ErrorActionPreference='Continue'; (& $Cmd) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $r = [ordered]@{}
  $r.pending = [ordered]@{
    cbs_reboot   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    wu_reboot    = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    file_renames = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
  }
  $dism = Invoke-Native { dism /online /cleanup-image /checkhealth }
  $lastLine = @(($dism.Trim() -split "`r?`n") | Where-Object { $_.Trim() })[-1]
  $r.component_store = if ($LASTEXITCODE -ne 0) { "error: dism exit $LASTEXITCODE : $lastLine" }
                       elseif ($dism -match 'No component store corruption detected') { 'healthy' }
                       elseif ($dism -match 'repairable|corrupt') { 'corruption detected' }
                       else { "unknown: $lastLine" }
  try {
    $au = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
    $r.last_search_success  = if ($au.LastSearchSuccessDate)       { $au.LastSearchSuccessDate.ToString('s') }       else { $null }
    $r.last_install_success = if ($au.LastInstallationSuccessDate) { $au.LastInstallationSuccessDate.ToString('s') } else { $null }
  } catch { $r.wu_com_error = $_.Exception.Message }
  try {
    $r.recent_hotfixes = @(Get-HotFix | Where-Object InstalledOn |
                           Sort-Object InstalledOn -Descending | Select-Object -First 5 |
                           ForEach-Object { [ordered]@{ id = $_.HotFixID; installed = $_.InstalledOn.ToString('yyyy-MM-dd') } })
  } catch { $r.hotfix_error = $_.Exception.Message }
  $r | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn wu_servicing(_params: Option<&str>) -> Option<Value> {
    None
}

/// Virtualization-based-security / Credential Guard state — `Win32_DeviceGuard` in the
/// `root\Microsoft\Windows\DeviceGuard` namespace. Single object, no params. Enum values outside the
/// known ranges pass through as `unknown(N)` so a future OS that grows the enum can't panic-index.
#[cfg(windows)]
fn device_guard(_params: Option<&str>) -> Option<Value> {
    ps_json(r#"$ErrorActionPreference='Stop'
try {
  $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
  $svcMap = @{ 1='Credential Guard'; 2='HVCI'; 3='System Guard Secure Launch'; 4='SMM Firmware Protection' }
  $mapSvc = { param($ids) @(@($ids) | ForEach-Object { if ($svcMap[[int]$_]) { $svcMap[[int]$_] } else { "unknown($_)" } }) }
  $vbsNames = @('Off', 'Configured', 'Running')
  $vbsRaw = [int]$dg.VirtualizationBasedSecurityStatus
  [ordered]@{
    vbs_status          = if ($vbsRaw -ge 0 -and $vbsRaw -lt $vbsNames.Count) { $vbsNames[$vbsRaw] } else { "unknown($vbsRaw)" }
    services_configured = @(& $mapSvc $dg.SecurityServicesConfigured)
    services_running    = @(& $mapSvc $dg.SecurityServicesRunning)
  } | ConvertTo-Json -Depth 4 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
}
#[cfg(not(windows))]
fn device_guard(_params: Option<&str>) -> Option<Value> {
    None
}

/// Environment variables (read-only). Machine scope from the registry
/// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, user scope from `HKCU\Environment`
/// — NOT a process snapshot, so it reflects the persisted (machine/user) definitions. `params` JSON
/// `{scope:"machine"|"user"|"all" (default "all"), name_filter}` — `name_filter` is a case-insensitive
/// substring over the variable name. Returns `[{name,value,scope}, …]`, capped at 1000. This exposes
/// values, but the collector is admin-gated CONSOLE-SIDE (like fs/wmi) — no redaction here. Reads only.
#[cfg(windows)]
fn env_vars(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let scope = p.get("scope").and_then(|x| x.as_str()).unwrap_or("all");
    let want_machine = scope == "machine" || scope == "all";
    let want_user = scope == "user" || scope == "all";
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '*' | '?'))
            .take(256)
            .collect()
    };
    let where_clause = match p.get("name_filter").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        Some(n) => format!(" | Where-Object {{ $_.name -like '*{}*' }}", safe(n)),
        None => String::new(),
    };
    // Build the (registry-path, scope-label) source list per the requested scope. Each registry key's
    // value names are the variable names; `Get-Item`/`GetValue` only READS — we never write the hive.
    let mut sources: Vec<&str> = Vec::new();
    if want_machine {
        sources.push("@{ p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'; s='machine' }");
    }
    if want_user {
        sources.push("@{ p='HKCU:\\Environment'; s='user' }");
    }
    if sources.is_empty() {
        return Some(json!([]));
    }
    let script = format!(
        "{PS_GUARD}\
         $srcs=@({}); \
         @($srcs | ForEach-Object {{ $scope=$_.s; $k=Get-Item -LiteralPath $_.p -ErrorAction SilentlyContinue; \
           if($k){{ foreach($n in $k.GetValueNames()){{ [pscustomobject]@{{ name=[string]$n; value=[string]($k.GetValue($n)); scope=$scope }} }} }} \
         }}){} | Sort-Object scope,name | Select-Object -First 1000 | ConvertTo-Json -Depth 3 -Compress",
        sources.join(","),
        where_clause
    );
    // The capping array helper keeps an over-long value (e.g. a giant PATH) from blowing the result cap.
    ps_json_array(&script, 1000, params, "env-vars")
}
#[cfg(not(windows))]
fn env_vars(_params: Option<&str>) -> Option<Value> {
    None
}

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

/// PowerShell prelude that locates ServerUtil.exe and the service datafolder, defining `$su` (exe
/// path), `$df` (the resolved datafolder), `$dfSource` (`imagepath` | `probe-serverdb` |
/// `probe-exists` | empty), and `$dfArgs` (the `--server-datafolder` arg array, empty when the service
/// uses the default). Emits an `{ok:false,error}` JSON and exits if Duplicati isn't installed as a
/// service.
///
// Datafolder resolution has TWO consumers with different needs, hence `$dfArgs` vs `$df`:
//   `$dfArgs` — passed to ServerUtil. Bound to the EXPLICIT `--server-datafolder` from the service
//     ImagePath only. When the service uses a default, ServerUtil resolves the same default itself, so
//     passing a probed path would be redundant and could disagree with the server's own view.
//   `$df` — the folder path itself, for the ACL/owner ops. Falls back to probing when the ImagePath
//     carries no explicit value, because those ops need a real path or they cannot run at all.
//
// A trailing separator is stripped from the ImagePath value (except a bare drive root like `E:\`).
// At least one server in the field really is configured as `--server-datafolder="E:\Duplicati\"`.
// That survived every
// icacls call here — PowerShell passes a space-free path unquoted, so nothing can eat the quote — but
// the same path *with a space* would be quoted, and a trailing `\` immediately before the closing `"`
// escapes it. The native command line then sees an unterminated argument and swallows the next one.
// Identical failure mode to the 0.12.1 trailing-quote bug, one character over, and it would only ever
// bite on a path like `D:\Backup Data\Duplicati\` — the case least likely to be hit in testing.
//
// The probe order matters: **Duplicati 2.3 defaults a service install to `%ProgramData%\Duplicati`**,
// not `%LOCALAPPDATA%\Duplicati`. Verified 2026-07-20 on sulltec-g360nd3 (fresh 2.3.0.107 service
// install, ImagePath `…Duplicati.WindowsService.exe SERVER` with no datafolder arg): the live folder
// holding `Duplicati-server.sqlite` was `C:\ProgramData\Duplicati`, while SYSTEM's LOCALAPPDATA path
// did not exist. The old LOCALAPPDATA-only fallback therefore made every ACL op fail with
// `datafolder not found` on a default 2.3 install — the exact configuration the fleet lands on after
// upgrading. Prefer whichever candidate actually holds the server DB; fall back to whichever exists.
#[cfg(windows)]
const DUP_PRELUDE: &str = r#"$ErrorActionPreference='SilentlyContinue'
$img=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Duplicati' -EA SilentlyContinue).ImagePath
$exeDir=$null;$df=$null
if($img){
 if($img -match '^\s*"([^"]+)"'){$exeDir=Split-Path $Matches[1] -Parent}
 elseif($img -match '^\s*(\S+\.exe)'){$exeDir=Split-Path $Matches[1] -Parent}
 if($img -match '--server-datafolder="([^"]+)"'){ $df=$Matches[1] }
 elseif($img -match '--server-datafolder=([^"]+)"'){ $df=$Matches[1] }
 elseif($img -match '--server-datafolder=(\S+)'){ $df=$Matches[1] }
 if($df){ $df=$df.Trim().Trim('"'); if($df.Length -gt 3){ $df=$df.TrimEnd('\') } }
}
if(-not $exeDir -or -not (Test-Path (Join-Path $exeDir 'Duplicati.CommandLine.ServerUtil.exe'))){
 foreach($d in @("$env:ProgramFiles\Duplicati 2","${env:ProgramFiles(x86)}\Duplicati 2")){ if(Test-Path (Join-Path $d 'Duplicati.CommandLine.ServerUtil.exe')){$exeDir=$d;break} }
}
$su=$null; if($exeDir){$su=Join-Path $exeDir 'Duplicati.CommandLine.ServerUtil.exe'}
if(-not $su -or -not (Test-Path $su)){ (@{ok=$false;error='Duplicati ServerUtil.exe not found; is Duplicati installed as a service?'}|ConvertTo-Json -Compress); exit }
$dfArgs=@(); if($df){$dfArgs=@('--server-datafolder',$df)}
$dfSource=$(if($df){'imagepath'}else{''})
if(-not $df){
 foreach($c in @("$env:ProgramData\Duplicati","$env:LOCALAPPDATA\Duplicati")){ if(Test-Path (Join-Path $c 'Duplicati-server.sqlite')){ $df=$c; $dfSource='probe-serverdb'; break } }
 if(-not $df){ foreach($c in @("$env:ProgramData\Duplicati","$env:LOCALAPPDATA\Duplicati")){ if(Test-Path $c){ $df=$c; $dfSource='probe-exists'; break } } }
}"#;

/// `run` action tail — enqueue a backup and shape the `{ok,command,backup,result,raw}` envelope. Uses
/// `$b` (the single-quoted backup id/name) set by the caller.
#[cfg(windows)]
const DUP_RUN_TAIL: &str = r#"$raw=(& $su --json @dfArgs run $b 2>&1 | Out-String)
$i=$raw.IndexOfAny([char[]]@('{','['));$p=$null;if($i -ge 0){try{$p=$raw.Substring($i)|ConvertFrom-Json}catch{}}
[pscustomobject]@{ok=[bool]($p -and $p.Success);command='run';backup=$b;datafolder=$df;result=$p;raw=$(if($p){$null}else{$raw.Trim()})}|ConvertTo-Json -Depth 20"#;

/// `pause` action tail — parse the `$raw` ServerUtil output into the `{ok,command,result,raw}` envelope.
#[cfg(windows)]
const DUP_PAUSE_TAIL: &str = r#"$i=$raw.IndexOfAny([char[]]@('{','['));$p=$null;if($i -ge 0){try{$p=$raw.Substring($i)|ConvertFrom-Json}catch{}}
[pscustomobject]@{ok=[bool]($p -and $p.Success);command='pause';datafolder=$df;result=$p;raw=$(if($p){$null}else{$raw.Trim()})}|ConvertTo-Json -Depth 20"#;

/// Prepend the discovery prelude to a Duplicati op `body` (which may use `$su`, `$dfArgs`, `$df`).
#[cfg(windows)]
fn dup_script(body: &str) -> String {
    format!("{DUP_PRELUDE}\n{body}")
}

/// Escape + wrap a value as a PowerShell single-quoted literal (control chars stripped, length-capped),
/// so an operator-supplied backup name / duration can't break out of the script.
#[cfg(windows)]
fn dup_squote(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).take(256).collect();
    format!("'{}'", cleaned.replace('\'', "''"))
}

/// Pull a bare-string OR `{key:…}` value out of the job params (first matching key wins).
///
/// **Accepts numbers and booleans, not just strings.** This read `as_str()` only, which returns `None`
/// for a JSON number — so `{"limit": 12}` was silently ignored and the collector fell through to its
/// default, while `{"limit": "12"}` worked. Measured 2026-07-21: `idrac-sel` asked for 12 entries and
/// returned 50. Every numeric collector param was affected (`pagesize`, `warning_cap`, `limit`), and
/// the failure is invisible — a plausible default comes back and nothing reports that the request was
/// dropped. Same family as the scalar-params bug in `inject_app_secret`: JSON type assumptions that
/// hold for one caller and not another.
#[cfg(windows)]
fn dup_param(params: Option<&str>, keys: &[&str]) -> String {
    let raw = params.unwrap_or("").trim();
    if raw.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            for k in keys {
                match v.get(*k) {
                    Some(Value::String(s)) => return s.trim().to_string(),
                    Some(Value::Number(n)) => return n.to_string(),
                    Some(Value::Bool(b)) => return b.to_string(),
                    _ => {}
                }
            }
        }
        return String::new();
    }
    raw.to_string()
}

/// Read-only: configured backups + their last-run status (`ServerUtil list-backups`).
#[cfg(windows)]
fn duplicati_backups() -> Option<Value> {
    ps_json(&dup_script(
        r#"$raw=(& $su --json @dfArgs list-backups 2>&1 | Out-String)
$i=$raw.IndexOfAny([char[]]@('{','['));$p=$null;if($i -ge 0){try{$p=$raw.Substring($i)|ConvertFrom-Json}catch{}}
[pscustomobject]@{ok=[bool]$p;command='list-backups';datafolder=$df;result=$p;raw=$(if($p){$null}else{$raw.Trim()})}|ConvertTo-Json -Depth 20"#,
    ))
}
#[cfg(not(windows))]
fn duplicati_backups() -> Option<Value> {
    None
}

/// Read-only: server status + health (`ServerUtil status` + `health`).
#[cfg(windows)]
fn duplicati_status() -> Option<Value> {
    ps_json(&dup_script(
        r#"function P($t){$i=$t.IndexOfAny([char[]]@('{','['));if($i -ge 0){try{return ($t.Substring($i)|ConvertFrom-Json)}catch{}};return $null}
$sp=P((& $su --json @dfArgs status 2>&1 | Out-String))
$hp=P((& $su --json @dfArgs health 2>&1 | Out-String))
[pscustomobject]@{ok=[bool]($sp -or $hp);command='status';datafolder=$df;status=$sp;health=$hp}|ConvertTo-Json -Depth 20"#,
    ))
}
#[cfg(not(windows))]
fn duplicati_status() -> Option<Value> {
    None
}

/// VSS self-test body — run Duplicati's `Snapshots.exe` against a throwaway temp folder on `$vol`
/// (created + cleaned up here; NEVER a backup source or user path — the tool writes a testfile.bin
/// into it), parse the result. Needs SYSTEM to create the shadow copy (the fork provides that); on a
/// non-elevated context it reports the "Access is denied" failure verbatim.
#[cfg(windows)]
const DUP_VSS_BODY: &str = r#"$snap=Join-Path $exeDir 'Duplicati.CommandLine.Snapshots.exe'
if(-not (Test-Path $snap)){ (@{ok=$false;error='Duplicati Snapshots.exe not found'}|ConvertTo-Json -Compress); exit }
if(-not $vol){ $vol=($env:SystemDrive).TrimEnd(':') }
$root=($vol+':\')
if(-not (Test-Path $root)){ (@{ok=$false;error=('volume not found: '+$root)}|ConvertTo-Json -Compress); exit }
$dir=Join-Path $root ('SullTecRemote-vsstest-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$out=''
try { $out=(& $snap $dir 2>&1 | Out-String) } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
$failed=[bool](($out -match 'Test failed') -or ($out -match 'tester failed') -or ($out -match 'Access is denied'))
$locked=[bool]($out -match 'correctly locked')
[pscustomobject]@{ok=(-not $failed);volume=$root;locked=$locked;snapshot_ok=(-not $failed);output=(($out.Trim() -split "`n" | Select-Object -Last 25) -join "`n")}|ConvertTo-Json -Depth 6"#;

/// Read-only: VSS snapshot self-test (`Snapshots.exe`) on `params.volume` (a drive letter; default the
/// system drive). Diagnoses the VSS-writer / locked-file failures Duplicati backups hit.
#[cfg(windows)]
fn duplicati_vss_test(params: Option<&str>) -> Option<Value> {
    let vol = dup_param(params, &["volume", "drive"]);
    let letter = vol.chars().find(|c| c.is_ascii_alphabetic()).map(|c| c.to_ascii_uppercase());
    let volline = match letter {
        Some(c) => format!("$vol='{c}'"),
        None => "$vol=($env:SystemDrive).TrimEnd(':')".to_string(),
    };
    ps_json(&dup_script(&format!("{volline}\n{DUP_VSS_BODY}")))
}
#[cfg(not(windows))]
fn duplicati_vss_test(_params: Option<&str>) -> Option<Value> {
    None
}

/// L2 action: run a backup now (`ServerUtil run <backup>`; fire-and-return — no `--wait`, since a
/// backup can run for a long time). `params` = the backup id/name (bare string or `{backup|id|name:…}`).
#[cfg(windows)]
fn duplicati_run(params: Option<&str>) -> Value {
    let backup = dup_param(params, &["backup", "id", "name"]);
    if backup.is_empty() {
        return json!({"ok": false, "error": "no backup id/name provided (params: a bare id/name, or {\"backup\":\"…\"})"});
    }
    let body = format!("$b={b}\n{tail}", b = dup_squote(&backup), tail = DUP_RUN_TAIL);
    ps_json(&dup_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati run produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_run(_params: Option<&str>) -> Value {
    json!({"ok": false, "error": "windows only"})
}

/// L1 action: pause the backup scheduler (`ServerUtil pause [<duration>]`). `params` = optional
/// duration (e.g. "5m", "1h"); omitted → pause until resumed.
#[cfg(windows)]
fn duplicati_pause(params: Option<&str>) -> Value {
    let dur = dup_param(params, &["duration"]);
    let call = if dur.is_empty() { "pause".to_string() } else { format!("pause {}", dup_squote(&dur)) };
    let body = format!(
        "$raw=(& $su --json @dfArgs {call} 2>&1 | Out-String)\n{tail}",
        call = call,
        tail = DUP_PAUSE_TAIL,
    );
    ps_json(&dup_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati pause produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_pause(_params: Option<&str>) -> Value {
    json!({"ok": false, "error": "windows only"})
}

/// L1 action: resume the backup scheduler (`ServerUtil resume`).
#[cfg(windows)]
fn duplicati_resume() -> Value {
    ps_json(&dup_script(
        r#"$raw=(& $su --json @dfArgs resume 2>&1 | Out-String)
$i=$raw.IndexOfAny([char[]]@('{','['));$p=$null;if($i -ge 0){try{$p=$raw.Substring($i)|ConvertFrom-Json}catch{}}
[pscustomobject]@{ok=[bool]($p -and $p.Success);command='resume';datafolder=$df;result=$p;raw=$(if($p){$null}else{$raw.Trim()})}|ConvertTo-Json -Depth 20"#,
    ))
    .unwrap_or_else(|| json!({"ok": false, "error": "Duplicati resume produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_resume() -> Value {
    json!({"ok": false, "error": "windows only"})
}

// ── Duplicati Server REST API actions (Phase 2b) ──────────────────────────────────────────────
// repair / recreate / verify / compact / vacuum go through the local Duplicati Server API (:8200) —
// the server owns the DB and runs the op in-process (web-UI parity), so no passphrase-on-disk and no
// DB-lock conflict. Auth: ServerUtil mints a long-lived bearer via `issue-forever-token` (which does
// the datafolder→signin-JWT→`auth/signin` flow internally); we cache it and send `Authorization:
// Bearer`. The mint requires the operator to have enabled `--webservice-enable-forever-token` on the
// service once; until then these actions return an actionable error.
// NOTE: this token + HTTP layer is NOT exercised by the Rust build/tests — validate on a box (against a
// throwaway backup) before first real use.

/// `Invoke-DupApi` (appended after `DUP_PRELUDE`) — a Bearer call to the local Duplicati server API.
/// The token arrives with the job from the console vault; nothing is read from or written to disk here.
/// Windows PowerShell 5.1: `Invoke-RestMethod` throws on non-2xx, so the status is read from the
/// exception.
///
/// **Timeout is sized for the largest backup in the fleet, not the smallest.** This was 60s, which is
/// ample on a few-hundred-GiB backup and *not* ample on a multi-TiB one: measured 2026-07-20, a
/// `/filesets` read (nominally cheap — it lists restore points) blew past 60s on a 1.87 TiB / 2.3M-file
/// backup while the same call on a 323 GiB / 426k-file backup returned promptly. The failure is
/// especially unhelpful to diagnose because a job sitting in its timeout is indistinguishable from one
/// that was never picked up: both read `queued`. There is no job-level timeout in the fork, so this
/// value is the real ceiling.
#[cfg(windows)]
const DUP_API_HELPER: &str = r#"if(-not $dupTimeout){ $dupTimeout=300 }
function Invoke-DupApi([string]$method,[string]$path,$bodyObj){
  if(-not $tok){ return [pscustomobject]@{ok=$false;status=0;error='no Duplicati API token delivered for this device; run the duplicati-token-issue action first'} }
  $h=@{ Authorization="Bearer $tok" }
  $uri="http://127.0.0.1:8200$path"
  try {
    if($null -ne $bodyObj){ $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -Body ($bodyObj|ConvertTo-Json) -ContentType 'application/json' -TimeoutSec $dupTimeout }
    # A bodyless POST carries no Content-Type, and endpoints that accept an optional DTO (repair takes
    # RepairInputDto) reject that with 415 — while ones taking no body at all (verify/compact/vacuum) are
    # fine either way. Send an empty JSON object so both shapes work (2026-07-20: repair returned 415,
    # which also broke recreate, since its second step is /repair).
    elseif($method -eq 'POST'){ $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -Body '{}' -ContentType 'application/json' -TimeoutSec $dupTimeout }
    else { $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -TimeoutSec $dupTimeout }
    return [pscustomobject]@{ok=$true;status=200;result=$res}
  } catch {
    $sc=0; try{ $sc=[int]$_.Exception.Response.StatusCode }catch{}
    $msg="$($_.Exception.Message)"
    # Name the timeout explicitly: the bare .NET text ("The operation has timed out.") with status 0
    # gives an operator nothing to act on, and this is the expected failure on very large backups.
    if($msg -match 'timed out'){ $msg="Duplicati API call timed out after ${dupTimeout}s ($path). Very large backups can exceed this; the Duplicati server itself is unaffected and may still be working." }
    return [pscustomobject]@{ok=$false;status=$sc;error=$msg}
  }
}"#;

/// Mint a fresh Duplicati API token and hand it straight back to the console, which seals it into the
/// `app_secret` vault and stores only a redacted result. **Nothing is written to disk here** — this is
/// what replaced the old `%ProgramData%` token cache (which inherited `BUILTIN\Users:(RX)`).
#[cfg(windows)]
const DUP_TOKEN_ISSUE_BODY: &str = r#"$raw=(& $su --json @dfArgs issue-forever-token 2>&1 | Out-String)
$tok=$null
$i=$raw.IndexOfAny([char[]]@('{','[')); if($i -ge 0){ try{ $p=$raw.Substring($i)|ConvertFrom-Json; if($p.Token){$tok=$p.Token} }catch{} }
# ServerUtil nests this: $p.Token can itself be an object ({Token=...}) rather than the string. Walk
# down until we actually hold a string, or the console stores whatever shape this is (2026-07-20).
$guard=0
while($tok -and ($tok -isnot [string]) -and $guard -lt 5){
  $guard++
  if($tok.PSObject.Properties['Token']){ $tok=$tok.Token }
  else { $tok=($tok.PSObject.Properties | Where-Object { $_.Value -is [string] } | Select-Object -First 1 -ExpandProperty Value) }
}
if($tok -isnot [string]){ $tok=$null }
if(-not $tok -and $raw -match 'Bearer\s+([A-Za-z0-9._\-]+)'){ $tok=$Matches[1] }
# Last resort: a bare JWT anywhere in the output.
if(-not $tok -and $raw -match '(eyJ[A-Za-z0-9._\-]{20,})'){ $tok=$Matches[1] }
if($tok){ [pscustomobject]@{ok=$true;token=$tok}|ConvertTo-Json -Compress }
else { [pscustomobject]@{ok=$false;error='could not mint a Duplicati token; enable --webservice-enable-forever-token on the Duplicati service (one-time), then retry';detail=(($raw.Trim() -split "`n" | Select-Object -Last 6) -join ' | ')}|ConvertTo-Json -Compress }"#;

/// L2 action: mint a Duplicati API token. The token is returned to the console over the SIGNED result
/// channel and sealed server-side; it is never persisted on this endpoint.
#[cfg(windows)]
fn duplicati_token_issue(_params: Option<&str>) -> Value {
    ps_json(&dup_script(DUP_TOKEN_ISSUE_BODY))
        .unwrap_or_else(|| json!({"ok": false, "error": "Duplicati token-issue produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_token_issue(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }

/// One-time enablement of `--webservice-enable-forever-token` on the Duplicati service, so
/// `issue-forever-token` (and therefore every API-backed kind) can work on this box.
///
/// This edits the service `ImagePath` and restarts Duplicati, so it is written to be **reversible**:
/// the original string is captured first, and if the service does not come back healthy the original
/// is written back and the service restarted again. A malformed ImagePath means the service will not
/// start at all — on a domain controller that silently stops the backups.
///
/// Two non-obvious details:
///
/// * **Trailing separator inside a quoted datafolder.** `--server-datafolder="E:\Duplicati\"` ends in
///   `\"`, which `CommandLineToArgvW` reads as an *escaped quote*, not a closing one. The quoted run
///   is then unterminated, so anything appended after it is swallowed into that argument. **Measured
///   2026-07-20 on the test rig, and the outcome is worse than a lost flag: the Duplicati service
///   fails to start at all.** The same ImagePath with nothing appended after the `\"` starts fine —
///   it is specifically appending *past* the escaped quote that kills it. A server in the field has
///   a datafolder of exactly this shape, so an append-only implementation would have stopped
///   Duplicati on a production DC. (Same family as the 0.12.1 trailing-quote bug and DUP_PRELUDE's
///   `TrimEnd('\')`.)
///
///   Two quoting styles occur in the field — `--server-datafolder="V"` and `"--server-datafolder=V"`
///   — so both are normalized. Any *other* shape that still ends in `\"` after those rules is
///   refused rather than appended to: silently writing an ImagePath that stops the service is the
///   one outcome worth failing closed over, and the rollback should be the backstop, not the plan.
/// * **Value kind.** `ImagePath` is normally `REG_EXPAND_SZ`. `Set-ItemProperty` can rewrite it as
///   `REG_SZ`, which stops `%SystemRoot%`-style expansion for services that rely on it, so the
///   existing kind is read and preserved.
///
/// Refuses to restart while a backup is running unless `force=true`.
#[cfg(windows)]
const DUP_FOREVER_TOKEN_ENABLE_BODY: &str = r#"$svcKey='HKLM:\SYSTEM\CurrentControlSet\Services\Duplicati'
$img=(Get-ItemProperty $svcKey -EA SilentlyContinue).ImagePath
if(-not $img){ (@{ok=$false;error='Duplicati service ImagePath not found; is Duplicati installed as a service?'}|ConvertTo-Json -Compress); exit }
$flag='--webservice-enable-forever-token=true'
if($img -match '--webservice-enable-forever-token'){
  ([pscustomobject]@{ok=$true;already_enabled=$true;changed=$false;image_path=$img;datafolder=$df;service_status=[string](Get-Service Duplicati -EA SilentlyContinue).Status}|ConvertTo-Json -Depth 6); exit
}
# Refuse to bounce the service mid-operation unless explicitly forced.
$act=''
$st=(& $su --json @dfArgs status 2>&1 | Out-String)
$k=$st.IndexOfAny([char[]]@('{','[')); if($k -ge 0){ try{ $sp=$st.Substring($k)|ConvertFrom-Json; if($sp.ActiveTask){$act=[string]$sp.ActiveTask} }catch{} }
if($act -and -not $force){
  ([pscustomobject]@{ok=$false;changed=$false;error='a Duplicati task is currently running; refusing to restart the service (re-run with force=true to override)';active_task=$act}|ConvertTo-Json -Depth 6); exit
}
$orig=$img
# Strip separators immediately before a closing quote. BOTH quoting styles occur in the field:
#   value-quoted      --server-datafolder="V\"
#   whole-arg-quoted "--server-datafolder=V\"
$new=($orig -replace '(--server-datafolder="[^"]*[^"\\])\\+"','$1"')
$new=($new  -replace '("--server-datafolder=[^"]*[^"\\])\\+"','$1"')
$normalized=($new -ne $orig)
$new=$new.TrimEnd()
# Fail closed on any quoting shape the two rules above did not flatten. Appending after a trailing
# \" does not merely lose the flag - it stops the service outright (verified 2026-07-20).
if($new -match '\\"$'){
  ([pscustomobject]@{ok=$false;changed=$false;error='the service ImagePath ends in an escaped quote (\") in a form this action does not recognise; appending after it would prevent the Duplicati service from starting. Correct the ImagePath quoting by hand, then re-run.';image_path=$orig}|ConvertTo-Json -Depth 6); exit
}
$new=$new+' '+$flag
if($dry){
  ([pscustomobject]@{ok=$true;dry_run=$true;changed=$false;normalized_trailing_sep=$normalized;datafolder=$df;image_path_before=$orig;image_path_after=$new}|ConvertTo-Json -Depth 6); exit
}
$kind=[string](Get-Item $svcKey).GetValueKind('ImagePath')
if($kind -ne 'ExpandString' -and $kind -ne 'String'){ $kind='ExpandString' }
$steps=@()
function Set-Img([string]$v){ $null=New-ItemProperty -Path $svcKey -Name ImagePath -Value $v -PropertyType $kind -Force -EA SilentlyContinue }
function Test-Healthy(){
  for($i=0;$i -lt 10;$i++){
    Start-Sleep -Seconds 3
    $h=(& $su --json @dfArgs health 2>&1 | Out-String)
    $j=$h.IndexOfAny([char[]]@('{','['))
    if($j -ge 0){ try{ $hp=$h.Substring($j)|ConvertFrom-Json; if($hp.healthy -or $hp.Success){ return $true } }catch{} }
  }
  return $false
}
Set-Img $new
$steps+='ImagePath updated'
try{ Restart-Service Duplicati -Force -EA Stop; $steps+='service restarted' }catch{ $steps+=('restart failed: '+$_.Exception.Message) }
$svc=Get-Service Duplicati -EA SilentlyContinue
$running=($svc -and $svc.Status -eq 'Running')
$healthy=$(if($running){ Test-Healthy }else{ $false })
$rolled=$false
if(-not ($running -and $healthy)){
  # Put it back exactly as found and bring the service up again.
  Set-Img $orig
  $steps+='VERIFY FAILED - ImagePath rolled back to original'
  try{ Restart-Service Duplicati -Force -EA Stop; $steps+='service restarted (rollback)' }catch{ try{ Start-Service Duplicati -EA Stop; $steps+='service started (rollback)' }catch{ $steps+=('rollback restart failed: '+$_.Exception.Message) } }
  $rolled=$true
  $svc=Get-Service Duplicati -EA SilentlyContinue
  $running=($svc -and $svc.Status -eq 'Running')
  $healthy=$(if($running){ Test-Healthy }else{ $false })
}
[pscustomobject]@{ok=(-not $rolled -and $running -and $healthy);changed=(-not $rolled);rolled_back=$rolled;normalized_trailing_sep=$normalized;datafolder=$df;datafolder_source=$dfSource;service_running=$running;server_healthy=$healthy;value_kind=$kind;steps=$steps;image_path_before=$orig;image_path_after=$(if($rolled){$orig}else{$new})}|ConvertTo-Json -Depth 6"#;

/// L2 action: enable the forever-token webservice flag (idempotent; `dry_run=true` previews,
/// `force=true` restarts even while a backup is running).
#[cfg(windows)]
fn duplicati_forever_token_enable(params: Option<&str>) -> Value {
    let dry = dup_param(params, &["dry_run", "dryrun", "whatif"]).eq_ignore_ascii_case("true");
    let force = dup_param(params, &["force"]).eq_ignore_ascii_case("true");
    let body = format!(
        "$dry=${d}\n$force=${f}\n{DUP_FOREVER_TOKEN_ENABLE_BODY}",
        d = if dry { "true" } else { "false" },
        f = if force { "true" } else { "false" }
    );
    ps_json(&dup_script(&body))
        .unwrap_or_else(|| json!({"ok": false, "error": "forever-token-enable produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_forever_token_enable(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }

/// Recreate = delete the local DB then repair (rebuild from the target). Two API calls; abort if the
/// first fails.
#[cfg(windows)]
const DUP_RECREATE_CALLS: &str = r#"$d=Invoke-DupApi 'POST' "/api/v1/backup/$id/deletedb" $null
if(-not $d.ok){ [pscustomobject]@{ok=$false;command='recreate';step='deletedb';backup=$id;status=$d.status;error=$d.error}|ConvertTo-Json -Depth 15 }
else { $r=Invoke-DupApi 'POST' "/api/v1/backup/$id/repair" $null; [pscustomobject]@{ok=$r.ok;command='recreate';step='repair';backup=$id;status=$r.status;result=$r.result;error=$r.error}|ConvertTo-Json -Depth 15 }"#;

/// Prepend the discovery prelude + the API helper to an action `body` (which uses `$id`, `Invoke-DupApi`).
#[cfg(windows)]
fn dup_api_script(body: &str) -> String {
    format!("{DUP_PRELUDE}\n{DUP_API_HELPER}\n{body}")
}

/// Extract + validate the numeric backup id (the API path is `/backup/{id}` — a numeric id, not a name).
#[cfg(windows)]
fn dup_backup_id(params: Option<&str>) -> Option<String> {
    let raw = dup_param(params, &["backup", "id", "name"]);
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() { None } else { Some(digits) }
}

/// Escape a **secret** as a PowerShell single-quoted literal. Same injection-safety as [`dup_squote`]
/// (control chars stripped, `'` doubled) but without its short operator-input cap.
///
/// `dup_squote` truncates at 256 chars, which is right for a backup name or a duration and WRONG for a
/// credential: a Duplicati forever-token JWT is ~277 chars, so it silently lost 21 characters of
/// signature and every API call came back `401 Unauthorized` with a token that still looked
/// well-formed (2026-07-20). The 8 KB bound here is a sanity limit, not a content assumption.
#[cfg(windows)]
fn dup_squote_secret(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).take(8192).collect();
    format!("'{}'", cleaned.replace('\'', "''"))
}

/// The console-delivered Duplicati API token as a PowerShell assignment. The console merges it into the
/// params of a signed params-fetch (docs/PLAN-app-secrets.md §4); it is never read from or written to
/// disk on this endpoint.
#[cfg(windows)]
fn dup_token_line(params: Option<&str>) -> Option<String> {
    let t = dup_param(params, &["token"]);
    if t.is_empty() { None } else { Some(format!("$tok={}", dup_squote_secret(&t))) }
}

/// The error returned when the console delivered no token for this device.
#[cfg(windows)]
fn dup_no_token() -> Value {
    json!({"ok": false, "error": "no Duplicati API token for this device — run the duplicati-token-issue action (L2) first"})
}

/// A single-call API action (`repair`/`verify`/`compact`/`vacuum`) — `POST /backup/{id}/{op}`.
#[cfg(windows)]
fn dup_api_simple(params: Option<&str>, op: &str) -> Value {
    let Some(id) = dup_backup_id(params) else {
        return json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"});
    };
    let Some(tok) = dup_token_line(params) else { return dup_no_token() };
    let body = format!(
        "{tok}\n$id='{id}'\n$r=Invoke-DupApi 'POST' \"/api/v1/backup/$id/{op}\" $null\n[pscustomobject]@{{ok=$r.ok;command='{op}';backup=$id;status=$r.status;result=$r.result;error=$r.error}}|ConvertTo-Json -Depth 15",
        tok = tok, id = id, op = op
    );
    ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati API call produced no parseable output"}))
}

/// L2: repair the backup database (Server API `/repair`).
#[cfg(windows)]
fn duplicati_repair(params: Option<&str>) -> Value {
    dup_api_simple(params, "repair")
}
/// L1: verify/integrity-test the backup (Server API `/verify`).
#[cfg(windows)]
fn duplicati_verify(params: Option<&str>) -> Value {
    dup_api_simple(params, "verify")
}
/// L2: compact — reclaim wasted remote space (Server API `/compact`).
#[cfg(windows)]
fn duplicati_compact(params: Option<&str>) -> Value {
    dup_api_simple(params, "compact")
}
/// L1: vacuum the local DB (Server API `/vacuum`).
#[cfg(windows)]
fn duplicati_vacuum(params: Option<&str>) -> Value {
    dup_api_simple(params, "vacuum")
}
/// L2: recreate the local DB — delete it then rebuild from the target (Server API `/deletedb`+`/repair`).
#[cfg(windows)]
fn duplicati_recreate(params: Option<&str>) -> Value {
    let Some(id) = dup_backup_id(params) else {
        return json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"});
    };
    let Some(tok) = dup_token_line(params) else { return dup_no_token() };
    let body = format!("{tok}\n$id='{id}'\n{calls}", tok = tok, id = id, calls = DUP_RECREATE_CALLS);
    ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati recreate produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_repair(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }
#[cfg(not(windows))]
fn duplicati_verify(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }
#[cfg(not(windows))]
fn duplicati_compact(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }
#[cfg(not(windows))]
fn duplicati_vacuum(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }
#[cfg(not(windows))]
fn duplicati_recreate(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }

/// A read-only API GET (`/backup/{id}/{suffix}{query}`) via the same token/Bearer helper as the
/// actions. Returns the parsed server JSON in an envelope. Reads still need the forever-token (all API
/// calls are authed), so they share the actions' `--webservice-enable-forever-token` prerequisite.
#[cfg(windows)]
fn dup_api_get(params: Option<&str>, suffix: &str, command: &str, query: &str) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let body = format!(
        "{tok}\n$id='{id}'\n$r=Invoke-DupApi 'GET' \"/api/v1/backup/$id/{suffix}{query}\" $null\n[pscustomobject]@{{ok=$r.ok;command='{command}';backup=$id;status=$r.status;result=$r.result;error=$r.error}}|ConvertTo-Json -Depth 20",
        tok = tok, id = id, suffix = suffix, query = query, command = command
    );
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati API read produced no parseable output"})))
}

/// Read-only: list the backup's restore points / versions (Server API `/filesets`).
#[cfg(windows)]
fn duplicati_browse(params: Option<&str>) -> Option<Value> {
    dup_api_get(params, "filesets", "browse", "")
}
#[cfg(not(windows))]
fn duplicati_browse(_p: Option<&str>) -> Option<Value> { None }

/// `log` body — fetch a few log entries and **project** them. Each entry's `Message` is a complete
/// serialized operation result: filesets, the full `Messages` array, `BackendStatistics`, and every
/// warning. Returning those verbatim does not scale — measured 2026-07-20, `?pagesize=200` against a
/// 2.3M-file backup never completed, because `ConvertTo-Json -Depth 20` over that much data is far
/// slower than the HTTP fetch that produced it. The console clamps the stored result to 64 KB, so the
/// old shape built hundreds of MB in order to throw nearly all of it away.
///
/// What an operator actually needs from this collector is the *warnings* — the EFS `PermissionDenied`
/// lines and missing-fileset errors. So keep the per-run outcome, keep the authoritative
/// `*ActualLength` counts, keep a bounded sample of the warning/error text, and drop the informational
/// `Messages` array and `BackendStatistics` entirely. `warnings_truncated` states plainly when the
/// sample is short of the real count, so a partial list can never be mistaken for a complete one.
#[cfg(windows)]
const DUP_LOG_BODY: &str = r#"$r=Invoke-DupApi 'GET' "/api/v1/backup/$id/log?pagesize=$pagesize" $null
if(-not $r.ok){ ([pscustomobject]@{ok=$false;command='log';backup=$id;status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6); exit }
$entries=@()
foreach($e in @($r.result)){
  $m=$null
  try{ if($e.Message){ $m=$e.Message|ConvertFrom-Json } }catch{}
  $o=[ordered]@{id=$e.ID;type=[string]$e.Type;timestamp=$e.Timestamp}
  if($m){
    $o.operation=[string]$m.MainOperation
    $o.parsed_result=[string]$m.ParsedResult
    $o.interrupted=$m.Interrupted
    $o.begin=[string]$m.BeginTime
    $o.end=[string]$m.EndTime
    $o.duration=[string]$m.Duration
    $o.messages_total=$m.MessagesActualLength
    $o.warnings_total=$m.WarningsActualLength
    $o.errors_total=$m.ErrorsActualLength
    $o.warnings=@(@($m.Warnings) | Where-Object { $_ } | Select-Object -First $cap)
    $o.errors=@(@($m.Errors) | Where-Object { $_ } | Select-Object -First $cap)
    $o.warnings_truncated=([int]$m.WarningsActualLength -gt @($o.warnings).Count)
    $o.errors_truncated=([int]$m.ErrorsActualLength -gt @($o.errors).Count)
  } else {
    $t=[string]$e.Message
    if($t.Length -gt 1500){ $t=$t.Substring(0,1500)+' ...[truncated]' }
    $o.raw=$t
  }
  $entries+=[pscustomobject]$o
}
[pscustomobject]@{ok=$true;command='log';backup=$id;pagesize=$pagesize;warning_cap=$cap;count=@($entries).Count;entries=$entries}|ConvertTo-Json -Depth 8"#;

/// Read-only: the backup job's own log — per-run outcome + warnings/errors (Server API `/log`).
/// Surfaces the EFS `PermissionDenied` / missing-fileset entries we otherwise dig for by hand.
/// `pagesize` (default 5, max 50) and `warning_cap` (default 100, max 500) are overridable.
#[cfg(windows)]
fn duplicati_log(params: Option<&str>) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let pagesize = match dup_param(params, &["pagesize", "pages"]).parse::<u32>() {
        Ok(n) if n > 0 => n.min(50),
        _ => 5,
    };
    let cap = match dup_param(params, &["warning_cap", "cap"]).parse::<u32>() {
        Ok(n) if n > 0 => n.min(500),
        _ => 100,
    };
    let body = format!("{tok}\n$id='{id}'\n$pagesize={pagesize}\n$cap={cap}\n{DUP_LOG_BODY}");
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati log read produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_log(_p: Option<&str>) -> Option<Value> { None }

/// target-check body — pull the backup's command line in-memory (`GET /export-cmdline`, no secrets on
/// disk), regex out the backend target URL (robust to the exact response shape), then `BackendTool
/// LIST` it (read-only — lists remote files, never modifies). Backend creds are redacted in the output.
#[cfg(windows)]
const DUP_TARGETCHECK_BODY: &str = r#"$e=Invoke-DupApi 'GET' "/api/v1/backup/$id/export-argsonly" $null
if(-not $e.ok){ $e=Invoke-DupApi 'GET' "/api/v1/backup/$id/export-cmdline" $null }
if(-not $e.ok){ [pscustomobject]@{ok=$false;command='target-check';backup=$id;status=$e.status;error=$e.error}|ConvertTo-Json -Depth 8; exit }
$s=($e.result|ConvertTo-Json -Depth 20 -Compress)
$target=$null; if($s -match '([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s",]+)'){ $target=$Matches[1] }
# The commandline form doubles every '%' for Windows cmd expansion (2.3 "Escaped Windows commandline
# percent expansion"), on TOP of the URL's own percent-encoding — so a target arrives as
# file:///C%%3A%%5CUsers... and BackendTool then hunts for a folder literally containing '%'.
# Collapse the cmd escaping; leave the URL encoding, which the backends decode themselves.
if($target){ $target=$target -replace '%%','%' }
# Trailing separators confuse the file backend the same way they confused the datafolder parse.
if($target){ $target=$target.TrimEnd('\','/') }
if(-not $target){ [pscustomobject]@{ok=$false;command='target-check';backup=$id;error='no backend target URL found in export'}|ConvertTo-Json -Depth 8; exit }
$bt=Join-Path $exeDir 'Duplicati.CommandLine.BackendTool.exe'
if(-not (Test-Path $bt)){ [pscustomobject]@{ok=$false;command='target-check';backup=$id;error='BackendTool.exe not found'}|ConvertTo-Json -Depth 8; exit }
$out=(& $bt LIST $target 2>&1 | Out-String)
$red=($target -replace '://[^@/]+@','://***@')
$errline=[bool]($out -match '(?i)exception|error|denied|not found|failed|unable|refused')
# Count only real volume files (duplicati-*.dblock/dindex/dlist), not any line that happens to contain
# "duplicati-" — an error mentioning the target folder name was being counted as a file.
$files=@($out -split "`n" | Where-Object { $_ -match 'duplicati-.*\.(dblock|dindex|dlist)' }).Count
[pscustomobject]@{ok=(-not $errline);command='target-check';backup=$id;target=$red;reachable=(-not $errline);duplicati_files=$files;output=(($out.Trim() -split "`n" | Select-Object -Last 20) -join "`n")}|ConvertTo-Json -Depth 8"#;

/// Read-only: is the backup's remote target reachable + how many volumes are there (BackendTool LIST).
#[cfg(windows)]
fn duplicati_target_check(params: Option<&str>) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let body = format!("{tok}\n$id='{id}'\n{DUP_TARGETCHECK_BODY}", tok = tok, id = id);
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati target-check produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_target_check(_p: Option<&str>) -> Option<Value> { None }

// ── Duplicati datafolder ACL check / secure ───────────────────────────────────────────────────
// Duplicati 2.3.0.107 makes the data folder permissions a HARD requirement: the server refuses to use
// a folder whose permissions aren't exactly as expected (opt-out only via --allow-insecure-datafolder).
// A box with a custom datafolder + inherited/lax ACLs will simply stop backing up on upgrade, so we
// expose a read-only compliance check and an L2 corrective action. 2.3 ships
// `ConfigureTool secure-datafolder`; it does NOT exist in 2.2.x, so the fix falls back to setting the
// ACL directly. Principals are matched by **SID**, not name, so this works on non-English Windows.

/// Compliance check: SYSTEM (S-1-5-18) + Administrators (S-1-5-32-544) only, inheritance disabled,
/// AND the folder **owner** is one of those two SIDs. Anything else holding an Allow ACE is reported
/// as an offender.
///
/// The owner leg is not optional: 2.3.0.107 rejects the folder on owner alone, independently of the
/// ACL (`the folder owner is S-1-12-1-… but expected one of SYSTEM, Administrators or the current
/// user`). A folder can therefore have a textbook SYSTEM+Administrators ACL and still hard-crash the
/// service at startup — which is exactly what a hand-created datafolder looks like, since the admin
/// who made it owns it. Duplicati's "or the current user" leg is deliberately NOT honoured here: the
/// service runs as LocalSystem, so for it that reduces to SYSTEM, and accepting an interactive user's
/// SID would pass folders that the service itself will reject.
#[cfg(windows)]
const DUP_ACLCHECK_BODY: &str = r#"if(-not $df -or -not (Test-Path $df)){ (@{ok=$false;error=('datafolder not found'+$(if($df){': '+$df}else{' (no --server-datafolder in the service ImagePath, and neither %ProgramData%\Duplicati nor %LOCALAPPDATA%\Duplicati exists)'}))}|ConvertTo-Json -Compress); exit }
$ct=Join-Path $exeDir 'Duplicati.CommandLine.ConfigureTool.exe'
$acl=Get-Acl -LiteralPath $df
$allowed=@('S-1-5-18','S-1-5-32-544')
$entries=@(); $offenders=@()
foreach($a in $acl.Access){
  $sid=''
  try{ $sid=$a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }catch{ $sid='' }
  $e=[pscustomobject]@{identity=[string]$a.IdentityReference;sid=$sid;rights=[string]$a.FileSystemRights;type=[string]$a.AccessControlType;inherited=$a.IsInherited}
  $entries+=$e
  if($a.AccessControlType -eq 'Allow' -and ($allowed -notcontains $sid)){ $offenders+=$e }
}
$prot=$acl.AreAccessRulesProtected
$ownerSid=''
try{ $ownerSid=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }catch{ $ownerSid='' }
$ownerName=$ownerSid
try{ $ownerName=[string]$acl.Owner }catch{ }
$ownerOk=($allowed -contains $ownerSid)
[pscustomobject]@{ok=$true;datafolder=$df;datafolder_source=$dfSource;owner=$ownerName;owner_sid=$ownerSid;owner_ok=$ownerOk;inheritance_protected=$prot;compliant=(($offenders.Count -eq 0) -and $prot -and $ownerOk);offender_count=$offenders.Count;offenders=$offenders;entries=$entries;configure_tool_present=(Test-Path $ct)}|ConvertTo-Json -Depth 6"#;

/// **`--apply` and `--data-folder` are both mandatory here, and omitting either was a silent no-op.**
/// Verified against 2.3.0.107's own help on 2026-07-20:
///   `--apply`        Apply the restricted permissions without prompting. By default a warning is
///                    shown and the user must confirm.
///   `--data-folder`  Path to the Duplicati data folder (defaults to standard location).
/// Without `--apply` the tool prints its warning, prompts `Apply restricted permissions? [y/N]`,
/// reads EOF in a service context and exits `Aborted. No changes were made.` — observed directly.
/// Without `--data-folder` it operates on the *standard* location, which is the wrong folder on every
/// box that passes `--server-datafolder` (i.e. all three that run Duplicati today), so it would have
/// "secured" a directory the service does not use while leaving the real one untouched.
///
/// With both flags it works and **does fix ownership** — verified 2026-07-20 on sulltec-g360nd3:
/// owner forced to `BUILTIN\Users`, then `secure-datafolder --apply --data-folder` reported
/// "Restricted permissions applied" and left owner = `NT AUTHORITY\SYSTEM`. So on 2.3 the setowner
/// step below is a no-op; on 2.2.x, where no ConfigureTool exists, it is the only thing that fixes
/// the owner. Both paths are kept for that reason.
///
/// **This must run as SYSTEM, which is why it belongs in the client and not an operator's shell.**
/// ConfigureTool grants "the current user, SYSTEM and Administrators" and sets the owner to *its own*
/// current user. Run from the client (a SYSTEM service) that is SYSTEM — correct. Run by hand from an
/// elevated *user* prompt it sets the owner to that admin, which satisfies ConfigureTool but NOT the
/// service: Duplicati runs as LocalSystem, so its "or the current user" leg resolves to SYSTEM, and an
/// admin-owned folder still fails startup. An operator "fixing" this manually can therefore create the
/// exact failure they are trying to clear.
///
/// Corrective action. Prefers `ConfigureTool secure-datafolder` (2.3+); otherwise grants SYSTEM +
/// Administrators by SID, strips inherited ACEs, then removes any remaining non-allowed explicit ACE.
/// Grants happen BEFORE inheritance is stripped so the folder is never left without an owner-capable
/// ACE. `$dry` reports the plan and the current ACL without changing anything.
///
/// Ownership is then reconciled *after* whichever method ran: if the owner SID still isn't SYSTEM or
/// Administrators, `icacls /setowner` reassigns it to Administrators. This runs for BOTH paths and is
/// a no-op when the owner is already compliant — ConfigureTool does handle ownership (verified), so on
/// 2.3 this step does nothing, while on 2.2.x, which has no ConfigureTool, it is the only thing that
/// fixes the owner. Without it the action reports success on a folder whose ACL is perfect but
/// whose owner still fails 2.3.0.107's startup check — see DUP_ACLCHECK_BODY.
#[cfg(windows)]
const DUP_ACLFIX_BODY: &str = r#"if(-not $df -or -not (Test-Path $df)){ (@{ok=$false;error=('datafolder not found'+$(if($df){': '+$df}else{' (no --server-datafolder in the service ImagePath, and neither %ProgramData%\Duplicati nor %LOCALAPPDATA%\Duplicati exists)'}))}|ConvertTo-Json -Compress); exit }
$ct=Join-Path $exeDir 'Duplicati.CommandLine.ConfigureTool.exe'
$allowed=@('S-1-5-18','S-1-5-32-544')
function DfSnap(){ $o='?';$n='?'; try{ $a=Get-Acl -LiteralPath $df; $o=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; $n=[string]$a.Owner }catch{}; return (('owner: {0} [{1}]' -f $n,$o) + [Environment]::NewLine + (icacls $df 2>&1 | Out-String)) }
$before=(DfSnap)
$steps=@(); $method='none'
if($dry){
  $method=$(if(Test-Path $ct){'ConfigureTool secure-datafolder --apply --data-folder <df>, then setowner if still non-compliant'}else{'icacls: grant SYSTEM+Administrators, strip inheritance, remove others, setowner Administrators'})
  $steps+='DRY RUN - no changes made'
} elseif(Test-Path $ct){
  $method='ConfigureTool secure-datafolder --apply'
  $steps+=((& $ct secure-datafolder --apply --data-folder $df 2>&1 | Out-String).Trim())
} else {
  $method='icacls'
  $steps+=('grant: '+((icacls $df /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" 2>&1|Out-String).Trim()))
  $steps+=('inheritance: '+((icacls $df /inheritance:r 2>&1|Out-String).Trim()))
  $acl2=Get-Acl -LiteralPath $df
  foreach($a in $acl2.Access){
    $sid=''
    try{ $sid=$a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }catch{ $sid='' }
    if($sid -and ($allowed -notcontains $sid)){
      $null=(icacls $df /remove:g ('*'+$sid) 2>&1)
      $steps+=('removed '+[string]$a.IdentityReference)
    }
  }
}
if(-not $dry){
  $aclO=Get-Acl -LiteralPath $df
  $oSid=''
  try{ $oSid=$aclO.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }catch{ $oSid='' }
  if($allowed -notcontains $oSid){
    $steps+=('setowner (was '+$(if($oSid){$oSid}else{'<unresolvable>'})+'): '+((icacls $df /setowner "*S-1-5-32-544" 2>&1|Out-String).Trim()))
  }
}
$after=(DfSnap)
$acl3=Get-Acl -LiteralPath $df
$off=@($acl3.Access | Where-Object { $_.AccessControlType -eq 'Allow' } | Where-Object { $sid2=''; try{ $sid2=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }catch{}; $allowed -notcontains $sid2 })
$oSid3=''
try{ $oSid3=$acl3.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }catch{ $oSid3='' }
$oName3=$oSid3
try{ $oName3=[string]$acl3.Owner }catch{ }
$ownerOk3=($allowed -contains $oSid3)
[pscustomobject]@{ok=$true;datafolder=$df;datafolder_source=$dfSource;dry_run=$dry;method=$method;steps=$steps;owner=$oName3;owner_sid=$oSid3;owner_ok=$ownerOk3;compliant_now=(($off.Count -eq 0) -and $acl3.AreAccessRulesProtected -and $ownerOk3);before=$before.Trim();after=$after.Trim()}|ConvertTo-Json -Depth 6"#;

// ── iDRAC / Redfish hardware health (docs/PLAN-idrac-collectors.md) ──────────────────────────────
//
// Windows cannot see behind hardware RAID: the `disks` collector reports PERC *virtual* disks as
// Healthy while a physical member is throwing media errors, because the array's redundancy hides it.
// These collectors read the hardware layer directly from the host's own iDRAC.
//
// **Redfish, not racadm, and over the iSM pass-through.** Measured 2026-07-21:
//   * `racadm --output json` returns NOTHING on iDRAC 7.10 with racadm 11.3 — the newest combination
//     in the fleet — so racadm means parsing text tables that vary by firmware, forever.
//   * `racadm.exe` is not even installed on 2 of 3 Dell hosts (it ships in *iDRAC Tools*, not iSM).
//   * `https://169.254.0.1/redfish/v1` over the iSM OS-to-iDRAC pass-through returned a service root
//     byte-identical to the one from the iDRAC's LAN address. So the host always reaches its own
//     controller with no configured IP, no route from the console, and nothing to renumber.
//
// The pass-through NIC is named for the service tag (e.g. `iDRAC 9 <tag>`), which matches the chassis
// serial — a free check that we are talking to THIS host's controller and not something else squatting
// a link-local address.

/// TLS + auth prelude for a Redfish call. iDRACs ship a self-signed certificate, so validation is
/// bypassed for this process — acceptable because the endpoint is a link-local address on the host's
/// own management NIC, not a routed host. Windows PowerShell 5.1 needs the `ICertificatePolicy` shim;
/// TLS 1.2 must be forced because 5.1 still defaults to older protocols an iDRAC will refuse.
#[cfg(windows)]
const IDRAC_PRELUDE: &str = r#"$ErrorActionPreference='SilentlyContinue'
if(-not $user -or -not $secret){ (@{ok=$false;error='no iDRAC credential delivered for this device; store one under Credentials -> Application Secrets (application: idrac, scope: this device)'}|ConvertTo-Json -Compress); exit }
if(-not $idracHost){ $idracHost='169.254.0.1' }
try{ Add-Type -TypeDefinition 'using System.Net;using System.Security.Cryptography.X509Certificates;public class STIdracTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest r,int p){return true;} }' }catch{}
try{ [System.Net.ServicePointManager]::CertificatePolicy = New-Object STIdracTrust }catch{}
try{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }catch{}
$pair="$($user):$($secret)"
$b64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
$hdr=@{ Authorization = "Basic $b64" }
$base="https://$idracHost"
function Get-Redfish([string]$path){
  try{ return Invoke-RestMethod -Uri ($base+$path) -Headers $hdr -Method GET -TimeoutSec 45 -EA Stop }
  catch{
    $sc=0; try{ $sc=[int]$_.Exception.Response.StatusCode }catch{}
    $script:lastErr=[pscustomobject]@{path=$path;status=$sc;error=("$($_.Exception.Message)" -replace '\s+',' ')}
    return $null
  }
}
function Leaf([string]$odata){ if(-not $odata){ return '' }; return ($odata -split '/')[-1] }"#;

/// `idrac-storage` — controllers, physical disks and virtual disks from Redfish.
///
/// The field that matters is `failure_predicted` (Redfish `FailurePredicted`, the SMART predictive-
/// failure bit): it is set on a drive that is dying while Windows still calls the virtual disk Healthy.
/// `oem_keys` lists the Dell OEM property NAMES present on a drive without dumping their values — the
/// vendor extension carries the media/other error counters, and their exact names vary by firmware, so
/// this reports what is actually available on a given box instead of guessing at a schema.
#[cfg(windows)]
const IDRAC_STORAGE_BODY: &str = r#"$sys='/redfish/v1/Systems/System.Embedded.1'
$root=Get-Redfish '/redfish/v1'
if(-not $root){ ([pscustomobject]@{ok=$false;error='could not reach the iDRAC Redfish service';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$coll=Get-Redfish "$sys/Storage"
if(-not $coll){ ([pscustomobject]@{ok=$false;error='Redfish reachable but the Storage collection was refused (check the account has at least read privilege)';idrac=$idracHost;redfish_version=$root.RedfishVersion;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$controllers=@()
$drives=@()
$volumes=@()
foreach($m in @($coll.Members)){
  $cid=Leaf $m.'@odata.id'
  $c=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','')
  if(-not $c){ continue }
  $sc=@($c.StorageControllers)[0]
  $controllers+=[pscustomobject]@{
    id=$cid; name=[string]$c.Name
    model=[string]$sc.Model; firmware=[string]$sc.FirmwareVersion
    health=[string]$c.Status.Health; state=[string]$c.Status.State
    drive_count=@($c.Drives).Count
  }
  foreach($d in @($c.Drives)){
    if(@($drives).Count -ge 64){ break }
    $dd=Get-Redfish ($d.'@odata.id' -replace '^https?://[^/]+','')
    if(-not $dd){ continue }
    $oemKeys=@()
    if($wantOem){ try{ $oemKeys=@($dd.Oem.Dell.DellPhysicalDisk.PSObject.Properties.Name | Where-Object { $_ -notlike '@odata*' }) }catch{} }
    $od=$null; try{ $od=$dd.Oem.Dell.DellPhysicalDisk }catch{}
    # ServiceLabel is empty on this firmware (measured 2026-07-21, iDRAC 7.10) but the bay is encoded in
    # the Id (`Disk.Bay.4:Enclosure.Internal.0-1:RAID.Slot.4-1`). The bay is how a human finds the drive
    # in the chassis, so derive it rather than reporting a blank.
    $loc=[string]$dd.PhysicalLocation.PartLocation.ServiceLabel
    if(-not $loc){
      if([string]$dd.Id -match 'Disk\.Bay\.(\d+)'){ $loc='Bay '+$Matches[1] } else { $loc=[string]$dd.Name }
    }
    $drives+=[pscustomobject]@{
      controller=$cid
      id=[string]$dd.Id
      location=$loc
      name=[string]$dd.Name
      model=[string]$dd.Model
      manufacturer=[string]$dd.Manufacturer
      serial=[string]$dd.SerialNumber
      firmware=[string]$dd.Revision
      media_type=[string]$dd.MediaType
      protocol=[string]$dd.Protocol
      capacity_bytes=$dd.CapacityBytes
      health=[string]$dd.Status.Health
      state=[string]$dd.Status.State
      failure_predicted=$dd.FailurePredicted
      life_left_percent=$dd.PredictedMediaLifeLeftPercent
      hotspare=[string]$dd.HotspareType
      # Dell OEM. PredictiveFailureState is the vendor twin of FailurePredicted; RaidStatus tells you a
      # member is Failed/Degraded/Rebuilding, which the Redfish Status alone does not. NOTE: this OEM
      # block carries NO media/other error counters on iDRAC 7.10 — those events only appear in the SEL.
      predictive_failure_state=[string]$od.PredictiveFailureState
      raid_status=[string]$od.RaidStatus
      power_status=[string]$od.PowerStatus
      spare_percent=$od.AvailableSparePercent
      error_desc=[string]$od.ErrorDescription
      oem_keys=$oemKeys
    }
  }
  $vc=Get-Redfish ("$sys/Storage/$cid/Volumes")
  foreach($v in @($vc.Members)){
    if(@($volumes).Count -ge 64){ break }
    $vv=Get-Redfish ($v.'@odata.id' -replace '^https?://[^/]+','')
    if(-not $vv){ continue }
    $volumes+=[pscustomobject]@{
      controller=$cid
      id=[string]$vv.Id
      name=[string]$vv.Name
      raid=[string]$vv.RAIDType
      capacity_bytes=$vv.CapacityBytes
      health=[string]$vv.Status.Health
      state=[string]$vv.Status.State
      drive_count=@($vv.Links.Drives).Count
    }
  }
}
# The headline: a drive Windows cannot see is failing. Surfaced at the top level so an operator (or a
# fleet-health rule) never has to walk the array to find out something is wrong.
$predicted=@($drives | Where-Object { $_.failure_predicted -eq $true -or ($_.predictive_failure_state -and $_.predictive_failure_state -notmatch '^(No|Unknown)$') })
$unhealthy=@($drives | Where-Object { ($_.health -and $_.health -ne 'OK') -or ($_.raid_status -and $_.raid_status -notmatch '^(Online|Ready|NonRAID|Spare)$') })
[pscustomobject]@{
  ok=$true; idrac=$idracHost; redfish_version=[string]$root.RedfishVersion
  controllers=$controllers; drives=$drives; volumes=$volumes
  drive_count=@($drives).Count
  predicted_failure_count=@($predicted).Count
  predicted_failures=@($predicted | ForEach-Object { '{0} ({1}) {2}' -f $_.location,$_.id,$_.model })
  unhealthy_count=@($unhealthy).Count
  unhealthy=@($unhealthy | ForEach-Object { '{0} ({1}) health={2} raid={3}' -f $_.location,$_.id,$_.health,$_.raid_status })
}|ConvertTo-Json -Depth 8"#;

/// `idrac-health` — the whole-box roll-up: is anything wrong, and where.
#[cfg(windows)]
const IDRAC_HEALTH_BODY: &str = r#"$sys=Get-Redfish '/redfish/v1/Systems/System.Embedded.1'
if(-not $sys){ ([pscustomobject]@{ok=$false;error='could not read the system resource';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$ch=Get-Redfish '/redfish/v1/Chassis/System.Embedded.1'
$subs=@()
foreach($n in @('MemorySummary','ProcessorSummary')){
  $s=$sys.$n
  if($s){ $subs+=[pscustomobject]@{ area=$n; health=[string]$s.Status.Health; state=[string]$s.Status.HealthRollup } }
}
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  hostname=[string]$sys.HostName
  model=[string]$sys.Model
  manufacturer=[string]$sys.Manufacturer
  service_tag=[string]$sys.SKU
  bios_version=[string]$sys.BiosVersion
  power_state=[string]$sys.PowerState
  health=[string]$sys.Status.Health
  health_rollup=[string]$sys.Status.HealthRollup
  state=[string]$sys.Status.State
  memory_gib=$sys.MemorySummary.TotalSystemMemoryGiB
  memory_health=[string]$sys.MemorySummary.Status.Health
  cpu_count=$sys.ProcessorSummary.Count
  cpu_model=[string]$sys.ProcessorSummary.Model
  cpu_health=[string]$sys.ProcessorSummary.Status.Health
  chassis_health=[string]$ch.Status.Health
  chassis_state=[string]$ch.Status.State
  intrusion=[string]$ch.PhysicalSecurity.IntrusionSensor
  subsystems=$subs
}|ConvertTo-Json -Depth 6"#;

/// `idrac-sel` — the hardware System Event Log. This is where disk media errors, PSU loss, thermal
/// events and memory corrections actually appear; the per-drive OEM block carries no error counters, so
/// for "is this drive throwing errors" the SEL is the only source.
#[cfg(windows)]
const IDRAC_SEL_BODY: &str = r#"$path='/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries?$top=' + $limit
$e=Get-Redfish $path
if(-not $e){
  # Older/newer firmware moves the SEL; try the documented alternates before giving up.
  foreach($p in @('/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries','/redfish/v1/Systems/System.Embedded.1/LogServices/Sel/Entries')){
    $e=Get-Redfish $p; if($e){ break }
  }
}
if(-not $e){ ([pscustomobject]@{ok=$false;error='could not read the System Event Log';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$rows=@()
foreach($m in @($e.Members)){
  if(@($rows).Count -ge $limit){ break }
  $sev=[string]$m.Severity
  if($sevFilter -and $sev -notmatch $sevFilter){ continue }
  $msg=[string]$m.Message
  if($msg.Length -gt 300){ $msg=$msg.Substring(0,300)+' ...' }
  $rows+=[pscustomobject]@{
    id=[string]$m.Id
    created=[string]$m.Created
    severity=$sev
    message_id=[string]$m.MessageId
    message=$msg
  }
}
$crit=@($rows | Where-Object { $_.severity -eq 'Critical' })
$warn=@($rows | Where-Object { $_.severity -eq 'Warning' })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  total_in_log=$e.'Members@odata.count'
  returned=@($rows).Count
  critical_count=@($crit).Count
  warning_count=@($warn).Count
  entries=$rows
}|ConvertTo-Json -Depth 6"#;

/// `idrac-thermal` — temperature probes and fans. A fan that has failed or a probe above its critical
/// threshold is a warning the OS never sees.
#[cfg(windows)]
const IDRAC_THERMAL_BODY: &str = r#"$t=Get-Redfish '/redfish/v1/Chassis/System.Embedded.1/Thermal'
if(-not $t){ ([pscustomobject]@{ok=$false;error='could not read the thermal resource';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$temps=@()
foreach($p in @($t.Temperatures)){
  if([string]$p.Status.State -eq 'Absent'){ continue }
  $temps+=[pscustomobject]@{
    name=[string]$p.Name
    celsius=$p.ReadingCelsius
    health=[string]$p.Status.Health
    state=[string]$p.Status.State
    warn_at=$p.UpperThresholdNonCritical
    crit_at=$p.UpperThresholdCritical
  }
}
$fans=@()
foreach($f in @($t.Fans)){
  if([string]$f.Status.State -eq 'Absent'){ continue }
  $fans+=[pscustomobject]@{
    name=[string]$f.Name
    reading=$f.Reading
    units=[string]$f.ReadingUnits
    health=[string]$f.Status.Health
    state=[string]$f.Status.State
    min=$f.LowerThresholdCritical
  }
}
$badT=@($temps | Where-Object { $_.health -and $_.health -ne 'OK' })
$badF=@($fans | Where-Object { $_.health -and $_.health -ne 'OK' })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  temperatures=$temps; fans=$fans
  temp_count=@($temps).Count; fan_count=@($fans).Count
  unhealthy_temp_count=@($badT).Count; unhealthy_fan_count=@($badF).Count
  unhealthy=@(@($badT | ForEach-Object { 'temp {0} = {1}C health={2}' -f $_.name,$_.celsius,$_.health }) + @($badF | ForEach-Object { 'fan {0} = {1} health={2}' -f $_.name,$_.reading,$_.health }))
}|ConvertTo-Json -Depth 6"#;

/// `idrac-power` — PSUs, redundancy and draw. A server running on one of two supplies is one failure
/// from an outage and looks perfectly healthy from inside the OS.
#[cfg(windows)]
const IDRAC_POWER_BODY: &str = r#"$p=Get-Redfish '/redfish/v1/Chassis/System.Embedded.1/Power'
if(-not $p){ ([pscustomobject]@{ok=$false;error='could not read the power resource';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$psus=@()
foreach($s in @($p.PowerSupplies)){
  $psus+=[pscustomobject]@{
    name=[string]$s.Name
    model=[string]$s.Model
    serial=[string]$s.SerialNumber
    firmware=[string]$s.FirmwareVersion
    type=[string]$s.PowerSupplyType
    capacity_watts=$s.PowerCapacityWatts
    input_volts=$s.LineInputVoltage
    output_watts=$s.LastPowerOutputWatts
    health=[string]$s.Status.Health
    state=[string]$s.Status.State
  }
}
$red=@()
foreach($r in @($p.Redundancy)){
  $red+=[pscustomobject]@{
    name=[string]$r.Name
    mode=[string]$r.Mode
    health=[string]$r.Status.Health
    state=[string]$r.Status.State
    min_needed=$r.MinNumNeeded
    max_supported=$r.MaxNumSupported
  }
}
$pc=@($p.PowerControl)[0]
$present=@($psus | Where-Object { [string]$_.state -ne 'Absent' })
$badP=@($present | Where-Object { $_.health -and $_.health -ne 'OK' })
$badR=@($red | Where-Object { $_.health -and $_.health -ne 'OK' })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  supplies=$psus; redundancy=$red
  psu_present=@($present).Count
  consumed_watts=$pc.PowerConsumedWatts
  capacity_watts=$pc.PowerCapacityWatts
  average_watts=$pc.PowerMetrics.AverageConsumedWatts
  unhealthy_psu_count=@($badP).Count
  redundancy_lost=@($badR).Count -gt 0
  unhealthy=@(@($badP | ForEach-Object { 'psu {0} health={1} state={2}' -f $_.name,$_.health,$_.state }) + @($badR | ForEach-Object { 'redundancy {0} mode={1} health={2}' -f $_.name,$_.mode,$_.health }))
}|ConvertTo-Json -Depth 6"#;

/// `idrac-memory` — DIMM inventory + per-module health. Catches a DIMM the OS still counts but the
/// controller has flagged, and shows population/speed for capacity planning.
#[cfg(windows)]
const IDRAC_MEMORY_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/Systems/System.Embedded.1/Memory'
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the memory collection';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$dimms=@()
foreach($m in @($c.Members)){
  if(@($dimms).Count -ge 64){ break }
  $d=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','')
  if(-not $d){ continue }
  if([string]$d.Status.State -eq 'Absent'){ continue }
  $dimms+=[pscustomobject]@{
    id=[string]$d.Id
    location=[string]$d.DeviceLocator
    slot=[string]$d.MemoryLocation.Slot
    channel=[string]$d.MemoryLocation.Channel
    socket=[string]$d.MemoryLocation.Socket
    capacity_mib=$d.CapacityMiB
    speed_mhz=$d.OperatingSpeedMhz
    rated_speed_mhz=$d.AllowedSpeedsMHz -join ','
    type=[string]$d.MemoryDeviceType
    rank=$d.RankCount
    manufacturer=[string]$d.Manufacturer
    part_number=([string]$d.PartNumber).Trim()
    serial=[string]$d.SerialNumber
    health=[string]$d.Status.Health
    state=[string]$d.Status.State
  }
}
$bad=@($dimms | Where-Object { $_.health -and $_.health -ne 'OK' })
$total=0; foreach($d in $dimms){ $total += [int]$d.capacity_mib }
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  dimms=$dimms; dimm_count=@($dimms).Count; total_gib=[math]::Round($total/1024,1)
  unhealthy_count=@($bad).Count
  unhealthy=@($bad | ForEach-Object { '{0} ({1}) health={2}' -f $_.location,$_.part_number,$_.health })
}|ConvertTo-Json -Depth 6"#;

/// `idrac-cpu` — processor inventory + per-socket health.
#[cfg(windows)]
const IDRAC_CPU_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/Systems/System.Embedded.1/Processors'
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the processor collection';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$cpus=@()
foreach($m in @($c.Members)){
  $p=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','')
  if(-not $p){ continue }
  if([string]$p.Status.State -eq 'Absent'){ continue }
  $cpus+=[pscustomobject]@{
    id=[string]$p.Id
    socket=[string]$p.Socket
    model=([string]$p.Model).Trim()
    manufacturer=[string]$p.Manufacturer
    cores=$p.TotalCores
    threads=$p.TotalThreads
    max_speed_mhz=$p.MaxSpeedMHz
    family=[string]$p.ProcessorArchitecture
    health=[string]$p.Status.Health
    state=[string]$p.Status.State
  }
}
$bad=@($cpus | Where-Object { $_.health -and $_.health -ne 'OK' })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  cpus=$cpus; cpu_count=@($cpus).Count
  unhealthy_count=@($bad).Count
  unhealthy=@($bad | ForEach-Object { 'socket {0} ({1}) health={2}' -f $_.socket,$_.model,$_.health })
}|ConvertTo-Json -Depth 6"#;

/// `idrac-nic` — physical network interface inventory as the HARDWARE sees it: MACs, link state and
/// speed, independent of what Windows has bound on top.
#[cfg(windows)]
const IDRAC_NIC_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces'
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the ethernet collection';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$nics=@()
foreach($m in @($c.Members)){
  if(@($nics).Count -ge 32){ break }
  $n=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','')
  if(-not $n){ continue }
  $nics+=[pscustomobject]@{
    id=[string]$n.Id
    name=[string]$n.Name
    mac=[string]$n.MACAddress
    permanent_mac=[string]$n.PermanentMACAddress
    link_status=[string]$n.LinkStatus
    speed_mbps=$n.SpeedMbps
    enabled=$n.InterfaceEnabled
    health=[string]$n.Status.Health
    state=[string]$n.Status.State
  }
}
$down=@($nics | Where-Object { $_.link_status -and $_.link_status -notmatch '^(LinkUp|Up)$' })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  nics=$nics; nic_count=@($nics).Count
  link_down_count=@($down).Count
  link_down=@($down | ForEach-Object { '{0} ({1}) {2}' -f $_.name,$_.mac,$_.link_status })
}|ConvertTo-Json -Depth 6"#;

/// `idrac-firmware` — every component's firmware version. The point is FLEET DRIFT: comparing this
/// across hosts is how you find the one box still on a BIOS with a known bug.
#[cfg(windows)]
const IDRAC_FIRMWARE_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/UpdateService/FirmwareInventory'
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the firmware inventory';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$items=@()
foreach($m in @($c.Members)){
  $id=[string]$m.'@odata.id'
  # The collection lists both INSTALLED and AVAILABLE (staged) images; only installed reflects reality.
  if($id -notmatch '/Installed'){ continue }
  if(@($items).Count -ge 80){ break }
  $f=Get-Redfish ($id -replace '^https?://[^/]+','')
  if(-not $f){ continue }
  $items+=[pscustomobject]@{
    name=[string]$f.Name
    version=[string]$f.Version
    updateable=$f.Updateable
    status=[string]$f.Status.Health
  }
}
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  components=($items | Sort-Object name)
  component_count=@($items).Count
}|ConvertTo-Json -Depth 6"#;

/// `idrac-jobs` — the Lifecycle Controller job queue. A stuck or failed job here silently blocks
/// firmware updates and config changes, and nothing in the OS reports it.
#[cfg(windows)]
const IDRAC_JOBS_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs?$expand=*($levels=1)'
if(-not $c){ $c=Get-Redfish '/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs' }
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the Lifecycle Controller job queue';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$jobs=@()
foreach($m in @($c.Members)){
  if(@($jobs).Count -ge 50){ break }
  $j=$m
  if(-not $j.Id){ $j=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','') }
  if(-not $j){ continue }
  $jobs+=[pscustomobject]@{
    id=[string]$j.Id
    name=[string]$j.Name
    type=[string]$j.JobType
    state=[string]$j.JobState
    percent=$j.PercentComplete
    message=[string]$j.Message
    start=[string]$j.StartTime
    end=[string]$j.EndTime
  }
}
$stuck=@($jobs | Where-Object { $_.state -and $_.state -match 'Failed|Paused|Scheduled|Running|New' })
$failed=@($jobs | Where-Object { $_.state -match 'Failed' })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  jobs=$jobs; job_count=@($jobs).Count
  incomplete_count=@($stuck).Count
  failed_count=@($failed).Count
  incomplete=@($stuck | ForEach-Object { '{0} [{1}] {2}% {3}' -f $_.name,$_.state,$_.percent,$_.message })
}|ConvertTo-Json -Depth 6"#;

/// `idrac-network` — the iDRAC's OWN management addressing. Answers "what IP is this controller on"
/// without walking a rack, and inventories management addresses across the fleet.
#[cfg(windows)]
const IDRAC_NETWORK_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces'
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the iDRAC ethernet collection';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$ifs=@()
foreach($m in @($c.Members)){
  $n=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','')
  if(-not $n){ continue }
  $v4=@()
  foreach($a in @($n.IPv4Addresses)){ if($a.Address){ $v4+=('{0}/{1} via {2} ({3})' -f $a.Address,$a.SubnetMask,$a.Gateway,$a.AddressOrigin) } }
  $ifs+=[pscustomobject]@{
    id=[string]$n.Id
    name=[string]$n.Name
    mac=[string]$n.MACAddress
    enabled=$n.InterfaceEnabled
    speed_mbps=$n.SpeedMbps
    autoneg=$n.AutoNeg
    full_duplex=$n.FullDuplex
    hostname=[string]$n.HostName
    fqdn=[string]$n.FQDN
    dhcp=[string]$n.DHCPv4.DHCPEnabled
    ipv4=$v4
    vlan_enabled=$n.VLAN.VLANEnable
    vlan_id=$n.VLAN.VLANId
    link_status=[string]$n.LinkStatus
  }
}
[pscustomobject]@{ok=$true;idrac=$idracHost;interfaces=$ifs;interface_count=@($ifs).Count}|ConvertTo-Json -Depth 6"#;

/// `idrac-accounts` — local iDRAC users and their roles. **Never returns a password**: Redfish does not
/// expose them and this asks for no such field. This is a security-posture read — it finds the default
/// `root` account still enabled, stale technician logins, and accounts with Administrator where
/// ReadOnly would do. A management controller with a forgotten admin account is a real way in.
#[cfg(windows)]
const IDRAC_ACCOUNTS_BODY: &str = r#"$c=Get-Redfish '/redfish/v1/AccountService/Accounts'
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the account service (the credential may lack the privilege to enumerate accounts)';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$accts=@()
foreach($m in @($c.Members)){
  $a=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','')
  if(-not $a){ continue }
  $u=[string]$a.UserName
  # Empty slots come back as unnamed, disabled entries; they are noise, not accounts.
  if(-not $u){ continue }
  $accts+=[pscustomobject]@{
    id=[string]$a.Id
    username=$u
    role=[string]$a.RoleId
    enabled=$a.Enabled
    locked=$a.Locked
  }
}
$enabled=@($accts | Where-Object { $_.enabled -eq $true })
$admins=@($enabled | Where-Object { [string]$_.role -match 'Admin' })
$default=@($enabled | Where-Object { [string]$_.username -in @('root','admin','Administrator') })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  accounts=$accts; account_count=@($accts).Count
  enabled_count=@($enabled).Count
  admin_count=@($admins).Count
  default_named_enabled=@($default | ForEach-Object { $_.username })
}|ConvertTo-Json -Depth 6"#;

/// `idrac-services` — which management services are listening, on what ports. The attack surface of
/// the controller itself: IPMI-over-LAN and SNMP left on are the classic findings.
#[cfg(windows)]
const IDRAC_SERVICES_BODY: &str = r#"$n=Get-Redfish '/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol'
if(-not $n){ ([pscustomobject]@{ok=$false;error='could not read the network protocol resource';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$svcs=@()
foreach($p in @('HTTP','HTTPS','SSH','SNMP','IPMI','VirtualMedia','VirtualConsole','KVMIP','Telnet','SSDP','NTP')){
  $s=$n.$p
  if($null -eq $s){ continue }
  $svcs+=[pscustomobject]@{ name=$p; enabled=$s.ProtocolEnabled; port=$s.Port }
}
$on=@($svcs | Where-Object { $_.enabled -eq $true } | ForEach-Object { '{0}:{1}' -f $_.name,$_.port })
# Plaintext / legacy management protocols worth flagging if they are on.
$risky=@($svcs | Where-Object { $_.enabled -eq $true -and $_.name -in @('HTTP','Telnet','SNMP','IPMI') } | ForEach-Object { $_.name })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  hostname=[string]$n.HostName; fqdn=[string]$n.FQDN
  services=$svcs; enabled=$on
  legacy_enabled=$risky
  ntp_servers=@($n.NTP.NTPServers)
}|ConvertTo-Json -Depth 6"#;

/// `idrac-boot` — boot order + Secure Boot state, read from the hardware rather than from inside the OS
/// (where a compromised OS is exactly what you would not want to ask).
#[cfg(windows)]
const IDRAC_BOOT_BODY: &str = r#"$s=Get-Redfish '/redfish/v1/Systems/System.Embedded.1'
if(-not $s){ ([pscustomobject]@{ok=$false;error='could not read the system resource';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$sb=Get-Redfish '/redfish/v1/Systems/System.Embedded.1/SecureBoot'
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  boot_mode=[string]$s.Boot.BootSourceOverrideMode
  override_enabled=[string]$s.Boot.BootSourceOverrideEnabled
  override_target=[string]$s.Boot.BootSourceOverrideTarget
  boot_order=@($s.Boot.BootOrder)
  boot_order_count=@($s.Boot.BootOrder).Count
  secure_boot=[string]$sb.SecureBootCurrentBoot
  secure_boot_enabled=$sb.SecureBootEnable
  secure_boot_mode=[string]$sb.SecureBootMode
}|ConvertTo-Json -Depth 6"#;

/// `idrac-licenses` — iDRAC Express vs Enterprise vs Datacenter. This gates what the controller can do
/// at all (Enterprise is what gives you virtual console/media and much of the telemetry), so it explains
/// why a given collector returns less on one box than another.
#[cfg(windows)]
const IDRAC_LICENSES_BODY: &str = r#"$c=$null
foreach($p in @('/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellLicenses','/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DellLicenseCollection')){
  $c=Get-Redfish $p; if($c){ break }
}
if(-not $c){ ([pscustomobject]@{ok=$false;error='could not read the license collection (path varies by firmware)';idrac=$idracHost;detail=$script:lastErr}|ConvertTo-Json -Depth 6); exit }
$lics=@()
foreach($m in @($c.Members)){
  $l=$m
  if(-not $l.LicenseDescription){ $l=Get-Redfish ($m.'@odata.id' -replace '^https?://[^/]+','') }
  if(-not $l){ continue }
  $lics+=[pscustomobject]@{
    id=[string]$l.Id
    description=@($l.LicenseDescription) -join '; '
    type=[string]$l.LicenseType
    status=@($l.LicensePrimaryStatus) -join ';'
    expiry=[string]$l.LicenseEndDate
    assigned_to=[string]$l.AssignedDevices
  }
}
[pscustomobject]@{ok=$true;idrac=$idracHost;licenses=$lics;license_count=@($lics).Count}|ConvertTo-Json -Depth 6"#;

/// Build an iDRAC collector script: credentials + endpoint prelude, then the per-collector body.
/// `extra` injects collector-specific PowerShell variables ahead of the prelude.
#[cfg(windows)]
fn idrac_script(params: Option<&str>, extra: &str, body: &str) -> String {
    let user = dup_param(params, &["username", "user"]);
    let secret = dup_param(params, &["secret", "password"]);
    let host = dup_param(params, &["host", "idrac", "address"]);
    format!(
        "$user={u}\n$secret={s}\n$idracHost={h}\n{extra}\n{IDRAC_PRELUDE}\n{body}",
        u = dup_squote_secret(&user),
        s = dup_squote_secret(&secret),
        h = if host.is_empty() { "$null".to_string() } else { dup_squote(&host) },
    )
}

#[cfg(windows)]
fn idrac_run(params: Option<&str>, extra: &str, body: &str, what: &str) -> Option<Value> {
    Some(
        ps_json(&idrac_script(params, extra, body))
            .unwrap_or_else(|| json!({"ok": false, "error": format!("iDRAC {what} read produced no parseable output")})),
    )
}

/// Read-only: hardware storage health from the host's own iDRAC. `host` overrides the pass-through
/// address for a box where iSM is absent but the iDRAC is reachable by IP; `oem=true` additionally
/// lists the Dell OEM property names present on each drive (noisy — one list per drive).
#[cfg(windows)]
fn idrac_storage(params: Option<&str>) -> Option<Value> {
    let want_oem = dup_param(params, &["oem", "oem_keys"]).eq_ignore_ascii_case("true");
    let extra = format!("$wantOem=${}", if want_oem { "true" } else { "false" });
    idrac_run(params, &extra, IDRAC_STORAGE_BODY, "storage")
}
#[cfg(not(windows))]
fn idrac_storage(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: whole-box health roll-up (system, chassis, memory, CPU, intrusion).
#[cfg(windows)]
fn idrac_health(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_HEALTH_BODY, "health")
}
#[cfg(not(windows))]
fn idrac_health(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: the hardware System Event Log. `limit` (default 50, max 200), `severity` filters to
/// `Critical` / `Warning` / `OK` (regex-matched, so `Critical|Warning` works).
#[cfg(windows)]
fn idrac_sel(params: Option<&str>) -> Option<Value> {
    let limit = match dup_param(params, &["limit", "max"]).parse::<u32>() {
        Ok(n) if n > 0 => n.min(200),
        _ => 50,
    };
    let sev = dup_param(params, &["severity", "sev"]);
    let extra = format!(
        "$limit={limit}\n$sevFilter={s}",
        s = if sev.is_empty() { "$null".to_string() } else { dup_squote(&sev) }
    );
    idrac_run(params, &extra, IDRAC_SEL_BODY, "SEL")
}
#[cfg(not(windows))]
fn idrac_sel(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: temperature probes + fans.
#[cfg(windows)]
fn idrac_thermal(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_THERMAL_BODY, "thermal")
}
#[cfg(not(windows))]
fn idrac_thermal(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: power supplies, redundancy and consumption.
#[cfg(windows)]
fn idrac_power(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_POWER_BODY, "power")
}
#[cfg(not(windows))]
fn idrac_power(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: DIMM inventory + per-module health.
#[cfg(windows)]
fn idrac_memory(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_MEMORY_BODY, "memory")
}
#[cfg(not(windows))]
fn idrac_memory(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: processor inventory + per-socket health.
#[cfg(windows)]
fn idrac_cpu(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_CPU_BODY, "cpu")
}
#[cfg(not(windows))]
fn idrac_cpu(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: physical NIC inventory as the hardware sees it.
#[cfg(windows)]
fn idrac_nic(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_NIC_BODY, "nic")
}
#[cfg(not(windows))]
fn idrac_nic(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: installed firmware versions for every component (fleet-drift source).
#[cfg(windows)]
fn idrac_firmware(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_FIRMWARE_BODY, "firmware")
}
#[cfg(not(windows))]
fn idrac_firmware(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: the Lifecycle Controller job queue.
#[cfg(windows)]
fn idrac_jobs(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_JOBS_BODY, "jobs")
}
#[cfg(not(windows))]
fn idrac_jobs(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: the iDRAC's own management addressing.
#[cfg(windows)]
fn idrac_network(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_NETWORK_BODY, "network")
}
#[cfg(not(windows))]
fn idrac_network(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: local iDRAC accounts + roles. Never a password.
#[cfg(windows)]
fn idrac_accounts(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_ACCOUNTS_BODY, "accounts")
}
#[cfg(not(windows))]
fn idrac_accounts(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: which management protocols are enabled, on which ports.
#[cfg(windows)]
fn idrac_services(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_SERVICES_BODY, "services")
}
#[cfg(not(windows))]
fn idrac_services(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: boot order + Secure Boot, read from the hardware.
#[cfg(windows)]
fn idrac_boot(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_BOOT_BODY, "boot")
}
#[cfg(not(windows))]
fn idrac_boot(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: installed iDRAC licenses (Express / Enterprise / Datacenter).
#[cfg(windows)]
fn idrac_licenses(params: Option<&str>) -> Option<Value> {
    idrac_run(params, "", IDRAC_LICENSES_BODY, "licenses")
}
#[cfg(not(windows))]
fn idrac_licenses(_p: Option<&str>) -> Option<Value> { None }

/// Read-only: is the Duplicati datafolder's ACL compliant with the 2.3 lockdown?
#[cfg(windows)]
fn duplicati_datafolder_check(_params: Option<&str>) -> Option<Value> {
    ps_json(&dup_script(DUP_ACLCHECK_BODY))
}
#[cfg(not(windows))]
fn duplicati_datafolder_check(_p: Option<&str>) -> Option<Value> { None }

/// L2: force the Duplicati datafolder ACL to the expected shape. `params.dry_run=true` previews only.
#[cfg(windows)]
fn duplicati_datafolder_secure(params: Option<&str>) -> Value {
    let dry = dup_param(params, &["dry_run", "dryrun", "whatif"]).eq_ignore_ascii_case("true");
    let body = format!("$dry=${d}\n{DUP_ACLFIX_BODY}", d = if dry { "true" } else { "false" });
    ps_json(&dup_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "datafolder-secure produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_datafolder_secure(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }

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

/// Launch a PowerShell script and capture its stdout/stderr/exit status.
#[cfg(windows)]
fn ps_capture(script: &str) -> Option<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
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

/// Whether a collector result is the `{ok:false,error}` failure shape rather than data — the check a
/// caller makes before treating a guarded object result as an answer.
#[cfg(windows)]
fn is_collector_error(v: &Value) -> bool {
    v.get("ok").and_then(|x| x.as_bool()) == Some(false)
}

/// [`ps_json`] for a [`PS_GUARD`] script: the parsed value, or the collector error shape when a read
/// failed. `what` names the collector for the operator-facing message.
#[cfg(windows)]
fn ps_json_guarded(script: &str, what: &str) -> Option<Value> {
    let out = ps_capture(script)?;
    if let Some(e) = guard_failure(&out, what) {
        return Some(e);
    }
    serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).ok()
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

/// Rows from a [`PS_GUARD`] script — normalizing `ConvertTo-Json`'s bare-object case for a single row —
/// the collector error on a failed read, and an empty row set for a genuine empty result.
#[cfg(windows)]
fn ps_rows_guarded(script: &str, what: &str) -> GuardedRows {
    let Some(out) = ps_capture(script) else {
        return GuardedRows::Failed(json!({ "ok": false, "error": format!("{what} failed: PowerShell could not be started") }));
    };
    if let Some(e) = guard_failure(&out, what) {
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

/// Soft byte budget for one paginated diag page — comfortably under the console's ~64 KB signed-result
/// cap, leaving headroom for the wrapper object + pagination metadata.
#[cfg(windows)]
const PAGE_BUDGET: usize = 48 * 1024;

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
    let mut page: Vec<Value> = Vec::new();
    let mut used = 0usize;
    for item in items.iter().skip(offset).take(limit) {
        let sz = serde_json::to_string(item).map(|s| s.len() + 1).unwrap_or(0);
        if !page.is_empty() && used + sz > PAGE_BUDGET {
            break; // budget reached — always return >=1 item so a single wide row still lands
        }
        used += sz;
        page.push(item.clone());
    }
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

/// Cursor-token pagination for the high-volume AD collectors (docs/PLAN-role-collectors.md §2). Presents
/// the `{cursor}` continuation-token contract — the incoming `cursor` param is the opaque token and the
/// envelope returns `{total, count, cursor?, items}` (no `offset`/`next_offset`). The token is currently
/// the encoded page offset and the search re-runs per page; the stateful device-side LDAP-cookie
/// optimization (resume instead of re-walk) is the one deferred follow-up. The wire contract is already
/// cursor-shaped, so that optimization is internal and non-breaking when it lands.
#[cfg(windows)]
fn paginate_cursor(items: Vec<Value>, params: Option<&str>, default_limit: usize) -> Value {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let total = items.len();
    let offset = p
        .get("cursor")
        .and_then(|x| x.as_str().and_then(|s| s.parse::<usize>().ok()).or_else(|| x.as_u64().map(|n| n as usize)))
        .unwrap_or(0);
    let limit = p.get("limit").and_then(|x| x.as_u64()).map(|n| (n as usize).max(1)).unwrap_or(default_limit);
    let mut page: Vec<Value> = Vec::new();
    let mut used = 0usize;
    for item in items.iter().skip(offset).take(limit) {
        let sz = serde_json::to_string(item).map(|s| s.len() + 1).unwrap_or(0);
        if !page.is_empty() && used + sz > PAGE_BUDGET {
            break;
        }
        used += sz;
        page.push(item.clone());
    }
    let end = offset + page.len();
    let mut out = json!({ "total": total, "count": page.len(), "items": page });
    if end < total {
        out["cursor"] = json!(end.to_string());
    }
    out
}

/// Run a PowerShell one-liner that emits `ConvertTo-Json` and return its rows as a paginated page,
/// read at most `max_entries` deep and with any over-long string field char-safe-truncated. The shared
/// shape for the read-only list kinds (scheduled tasks / startup / network connections / PnP / env).
///
/// The script is wrapped in [`PS_GUARD`] and checked afterwards, so a read that fails reports
/// `{ok:false,error}` rather than the empty list it used to. And the page comes from `paginate` rather
/// than a bare `truncate`: the old byte guard dropped the tail with no marker at all, so an operator
/// could not tell a complete list from a clipped one — which is the error≠absent problem applied to
/// volume instead of failure. Empty off-Windows.
#[cfg(windows)]
fn ps_json_array(script: &str, max_entries: usize, params: Option<&str>, what: &str) -> Option<Value> {
    let guarded = format!("{PS_GUARD}{script}; Stop-OnError '{what}'");
    let mut rows = match ps_rows_guarded(&guarded, what) {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
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
    Some(paginate(rows, params, max_entries))
}
#[cfg(not(windows))]
fn ps_json_array(_script: &str, _max_entries: usize, _params: Option<&str>, _what: &str) -> Option<Value> {
    None
}

/// Run a PowerShell script that emits `ConvertTo-Json` and return the parsed value **as-is** (object
/// OR array) — for the object-shaped read models (Defender status, Windows-update lists) that
/// `ps_json_array` would wrongly flatten. The caller bounds size at collection time (e.g.
/// `Select-Object -First N`). `None` off-Windows or on any launch/parse failure.
#[cfg(windows)]
pub(crate) fn ps_json(script: &str) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).ok()
}
#[cfg(not(windows))]
pub(crate) fn ps_json(_script: &str) -> Option<Value> {
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

/// Force-disconnect (S6): close every active incoming session (remote control / file transfer /
/// view camera / terminal) by handing each authorized connection an `ipc::Data::Close` on its authed
/// channel — the same graceful path the endpoint's own connection manager uses. Port-forward
/// tunnels run a separate raw loop that can't be reached this way; they're reported as skipped so
/// the operator isn't told they were closed.
fn disconnect_sessions() -> Value {
    let (closed, skipped_port_forward, peers) = crate::server::close_all_authed_conns();
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
    let ps = powershell_exe();
    run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &script], ok_label)
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

/// Start a Microsoft Defender scan. `params` JSON `{type:"quick"|"full"}` (default quick). The type
/// maps to a fixed `-ScanType` literal (never operator text), so the formatted command is safe.
#[cfg(windows)]
fn defender_scan(params: Option<&str>) -> Value {
    let kind = params
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("type").and_then(|x| x.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "quick".to_owned());
    let scan_type = if kind == "full" { "FullScan" } else { "QuickScan" };
    let ps = powershell_exe();
    let cmd = format!("Start-MpScan -ScanType {scan_type}");
    run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &cmd], "scan started")
}

/// Update Microsoft Defender signatures (`Update-MpSignature`). No params.
#[cfg(windows)]
fn defender_update_sigs() -> Value {
    let ps = powershell_exe();
    run_action(
        &[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", "Update-MpSignature"],
        "signature update started",
    )
}
#[cfg(not(windows))]
fn defender_scan(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}
#[cfg(not(windows))]
fn defender_update_sigs() -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Install Windows updates via the WU COM API (`Microsoft.Update.Session`), run BY the client (no
/// `PSWindowsUpdate` module / resident agent). `params` JSON `{kbs:"all"|["KB5000001",...], reboot:false}`
/// — `kbs` selects which available updates to install (all, or a specific KB list; KB ids are stripped
/// to bare digits so the PS filter is injection-safe), `reboot` (default false, operator-choice-per-job)
/// controls whether the client reboots when an installed update requires it. Always reports
/// `reboot_required`; on opt-in it schedules a 60 s-delayed reboot so the signed result posts first.
#[cfg(windows)]
fn win_update_install(params: Option<&str>) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let reboot = p.get("reboot").and_then(|x| x.as_bool()).unwrap_or(false);
    // A PowerShell array of bare KB numbers (digits only) to match KBArticleIDs, or `@()` = all
    // available. Non-digit input is dropped, so the interpolated literal can't carry PS injection.
    let sel = match p.get("kbs") {
        Some(Value::Array(arr)) => {
            let kbs: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().trim_start_matches(['K', 'k']).trim_start_matches(['B', 'b']))
                .filter(|s| !s.is_empty() && s.len() <= 12 && s.chars().all(|c| c.is_ascii_digit()))
                .map(|s| format!("'{s}'"))
                .collect();
            if kbs.is_empty() {
                return json!({ "ok": false, "error": "no valid KB ids" });
            }
            format!("@({})", kbs.join(","))
        }
        _ => "@()".to_owned(),
    };
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
try {{
  $sel = {sel}
  $session = New-Object -ComObject Microsoft.Update.Session
  $res = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
  $coll = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $res.Updates) {{
    $match = ($sel.Count -eq 0)
    if (-not $match) {{ foreach ($id in $u.KBArticleIDs) {{ if ($sel -contains [string]$id) {{ $match=$true }} }} }}
    if ($match) {{ if (-not $u.EulaAccepted) {{ try {{ $u.AcceptEula() }} catch {{}} }}; [void]$coll.Add($u) }}
  }}
  if ($coll.Count -eq 0) {{ '{{"ok":true,"installed":0,"reboot_required":false,"note":"no matching updates"}}'; exit }}
  $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
  $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll; $r = $inst.Install()
  [PSCustomObject]@{{ ok=($r.ResultCode -eq 2); installed=$coll.Count; result_code=[int]$r.ResultCode; reboot_required=[bool]$r.RebootRequired }} | ConvertTo-Json -Compress
}} catch {{
  [PSCustomObject]@{{ ok=$false; error=[string]$_.Exception.Message }} | ConvertTo-Json -Compress
}}
"#
    );
    let mut result = ps_json(&script).unwrap_or_else(|| json!({ "ok": false, "error": "update install failed to launch" }));
    let reboot_required = result.get("reboot_required").and_then(|x| x.as_bool()).unwrap_or(false);
    if reboot && reboot_required {
        let _ = std::process::Command::new("shutdown")
            .args(["/r", "/t", "60", "/c", "SullTec console: rebooting to finish Windows updates"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        if let Some(o) = result.as_object_mut() {
            o.insert("rebooting".to_owned(), json!(true));
        }
    }
    result
}
#[cfg(not(windows))]
fn win_update_install(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
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
/// char-safe-truncates the combined output to stay under the console's 64 KB result cap. Returns
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

/// The SAM and SECURITY hives hold password material and are never a legitimate diagnostic read; this
/// mirrors the backend's dispatch-time denylist client-side so no path to a `reg-read` job can reach
/// them. Case-insensitive; matches the hive root exactly or any subkey beneath it.
#[cfg(windows)]
fn reg_path_denied(path: &str) -> bool {
    let p = path.trim().to_ascii_uppercase();
    ["HKLM:\\SAM", "HKLM:\\SECURITY"]
        .iter()
        .any(|d| p == *d || p.starts_with(format!("{d}\\").as_str()))
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

/// Read a registry key's values + immediate subkey names (F11, read-only). `params` is a PS-drive
/// path like `HKLM:\SOFTWARE\Microsoft\Windows`. Returns `{key, subkeys:[…], values:[{name,type,data}]}`;
/// each value's data is char-capped so the signed result stays under the console's 64 KB cap.
#[cfg(windows)]
fn reg_read(params: Option<&str>) -> Option<Value> {
    // Accept a bare `HKLM:\…` string (console UI) or a `{"path":"HKLM:\\…"}` object (/api/diag body).
    let path_owned = json_field_or_raw(params.unwrap_or(""), &["path"]);
    let path = path_owned.trim();
    if !valid_reg_path(path) {
        return Some(json!({ "error": "invalid registry path (expected HKLM:\\, HKCU:\\, HKCR:\\, HKU:\\ or HKCC:\\ …)" }));
    }
    if reg_path_denied(path) {
        return Some(json!({ "error": "reading the SAM / SECURITY credential hives is not permitted" }));
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = format!(
        "$ErrorActionPreference='Stop'; $k=Get-Item -LiteralPath '{path}'; \
         $vals=foreach($n in $k.GetValueNames()){{[pscustomobject]@{{name=$n;type=$k.GetValueKind($n).ToString();data=[string]($k.GetValue($n))}}}}; \
         [pscustomobject]@{{key=$k.Name;subkeys=@($k.GetSubKeyNames());values=@($vals)}}|ConvertTo-Json -Compress -Depth 4"
    );
    let out = std::process::Command::new(powershell_exe())
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
    if reg_path_denied(path) {
        return json!({ "ok": false, "error": "writing the SAM / SECURITY credential hives is not permitted" });
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
    let out = std::process::Command::new(powershell_exe())
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
///
/// Intentionally reads an ARBITRARY path (an operator pulls a log from anywhere), so — unlike
/// `file_push`/`deploy` — it must NOT be constrained to a write-root via `safe_path`; that would break
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

/// The MAIN service log — the newest **top-level** `*.log` (the persistent log the service writes its
/// heartbeat / job-channel / updater-*check* activity to). Falls back to `newest_log` (anywhere) only
/// when no top-level log exists yet. Preferred over `newest_log` for the default pull: short-lived
/// per-component subprocess logs (`update`, `check-hwcodec-config`, …) can be newer but usually aren't
/// what an operator wants.
#[cfg(windows)]
fn main_log(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let top = std::fs::read_dir(dir).ok().and_then(|rd| {
        rd.flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("log"))
            .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()).map(|m| (m, e.path())))
            .max_by_key(|(m, _)| *m)
            .map(|(_, p)| p)
    });
    top.or_else(|| newest_log(dir))
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
    match std::fs::read(&path) {
        Ok(bytes) => {
            let size = bytes.len();
            let truncated = size > CAP;
            // Keep the LAST CAP bytes (recent activity) — drop the leading partial line + lossily
            // decode (a run log is always UTF-8 text, so no base64 fallback needed).
            let mut slice: &[u8] = if truncated { &bytes[size - CAP..] } else { &bytes[..] };
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
    let out = std::process::Command::new(powershell_exe())
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
        let ps = powershell_exe();
        return run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &script], &format!("moved to {target}"));
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
    let ps = powershell_exe();
    run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &script], &format!("{op} {user}"))
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
    // Data plane: a job result carries collector output (capped at 64 KB today, but that cap is the
    // only reason the old 12 s total budget held — any collector that outgrows it inherits exactly
    // the failure the updater hit). Bulk budget, not the heartbeat's.
    match crate::post_request_timeout(url, body, "", crate::API_TIMEOUT_DATA).await {
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
    // Data plane: the request is tiny but the RESPONSE carries the withheld params of a sensitive
    // kind — `file-push`/`deploy` payloads are the bulk case, and the timeout covers the response.
    let rsp = crate::post_request_timeout(url, body, "", crate::API_TIMEOUT_DATA).await.ok()?;
    serde_json::from_str::<Value>(&rsp)
        .ok()?
        .get("params")
        .and_then(|x| x.as_str())
        .map(str::to_owned)
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

#[cfg(all(test, windows))]
mod eventlog_filter_tests {
    // The `eventlog` filter keys carry two traps worth pinning: an omitted `level` must emit NO key
    // (that absence is what makes level-0 audit events reachable at all), and a scalar `level` must
    // keep its cumulative meaning so a caller that pinned one is not silently widened.
    use super::eventlog_filter_clauses;
    use serde_json::json;

    #[test]
    fn omitted_level_emits_no_key() {
        assert_eq!(eventlog_filter_clauses(&json!({})), "");
        assert_eq!(eventlog_filter_clauses(&json!({ "log": "System" })), "");
        assert_eq!(eventlog_filter_clauses(&json!({ "level": null })), "");
    }

    #[test]
    fn scalar_level_stays_cumulative() {
        assert_eq!(eventlog_filter_clauses(&json!({ "level": 3 })), "; Level=@(1,2,3)");
        assert_eq!(eventlog_filter_clauses(&json!({ "level": 5 })), "; Level=@(1,2,3,4,5)");
        // A numeric string is the same param — the diag route can deliver either spelling.
        assert_eq!(eventlog_filter_clauses(&json!({ "level": "3" })), "; Level=@(1,2,3)");
        // A scalar CANNOT reach 0; it clamps to 1. The list form is the only way to ask for audit
        // events, and the help text says so.
        assert_eq!(eventlog_filter_clauses(&json!({ "level": 0 })), "; Level=@(1)");
        assert_eq!(eventlog_filter_clauses(&json!({ "level": 9 })), "; Level=@(1,2,3,4,5)");
    }

    #[test]
    fn list_level_is_exact() {
        assert_eq!(eventlog_filter_clauses(&json!({ "level": [0, 4] })), "; Level=@(0,4)");
        assert_eq!(eventlog_filter_clauses(&json!({ "level": "0,4" })), "; Level=@(0,4)");
        assert_eq!(eventlog_filter_clauses(&json!({ "level": [0] })), "; Level=@(0)");
        // Out-of-range entries clamp and collapse rather than emitting a duplicate.
        assert_eq!(eventlog_filter_clauses(&json!({ "level": [7, 8] })), "; Level=@(5)");
        // Nothing parseable is the same as not asking — no key, not an empty one.
        assert_eq!(eventlog_filter_clauses(&json!({ "level": ["x", "y"] })), "");
    }

    #[test]
    fn id_and_provider_filter_at_the_source() {
        assert_eq!(eventlog_filter_clauses(&json!({ "id": 4624 })), "; Id=@(4624)");
        assert_eq!(eventlog_filter_clauses(&json!({ "id": [24, 21, 23] })), "; Id=@(21,23,24)");
        assert_eq!(eventlog_filter_clauses(&json!({ "id": "21,23" })), "; Id=@(21,23)");
        assert_eq!(eventlog_filter_clauses(&json!({ "event_id": 1149 })), "; Id=@(1149)");
        assert_eq!(
            eventlog_filter_clauses(&json!({ "provider": "Microsoft-Windows-Winlogon" })),
            "; ProviderName=@('Microsoft-Windows-Winlogon')"
        );
        // An embedded quote is stripped, not escaped — the value lands inside a PowerShell literal.
        assert_eq!(eventlog_filter_clauses(&json!({ "provider": "a'b,c" })), "; ProviderName=@('ab','c')");
    }

    #[test]
    fn keys_compose_in_a_fixed_order() {
        assert_eq!(
            eventlog_filter_clauses(&json!({ "level": [0], "id": 4624, "provider": "Microsoft-Windows-Security-Auditing" })),
            "; Level=@(0); Id=@(4624); ProviderName=@('Microsoft-Windows-Security-Auditing')"
        );
    }
}

#[cfg(all(test, windows))]
mod bare_param_tests {
    // Scalar collector params arrive in three shapes depending on the surface: a bare string from the
    // console UI, a JSON string, or a JSON object from the REST route. Each has silently regressed a
    // collector at least once — an unwrapped body reaches the filesystem as a literal filename — so the
    // three shapes and every accepted alias are pinned here.
    use super::{json_field_or_raw, reg_path_denied, valid_reg_path};

    #[test]
    fn every_param_shape_yields_the_value() {
        assert_eq!(json_field_or_raw(r#"{"path":"HKLM:\\SOFTWARE"}"#, &["path"]), r"HKLM:\SOFTWARE");
        assert_eq!(json_field_or_raw(r#""HKLM:\\SOFTWARE""#, &["path"]), r"HKLM:\SOFTWARE");
        assert_eq!(json_field_or_raw(r"HKLM:\SOFTWARE", &["path"]), r"HKLM:\SOFTWARE");
        // Whitespace around any of the three is the caller's, not the value's.
        assert_eq!(json_field_or_raw(r#"  {"path":" C:\\a.txt "}  "#, &["path"]), r"C:\a.txt");
    }

    #[test]
    fn aliases_are_tried_in_order() {
        assert_eq!(json_field_or_raw(r#"{"file":"C:\\a.txt"}"#, &["path", "file"]), r"C:\a.txt");
        assert_eq!(json_field_or_raw(r#"{"path":"first","file":"second"}"#, &["path", "file"]), "first");
        // An empty value is not a value — fall through to the next alias rather than returning "".
        assert_eq!(json_field_or_raw(r#"{"path":"","file":"second"}"#, &["path", "file"]), "second");
        // No alias present → empty, which each caller reports as a missing param.
        assert_eq!(json_field_or_raw(r#"{"other":"x"}"#, &["path", "file"]), "");
        assert_eq!(json_field_or_raw("{}", &["path"]), "");
    }

    #[test]
    fn only_ps_drive_registry_paths_are_accepted() {
        assert!(valid_reg_path(r"HKLM:\SOFTWARE\Microsoft"));
        assert!(valid_reg_path(r"HKCU:\Environment"));
        assert!(valid_reg_path(r"HKCR:\.txt"));
        assert!(valid_reg_path(r"HKU:\.DEFAULT"));
        assert!(valid_reg_path(r"HKCC:\System"));
        // The registry-API spelling has no colon and must not pass as a PS-drive path.
        assert!(!valid_reg_path(r"HKEY_LOCAL_MACHINE\SOFTWARE"));
        assert!(!valid_reg_path(r"HKLM\SOFTWARE"));
        assert!(!valid_reg_path(""));
        // A quote or newline would break out of the single-quoted PowerShell literal it lands in.
        assert!(!valid_reg_path("HKLM:\\SOFTWARE'; Remove-Item C:\\ #"));
        assert!(!valid_reg_path("HKLM:\\SOFTWARE\nfoo"));
        assert!(!valid_reg_path(&format!(r"HKLM:\{}", "a".repeat(600))));
    }

    #[test]
    fn credential_hives_are_refused_at_the_root_and_below() {
        assert!(reg_path_denied(r"HKLM:\SAM"));
        assert!(reg_path_denied(r"hklm:\sam\SAM\Domains"));
        assert!(reg_path_denied(r"HKLM:\SECURITY\Policy"));
        // A key that merely starts with the same letters is a different key.
        assert!(!reg_path_denied(r"HKLM:\SAMPLE"));
        assert!(!reg_path_denied(r"HKLM:\SOFTWARE"));
    }
}
