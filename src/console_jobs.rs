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
    "duplicati-vacuum", "duplicati-browse", "duplicati-log", "duplicati-sources",
    "duplicati-notifications", "duplicati-files", "duplicati-tasks", "duplicati-task-stop",
    "duplicati-cli",
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
        // Id and kind ONLY — params can carry a registry path, a file path or credentials merged in
        // by the signed fetch, and this log gets pulled off devices.
        hbb_common::log::info!("console job {job_id} starting ({kind})");
        let url = heartbeat_url.clone();
        let id = id.clone();
        hbb_common::tokio::spawn(async move {
            let _in_flight = in_flight;
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
            400, FIELD_VALUE_CAP, params.as_deref(), "schtasks",
        )).await.ok().flatten(),
        "startup" => spawn_blocking(move || ps_json_array(
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress",
            200, FIELD_VALUE_CAP, params.as_deref(), "startup",
        )).await.ok().flatten(),
        // `State` is a bare MIB_TCP_STATE integer, and reading `100` (bound) as `5` (established) turns
        // a socket that has merely reserved a port into a phantom outbound connection. `state_name`
        // decodes it alongside the raw value; an unrecognized code renders as `unknown(<raw>)` rather
        // than guessing at one of the known states.
        // ⚠ UDP IS INCLUDED, and its absence was a real blind spot: this collector read
        // `Get-NetTCPConnection` alone, its deep-read companion `netconn-owner` did the same, and no
        // other shipped collector read `Get-NetUDPEndpoint` — so a UDP listener was invisible to the
        // whole console. That is the wrong way round for a security read: a listening UDP socket is
        // exactly what a caller is hunting when they ask what this box has open.
        //
        // Every row carries `protocol`. UDP is CONNECTIONLESS, so a UDP row has no remote peer and no
        // state at all — those fields are `null` rather than zero or an empty string, and `state_name`
        // says `n/a (udp is connectionless)` so the absence reads as a property of the protocol rather
        // than as a state we failed to read. A UDP row is a LISTENING ENDPOINT, never a connection.
        "netconn" => spawn_blocking(move || ps_json_array(
            "$st=@{'1'='closed';'2'='listen';'3'='syn-sent';'4'='syn-received';'5'='established';\
             '6'='fin-wait-1';'7'='fin-wait-2';'8'='close-wait';'9'='closing';'10'='last-ack';\
             '11'='time-wait';'12'='delete-tcb';'100'='bound'}; \
             $tcp=@(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object \
               @{n='protocol';e={'tcp'}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State,\
               @{n='state_name';e={$n=$_.State -as [int]; \
               if ($null -ne $n -and $st.ContainsKey([string]$n)) { $st[[string]$n] } \
               else { 'unknown(' + [string]$_.State + ')' }}},\
               OwningProcess); \
             $udp=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object \
               @{n='protocol';e={'udp'}},LocalAddress,LocalPort,\
               @{n='RemoteAddress';e={$null}},@{n='RemotePort';e={$null}},@{n='State';e={$null}},\
               @{n='state_name';e={'n/a (udp is connectionless)'}},\
               OwningProcess); \
             @($tcp + $udp) | ConvertTo-Json -Compress",
            300, FIELD_VALUE_CAP, params.as_deref(), "netconn",
        )).await.ok().flatten(),
        "pnp" => spawn_blocking(move || ps_json_array(
            "Get-PnpDevice | Select-Object FriendlyName,Class,Status,InstanceId | Sort-Object Class,FriendlyName | ConvertTo-Json -Compress",
            600, FIELD_VALUE_CAP, params.as_deref(), "pnp",
        )).await.ok().flatten(),
        // Read-only diagnostic deep-read collectors (PLAN §2.5). Each takes an optional JSON filter
        // body and returns a structured, source-filtered result; no state change regardless of params.
        "firewall" => spawn_blocking(move || firewall(params.as_deref())).await.ok().flatten(),
        "firewall-rule" => spawn_blocking(move || firewall_rule(params.as_deref())).await.ok().flatten(),
        "system" => spawn_blocking(|| system_info()).await.ok().flatten(),
        "disks" => spawn_blocking(|| disks()).await.ok().flatten(),
        "localusers" => spawn_blocking(move || localusers(params.as_deref())).await.ok().flatten(),
        // SID → account name. Ungated metadata: it resolves an identifier the caller already holds and
        // enumerates nothing, so it reveals no more than the SID did.
        "sid-resolve" => spawn_blocking(move || sid_resolve(params.as_deref())).await.ok().flatten(),
        // Deep-read companions to the `processes` / `schtasks` / `netconn` / `startup` sweeps, plus the
        // User-Profile-Disk reader. CONTENT-BEARING, each REQUIRES a narrowing selector, and each is
        // admin-gated console-side the way `fs`/`wmi` are — the fork doesn't gate, it serves the data.
        "process-detail" => spawn_blocking(move || process_detail(params.as_deref())).await.ok().flatten(),
        "schtask-detail" => spawn_blocking(move || schtask_detail(params.as_deref())).await.ok().flatten(),
        "netconn-owner" => spawn_blocking(move || netconn_owner(params.as_deref())).await.ok().flatten(),
        "startup-detail" => spawn_blocking(move || startup_detail(params.as_deref())).await.ok().flatten(),
        "user-profile-disks" => spawn_blocking(move || user_profile_disks(params.as_deref())).await.ok().flatten(),
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
        "features" => spawn_blocking(move || features(params.as_deref())).await.ok().flatten(),
        "capabilities" => spawn_blocking(move || capabilities(params.as_deref())).await.ok().flatten(),
        "appx" => spawn_blocking(move || appx(params.as_deref())).await.ok().flatten(),
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
        "rds-logons" => spawn_blocking(move || rds_logons(params.as_deref())).await.ok().flatten(),
        "rds-logon-failures" => spawn_blocking(move || rds_logon_failures(params.as_deref())).await.ok().flatten(),
        "rds-session-events" => spawn_blocking(move || rds_session_events(params.as_deref())).await.ok().flatten(),
        "rds-session-perf" => spawn_blocking(move || rds_session_perf(params.as_deref())).await.ok().flatten(),
        "rds-licensing" => spawn_blocking(move || rds_licensing(params.as_deref())).await.ok().flatten(),
        "rds-connection-quality" => spawn_blocking(move || rds_connection_quality(params.as_deref())).await.ok().flatten(),
        "rds-profiles" => spawn_blocking(move || rds_profiles(params.as_deref())).await.ok().flatten(),
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
        "duplicati-sources" => spawn_blocking(move || duplicati_sources(params.as_deref())).await.ok().flatten(),
        "duplicati-notifications" => spawn_blocking(move || duplicati_notifications(params.as_deref())).await.ok().flatten(),
        "duplicati-files" => spawn_blocking(move || duplicati_files(params.as_deref())).await.ok().flatten(),
        "duplicati-tasks" => spawn_blocking(move || duplicati_tasks(params.as_deref())).await.ok().flatten(),
        "duplicati-cli" => spawn_blocking(move || duplicati_cli(params.as_deref())).await.ok().flatten(),
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
        "duplicati-task-stop" => spawn_blocking(move || duplicati_task_stop(params.as_deref())).await.ok(),
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

/// Ceiling on how deep [`eventlog`] will read. It reads `offset + max + 1` events, so a deep `offset`
/// is what makes the read expensive; past this the right tool is a narrower filter, not another page.
/// Refused rather than silently clamped — a clamp is exactly the bound-nobody-measured this collector
/// must never state.
#[cfg(windows)]
const EVENTLOG_FETCH_MAX: i64 = 5000;

/// Recent Windows event-log entries via PowerShell `Get-WinEvent` — System + Application, every
/// severity, newest first, paginated so a page of long messages can't overflow the console's result
/// cap. Optional `params` JSON `{log:"System,Application", level:3|[0,4], id:4624|[21,23], provider:"…",
/// since:"yyyy-MM-dd"|days-int, max:60, offset:0, limit:60}` narrows it (`level` scalar = cumulative
/// max severity, 1 crit … 5 verbose; `level` list = exactly those levels, the only way to ask for 0
/// (LogAlways) and therefore for Security audit events; `since` bounds the window — integer OR an
/// all-digit string = N days back, any other string = a date literal, omitted = newest `max` with no
/// lower bound). Returns a `{total,total_measured,offset,count,truncated,next_offset?,items}` envelope
/// when the filter matched — with `items: []` when it genuinely matched nothing, including a **cleared
/// or quiet log**, which is the normal state for a low-traffic host and NOT an error — but
/// `{ok:false,error}` when the query itself failed OR a requested channel could not be read. Those are
/// NOT the same: neither may be reported as the other, so an empty page never hides a blow-up and a
/// failure never hides an empty log.
///
/// ⚠ **`offset` pages the LOG, and `total` is a count only when something counted it.** `max` caps the
/// READ, so `offset` applied to the fetched rows would page inside an already-truncated set: every
/// `offset >= max` came back empty, which is indistinguishable from the end of the log, and `total`
/// echoed the page size as if it were the log's. So the read takes `offset + max + 1` events and skips
/// `offset` at the source. The extra event is a probe, and its presence is the whole discrimination:
///
/// - cap did NOT bite → every matching event was seen → `total` is exact, `total_measured: true`
/// - cap DID bite → more events match than were read → `total: null`, `total_measured: false`,
///   `truncated: true`; the log holds more and nothing here knows how many
///
/// Reading past [`EVENTLOG_FETCH_MAX`] is refused with `{ok:false,error}`.
/// Empty off-Windows.
#[cfg(windows)]
fn eventlog(params: Option<&str>) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let logs = p.get("log").and_then(|x| x.as_str()).unwrap_or("System,Application");
    // Row cap. `max` is the documented name; accept the legacy `count` too. Default 60, max 200.
    let max = p.get("max").or_else(|| p.get("count")).and_then(|x| x.as_i64()).unwrap_or(60).clamp(1, 200);
    // How many events to skip AT THE SOURCE, plus the one probe event beyond the page.
    let offset = p.get("offset").and_then(|x| x.as_i64()).filter(|n| *n >= 0).unwrap_or(0);
    let fetch = offset + max + 1;
    if fetch > EVENTLOG_FETCH_MAX {
        return Some(json!({
            "ok": false,
            "error": format!(
                "event-log query refused: offset {offset} + max {max} would read past the \
                 {EVENTLOG_FETCH_MAX}-event ceiling. Narrow the query (since/level/id/provider) rather \
                 than paging deeper."
            )
        }));
    }
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
    //   rows found            → envelope on stdout, exit 0
    //   nothing matched       → envelope on stdout with `fetched:0`, exit 0 ⇒ the valid-empty branch
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
    //
    // The script reports `fetched` — how many events came back BEFORE the skip — beside the page's
    // rows. That number is the only thing that can tell an exhausted log from a read stopped at the
    // cap, and it is also what makes `offset` past the end honest rather than silently empty. The
    // `.Message` projection runs after the skip, so a deep offset does not pay to format rows it
    // discards.
    let script = format!(
        "$Error.Clear(); \
         $logs = @({log_arr}); \
         $all = @(Get-WinEvent -FilterHashtable @{{LogName=$logs{narrowing}{start_clause}}} -MaxEvents {fetch} -ErrorAction SilentlyContinue); \
         if ($all.Count -eq 0) {{ \
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
         $rows = @($all | Select-Object -Skip {offset} | \
         Select-Object @{{n='time';e={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}},@{{n='log';e={{$_.LogName}}}},@{{n='id';e={{$_.Id}}}},@{{n='level';e={{$_.LevelDisplayName}}}},@{{n='provider';e={{$_.ProviderName}}}},@{{n='message';e={{$_.Message}}}}); \
         [pscustomobject]@{{ fetched = $all.Count; rows = $rows }} | ConvertTo-Json -Compress -Depth 4; \
         exit 0"
    );
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let trimmed = text.trim();
    // The script writes its envelope on EVERY successful path, including a log that matched nothing, so
    // empty stdout now means the query failed — loudly (stderr + exit 1, which is also how an unreadable
    // channel arrives) or silently. Reporting that as an empty page reads as "the log is clean", the
    // worst possible lie for an audit, so it takes the collector error shape (`{ok:false,error}`, as
    // `gpo-list` and friends do). The other direction matters just as much: a quiet or freshly cleared
    // log is a valid empty result and must NOT come back as a failure, which is what the script's own
    // no-match classification above preserves.
    if trimmed.is_empty() {
        let err_text = String::from_utf8_lossy(&out.stderr);
        let err_text = err_text.trim();
        let detail: String = if err_text.is_empty() {
            format!("Get-WinEvent wrote nothing and exited {}", out.status.code().unwrap_or(-1))
        } else {
            err_text.chars().take(2000).collect()
        };
        return Some(json!({ "ok": false, "error": format!("event-log query failed: {detail}") }));
    }
    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return Some(json!({ "ok": false, "error": "event-log query returned unreadable output" }));
    };
    // Events seen before the skip. Absent only if the envelope came back malformed, and then the total
    // is unknown rather than assumed — the assumption is the bug.
    let fetched = parsed.get("fetched").and_then(|x| x.as_i64());
    let rows: Vec<Value> = match parsed.get("rows") {
        Some(Value::Array(a)) => a.clone(),
        Some(v) if v.is_object() => vec![v.clone()], // ConvertTo-Json emits a bare object for one row
        _ => Vec::new(),
    };
    // Collapse whitespace + char-safe truncate each message so the whole result fits the cap.
    let mut entries: Vec<Value> = rows
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
    // Drop the probe: it is evidence that the read stopped at the cap, not a row the caller asked for.
    entries.truncate(max as usize);
    // The cap did not bite ⇒ the read saw every event matching the filter, so `fetched` IS the total —
    // and it is exact even when `offset` ran past the end, which is the case that used to come back as
    // an empty page with `total` set to the page size.
    let measured_total = fetched.filter(|f| *f < fetch);
    let window = entries.len() as i64;
    // 200 rows of 400-char messages clear the store cap on their own, so the page is byte-budgeted like
    // every other list collector. `paginate` must not apply `offset` a second time — the read already
    // skipped it — so it sees the window's own start.
    let mut page_params = p.clone();
    if let Some(o) = page_params.as_object_mut() {
        o.remove("offset");
    }
    let page_params = page_params.is_object().then(|| page_params.to_string());
    let mut page = paginate(entries, page_params.as_deref(), max as usize);
    let count = page.get("count").and_then(|x| x.as_i64()).unwrap_or(0);
    // Two independent reasons the answer is incomplete: the page did not cover the window, or the
    // window did not cover the log. Either one has to say so.
    let truncated = count < window || measured_total.is_none();
    page["offset"] = json!(offset);
    page["truncated"] = json!(truncated);
    page["total"] = measured_total.map(|t| json!(t)).unwrap_or(Value::Null);
    page["total_measured"] = json!(measured_total.is_some());
    if truncated {
        page["next_offset"] = json!(offset + count);
    } else if let Some(o) = page.as_object_mut() {
        o.remove("next_offset");
    }
    Some(page)
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

/// Index a whole-set `Get-NetFirewall*Filter` read by `InstanceID` (which equals the owning rule's
/// `Name`), for joining filters onto rules in memory instead of querying per rule.
///
/// ⚠ The whole-set read is not guaranteed complete: without the privilege to read every policy store
/// it returns only the filters it could see and raises "Access is denied" for the rest. A rule missing
/// from the index must therefore fall back to its own association query — an absent port filter would
/// otherwise render as empty ports, which reads as "unrestricted" and is the wrong answer to a firewall
/// question. Callers skip blank keys so a filter type that exposes no `InstanceID` collapses to an empty
/// index (every rule falls back) rather than joining every rule onto one arbitrary filter.
#[cfg(windows)]
const FW_INDEX_FN: &str = "function New-FwIndex { param($Items) $h=@{}; \
foreach ($x in @($Items)) { $k=[string]$x.InstanceID; if ($k) { $h[$k]=$x } }; return $h }; ";

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
    // Port/program live on separate filter objects. Resolving them by piping each rule into
    // `Get-NetFirewallPortFilter` &co costs ~200 ms PER RULE, so a host with a few hundred rules ran
    // for minutes and timed out the caller. Each filter type is instead enumerated ONCE and indexed by
    // `InstanceID`, which equals the rule's `Name` — a whole-set read that takes well under a second.
    // Pull up to 2000 rules as a safety bound; the small per-profile on/off summary is always returned
    // in full, and the rules list is paginated + size-capped below so a firewall with hundreds of rules
    // can't overflow the result cap.
    let script = format!(
        "{PS_GUARD}\
         $pr=@(Get-NetFirewallProfile); Stop-OnError 'firewall profiles'; \
         $rl=@(Get-NetFirewallRule{where_clause} | Select-Object -First 2000); Stop-OnError 'firewall rules'; \
         {FW_INDEX_FN}\
         $pfm=New-FwIndex (Get-NetFirewallPortFilter); \
         $afm=New-FwIndex (Get-NetFirewallApplicationFilter); \
         $adm=New-FwIndex (Get-NetFirewallAddressFilter); \
         $Error.Clear(); \
         $profiles=@($pr | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.Name; enabled=[bool]$_.Enabled; \
           default_inbound=[string]$_.DefaultInboundAction; default_outbound=[string]$_.DefaultOutboundAction; \
           allow_inbound_rules=[string]$_.AllowInboundRules; allow_local_firewall_rules=[string]$_.AllowLocalFirewallRules; \
           log_blocked=[bool]$_.LogBlocked; log_allowed=[bool]$_.LogAllowed; log_file=[string]$_.LogFileName }} }}); \
         $rules=@($rl | ForEach-Object {{ \
           $k=[string]$_.Name; \
           $pf=$pfm[$k]; if ($null -eq $pf) {{ $pf=$_ | Get-NetFirewallPortFilter }}; \
           $af=$afm[$k]; if ($null -eq $af) {{ $af=$_ | Get-NetFirewallApplicationFilter }}; \
           $adr=$adm[$k]; if ($null -eq $adr) {{ $adr=$_ | Get-NetFirewallAddressFilter }}; \
           [pscustomobject]@{{ name=[string]$_.Name; display=[string]$_.DisplayName; direction=[string]$_.Direction; action=[string]$_.Action; enabled=($_.Enabled -eq 'True'); profile=[string]$_.Profile; protocol=[string]$pf.Protocol; local_port=([string]($pf.LocalPort -join ',')); remote_port=([string]($pf.RemotePort -join ',')); program=[string]$af.Program; \
             remote_address=([string]($adr.RemoteAddress -join ',')); local_address=([string]($adr.LocalAddress -join ',')) }} \
         }}); \
         $Error.Clear(); \
         [pscustomobject]@{{ profiles=$profiles; rules=$rules }} | ConvertTo-Json -Depth 4 -Compress"
    );
    let raw = ps_json_guarded(&script, "firewall")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let profiles = raw.get("profiles").cloned().unwrap_or_else(|| json!([]));
    let rules = raw.get("rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    // Split by action. On a locked-down host the BLOCK rules are the whole story and there are usually
    // few of them, but paginated among hundreds of Allow rules they land on page 3 and are never seen —
    // reading the first page and concluding "nothing blocks this" is a conclusion drawn from the page
    // size, not from the firewall. Enabled blocks are surfaced whole, outside the pagination.
    let enabled = |r: &Value| r.get("enabled").and_then(|e| e.as_str()).map(|s| s.eq_ignore_ascii_case("true")).unwrap_or(false);
    let is_block = |r: &Value| r.get("action").and_then(|a| a.as_str()).map(|s| s.eq_ignore_ascii_case("block")).unwrap_or(false);
    let blocks: Vec<Value> = rules.iter().filter(|r| is_block(r) && enabled(r)).cloned().collect();
    let allow_enabled = rules.iter().filter(|r| !is_block(r) && enabled(r)).count();
    let block_disabled = rules.iter().filter(|r| is_block(r) && !enabled(r)).count();
    Some(json!({
        "profiles": profiles,
        // Counts describe the WHOLE rule set, not the page below it.
        "rule_total": rules.len(),
        "enabled_allow_count": allow_enabled,
        "enabled_block_count": blocks.len(),
        "disabled_block_count": block_disabled,
        "enabled_blocks": blocks,
        "rules": paginate(rules, params, 150),
    }))
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
    // Require a narrowing selector — a full-detail dump of every rule is never allowed. `ok:false`
    // because a refusal is not an answer: see [`wmi_error`] for why the body carries the verdict while
    // the dispatch `status` stays `done`.
    if name.is_none() && id.is_none() && port.is_none() {
        return Some(json!({ "ok": false, "error": "firewall-rule requires at least one of: name (DisplayName glob), id (rule id substring), or port" }));
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
    // Join every NetSecurity filter object onto its rule. Seven per-rule association queries cost ~450 ms
    // a rule, so each filter type is enumerated ONCE and indexed by `InstanceID` (see [`FW_INDEX_FN`]);
    // a rule the index missed falls back to its own query. `-First 400` bounds the result; the final list
    // is paginated + byte-capped so a wide-detail result can't overflow the signed cap.
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-NetFirewallRule{where_clause} | Select-Object -First 400); Stop-OnError 'firewall rules'; \
         {FW_INDEX_FN}\
         $pfm=New-FwIndex (Get-NetFirewallPortFilter); \
         $afm=New-FwIndex (Get-NetFirewallAddressFilter); \
         $apm=New-FwIndex (Get-NetFirewallApplicationFilter); \
         $svm=New-FwIndex (Get-NetFirewallServiceFilter); \
         $iam=New-FwIndex (Get-NetFirewallInterfaceFilter); \
         $itm=New-FwIndex (Get-NetFirewallInterfaceTypeFilter); \
         $sem=New-FwIndex (Get-NetFirewallSecurityFilter); \
         $Error.Clear(); \
         $out=@($src | ForEach-Object {{ \
           $k=[string]$_.Name; \
           $pf=$pfm[$k]; if ($null -eq $pf) {{ $pf=$_ | Get-NetFirewallPortFilter }}; \
           {port_gate}\
           $af=$afm[$k]; if ($null -eq $af) {{ $af=$_ | Get-NetFirewallAddressFilter }}; \
           $ap=$apm[$k]; if ($null -eq $ap) {{ $ap=$_ | Get-NetFirewallApplicationFilter }}; \
           $sv=$svm[$k]; if ($null -eq $sv) {{ $sv=$_ | Get-NetFirewallServiceFilter }}; \
           $ia=$iam[$k]; if ($null -eq $ia) {{ $ia=$_ | Get-NetFirewallInterfaceFilter }}; \
           $it=$itm[$k]; if ($null -eq $it) {{ $it=$_ | Get-NetFirewallInterfaceTypeFilter }}; \
           $se=$sem[$k]; if ($null -eq $se) {{ $se=$_ | Get-NetFirewallSecurityFilter }}; \
           [pscustomobject]@{{ \
             id=[string]$_.Name; display=[string]$_.DisplayName; description=[string]$_.Description; group=[string]$_.DisplayGroup; \
             enabled=($_.Enabled -eq 'True'); direction=[string]$_.Direction; action=[string]$_.Action; profile=[string]$_.Profile; \
             edge_traversal=[string]$_.EdgeTraversalPolicy; policy_store_source=[string]$_.PolicyStoreSource; policy_store_source_type=[string]$_.PolicyStoreSourceType; \
             primary_status=[string]$_.PrimaryStatus; status=[string]$_.Status; owner=[string]$_.Owner; \
             protocol=[string]$pf.Protocol; local_port=([string]($pf.LocalPort -join ',')); remote_port=([string]($pf.RemotePort -join ',')); icmp_type=([string]($pf.IcmpType -join ',')); dynamic_target=[string]$pf.DynamicTarget; \
             local_address=([string]($af.LocalAddress -join ',')); remote_address=([string]($af.RemoteAddress -join ',')); \
             program=[string]$ap.Program; package=[string]$ap.Package; service=[string]$sv.Service; \
             interface_alias=([string]($ia.InterfaceAlias -join ',')); interface_type=([string]$it.InterfaceType); \
             authentication=[string]$se.Authentication; encryption=[string]$se.Encryption; override_block_rules=[string]$se.OverrideBlockRules; \
             local_user=[string]$se.LocalUser; remote_user=[string]$se.RemoteUser; remote_machine=[string]$se.RemoteMachine \
           }} \
         }}); \
         $Error.Clear(); \
         $out | ConvertTo-Json -Depth 4 -Compress"
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
  bios_release = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { $null }
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
  last_boot = if ($lastboot) { $lastboot.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
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
$vall = @(Get-Volume)
Stop-OnError 'volumes'
# `volumes` is DELIBERATELY only the lettered ones: the health alerts read it for free space, and an
# EFI or recovery partition sitting at 6% free would trip low-disk on every machine that has one.
# But dropping them silently made `volumes` read as "the volumes on this host" when it is not —
# measured here, 3 of 4 were omitted, including a 1.37 GB recovery partition with 74 MB free. The
# omitted ones are reported separately so the exclusion is visible without changing what alerts on.
# An EMPTY array means none exist; the key ABSENT means a client older than this.
$vsrc = @($vall | Where-Object { $_.DriveLetter })
$unlettered = @($vall | Where-Object { -not $_.DriveLetter } | ForEach-Object {
  [PSCustomObject]@{
    label = [string]$_.FileSystemLabel
    fs = [string]$_.FileSystem
    size_gb = [math]::Round($_.Size/1GB,1)
    free_gb = [math]::Round($_.SizeRemaining/1GB,1)
    free_pct = if ($_.Size -gt 0) { [math]::Round(($_.SizeRemaining/$_.Size)*100,1) } else { $null }
    health = [string]$_.HealthStatus
  }
})
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
[PSCustomObject]@{ disks=$disks; volumes=$volumes; volumes_without_letter=$unlettered } | ConvertTo-Json -Depth 4 -Compress
"#;
    let mut out = ps_json_guarded(&format!("{PS_GUARD}{SCRIPT}"), "disks")?;
    // All three are lists whose one-element case is ordinary — a single disk, a single volume, a
    // single unlettered partition — and that is exactly where `ConvertTo-Json` degrades an array to
    // a bare object. Belt-and-braces: the `@(…)`-into-a-variable form used above already survives it,
    // but a caller must never have to know which construction produced its field.
    for k in ["disks", "volumes", "volumes_without_letter"] {
        force_array_field(&mut out, k);
    }
    Some(out)
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
             last_logon=if($_.LastLogon){{$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}}else{{$null}}; \
             password_expires=if($_.PasswordExpires){{$_.PasswordExpires.ToString('yyyy-MM-dd')}}else{{'never'}}; \
             password_last_set=if($_.PasswordLastSet){{$_.PasswordLastSet.ToString('yyyy-MM-dd')}}else{{$null}}; \
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

/// The most SIDs one `sid-resolve` call will take. The bound is on the *work*, not the payload: each
/// unique SID can be a DC round-trip, so an unbounded list is an unbounded number of network lookups
/// behind a single collector dispatch. Over the cap the call is refused outright — resolving the first
/// 200 and returning them would hand back a short list that looks complete, which is the same
/// confident-but-incomplete answer this collector exists to stop.
#[cfg(windows)]
const SID_RESOLVE_MAX: usize = 200;

/// Whether `s` is a SID in the SDDL string form Windows hands out (`S-1-5-21-…`). Strict on purpose:
/// what passes here is interpolated into the script as a single-quoted literal, and the character set
/// this admits (`S` plus digits and hyphens) cannot carry a quote to break out with.
#[cfg(windows)]
fn is_sid_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (6..=190).contains(&lower.len())
        && lower.starts_with("s-1-")
        && !lower.ends_with('-')
        && lower[2..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Resolve Windows SIDs to account names — a direction nothing else in the collector set can go. SIDs
/// are how Windows actually labels per-user state, so they surface constantly (scheduled-task names,
/// `ProfileList`, User-Profile-Disk filenames, ACLs, event records) and each one is otherwise a dead
/// end that ends in a manual lookup outside the console.
///
/// `[SecurityIdentifier]::Translate([NTAccount])` rather than reading `objectSid` out of the directory:
/// it runs on any domain member with no directory role required — which is what matters, because the
/// SIDs are found on the session host, not on a DC — and it resolves local accounts, groups and
/// well-known SIDs as well as domain users. It is a point lookup, never an enumeration.
///
/// `params` `{sids:["S-1-…", …] | "comma/space-separated", sid:"S-1-… (single)"}`, at most
/// [`SID_RESOLVE_MAX`] distinct SIDs. Returns one row per requested SID **in request order**:
/// `{sid, account, domain, resolved, error}`, paginated.
///
/// ⚠ **The status is per item, never a verdict on the call.** A failed translate means *could not
/// resolve* — a deleted account, an unreachable DC, a RID from another domain — and those are three
/// different things, none of which is "no such user". So an unresolved row reports `resolved:false`
/// with `account`/`domain` **null** — never the literal `Unknown`, which a caller reads as a name —
/// and carries the reason in `error`. One unresolvable SID never discards the ones that did resolve.
#[cfg(windows)]
fn sid_resolve(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    const SEPS: [char; 5] = [',', ';', ' ', '\n', '\t'];
    // An array, a separator-joined string, or a single `sid`: the SIDs a caller has in hand came out of
    // a task name, a filename or a log line, so accept the forms they arrive in.
    let mut raw: Vec<String> = Vec::new();
    match p.get("sids") {
        Some(Value::Array(a)) => raw.extend(a.iter().filter_map(|v| v.as_str()).map(str::to_string)),
        Some(Value::String(s)) => raw.extend(s.split(&SEPS[..]).map(str::to_string)),
        _ => {}
    }
    if let Some(s) = p.get("sid").and_then(|x| x.as_str()) {
        raw.extend(s.split(&SEPS[..]).map(str::to_string));
    }
    // Dedupe case-insensitively (a repeat is a repeated DC round-trip) but echo the caller's spelling.
    let mut seen: Vec<String> = Vec::new();
    let mut wanted: Vec<String> = Vec::new();
    for r in raw {
        let t = r.trim().to_string();
        if t.is_empty() {
            continue;
        }
        let key = t.to_ascii_uppercase();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        wanted.push(t);
    }
    if wanted.is_empty() {
        return Some(json!({ "ok": false, "error": "sid-resolve requires sids (an array of SID strings) or sid" }));
    }
    if wanted.len() > SID_RESOLVE_MAX {
        return Some(json!({ "ok": false, "error": format!(
            "sid-resolve accepts at most {SID_RESOLVE_MAX} distinct SIDs per call (got {}); split the list",
            wanted.len()) }));
    }

    let valid: Vec<&str> = wanted.iter().map(String::as_str).filter(|s| is_sid_string(s)).collect();
    let mut rows: Vec<Value> = Vec::new();
    if !valid.is_empty() {
        rows = match sid_translate_rows(&valid, "sid-resolve") {
            GuardedRows::Failed(e) => return Some(e),
            GuardedRows::Rows(v) => v,
        };
    }
    // Rebuild in request order against what was asked for, so the answer is one row per requested SID:
    // a malformed entry is answered here rather than costing the caller the entries that were fine, and
    // a SID the script somehow did not report back says so instead of vanishing from the list.
    let items: Vec<Value> = wanted
        .iter()
        .map(|s| {
            if !is_sid_string(s) {
                return json!({ "sid": s, "account": null, "domain": null, "resolved": false,
                               "error": "not a SID string (expected the S-1-… form)" });
            }
            rows.iter()
                .find(|r| r.get("sid").and_then(|x| x.as_str()) == Some(s.as_str()))
                .cloned()
                .unwrap_or_else(|| json!({ "sid": s, "account": null, "domain": null, "resolved": false,
                                           "error": "no result returned for this SID" }))
        })
        .collect();
    Some(paginate(items, params, SID_RESOLVE_MAX))
}
#[cfg(not(windows))]
fn sid_resolve(_params: Option<&str>) -> Option<Value> {
    None
}

/// Translate SIDs → account names with `[SecurityIdentifier]::Translate([NTAccount])`, one attempt per
/// SID and its outcome on its own row: `{sid, account, domain, resolved, error}`. The mechanism behind
/// [`sid_resolve`], shared with [`user_profile_disks`] so both report an unresolvable SID identically —
/// `account`/`domain` **null** and a reason, never the literal `Unknown` (which a caller reads as a
/// name) — and so one unresolvable SID never discards the ones that did resolve.
///
/// No `Stop-OnError`: there is no bulk read here to fail. Each translate is its own attempt and its
/// outcome belongs to its own row, so a failure is recorded per item rather than ending the run. The
/// guard still stands behind the script as a whole — if PowerShell or the type itself is unavailable
/// nothing reaches stdout, and that reads as a failed collector, not as an empty answer.
/// `$Error.Clear()` per iteration keeps a caught translate failure from leaking into the next one's
/// judgement. Callers must pass only [`is_sid_string`]-validated SIDs: the value lands in a
/// single-quoted PowerShell literal, and that predicate admits no character that could leave it.
#[cfg(windows)]
fn sid_translate_rows(sids: &[&str], what: &str) -> GuardedRows {
    let list = sids.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",");
    let script = format!(
        "{PS_GUARD}\
         $sids=@({list}); $out=@(); \
         foreach($s in $sids){{ \
           $acct=$null; $dom=$null; $ok=$false; $err=$null; \
           try {{ \
             $nt=[System.Security.Principal.SecurityIdentifier]::new($s).Translate([System.Security.Principal.NTAccount]); \
             $v=[string]$nt.Value; \
             if($v){{ $ok=$true; $i=$v.IndexOf([char]92); \
               if($i -ge 0){{ $dom=$v.Substring(0,$i); $acct=$v.Substring($i+1) }} else {{ $acct=$v }} }} \
             else {{ $err='translate returned an empty account name' }} \
           }} catch {{ $err=[string]$_.Exception.Message }}; \
           if($err -and $err.Length -gt 200){{ $err=$err.Substring(0,200) }}; \
           $Error.Clear(); \
           $out+=[pscustomobject]@{{ sid=$s; account=$acct; domain=$dom; resolved=$ok; error=$err }} \
         }}; \
         ConvertTo-Json -InputObject @($out) -Depth 3 -Compress"
    );
    ps_rows_guarded(&script, what)
}

// ---------------------------------------------------------------------------------------------
// Deep-read companions to the four sweep collectors (`processes` / `schtasks` / `netconn` /
// `startup`), plus the User-Profile-Disk reader.
//
// The sweep collectors return a SUBSET of each object, and the omitted field is precisely the one an
// attacker controls: a process without its path or command line cannot show masquerading, a task
// without its action cannot show what it runs. Rather than widen those kinds — which would remove
// them from every non-admin key at runtime, with nothing to warn an existing integration — each
// risk-bearing field lands here, in an admin-only companion, exactly as `firewall` / `firewall-rule`
// already pair. Nothing moves OUT of the cheap views; a caller that only needs "is this running"
// keeps working unchanged.
//
// Three properties every companion shares, taken from what makes `firewall-rule` work:
//   1. A SELECTOR IS REQUIRED. These answer "tell me about the ones I name", never "dump every command
//      line on the box". That bounds the content exposure, bounds the result size, and keeps the
//      expensive per-item calls (`Get-AuthenticodeSignature`, `Get-ScheduledTaskInfo`) off a
//      whole-fleet sweep. A call with no selector REFUSES, with `ok:false` like every other in-band
//      refusal in this file.
//   2. THE CHEAP VIEW LOSES NOTHING.
//   3. PAGINATED through the shared `paginate`, so a wide-detail result can never silently overflow
//      the store cap.
// ---------------------------------------------------------------------------------------------

/// The per-value character cap for the deep-read companions.
///
/// Deliberately NOT [`ps_json_array`]'s 300. That helper governs the cheap metadata kinds and cuts
/// every string field at 300 characters — fine for a `TaskName`, useless for the fields these
/// companions exist to surface. A command line, a task's `Arguments` and an autostart payload are the
/// whole point of the split, the interesting part of a hostile one is rarely in the first 300 bytes,
/// and a value cut there still *looks* complete. Raising 300 is a separate measured decision (it is
/// shared with five shipped collectors), so these collectors take their own path rather than inherit
/// it.
///
/// A cut value DECLARES itself: the row gains `truncated_fields` naming every key that was shortened
/// (dotted for a nested one, e.g. `actions[0].arguments`), and each envelope states `value_char_cap`.
/// So a caller can tell a cut value from a whole one by a key, not by sniffing for an ellipsis. `wmi`
/// now carries the same pair ([`cap_wmi_row`]), and this constant is its `max_value_len` ceiling too.
#[cfg(windows)]
const DETAIL_VALUE_CAP: usize = 8000;

/// Cap one JSON value's strings in place, recording the dotted key path of each one it shortened.
#[cfg(windows)]
fn cap_detail_value(v: &mut Value, path: &str, cut: &mut Vec<Value>) {
    match v {
        Value::String(s) => {
            if s.chars().count() > DETAIL_VALUE_CAP {
                *s = s.chars().take(DETAIL_VALUE_CAP).collect();
                cut.push(json!(path));
            }
        }
        Value::Array(a) => {
            for (i, e) in a.iter_mut().enumerate() {
                cap_detail_value(e, &format!("{path}[{i}]"), cut);
            }
        }
        Value::Object(o) => {
            for (k, e) in o.iter_mut() {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                cap_detail_value(e, &p, cut);
            }
        }
        _ => {}
    }
}

/// Apply [`DETAIL_VALUE_CAP`] to every string in every row, nested values included, and stamp the rows
/// that lost something with `truncated_fields`. A row with no key is a row that was returned whole.
#[cfg(windows)]
fn cap_detail_strings(rows: &mut [Value]) {
    for r in rows.iter_mut() {
        let mut cut: Vec<Value> = Vec::new();
        cap_detail_value(r, "", &mut cut);
        if let (false, Some(obj)) = (cut.is_empty(), r.as_object_mut()) {
            obj.insert("truncated_fields".to_owned(), Value::Array(cut));
        }
    }
}

/// Constrain a caller-supplied glob to a character set that cannot leave the single-quoted PowerShell
/// literal it is interpolated into — the same allowlist `firewall`/`firewall-rule` apply, hoisted so
/// the companions share one definition rather than each carrying a copy that can drift.
#[cfg(windows)]
fn ps_glob_safe(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?' | '\\' | ':' | '/' | '(' | ')' | '[' | ']' | '{' | '}' | '@' | '+' | ','))
        .take(256)
        .collect()
}

/// Row builders shared by the companion scripts. `Add-S` / `Add-N` / `Add-D` add a key ONLY when the
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
if ($null -ne $V) { try { $d=[datetime]$V; if ($d -ge [datetime]'2000-01-01') { $H[$K]=$d.ToString('yyyy-MM-dd HH:mm:ss') } } catch { } } }; ";

/// The refusal every companion returns when it was given no narrowing selector.
#[cfg(windows)]
fn selector_required(kind: &str, selectors: &str) -> Value {
    json!({ "ok": false, "error": format!(
        "{kind} requires at least one of: {selectors}. It is a deep-read companion — it answers \
         'tell me about the ones I name', never 'dump every one on the box'") })
}

/// Process DEEP-READ (read-only) — the drill-down companion to `processes`. CONTENT-BEARING
/// (admin-gated console-side). `processes` returns `name`/`pid`/`cpu`/`mem_mb` only, so a malicious
/// binary named `svchost.exe` running from `%TEMP%` is byte-identical in that output to the real one
/// in `System32`. This returns the fields that tell them apart: `executable_path`,
/// `parent_process_id`, `command_line`, and — opt-in — the Authenticode signer and validity.
///
/// `params` REQUIRES at least one of `name` (image-name glob), `pid` (int, list or `"1,2"`) or `path`
/// (executable-path glob); several are ANDed. Plus `{signature:bool, offset, limit}`.
///
/// `Win32_Process` already carries path, PPID and command line, so those cost nothing beyond the one
/// enumeration this collector already does. The SIGNER does not: `Get-AuthenticodeSignature` is a
/// per-file read that hashes the image and can walk a revocation chain, so it is **opt-in** via
/// `signature:true` rather than always-on. Every row therefore states `signature_checked` — ⚠ a row
/// with `signature_checked:false` says the check did not RUN; it is not a statement that the binary is
/// unsigned, and reading it as one is the same absent-vs-negative conflation this collector exists to
/// undo. A check that ran reports `signature_status` (`Valid`/`NotSigned`/`HashMismatch`/…) with the
/// signer subject, issuer, thumbprint and validity window.
///
/// **The parent is reported honestly or not at all.** A PPID is reused freely once its process exits,
/// so a row whose parent is gone says so (`parent_note`) rather than naming whatever holds that PID
/// now, and a parent that started *after* its child is flagged `parent_pid_reused` with the name
/// withheld.
#[cfg(windows)]
fn process_detail(params: Option<&str>) -> Option<Value> {
    const MATCH_CAP: usize = 200;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let name = p.get("name").and_then(|x| x.as_str()).map(ps_glob_safe).filter(|s| !s.is_empty());
    let path = p.get("path").and_then(|x| x.as_str()).map(ps_glob_safe).filter(|s| !s.is_empty());
    let pids = int_list(p.get("pid"));
    if name.is_none() && path.is_none() && pids.is_empty() {
        return Some(selector_required("process-detail", "name (image-name glob), pid (int or list), path (executable-path glob)"));
    }
    let want_sig = p.get("signature").and_then(|x| x.as_bool()).unwrap_or(false);
    let mut clauses: Vec<String> = Vec::new();
    if !pids.is_empty() {
        clauses.push(format!("@({}) -contains [int]$_.ProcessId", pids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")));
    }
    if let Some(ref n) = name {
        clauses.push(format!("[string]$_.Name -like '{n}'"));
    }
    if let Some(ref pt) = path {
        clauses.push(format!("[string]$_.ExecutablePath -like '{pt}'"));
    }
    let where_clause = format!(" | Where-Object {{ {} }}", clauses.join(" -and "));
    let script = format!(
        "{PS_GUARD}{PS_ADD_FNS}\
         $want_sig=${want_sig}; \
         $all=@(Get-CimInstance Win32_Process); Stop-OnError 'process-detail'; \
         $sel=@($all{where_clause} | Select-Object -First {MATCH_CAP}); "
    ) + PROCESS_DETAIL_BODY;
    let mut items = match ps_rows_guarded(&script, "process-detail") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    cap_detail_strings(&mut items);
    Some(json!({
        "signature_requested": want_sig,
        "match_cap_hit": items.len() >= MATCH_CAP,
        "value_char_cap": DETAIL_VALUE_CAP,
        "processes": paginate(items, params, 25),
    }))
}
#[cfg(not(windows))]
fn process_detail(_params: Option<&str>) -> Option<Value> {
    None
}

/// The per-process row builder for [`process_detail`]. Held apart from the `format!` header so the
/// PowerShell braces need no doubling — the escaping is where these scripts break.
#[cfg(windows)]
const PROCESS_DETAIL_BODY: &str = "\
$pmap=@{}; foreach ($x in $all) { $pmap[[string]$x.ProcessId]=$x }; \
$out=@(); \
foreach ($x in $sel) { \
  $h=[ordered]@{}; \
  Add-N $h 'pid' $x.ProcessId; \
  Add-S $h 'name' $x.Name; \
  Add-S $h 'executable_path' $x.ExecutablePath; \
  Add-N $h 'parent_process_id' $x.ParentProcessId; \
  Add-S $h 'command_line' $x.CommandLine; \
  Add-N $h 'session_id' $x.SessionId; \
  Add-D $h 'created' $x.CreationDate; \
  $pp=$pmap[[string]$x.ParentProcessId]; \
  if ($null -eq $pp) { \
    Add-S $h 'parent_note' 'the parent process is no longer running, so its identity cannot be read here; a PPID is reused freely once its process exits' } \
  elseif ($null -ne $pp.CreationDate -and $null -ne $x.CreationDate -and $pp.CreationDate -gt $x.CreationDate) { \
    $h['parent_pid_reused']=$true; \
    Add-S $h 'parent_note' 'the process now holding this PPID started AFTER this one, so the PPID has been reused and does not identify the real parent' } \
  else { Add-S $h 'parent_name' $pp.Name; Add-S $h 'parent_executable_path' $pp.ExecutablePath }; \
  $h['signature_checked']=$false; \
  if ($want_sig) { \
    $ep=[string]$x.ExecutablePath; \
    if ($ep.Trim() -eq '') { \
      Add-S $h 'signature_error' 'no executable path is readable for this process (a protected or system process), so there was nothing to verify' } \
    else { \
      try { \
        $sg=Get-AuthenticodeSignature -LiteralPath $ep -ErrorAction Stop; \
        $h['signature_checked']=$true; \
        Add-S $h 'signature_status' $sg.Status; \
        Add-S $h 'signature_status_message' $sg.StatusMessage; \
        if ($null -ne $sg.SignerCertificate) { \
          Add-S $h 'signer' $sg.SignerCertificate.Subject; \
          Add-S $h 'signer_issuer' $sg.SignerCertificate.Issuer; \
          Add-S $h 'signer_thumbprint' $sg.SignerCertificate.Thumbprint; \
          Add-D $h 'signer_not_before' $sg.SignerCertificate.NotBefore; \
          Add-D $h 'signer_not_after' $sg.SignerCertificate.NotAfter } } \
      catch { Add-S $h 'signature_error' $_.Exception.Message } } }; \
  $Error.Clear(); \
  $out+=[pscustomobject]$h }; \
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress";

/// Scheduled-task DEEP-READ (read-only) — the drill-down companion to `schtasks`. CONTENT-BEARING
/// (admin-gated console-side). `schtasks` returns `TaskName`/`TaskPath`/`State` only, so enumerating
/// 237 tasks establishes that none of them is safe — a benign name is free, and scheduled tasks are a
/// top-tier persistence mechanism. This returns what a task actually DOES: every action's `Execute` +
/// `Arguments` (+ working directory, and the COM handler's class id/data), `Principal.UserId` +
/// `RunLevel` + `LogonType`, `Author`, and the triggers.
///
/// `params` REQUIRES at least one of `name` (TaskName glob) or `path` (TaskPath glob); both are ANDed.
/// Plus `{offset, limit}`.
///
/// **`Get-ScheduledTask` returns the actions directly**, which retires the per-task `reg-read` under
/// the `TaskCache` hive that reading a task's action used to mean. That worked and is how it was done
/// by hand, but it is one PowerShell launch and one registry parse PER TASK; this is one enumeration
/// for the whole matched set. `Get-ScheduledTaskInfo` adds last/next run and the last result, and is
/// the only per-item call here — bounded by the required selector, and guarded per task so a task
/// whose run info cannot be read reports `run_info_error` and keeps everything else.
#[cfg(windows)]
fn schtask_detail(params: Option<&str>) -> Option<Value> {
    const MATCH_CAP: usize = 200;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let name = p.get("name").and_then(|x| x.as_str()).map(ps_glob_safe).filter(|s| !s.is_empty());
    let path = p.get("path").and_then(|x| x.as_str()).map(ps_glob_safe).filter(|s| !s.is_empty());
    if name.is_none() && path.is_none() {
        return Some(selector_required("schtask-detail", "name (TaskName glob), path (TaskPath glob)"));
    }
    let mut clauses: Vec<String> = Vec::new();
    if let Some(ref n) = name {
        clauses.push(format!("[string]$_.TaskName -like '{n}'"));
    }
    if let Some(ref pt) = path {
        clauses.push(format!("[string]$_.TaskPath -like '{pt}'"));
    }
    let where_clause = format!(" | Where-Object {{ {} }}", clauses.join(" -and "));
    let script = format!(
        "{PS_GUARD}{PS_ADD_FNS}\
         $src=@(Get-ScheduledTask{where_clause} | Select-Object -First {MATCH_CAP}); Stop-OnError 'schtask-detail'; "
    ) + SCHTASK_DETAIL_BODY;
    let mut items = match ps_rows_guarded(&script, "schtask-detail") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    cap_detail_strings(&mut items);
    Some(json!({
        "match_cap_hit": items.len() >= MATCH_CAP,
        "value_char_cap": DETAIL_VALUE_CAP,
        "tasks": paginate(items, params, 20),
    }))
}
#[cfg(not(windows))]
fn schtask_detail(_params: Option<&str>) -> Option<Value> {
    None
}

/// The per-task row builder for [`schtask_detail`]. A CIM object returns `$null` for a property its
/// class does not define, so the trigger projection can name every field any trigger type carries and
/// let `Add-S`/`Add-N` drop the ones that do not apply to this one.
#[cfg(windows)]
const SCHTASK_DETAIL_BODY: &str = "\
$out=@(); \
foreach ($t in $src) { \
  $h=[ordered]@{}; \
  Add-S $h 'task_name' $t.TaskName; \
  Add-S $h 'task_path' $t.TaskPath; \
  Add-S $h 'state' $t.State; \
  Add-S $h 'author' $t.Author; \
  Add-S $h 'description' $t.Description; \
  Add-S $h 'source' $t.Source; \
  Add-S $h 'uri' $t.URI; \
  if ($null -ne $t.Principal) { \
    Add-S $h 'principal_user_id' $t.Principal.UserId; \
    Add-S $h 'principal_group_id' $t.Principal.GroupId; \
    Add-S $h 'principal_run_level' $t.Principal.RunLevel; \
    Add-S $h 'principal_logon_type' $t.Principal.LogonType }; \
  if ($null -ne $t.Settings) { \
    Add-S $h 'settings_enabled' $t.Settings.Enabled; \
    Add-S $h 'settings_hidden' $t.Settings.Hidden; \
    Add-S $h 'settings_execution_time_limit' $t.Settings.ExecutionTimeLimit }; \
  $acts=@(); \
  foreach ($a in @($t.Actions)) { \
    $ah=[ordered]@{}; \
    Add-S $ah 'type' $a.CimClass.CimClassName; \
    Add-S $ah 'execute' $a.Execute; \
    Add-S $ah 'arguments' $a.Arguments; \
    Add-S $ah 'working_directory' $a.WorkingDirectory; \
    Add-S $ah 'class_id' $a.ClassId; \
    Add-S $ah 'data' $a.Data; \
    $acts+=[pscustomobject]$ah }; \
  $h['actions']=@($acts); \
  $trg=@(); \
  foreach ($g in @($t.Triggers)) { \
    $gh=[ordered]@{}; \
    Add-S $gh 'type' $g.CimClass.CimClassName; \
    Add-S $gh 'enabled' $g.Enabled; \
    Add-S $gh 'start_boundary' $g.StartBoundary; \
    Add-S $gh 'end_boundary' $g.EndBoundary; \
    Add-S $gh 'delay' $g.Delay; \
    Add-S $gh 'random_delay' $g.RandomDelay; \
    Add-S $gh 'user_id' $g.UserId; \
    Add-S $gh 'state_change' $g.StateChange; \
    Add-N $gh 'days_interval' $g.DaysInterval; \
    Add-N $gh 'weeks_interval' $g.WeeksInterval; \
    if ($null -ne $g.Repetition) { \
      Add-S $gh 'repetition_interval' $g.Repetition.Interval; \
      Add-S $gh 'repetition_duration' $g.Repetition.Duration }; \
    $trg+=[pscustomobject]$gh }; \
  $h['triggers']=@($trg); \
  try { \
    $i=$t | Get-ScheduledTaskInfo -ErrorAction Stop; \
    Add-D $h 'last_run_time' $i.LastRunTime; \
    Add-D $h 'next_run_time' $i.NextRunTime; \
    Add-N $h 'last_task_result' $i.LastTaskResult; \
    Add-N $h 'number_of_missed_runs' $i.NumberOfMissedRuns } \
  catch { Add-S $h 'run_info_error' $_.Exception.Message }; \
  $Error.Clear(); \
  $out+=[pscustomobject]$h }; \
ConvertTo-Json -InputObject @($out) -Depth 6 -Compress";

/// TCP-connection owner DEEP-READ (read-only) — the drill-down companion to `netconn`.
/// CONTENT-BEARING (admin-gated console-side). `netconn` returns a PID with no process identity, so
/// attributing a connection meant a second `processes` call taken at a DIFFERENT instant — and a PID
/// recycled in between silently mis-attributes to whatever holds it by then. This resolves the owner
/// **in the same enumeration**: image name, `process_path`, command line, start time.
///
/// `params` REQUIRES at least one of `pid` (int or list), `port` (int or list — matches LOCAL **or**
/// REMOTE) or `address` (glob — matches local or remote address). `state` (`listen`, `established`, …,
/// or the raw MIB code) narrows further but is not on its own a selector: "every established
/// connection" is not a bounded question. Plus `{offset, limit}`.
///
/// **A PID that has already exited comes back explicitly unresolved** — `process_error` on that row —
/// never dropped and never guessed at. And because both halves are read in one pass, a process whose
/// start time is LATER than the connection's is flagged `pid_reused` with the identity withheld: that
/// is the recycled-PID mis-attribution, caught rather than reported as fact.
#[cfg(windows)]
fn netconn_owner(params: Option<&str>) -> Option<Value> {
    const MATCH_CAP: usize = 300;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let pids = int_list(p.get("pid"));
    let ports = int_list(p.get("port"));
    let address = p.get("address").and_then(|x| x.as_str()).map(ps_glob_safe).filter(|s| !s.is_empty());
    if pids.is_empty() && ports.is_empty() && address.is_none() {
        return Some(selector_required("netconn-owner", "pid (int or list), port (int or list, local OR remote), address (glob, local OR remote)"));
    }
    let state = p
        .get("state")
        .and_then(|x| x.as_str().map(str::to_string).or_else(|| x.as_i64().map(|n| n.to_string())))
        .map(|s| ps_glob_safe(&s))
        .filter(|s| !s.is_empty());
    let mut clauses: Vec<String> = Vec::new();
    if !pids.is_empty() {
        clauses.push(format!("@({}) -contains [int]$_.OwningProcess", pids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")));
    }
    if !ports.is_empty() {
        let list = ports.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
        clauses.push(format!("(@({list}) -contains [int]$_.LocalPort -or @({list}) -contains [int]$_.RemotePort)"));
    }
    if let Some(ref a) = address {
        clauses.push(format!("([string]$_.LocalAddress -like '{a}' -or [string]$_.RemoteAddress -like '{a}')"));
    }
    let where_clause = format!(" | Where-Object {{ {} }}", clauses.join(" -and "));
    // The state filter runs against the DECODED name as well as the raw code, so `state:"bound"` and
    // `state:100` select the same rows — `netconn` already teaches callers the names. It is a
    // predicate scriptblock rather than an inlined statement so that the `continue` that acts on it
    // stays in the loop body, where it means what it reads as.
    let state_test = match &state {
        Some(s) => format!("([string]$c.State -like '{s}' -or [string]$sn -like '{s}' -or [string]([int]$c.State) -eq '{s}')"),
        None => "$true".to_owned(),
    };
    let script = format!(
        "{PS_GUARD}{PS_ADD_FNS}\
         $tcp=@(Get-NetTCPConnection -ErrorAction SilentlyContinue | \
           Select-Object @{{n='protocol';e={{'tcp'}}}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime); \
         $udp=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | \
           Select-Object @{{n='protocol';e={{'udp'}}}},LocalAddress,LocalPort,\
             @{{n='RemoteAddress';e={{$null}}}},@{{n='RemotePort';e={{$null}}}},@{{n='State';e={{$null}}}},OwningProcess,CreationTime); \
         $conns=@($tcp + $udp); Stop-OnError 'netconn-owner connections'; \
         $procs=@(Get-CimInstance Win32_Process); Stop-OnError 'netconn-owner processes'; \
         $sel=@($conns{where_clause}); \
         $cap={MATCH_CAP}; $gate={{ param($c,$sn) {state_test} }}; "
    ) + NETCONN_OWNER_BODY;
    let mut items = match ps_rows_guarded(&script, "netconn-owner") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    cap_detail_strings(&mut items);
    Some(json!({
        "match_cap_hit": items.len() >= MATCH_CAP,
        "value_char_cap": DETAIL_VALUE_CAP,
        "connections": paginate(items, params, 50),
    }))
}
#[cfg(not(windows))]
fn netconn_owner(_params: Option<&str>) -> Option<Value> {
    None
}

/// The per-connection row builder for [`netconn_owner`]. The state map is `netconn`'s, so one raw
/// `State` code decodes to the same name in both collectors and an unknown code renders
/// `unknown(<raw>)` rather than being guessed at.
///
/// A UDP row sets `remote_address`, `remote_port` and `state` to an EXPLICIT null rather than
/// letting the `Add-*` helpers drop them, so it reads identically to the same socket in the
/// `netconn` sweep. The three are written directly because those helpers skip a null — which is
/// also how this diverged: `$c.State -as [int]` turns a UDP row's `$null` into **0**, and 0 is not
/// null, so it was stored. A consumer joining on `state` read that 0 as data, even though it is not
/// one of the codes the map defines.
#[cfg(windows)]
const NETCONN_OWNER_BODY: &str = "\
$st=@{'1'='closed';'2'='listen';'3'='syn-sent';'4'='syn-received';'5'='established';\
'6'='fin-wait-1';'7'='fin-wait-2';'8'='close-wait';'9'='closing';'10'='last-ack';\
'11'='time-wait';'12'='delete-tcb';'100'='bound'}; \
$pmap=@{}; foreach ($x in $procs) { $pmap[[string]$x.ProcessId]=$x }; \
$out=@(); \
foreach ($c in $sel) { \
  if ($out.Count -ge $cap) { break }; \
  $n=$c.State -as [int]; \
  if ($c.protocol -eq 'udp') { $sn='n/a (udp is connectionless)' } \
  elseif ($null -ne $n -and $st.ContainsKey([string]$n)) { $sn=$st[[string]$n] } else { $sn='unknown(' + [string]$c.State + ')' }; \
  if (-not (& $gate $c $sn)) { continue }; \
  $h=[ordered]@{}; \
  Add-S $h 'protocol' $c.protocol; \
  Add-S $h 'local_address' $c.LocalAddress; \
  Add-N $h 'local_port' $c.LocalPort; \
  if ($c.protocol -eq 'udp') { $h['remote_address']=$null; $h['remote_port']=$null; $h['state']=$null } \
  else { Add-S $h 'remote_address' $c.RemoteAddress; Add-N $h 'remote_port' $c.RemotePort; Add-N $h 'state' $n }; \
  Add-S $h 'state_name' $sn; \
  Add-D $h 'creation_time' $c.CreationTime; \
  Add-N $h 'owning_process' $c.OwningProcess; \
  $x=$pmap[[string]$c.OwningProcess]; \
  if ($null -eq $x) { \
    Add-S $h 'process_error' 'the owning process is no longer running, so it could not be identified; a PID is reused freely once its process exits' } \
  elseif ($null -ne $x.CreationDate -and $null -ne $c.CreationTime -and $x.CreationDate -gt $c.CreationTime) { \
    $h['pid_reused']=$true; \
    Add-S $h 'process_error' 'the process now holding this PID started AFTER the connection did, so the PID has been reused and does not identify the owner' } \
  else { \
    Add-S $h 'process_name' $x.Name; \
    Add-S $h 'process_path' $x.ExecutablePath; \
    Add-S $h 'process_command_line' $x.CommandLine; \
    Add-N $h 'process_parent_process_id' $x.ParentProcessId; \
    Add-D $h 'process_created' $x.CreationDate }; \
  $out+=[pscustomobject]$h }; \
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress";

/// The autostart surfaces [`startup_detail`] can read, in the spelling the API uses. `run-keys` and
/// `startup-folders` are the two `startup` already covers (split apart here, since they are different
/// questions); the other five are the ones nothing surfaced.
#[cfg(windows)]
const STARTUP_SURFACES: &[&str] = &["run-keys", "startup-folders", "wmi-subscriptions", "ifeo", "appinit", "winlogon", "print-monitors"];

/// Autostart DEEP-READ (read-only) — the drill-down companion to `startup`. CONTENT-BEARING
/// (admin-gated console-side). `startup` covers the Run keys and the Startup folders and nothing else,
/// so a short list there is not the autostart surface: it does not see WMI event subscriptions (a
/// documented ransomware persistence spot), IFEO debuggers, `AppInit_DLLs`, Winlogon
/// `Shell`/`Userinit`, or print monitors. This reads all seven, and returns the **payload** — the
/// command or DLL each entry actually runs.
///
/// `params` REQUIRES `surface`: one or more of `run-keys`, `startup-folders`, `wmi-subscriptions`,
/// `ifeo`, `appinit`, `winlogon`, `print-monitors` (a string, `"a,b"`, or an array). `name` narrows
/// further by an entry-name glob, applied in-process against the entry name. Plus `{offset, limit}`.
/// The surface list is what bounds the work: each one is its own registry or WMI walk.
///
/// **Every row carries its `surface`**, so a finding names *where* the thing persists rather than just
/// that it exists. **A surface that could not be enumerated reports an error for that surface** in
/// `errors` rather than contributing zero rows and letting the total read as "nothing there" — a
/// missing hive and an empty one are different answers, and this is the collector where confusing them
/// is most expensive.
#[cfg(windows)]
fn startup_detail(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    // Surfaces are mapped onto a fixed allowlist rather than sanitized, so nothing a caller typed ever
    // reaches the script; a few plausible singular/short spellings are accepted for the same surface.
    let raw: Vec<String> = match p.get("surface") {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(str::to_string).collect(),
        Some(Value::String(s)) => s.split(&[',', ';', ' '][..]).map(str::to_string).collect(),
        _ => Vec::new(),
    };
    let mut surfaces: Vec<&'static str> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for r in raw {
        let k = r.trim().to_ascii_lowercase().replace('_', "-");
        if k.is_empty() {
            continue;
        }
        let hit = match k.as_str() {
            "run" | "run-key" | "run-keys" => Some("run-keys"),
            "startup-folder" | "startup-folders" | "folders" => Some("startup-folders"),
            "wmi" | "wmi-subscription" | "wmi-subscriptions" => Some("wmi-subscriptions"),
            "ifeo" | "image-file-execution-options" => Some("ifeo"),
            "appinit" | "appinit-dlls" => Some("appinit"),
            "winlogon" => Some("winlogon"),
            "print-monitor" | "print-monitors" => Some("print-monitors"),
            _ => None,
        };
        match hit {
            Some(s) => {
                if !surfaces.contains(&s) {
                    surfaces.push(s);
                }
            }
            // `all` is spelled out rather than refused: it is unambiguous, and the alternative is a
            // caller looping the seven names by hand and getting one of them wrong.
            None if k == "all" => surfaces = STARTUP_SURFACES.to_vec(),
            None => unknown.push(k),
        }
    }
    if !unknown.is_empty() {
        return Some(json!({ "ok": false, "error": format!(
            "startup-detail does not know the surface(s) {:?}; valid surfaces are {} (or 'all')",
            unknown, STARTUP_SURFACES.join(", ")) }));
    }
    if surfaces.is_empty() {
        return Some(selector_required(
            "startup-detail",
            &format!("surface — one or more of {} (or 'all')", STARTUP_SURFACES.join(", ")),
        ));
    }
    let list = surfaces.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",");
    let script = format!("{PS_GUARD}{PS_ADD_FNS}$surfaces=@({list}); ") + STARTUP_DETAIL_BODY;
    let raw = ps_json_guarded(&script, "startup-detail")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let mut items: Vec<Value> = raw.get("items").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    // The name glob is applied HERE rather than in the script: it narrows an already-collected list, so
    // pushing it into PowerShell would buy nothing and would put caller text in a script literal.
    if let Some(g) = p.get("name").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty()) {
        items.retain(|e| e.get("name").and_then(|n| n.as_str()).is_some_and(|n| glob_match(g.trim(), n)));
    }
    cap_detail_strings(&mut items);
    let errors = raw.get("errors").cloned().unwrap_or_else(|| json!([]));
    Some(json!({
        "surfaces": surfaces,
        // A surface that failed is named here. Non-empty means the entry list is short by an unknown
        // amount, which nothing else in this envelope can say.
        "errors": errors,
        "value_char_cap": DETAIL_VALUE_CAP,
        "entries": paginate(items, params, 100),
    }))
}
#[cfg(not(windows))]
fn startup_detail(_params: Option<&str>) -> Option<Value> {
    None
}

/// The seven autostart walks behind [`startup_detail`]. Each is wrapped in its own `try`/`catch` and
/// records `{surface, error}` on failure, so one unreadable hive costs that surface and not the run.
/// The top level is an OBJECT, so `ConvertTo-Json` always emits something — an empty `items` is `[]`,
/// never nothing, which the dispatcher's no-output arm would report as a failed collector.
///
/// ⚠ A `__FilterToConsumerBinding`'s `Filter` and `Consumer` properties come back as **key-only**
/// `CimInstance` references — they carry the `Name` and nothing else. Reading the payload off one
/// yields null for `CommandLineTemplate` / `ScriptText` / the filter's `Query`, which is silently the
/// whole point of the surface. So each ref is resolved BY NAME against the full `__EventConsumer` /
/// `__EventFilter` enumeration, and the key-only ref is kept only as a fallback for a consumer that
/// enumeration did not return.
#[cfg(windows)]
const STARTUP_DETAIL_BODY: &str = "\
$items=@(); $errs=@(); \
function New-Entry { param($Surface,$Name,$Command,$Location,$User,$Note,$Extra) \
  $h=[ordered]@{}; $h['surface']=[string]$Surface; \
  Add-S $h 'name' $Name; Add-S $h 'command' $Command; Add-S $h 'location' $Location; Add-S $h 'user' $User; \
  if ($null -ne $Extra) { foreach ($k in @($Extra.Keys)) { Add-S $h ([string]$k) $Extra[$k] } }; \
  Add-S $h 'note' $Note; \
  [pscustomobject]$h }; \
function Get-CimProp { param($Obj,[string]$Name) \
  if ($null -eq $Obj) { return $null }; \
  $pp=@($Obj.CimInstanceProperties | Where-Object { $_.Name -eq $Name }); \
  if ($pp.Count -eq 0) { return $null }; \
  return $pp[0].Value }; \
if (($surfaces -contains 'run-keys') -or ($surfaces -contains 'startup-folders')) { \
  try { \
    foreach ($s in @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)) { \
      $loc=[string]$s.Location; \
      if ($loc -match '^HK') { $sf='run-keys' } else { $sf='startup-folders' }; \
      if ($surfaces -contains $sf) { $items+=New-Entry $sf $s.Name $s.Command $loc $s.User $null $null } } } \
  catch { $errs+=[pscustomobject]@{ surface='run-keys/startup-folders'; error=[string]$_.Exception.Message } }; \
  $Error.Clear() }; \
if ($surfaces -contains 'ifeo') { \
  try { \
    foreach ($root in @('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options')) { \
      if (Test-Path -LiteralPath $root) { \
        foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) { \
          $dbg=[string]$k.GetValue('Debugger'); $vd=[string]$k.GetValue('VerifierDlls'); $gf=[string]$k.GetValue('GlobalFlag'); \
          if (($dbg.Trim() -ne '') -or ($vd.Trim() -ne '')) { \
            $x=[ordered]@{}; if ($vd.Trim() -ne '') { $x['verifier_dlls']=$vd }; if ($gf.Trim() -ne '') { $x['global_flag']=$gf }; \
            $items+=New-Entry 'ifeo' $k.PSChildName $dbg $k.Name $null 'an IFEO Debugger runs INSTEAD OF the named image every time it starts; VerifierDlls load into it' $x } } } }; \
    foreach ($sroot in @('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit')) { \
      if (Test-Path -LiteralPath $sroot) { \
        foreach ($k in @(Get-ChildItem -LiteralPath $sroot -ErrorAction SilentlyContinue)) { \
          $mp=[string]$k.GetValue('MonitorProcess'); \
          if ($mp.Trim() -ne '') { \
            $items+=New-Entry 'ifeo' $k.PSChildName $mp $k.Name $null 'a SilentProcessExit MonitorProcess runs when the named image exits - the IFEO variant that needs no Debugger value' $null } } } } } \
  catch { $errs+=[pscustomobject]@{ surface='ifeo'; error=[string]$_.Exception.Message } }; \
  $Error.Clear() }; \
if ($surfaces -contains 'appinit') { \
  try { \
    foreach ($root in @('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows')) { \
      if (Test-Path -LiteralPath $root) { \
        $k=Get-Item -LiteralPath $root -ErrorAction SilentlyContinue; \
        if ($null -ne $k) { \
          $x=[ordered]@{}; \
          $x['load_app_init_dlls']=[string]$k.GetValue('LoadAppInit_DLLs'); \
          $x['require_signed_app_init_dlls']=[string]$k.GetValue('RequireSignedAppInit_DLLs'); \
          $items+=New-Entry 'appinit' 'AppInit_DLLs' ([string]$k.GetValue('AppInit_DLLs')) $k.Name $null 'every DLL listed here loads into every process that links user32.dll, but only while load_app_init_dlls is 1; an absent command key means the value is empty' $x } } } } \
  catch { $errs+=[pscustomobject]@{ surface='appinit'; error=[string]$_.Exception.Message } }; \
  $Error.Clear() }; \
if ($surfaces -contains 'winlogon') { \
  try { \
    foreach ($root in @('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')) { \
      if (Test-Path -LiteralPath $root) { \
        $k=Get-Item -LiteralPath $root -ErrorAction SilentlyContinue; \
        if ($null -ne $k) { \
          foreach ($n in @('Shell','Userinit','Taskman','AppSetup','GinaDLL','VmApplet','System','UIHost')) { \
            $v=[string]$k.GetValue($n); \
            if ($v.Trim() -ne '') { \
              $items+=New-Entry 'winlogon' $n $v $k.Name $null 'Winlogon runs this at every interactive logon, as the logging-on user for Shell/Userinit and as SYSTEM for System' $null } } } } } } \
  catch { $errs+=[pscustomobject]@{ surface='winlogon'; error=[string]$_.Exception.Message } }; \
  $Error.Clear() }; \
if ($surfaces -contains 'print-monitors') { \
  try { \
    $pm='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors'; \
    if (Test-Path -LiteralPath $pm) { \
      foreach ($k in @(Get-ChildItem -LiteralPath $pm -ErrorAction SilentlyContinue)) { \
        $d=[string]$k.GetValue('Driver'); \
        if ($d.Trim() -ne '') { \
          $items+=New-Entry 'print-monitors' $k.PSChildName $d $k.Name $null 'a print monitor DLL is loaded by the spooler service, which runs as SYSTEM and starts at boot' $null } } } } \
  catch { $errs+=[pscustomobject]@{ surface='print-monitors'; error=[string]$_.Exception.Message } }; \
  $Error.Clear() }; \
if ($surfaces -contains 'wmi-subscriptions') { \
  try { \
    $bind=@(Get-CimInstance -Namespace 'root\\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop); \
    $cons=@(Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue); \
    $filt=@(Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue); \
    $payload_props=@('CommandLineTemplate','ExecutablePath','ScriptText','ScriptFileName','FileName','Text'); \
    $bound=@(); \
    foreach ($b in $bind) { \
      $fo=$b.Filter; $fn=$null; \
      if ($fo -is [string]) { if ($fo -match 'Name=\"([^\"]*)\"') { $fn=$matches[1] } } else { $fn=[string](Get-CimProp $fo 'Name') }; \
      $f=$null; if ($fn) { $f=@($filt | Where-Object { [string]$_.Name -eq $fn })[0] }; \
      if ($null -eq $f) { $f=$fo }; \
      $co=$b.Consumer; $cn=$null; \
      if ($co -is [string]) { if ($co -match 'Name=\"([^\"]*)\"') { $cn=$matches[1] } } else { $cn=[string](Get-CimProp $co 'Name') }; \
      $c=$null; if ($cn) { $c=@($cons | Where-Object { [string]$_.Name -eq $cn })[0] }; \
      if ($null -eq $c) { $c=$co }; \
      $name=[string](Get-CimProp $c 'Name'); \
      if ($name -ne '') { $bound+=$name }; \
      $pay=$null; \
      foreach ($pn in $payload_props) { if ($null -eq $pay) { $pv=[string](Get-CimProp $c $pn); if ($pv.Trim() -ne '') { $pay=$pv } } }; \
      $x=[ordered]@{}; \
      if ($null -ne $c) { $x['consumer_type']=[string]$c.CimClass.CimClassName }; \
      if ($null -ne $f) { $x['filter_name']=[string](Get-CimProp $f 'Name'); $x['filter_query']=[string](Get-CimProp $f 'Query'); $x['filter_namespace']=[string](Get-CimProp $f 'EventNamespace') }; \
      $items+=New-Entry 'wmi-subscriptions' $name $pay 'root\\subscription' $null 'a permanent WMI event subscription runs its consumer as SYSTEM whenever the filter query matches' $x }; \
    foreach ($c in $cons) { \
      $name=[string](Get-CimProp $c 'Name'); \
      if (($name -ne '') -and ($bound -notcontains $name)) { \
        $pay=$null; \
        foreach ($pn in $payload_props) { if ($null -eq $pay) { $pv=[string](Get-CimProp $c $pn); if ($pv.Trim() -ne '') { $pay=$pv } } }; \
        $x=[ordered]@{}; $x['consumer_type']=[string]$c.CimClass.CimClassName; \
        $items+=New-Entry 'wmi-subscriptions' $name $pay 'root\\subscription' $null 'this consumer has no __FilterToConsumerBinding, so it is registered but currently inert' $x } } } \
  catch { $errs+=[pscustomobject]@{ surface='wmi-subscriptions'; error=[string]$_.Exception.Message } }; \
  $Error.Clear() }; \
ConvertTo-Json -InputObject ([pscustomobject]@{ items=@($items); errors=@($errs) }) -Depth 5 -Compress";

/// A User-Profile-Disk filename → `(sid, rid)`, or `None` when it is not one. Matches
/// `UVHD-S-1-5-21-<3 sub-authorities>-<rid>.vhdx`: the RID is the tail of the SID, so a disk whose SID
/// will not translate still yields an identifier, which is the difference between "an unknown user"
/// and "a row we could not build". `UVHD-template.vhdx` and anything else in the directory falls out
/// here and is counted separately rather than silently ignored.
#[cfg(windows)]
fn parse_uvhd_name(file: &str) -> Option<(String, u64)> {
    let lower = file.to_ascii_lowercase();
    if !lower.starts_with("uvhd-") || !lower.ends_with(".vhdx") || file.len() <= 10 {
        return None;
    }
    let sid = &file[5..file.len() - 5];
    if !is_sid_string(sid) {
        return None;
    }
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() != 8 || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
        return None;
    }
    if parts[4..8].iter().any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    Some((sid.to_owned(), parts[7].parse::<u64>().ok()?))
}

/// Whether a VHDX is currently mounted, by asking for it with NO sharing: a mounted disk is held open
/// by the virtual-disk driver, so the open fails with a sharing/lock violation. Read-only and
/// momentary — it opens for READ and closes immediately, and never writes.
///
/// This is the fact the whole collector turns on. `LastWriteTime` on an idle VHDX is the last time that
/// profile was USED, which is the only way to find abandoned profiles consuming space; on a MOUNTED one
/// it tracks the mount instead, so quoting it as user activity would be worse than omitting it.
#[cfg(windows)]
fn vhdx_mounted(path: &std::path::Path) -> Result<bool, String> {
    use std::os::windows::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new().read(true).share_mode(0).open(path) {
        Ok(_) => Ok(false),
        // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION — something else holds the file open.
        Err(e) if matches!(e.raw_os_error(), Some(32) | Some(33)) => Ok(true),
        Err(e) => Err(format!("{e}")),
    }
}

/// User Profile Disks (read-only). CONTENT-ADJACENT: maps `UVHD-<SID>.vhdx` files to the accounts that
/// own them, with each disk's size, creation time and **last use**. Role-gated on `fileserver`
/// console-side, not `rdsh`: the disks observably live on a file server rather than the session host
/// that mounts them, which is also why `path` is a REQUIRED parameter and there is no local default.
///
/// `params` `{path (required — the profile-disk directory), sid (one or more, to narrow),
/// unused_days:N (only disks not used in N days), offset, limit}`. Returns
/// `{path, disk_count, total_size, mounted_count, unmatched_vhdx, cleanup_bin, disks:{…page…}}` with
/// each disk `{file, sid, rid, account, domain, size, created, last_used, mounted}`.
///
/// **Reading the UPD set directly recovers the whole population even while unmounted**, which
/// `fs` cannot: on a session host each `C:\Users\<name>` is a reparse point whose contents exist only
/// while its VHDX is mounted, so a directory listing answers for whoever happens to be logged on.
///
/// ⚠ **A mounted disk is locked and its timestamps track the MOUNT, not the user's activity.** Such a
/// row reports `mounted:true` with `last_used:null` — present and explicitly unknown, not a plausible
/// wrong date. `null` here is deliberate rather than an omission: the field was asked for, the answer
/// exists, and it is "not knowable while mounted".
///
/// ⚠ **`account` is null when the SID would not translate** — a deleted account, an unreachable DC, a
/// RID from another domain are three different things and none of them is "no such user" — with the
/// reason in `account_error`. Never the literal `Unknown`, which a caller reads as a name. One
/// unresolvable SID never costs the rows that resolved, and `file`/`sid`/`rid` are parsed from the
/// filename so an unresolvable row is still a complete row.
///
/// `UvhdCleanupBin` is counted SEPARATELY, never mixed into the disk list: it is where orphaned and
/// pending-delete profiles land, and a growing one is its own finding.
#[cfg(windows)]
fn user_profile_disks(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let dir = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if dir.is_empty() {
        return Some(json!({ "ok": false, "error":
            "user-profile-disks requires path — the directory holding the UVHD-*.vhdx files. There is no \
             default: the profile-disk share commonly lives on a FILE SERVER rather than on the session \
             host that mounts the disks, so the path has to be named" }));
    }
    match std::fs::metadata(dir) {
        Ok(m) if !m.is_dir() => return Some(fs_error(dir, "path exists but is not a directory")),
        Ok(_) => {}
        Err(e) => {
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "path not found".to_owned(),
                std::io::ErrorKind::PermissionDenied => "access denied reading the path".to_owned(),
                _ => format!("path could not be opened: {e}"),
            };
            return Some(fs_error(dir, reason));
        }
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => return Some(fs_error(dir, format!("path could not be listed: {e}"))),
    };
    let fmt_time = |t: std::time::SystemTime| chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M:%S").to_string();
    let want_sids: Vec<String> = match p.get("sid") {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_ascii_uppercase()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(&[',', ';', ' '][..]).map(|t| t.trim().to_ascii_uppercase()).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    };
    let unused_days = p.get("unused_days").and_then(|x| as_i64_loose(x)).filter(|d| *d > 0);
    let cutoff = unused_days.map(|d| std::time::SystemTime::now() - std::time::Duration::from_secs(d as u64 * 86400));

    struct Disk {
        file: String,
        sid: String,
        rid: u64,
        size: u64,
        created: Option<std::time::SystemTime>,
        modified: Option<std::time::SystemTime>,
        mounted: Result<bool, String>,
    }
    let mut found: Vec<Disk> = Vec::new();
    let mut unmatched: Vec<String> = Vec::new();
    let mut cleanup_dir: Option<std::path::PathBuf> = None;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let Ok(meta) = ent.metadata() else { continue };
        if meta.is_dir() {
            if name.eq_ignore_ascii_case("UvhdCleanupBin") {
                cleanup_dir = Some(ent.path());
            }
            continue;
        }
        // Parsed into its own binding first: the borrow of `name` must be over before an arm can move
        // the name into the row it builds.
        let parsed = parse_uvhd_name(&name);
        match parsed {
            Some((sid, rid)) => found.push(Disk {
                mounted: vhdx_mounted(&ent.path()),
                file: name,
                sid,
                rid,
                size: meta.len(),
                created: meta.created().ok(),
                modified: meta.modified().ok(),
            }),
            // Anything else that is still a .vhdx — `UVHD-template.vhdx` is the common one — is COUNTED,
            // not ignored: "there are disks here this collector did not map" is an answer.
            None if name.to_ascii_lowercase().ends_with(".vhdx") => unmatched.push(name),
            None => {}
        }
    }
    found.sort_by(|a, b| a.file.to_ascii_lowercase().cmp(&b.file.to_ascii_lowercase()));

    // Resolve the SIDs in ONE call, through the same mechanism `sid-resolve` uses, so an unresolvable
    // SID reports the same way here as it does there. Over the cap the extra rows say the resolution
    // was skipped rather than quietly arriving account-less.
    let mut distinct: Vec<&str> = Vec::new();
    for d in &found {
        if !distinct.iter().any(|s| s.eq_ignore_ascii_case(&d.sid)) {
            distinct.push(&d.sid);
        }
    }
    let over_cap = distinct.len() > SID_RESOLVE_MAX;
    let to_resolve: Vec<&str> = distinct.iter().take(SID_RESOLVE_MAX).copied().collect();
    let resolved: Vec<Value> = match to_resolve.is_empty() {
        true => Vec::new(),
        // A failed TRANSLATE run is not a failed collector: the disks, sizes and last-used dates are the
        // prize and they are already read. The reason lands on every row instead of replacing them all.
        false => match sid_translate_rows(&to_resolve, "user-profile-disks") {
            GuardedRows::Rows(v) => v,
            GuardedRows::Failed(e) => {
                let why = e.get("error").and_then(|x| x.as_str()).unwrap_or("SID translation failed").to_owned();
                to_resolve.iter().map(|s| json!({ "sid": s, "resolved": false, "error": why })).collect()
            }
        },
    };

    let mut rows: Vec<Value> = Vec::new();
    let (mut mounted_count, mut total_size, mut excluded_mounted, mut excluded_recent, mut excluded_sid) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for d in &found {
        total_size += d.size;
        if d.mounted == Ok(true) {
            mounted_count += 1;
        }
        if !want_sids.is_empty() && !want_sids.iter().any(|s| s.eq_ignore_ascii_case(&d.sid)) {
            excluded_sid += 1;
            continue;
        }
        // An `unused_days` query is a question about idle profiles, so a MOUNTED disk is excluded by
        // definition rather than by a timestamp it does not have — and the count says how many.
        if cutoff.is_some() {
            if d.mounted != Ok(false) {
                excluded_mounted += 1;
                continue;
            }
            match d.modified {
                Some(m) if m < cutoff.unwrap() => {}
                _ => {
                    excluded_recent += 1;
                    continue;
                }
            }
        }
        let mut row = json!({ "file": d.file, "sid": d.sid, "rid": d.rid, "size": d.size });
        if let Some(c) = d.created {
            row["created"] = json!(fmt_time(c));
        }
        match &d.mounted {
            Ok(true) => {
                row["mounted"] = json!(true);
                row["last_used"] = Value::Null;
                row["last_used_note"] = json!(
                    "this disk is mounted, so its LastWriteTime tracks the MOUNT rather than the user's own \
                     activity; last_used is null because the answer is not knowable while it is in use"
                );
            }
            Ok(false) => {
                row["mounted"] = json!(false);
                row["last_used"] = match d.modified {
                    Some(m) => json!(fmt_time(m)),
                    None => Value::Null,
                };
            }
            // The mount probe itself failed, so neither `mounted` nor `last_used` can be asserted.
            Err(e) => {
                row["mounted"] = Value::Null;
                row["last_used"] = Value::Null;
                row["mount_probe_error"] = json!(format!(
                    "could not determine whether this disk is mounted ({e}), so last_used is withheld — on a \
                     mounted disk it would be the mount time, not the user's last activity"
                ));
            }
        }
        let hit = resolved.iter().find(|r| r.get("sid").and_then(|x| x.as_str()).is_some_and(|s| s.eq_ignore_ascii_case(&d.sid)));
        match hit {
            Some(r) if r.get("resolved").and_then(|x| x.as_bool()) == Some(true) => {
                row["account"] = r.get("account").cloned().unwrap_or(Value::Null);
                if let Some(dm) = r.get("domain").filter(|v| !v.is_null()) {
                    row["domain"] = dm.clone();
                }
            }
            Some(r) => {
                row["account"] = Value::Null;
                row["account_error"] = json!(r
                    .get("error")
                    .and_then(|x| x.as_str())
                    .unwrap_or("the SID could not be translated to an account name"));
            }
            None => {
                row["account"] = Value::Null;
                row["account_error"] = json!(match over_cap {
                    true => format!(
                        "SID resolution was skipped: this directory holds more than {SID_RESOLVE_MAX} distinct \
                         profile SIDs, which is that many directory round-trips. Narrow with `sid` to resolve these"
                    ),
                    false => "no translation result came back for this SID".to_owned(),
                });
            }
        }
        rows.push(row);
    }

    // The cleanup bin is REPORTED, never merged into the disk list: it holds orphaned and
    // pending-delete profiles, so a growing one is its own finding rather than more profiles.
    let cleanup = match &cleanup_dir {
        None => json!({ "present": false }),
        Some(cd) => match std::fs::read_dir(cd) {
            Err(e) => json!({ "present": true, "path": cd.to_string_lossy(), "error": format!("could not be listed: {e}") }),
            Ok(entries) => {
                let (mut files, mut bytes) = (0u64, 0u64);
                let (mut oldest, mut newest): (Option<std::time::SystemTime>, Option<std::time::SystemTime>) = (None, None);
                for e in entries.flatten() {
                    let Ok(m) = e.metadata() else { continue };
                    if m.is_dir() {
                        continue;
                    }
                    files += 1;
                    bytes += m.len();
                    if let Ok(t) = m.modified() {
                        oldest = Some(oldest.map_or(t, |o| o.min(t)));
                        newest = Some(newest.map_or(t, |n| n.max(t)));
                    }
                }
                let mut c = json!({ "present": true, "path": cd.to_string_lossy(), "file_count": files, "total_size": bytes });
                if let Some(t) = oldest {
                    c["oldest"] = json!(fmt_time(t));
                }
                if let Some(t) = newest {
                    c["newest"] = json!(fmt_time(t));
                }
                c
            }
        },
    };

    let mut out = json!({
        "path": dir,
        "disk_count": found.len(),
        "total_size": total_size,
        "mounted_count": mounted_count,
        // Disks in the directory this collector did not map to a SID — `UVHD-template.vhdx` and any
        // hand-named file. Named, not just counted, so "what are those?" is answerable.
        "unmatched_vhdx": { "count": unmatched.len(), "names": unmatched.iter().take(20).collect::<Vec<_>>() },
        "cleanup_bin": cleanup,
        "disks": paginate(rows, params, 200),
    });
    // What a filter removed is stated rather than left to a difference of totals — the counts above
    // describe the WHOLE directory, the page below describes what survived the filters.
    if !want_sids.is_empty() {
        out["excluded_by_sid"] = json!(excluded_sid);
    }
    if let Some(d) = unused_days {
        out["unused_days"] = json!(d);
        out["excluded_recently_used"] = json!(excluded_recent);
        out["excluded_mounted"] = json!(excluded_mounted);
    }
    Some(out)
}
#[cfg(not(windows))]
fn user_profile_disks(_params: Option<&str>) -> Option<Value> {
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
    not_before=if($_.NotBefore){{$_.NotBefore.ToString('yyyy-MM-dd')}}else{{$null}}
    not_after=if($_.NotAfter){{$_.NotAfter.ToString('yyyy-MM-dd')}}else{{$null}}
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

# The computer-scope RSoP is the load-bearing read: every posture field below derives from it, so a
# failure here must surface as an error rather than as a device with no policy applied. The optional
# sections that follow stay best-effort on purpose and each clears $Error so an allowed failure in one
# cannot be blamed on the next.
$Error.Clear()
$cg = @(gpresult /r /scope:computer 2>$null)
$cp = Parse-Gpresult $cg
if (-not $cp.applied -and -not $cp.refresh) { Stop-OnError 'resultant set of policy' }
$Error.Clear()

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
    let script = format!(
        "{PS_GUARD}{}",
        RSOP_SCRIPT
            .replace("@INCLUDE_SETTINGS@", if include_settings { "$true" } else { "$false" })
            .replace("@USER_FILTER@", &safe_user)
            .replace("@MAX_USERS@", &max_users.to_string())
    );
    ps_json_guarded(&script, "rsop")
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
    // verbose posture fields so one page + context stays under the signed-result cap); otherwise drop
    // it. The trim was sized against 64 KiB and the cap is 256 KiB, so it is conservative — the posture
    // fields could be kept if a caller ever wants them back.
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

/// The three WMI **system** classes that describe event-subscription persistence — a documented
/// ransomware technique, and the one autostart surface no other collector can see (`startup` covers
/// the Run keys and the Startup folders only). They carry the `__` prefix of the whole WMI
/// meta-schema, so the blanket `__` refusal in [`wmi_refusal`] made the read that matters
/// unreachable. They are allowed BY NAME, in `root\subscription`, under the same SELECT-only
/// construction as every other query — the `__` rule itself is NOT relaxed.
///
/// The consumer classes carrying the actual payload — `CommandLineEventConsumer`
/// (`CommandLineTemplate`) and `ActiveScriptEventConsumer` (`ScriptText`) — have no `__` and always
/// passed this gate. They only *looked* unreachable because a zero-row answer was reported as a
/// collector failure; see the empty-rows envelope below.
#[cfg(windows)]
const WMI_SUBSCRIPTION_CLASSES: &[&str] = &["__EVENTFILTER", "__EVENTCONSUMER", "__FILTERTOCONSUMERBINDING"];

/// A WMI namespace in one comparable spelling: lowercased, `/` folded to `\`, and the leading or
/// trailing separators a caller reasonably writes dropped — so `ROOT/Subscription\` and
/// `root\subscription` are recognized as the same namespace rather than as two.
#[cfg(windows)]
fn wmi_ns_key(ns: &str) -> String {
    ns.trim().replace('/', "\\").trim_matches('\\').to_lowercase()
}

/// Every `__`-prefixed identifier in a query, in the query's own spelling — the WMI system-class
/// references [`wmi_refusal`] has to rule on one at a time rather than as a single substring.
#[cfg(windows)]
fn wmi_system_class_refs(query: &str) -> Vec<String> {
    let b = query.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i + 1 < b.len() {
        if b[i] == b'_' && b[i + 1] == b'_' && (i == 0 || !ident(b[i - 1])) {
            let mut j = i;
            while j < b.len() && ident(b[j]) {
                j += 1;
            }
            out.push(query[i..j].to_owned());
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Why `wmi` refuses a query, or `None` when it may run. SELECT-only by construction: a plain
/// `SELECT`, one statement, no write or method-invocation token, and no WMI system-class reference
/// beyond the [`WMI_SUBSCRIPTION_CLASSES`] carve-out.
///
/// Split out from the collector so that each rule states **which** rule fired. One shared "disallowed
/// token (method call / write / chaining)" message used to answer every refusal, including the `__`
/// one — so a caller whose query contained none of those three went looking for a syntax error that
/// was not there. A refusal that mis-names its own cause costs more than no message.
#[cfg(windows)]
fn wmi_refusal(ns: &str, query: &str) -> Option<String> {
    let upper = query.to_uppercase();
    if !upper.trim_start().starts_with("SELECT") {
        return Some("wmi is SELECT-only (the query must start with SELECT)".to_owned());
    }
    if query.contains(';') {
        return Some("wmi refuses ';': statement chaining. SELECT-only, one statement per query".to_owned());
    }
    // Write / method-invocation tokens, each named on its own so the message can quote the one that
    // matched instead of listing every rule the gate enforces.
    const FORBIDDEN: &[(&str, &str)] = &[
        ("EXECMETHOD", "method invocation"),
        ("EXECNOTIFICATION", "an event-notification query, which is not a SELECT read"),
        (" PUT", "an instance write"),
        ("PUTINSTANCE", "an instance write"),
        ("DELETEINSTANCE", "an instance delete"),
        ("CREATEINSTANCE", "an instance create"),
        ("INVOKE", "method invocation"),
        ("SPAWNINSTANCE", "an instance create"),
    ];
    if let Some((tok, why)) = FORBIDDEN.iter().find(|(t, _)| upper.contains(t)) {
        return Some(format!("wmi refuses the token '{}': {why}. SELECT-only", tok.trim()));
    }
    // WMI system classes. Ruled on per reference, and only after the tokens above, so the message
    // names the `__` rule rather than borrowing a neighbour's.
    let refs = wmi_system_class_refs(query);
    if refs.len() != upper.matches("__").count() {
        // A `__` that is not the start of an identifier (`Win32__Foo`) is nothing this gate can
        // reason about, so it stays refused rather than being parsed into a maybe.
        return Some("wmi refuses '__' inside an identifier: only a leading `__` system-class name can be ruled on".to_owned());
    }
    let Some(first) = refs.first() else { return None };
    if let Some(bad) = refs.iter().find(|r| !WMI_SUBSCRIPTION_CLASSES.contains(&r.to_uppercase().as_str())) {
        return Some(format!(
            "wmi refuses the WMI system class '{bad}': the '__' rule fired — not a method call, not a write, \
             not chaining. Only __EventFilter, __EventConsumer and __FilterToConsumerBinding are readable, \
             SELECT-only in namespace root\\subscription"
        ));
    }
    if wmi_ns_key(ns) != "root\\subscription" {
        return Some(format!(
            "wmi reads '{first}' only in namespace root\\subscription (this query used '{ns}'): the '__' rule \
             fired — not a method call, not a write, not chaining"
        ));
    }
    None
}

/// A `wmi` result that is NOT an answer — a refusal, or a query that failed. Carries `ok:false`
/// alongside `error`, so [`is_collector_error`] recognizes it: a bare `{error}` satisfies no predicate
/// in this file, and a caller using the repo's own "failure or answer?" check therefore read a refused
/// query as data.
///
/// The dispatch `status` deliberately stays `done`. That field answers "did the job run and produce a
/// result", which a refusal did; the `status:"error"` arm means *no result at all*, which is the
/// conflation the empty-rows fix exists to undo. Every other in-band refusal in this file reports the
/// same way — `fs`'s denylist ([`fs_error`]), `reg-read`'s invalid path ([`reg_error`]),
/// `firewall-rule`'s missing selector, `duplicati`'s missing token — and each carries the same
/// `ok:false`, so one [`is_collector_error`] check covers the whole tree rather than a per-collector
/// list of which error paths are marked.
#[cfg(windows)]
fn wmi_error(ns: &str, query: &str, why: impl Into<String>) -> Value {
    json!({ "ok": false, "namespace": ns, "query": query, "error": why.into() })
}

/// `wmi`'s default per-value character cap, unchanged — the `max_value_len` param below is what moves.
#[cfg(windows)]
const WMI_VALUE_CAP_DEFAULT: usize = 500;

/// The ceiling `max_value_len` clamps to. Shares [`DETAIL_VALUE_CAP`]'s number so the file has ONE
/// per-value ceiling rather than two that can drift, and it clears the measured need with room: the
/// command lines that motivated the param need ~1,500-2,500 characters.
#[cfg(windows)]
const WMI_VALUE_CAP_MAX: usize = DETAIL_VALUE_CAP;

/// The per-value character cap for one `wmi` call: `max_value_len`, or [`WMI_VALUE_CAP_DEFAULT`].
///
/// A PARAM rather than a new constant, because the measurement says there is no single right number.
/// Truncated `CommandLine` ran at **23% of 265 process rows** on one RDS host and ~1% on a DC, and the
/// distribution is **BIMODAL — zero values landed in the 400-499 band**: command lines are either
/// ≤~260 characters or well past 500, so raising the constant to 600-800 would recover *nothing* while
/// costing every collector call on every device. `Description` is the opposite shape, clustering just
/// under the cap (493, 461, 440, 420), so it wants ~520 and nothing more. One number cannot serve both,
/// and the caller is the only party that knows which read it is doing.
#[cfg(windows)]
fn wmi_value_cap(p: &Value) -> usize {
    p.get("max_value_len")
        .and_then(as_i64_loose)
        .map(|n| n.clamp(1, WMI_VALUE_CAP_MAX as i64) as usize)
        .unwrap_or(WMI_VALUE_CAP_DEFAULT)
}

/// Cap one `wmi` row's string values, and stamp the row with `truncated_fields` naming every key that
/// was cut — the same self-declaration the deep-read companions carry ([`cap_detail_strings`]), so a
/// caller tests a key rather than sniffing for a trailing ellipsis a real value may itself end with.
/// (The ellipsis stays, as the human cue; `truncated_fields` is the machine one.)
///
/// ⚠ `row_budget` is the reason this is per-ROW rather than a flat cap. [`paginate`] always emits at
/// least one item — otherwise a single wide row could never be fetched at all — so ONE row bypasses the
/// page byte budget entirely, and `max_value_len` × a class's property count is the size of that
/// bypass. Win32_Process alone can return ~45 non-null properties, which at the 8000 ceiling is 360 KB:
/// past `store::MAX_JOB_RESULT` = 256 KiB, where the result is **replaced wholesale** by a failure
/// notice. The pool bounds one row at [`PAGE_BUDGET`] characters no matter how wide the class is, so
/// the ceiling can be raised for the field that needs it without arming that cliff.
#[cfg(windows)]
fn cap_wmi_row(row: &mut Value, cap: usize, row_budget: usize) {
    let Some(obj) = row.as_object_mut() else { return };
    let mut left = row_budget;
    let mut cut: Vec<Value> = Vec::new();
    for (k, val) in obj.iter_mut() {
        let Some(s) = val.as_str() else { continue };
        let chars = s.chars().count();
        let take = cap.min(left);
        if chars > take {
            *val = json!(s.chars().take(take).collect::<String>() + "…");
            cut.push(json!(k));
        }
        left -= chars.min(take);
    }
    if !cut.is_empty() {
        obj.insert("truncated_fields".to_owned(), Value::Array(cut));
    }
}

/// Generic read-only WQL `SELECT` (the LLM escape hatch). CONTENT-BEARING (admin-gated console-side).
/// `params` JSON `{namespace:"root\\cimv2", query:"SELECT … FROM …", max:N, max_value_len:N}`.
/// SELECT-ONLY by construction — see [`wmi_refusal`] for the rules and the `__`-class carve-out; a
/// refused query returns [`wmi_error`]'s `{ok:false, namespace, query, error}` and nothing runs. Rows
/// capped (default 200, max 1000). Returns
/// `{namespace, query, row_cap_hit, value_char_cap, rows:{…page…}}` on success.
///
/// **A property WMI returned no value for is OMITTED from the row, never emitted as `""`.** WMI does
/// NOT narrow a row to the `SELECT a,b` projection — it returns the class's *whole* property set with
/// the unselected ones as **null**. Measured: `SELECT Name,ProcessId FROM Win32_Process` hands back 45
/// properties, 42 of them null. The row builder cast every value with `[string]`, and `[string]$null` is
/// `""`, so all 42 rendered as empty strings indistinguishable from a field that was asked for and is
/// genuinely empty (`Win32_OperatingSystem.Description` is a real one). That is the same error≠absent
/// conflation this collector's empty-rows fix exists to undo, one level down — inside the row instead
/// of around it.
///
/// So the projection filters on `$null -ne $_.Value` before the cast. `$null -ne ''` is TRUE in
/// PowerShell, so a genuine empty string still lands as `""` and stays a real value; only a
/// no-value-from-WMI property disappears. Absent and empty are now different shapes rather than the
/// same one. It also shrinks results by roughly the ratio of selected to total properties — the
/// two-column `Win32_OperatingSystem` read above went from 1392 serialized chars to 62.
///
/// ⚠ Rows are therefore **heterogeneous**: a key present on one row can be missing from the next when
/// that instance had no value for it. Read with a key-missing default, not by index. The distinction the
/// row cannot draw is "not selected" vs "selected but null on this instance" — both are genuinely "WMI
/// returned no value", so collapsing them loses nothing.
///
/// **A cut value declares itself.** Every string is capped at `max_value_len` characters (default 500,
/// max 8000 — see [`wmi_value_cap`]), and a row that lost anything gains `truncated_fields` naming each
/// key that was shortened, with the envelope stating `value_char_cap`. The trailing ellipsis remains as
/// the human cue but was never a machine test: a real value may end in one.
///
/// **A query that matches nothing returns the empty page, not a failure.** Zero rows is the normal
/// outcome of a targeted hunt — "is this specific bad thing here?" — and it used to arrive as
/// `status:"error", result:null`, because `@(…) | ConvertTo-Json` over an empty collection enumerates
/// zero objects and `ConvertTo-Json` therefore emits NOTHING, which the dispatcher's no-result arm
/// reports as a broken collector. So the script hands the collection to `-InputObject` instead, where
/// an empty array serializes as `[]`: the one query shape that can confirm an absence is now usable
/// for exactly that.
#[cfg(windows)]
fn wmi_query(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let ns_raw = p.get("namespace").and_then(|x| x.as_str()).unwrap_or("root\\cimv2").trim();
    let query = p.get("query").and_then(|x| x.as_str()).unwrap_or("").trim();
    let max = p.get("max").and_then(|x| x.as_i64()).unwrap_or(200).clamp(1, 1000);
    if query.is_empty() {
        return Some(json!({ "ok": false, "error": "wmi needs a WQL query" }));
    }
    // Namespace → a safe value (alnum + the WMI path separators); the query → single-quote-escaped for
    // the PS literal. Both interpolate into a Get-CimInstance -Query call, which itself only READS.
    // Sanitized BEFORE the gate, so the namespace the carve-out rules on is the one that reaches the
    // provider rather than the one the caller typed.
    let ns: String = ns_raw.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '\\' | '/' | '_' | '-')).take(128).collect();
    let ns = if ns.is_empty() { "root\\cimv2".to_owned() } else { ns };
    if let Some(why) = wmi_refusal(&ns, query) {
        return Some(wmi_error(&ns, query, why));
    }
    let q_esc = query.replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='Stop'; try {{ \
           $rows=@(Get-CimInstance -Namespace '{ns}' -Query '{q_esc}' -ErrorAction Stop | Select-Object -First {max} | \
             ForEach-Object {{ $o=$_; $h=[ordered]@{{}}; $o.CimInstanceProperties | Where-Object {{ $_.Name -notmatch '^Cim' -and $null -ne $_.Value }} | ForEach-Object {{ $h[$_.Name]=[string]$_.Value }}; [pscustomobject]$h }}); \
           ConvertTo-Json -InputObject $rows -Depth 3 -Compress \
         }} catch {{ [pscustomobject]@{{ error=[string]$_.Exception.Message }} | ConvertTo-Json -Compress }}"
    );
    // The script emits JSON on every path — `[]` for no rows, `{error:…}` from the catch — so nothing
    // parseable on stdout means the PowerShell RUN failed. Named as that, never as an empty result.
    let Some(parsed) = ps_json(&script) else {
        return Some(wmi_error(
            &ns,
            query,
            "wmi produced no readable output (PowerShell could not be started, or was killed before it wrote)",
        ));
    };
    // A bare {error:…} object surfaced from the catch → pass it through as an error result. Rows now
    // always arrive as an array, so a row that happens to carry an `error` column can't be mistaken
    // for one. Flagged `ok:false` like the refusals: a failed query ("Invalid class", "Access denied")
    // is no more an answer than a refused one, and a caller should not have to know which error paths
    // in one collector carry the flag.
    if parsed.get("error").is_some() && !parsed.is_array() {
        return Some(wmi_error(&ns, query, parsed.get("error").and_then(|x| x.as_str()).unwrap_or("query failed")));
    }
    let mut rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v],
        _ => Vec::new(),
    };
    let truncated = rows.len() as i64 >= max;
    // Char-cap the over-long string values, per row, out of a shared pool — see `cap_wmi_row` for why
    // the cap is a param and why the pool exists. An `ActiveScriptEventConsumer.ScriptText` is still
    // read only to its opening at the default; `max_value_len` is how you read further.
    let value_cap = wmi_value_cap(&p);
    for r in rows.iter_mut() {
        cap_wmi_row(r, value_cap, PAGE_BUDGET);
    }
    // `row_cap_hit` NOT `truncated`: the page envelope below carries its own `truncated`, meaning
    // the byte budget stopped the page, and the store cap has a third. Three meanings for one key is
    // the collision that produced a silent regression once already, so the row cap gets its own name.
    Some(json!({
        "namespace": ns,
        "query": query,
        "row_cap_hit": truncated,
        // What the rows were cut at, so a caller reading a `truncated_fields` key knows what it cost
        // and what to raise. Echoed even when nothing was cut — it is the contract, not an event.
        "value_char_cap": value_cap,
        "rows": paginate(rows, params, max as usize)
    }))
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
             date=if($_.DriverDate){{([datetime]$_.DriverDate).ToString('yyyy-MM-dd')}}else{{$null}}; class=[string]$_.DeviceClass; \
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

/// Installed Windows roles/features (read-only). Two different cmdlets back this depending on SKU, so
/// the result carries a `source` field: a **Server** SKU has `Get-WindowsFeature` (roles + features,
/// with display names and a tri-state install state), a **client** SKU has only
/// `Get-WindowsOptionalFeature -Online` (a flatter enabled/disabled list). The two sets are NOT the
/// same inventory, so a caller comparing across machines has to read `source` before comparing names.
/// `params` `{installed_only:"bool (default true)", name:"substring", offset, limit}`. Paginated.
///
/// This is a THIRD surface alongside `programs` (Uninstall registry) and `capabilities`
/// (Features-on-Demand) — a box can carry something in any one of them, so an inventory that reads
/// only one looks complete while hiding the rest.
#[cfg(windows)]
fn features(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let installed_only = p.get("installed_only").and_then(|x| x.as_bool()).unwrap_or(true);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '*' | '?')).take(128).collect()
    };
    let name_filter = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|n| format!(" | Where-Object {{ $_.name -like '*{}*' -or $_.display_name -like '*{}*' }}", safe(n), safe(n)))
        .unwrap_or_default();
    // `install_state` is normalized across the two sources: Installed / Available / Removed from the
    // server cmdlet, Enabled / Disabled / DisabledWithPayloadRemoved from the client one. The
    // installed_only filter keys on the two "present" spellings rather than on a source check.
    let installed_where = match installed_only {
        true => " | Where-Object { $_.install_state -eq 'Installed' -or $_.install_state -eq 'Enabled' }",
        false => "",
    };
    let script = format!(
        "{PS_GUARD}\
         $hasSM=[bool](Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue); $Error.Clear(); \
         if($hasSM){{ \
           $src=@(Get-WindowsFeature); Stop-OnError 'windows features'; \
           $rows=@($src | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.Name; \
             display_name=[string]$_.DisplayName; install_state=[string]$_.InstallState; \
             feature_type=[string]$_.FeatureType; source='Get-WindowsFeature' }} }}) \
         }} else {{ \
           $src=@(Get-WindowsOptionalFeature -Online); Stop-OnError 'optional features'; \
           $rows=@($src | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.FeatureName; \
             display_name=$(if($_.DisplayName){{ [string]$_.DisplayName }} else {{ $null }}); \
             install_state=[string]$_.State; \
             feature_type=$null; source='Get-WindowsOptionalFeature' }} }}) \
         }}; \
         @($rows){installed_where}{name_filter} | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "features") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 250))
}
#[cfg(not(windows))]
fn features(_params: Option<&str>) -> Option<Value> {
    None
}

/// Windows **capabilities** / Features-on-Demand (read-only) via `Get-WindowsCapability -Online` —
/// IE11, WMP, WordPad, Steps Recorder, supplemental fonts, the RSAT tools. A THIRD surface, distinct
/// from both `features` and `appx`: the cmdlet, the shape and the SKU behaviour all differ, which is
/// why this is its own collector rather than a mode of `features`.
/// `params` `{installed_only:"bool (default true)", name:"substring", offset, limit}`. Paginated.
///
/// ⚠ Slower than it looks — it interrogates the online image, so allow a generous wait.
#[cfg(windows)]
fn capabilities(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let installed_only = p.get("installed_only").and_then(|x| x.as_bool()).unwrap_or(true);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '~' | '*' | '?')).take(128).collect()
    };
    let name_filter = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|n| format!(" | Where-Object {{ $_.name -like '*{}*' }}", safe(n)))
        .unwrap_or_default();
    let installed_where = match installed_only {
        true => " | Where-Object { $_.state -eq 'Installed' }",
        false => "",
    };
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-WindowsCapability -Online); Stop-OnError 'windows capabilities'; \
         @($src | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.Name; state=[string]$_.State }} }}){installed_where}{name_filter} \
         | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = match ps_rows_guarded(&script, "capabilities") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 250))
}
#[cfg(not(windows))]
fn capabilities(_params: Option<&str>) -> Option<Value> {
    None
}

/// Installed Appx / UWP packages (read-only) via `Get-AppxPackage`.
/// `params` `{all_users:"bool (default TRUE)", provisioned:"bool (default false)", name:"substring",
/// offset, limit}`. Paginated.
///
/// `all_users` defaults to **true** because this collector runs as SYSTEM: the per-user default would
/// enumerate SYSTEM's own (near-empty) package set, so the useful answer would need opting in and an
/// operator would read the empty result as "no Appx packages installed".
///
/// `provisioned:true` switches to `Get-AppxProvisionedPackage -Online` — what a NEW user profile gets,
/// which is the actual remediation lever on a server or a fleet image: removing a per-user package
/// leaves the provisioned copy to reappear for the next profile.
#[cfg(windows)]
fn appx(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let all_users = p.get("all_users").and_then(|x| x.as_bool()).unwrap_or(true);
    let provisioned = p.get("provisioned").and_then(|x| x.as_bool()).unwrap_or(false);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '*' | '?')).take(128).collect()
    };
    let name_filter = p
        .get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|n| format!(" | Where-Object {{ $_.name -like '*{}*' }}", safe(n)))
        .unwrap_or_default();
    let script = match provisioned {
        true => format!(
            "{PS_GUARD}\
             $src=@(Get-AppxProvisionedPackage -Online); Stop-OnError 'provisioned appx packages'; \
             @($src | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.DisplayName; \
               package=[string]$_.PackageName; version=[string]$_.Version; publisher=[string]$_.PublisherId; \
               scope='provisioned' }} }}){name_filter} | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
        ),
        false => format!(
            "{PS_GUARD}\
             $src=@(Get-AppxPackage{all_users_arg}); Stop-OnError 'appx packages'; \
             @($src | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.Name; \
               package=[string]$_.PackageFullName; version=[string]$_.Version; publisher=[string]$_.Publisher; \
               install_location=[string]$_.InstallLocation; is_framework=[bool]$_.IsFramework; \
               signature_kind=[string]$_.SignatureKind; status=[string]$_.Status; \
               scope=$(if(${all_users_flag}){{'all-users'}}else{{'current-user'}}) }} }}){name_filter} \
             | Sort-Object name | ConvertTo-Json -Depth 3 -Compress",
            all_users_arg = if all_users { " -AllUsers" } else { "" },
            all_users_flag = if all_users { "true" } else { "false" },
        ),
    };
    let items = match ps_rows_guarded(&script, "appx") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(paginate(items, params, 200))
}
#[cfg(not(windows))]
fn appx(_params: Option<&str>) -> Option<Value> {
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
    // RecordData shape varies per type. `data` is the record's primary value — the address, the
    // target, the exchange — chosen as the first of the known properties that is set.
    //
    // The fields BESIDE that value are what a record is often read for, and flattening to `data`
    // alone silently drops them: an SRV keeps its target but loses the port, so `_ldap._tcp` (389)
    // and `_gc._tcp` (3268) render identically; an MX loses its preference, so the backup and the
    // primary look the same; an SOA loses its serial, which is the field replication is judged on.
    // They are reported alongside `data`, `null` where the type has no such notion.
    let script = format!(
        "{PS_GUARD}\
         $src=@(Get-DnsServerResourceRecord -ZoneName '{zone}'{type_arg}{name_filter}); Stop-OnError 'records'; \
         @($src | ForEach-Object {{ \
           $d=$_.RecordData; \
           $v=@($d.IPv4Address,$d.IPv6Address,$d.HostNameAlias,$d.NameServer,$d.DomainName,$d.PtrDomainName,$d.MailExchange,$d.PrimaryServer,$d.DescriptiveText,$d.StringData,$d.Text) | Where-Object {{ $_ }} | Select-Object -First 1; \
           [pscustomobject]@{{ name=[string]$_.HostName; type=[string]$_.RecordType; \
             ttl=[string]$_.TimeToLive; data=[string]$v; \
             port=$(if ($null -ne $d.Port) {{ [int]$d.Port }} else {{ $null }}); \
             priority=$(if ($null -ne $d.Priority) {{ [int]$d.Priority }} else {{ $null }}); \
             weight=$(if ($null -ne $d.Weight) {{ [int]$d.Weight }} else {{ $null }}); \
             preference=$(if ($null -ne $d.Preference) {{ [int]$d.Preference }} else {{ $null }}); \
             serial=$(if ($null -ne $d.SerialNumber) {{ [uint32]$d.SerialNumber }} else {{ $null }}) }} \
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
             failover_relationship=$(if ($null -ne $f -and $f.Name) {{ [string]$f.Name }} else {{ $null }}) }} \
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
           # A reservation has no expiry — it is permanent — so its LeaseExpiryTime is null. Emitted
           # as null rather than the empty string a cast produces, which would be indistinguishable
           # from an expiry the collector could not read. `type` already says which kind of row it is.
           [pscustomobject]@{{ ip=[string]$_.IPAddress; mac=[string]$_.ClientId; hostname=[string]$_.HostName; \
             state=[string]$_.AddressState; type=$ty; \
             lease_expiry=$(if ($null -ne $_.LeaseExpiryTime) {{ [string]$_.LeaseExpiryTime }} else {{ $null }}) }} \
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
         function Fts($v){{ if($v -and $v -gt 0 -and $v -lt 9223372036854775807){{ [datetime]::FromFileTimeUtc([int64]$v).ToString('yyyy-MM-dd HH:mm:ss') }} else {{ $null }} }}; \
         function P($x,$n){{ if($x[$n].Count -gt 0){{ [string]$x[$n][0] }} else {{ '' }} }}; \
         function OUOF($dn){{ if($dn -match '^(?:[^,]+,)(.*)$'){{ $Matches[1] }} else {{ '' }} }}; \
         $found=@($ds.FindAll()); Stop-OnError 'directory search'; \
         @($found | ForEach-Object {{ $x=$_.Properties; {project} }}){extra_where} | ConvertTo-Json -Depth 3 -Compress"
    );
    ps_rows_guarded(&script, "directory search")
}

/// `objectSid` arrives from ADSI as a raw `byte[]`, so a plain stringify yields `System.Byte[]`; this
/// builds the SDDL string every other surface shows a SID as. Leaves `$sid` as `''` if the attribute
/// was not returned.
#[cfg(windows)]
const PS_SID_FROM_BYTES: &str = "$sid=''; if($x['objectsid'].Count){ $sb=$x['objectsid'][0]; \
      if($sb -is [byte[]]){ $sid=[string](New-Object System.Security.Principal.SecurityIdentifier($sb,0)).Value } }";

/// How many principals hold each group as their PRIMARY group, keyed by that group's full SID.
///
/// A group's `member` attribute does **not** list a principal whose membership comes from its
/// `primaryGroupID` — which is the default membership of every user (Domain Users) and every computer
/// (Domain Computers). Read straight, `member_count` therefore reported **0** for Domain Users on a
/// domain where all 45 users were in it, and Domain Computers and Domain Controllers likewise; the
/// `members:true` drill-down returned an empty page for the same groups. Nothing in either answer said
/// the primary side had been left out, so an empty group and the largest group in the domain read
/// identically.
///
/// One extra search for the whole listing, joined in memory — not a query per group.
///
/// Keyed by the group's **full SID**, never the bare RID: a RID is unique only within its domain, and
/// the object's own SID carries the prefix needed to rebuild the primary group's. `Err` is the
/// collector error — the caller reports the primary side as unknown rather than as zero.
#[cfg(windows)]
fn primary_group_tally() -> Result<std::collections::HashMap<String, u64>, Value> {
    let project = format!(
        "{PS_SID_FROM_BYTES}; \
         $pg=''; if($sid -and $x['primarygroupid'].Count){{ $pg=($sid -replace '-\\d+$', ('-'+[int]$x['primarygroupid'][0])) }}; \
         [pscustomobject]@{{ pg=$pg }}"
    );
    // The presence term drops contacts, which are `objectCategory=person` but hold no primaryGroupID.
    let filter = "(&(primaryGroupID=*)(|(objectCategory=person)(objectCategory=computer)))";
    match adsi_search(None, filter, &["objectsid", "primarygroupid"], &project, "") {
        GuardedRows::Failed(e) => Err(e),
        GuardedRows::Rows(rows) => {
            let mut m: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for r in &rows {
                if let Some(pg) = r.get("pg").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                    *m.entry(pg.to_ascii_uppercase()).or_insert(0) += 1;
                }
            }
            Ok(m)
        }
    }
}

/// AD users (role `addc`). Hardened filter `(&(objectCategory=person)(objectClass=user)(!(objectClass=
/// computer)))` — `objectClass=user` alone also matches computers (they subclass user) and
/// `objectCategory=person` alone also matches contacts, so both terms plus the exclusion are needed.
/// `params` `{name:"glob (sam/display)", enabled:"bool", stale_days:"int", ou:"DN searchBase", limit,
/// cursor}`. Secrets are never requested. Cursor-paginated. `stale_days` uses `lastLogonTimestamp`
/// (replicated with ~9–14 day jitter — see the plan; meaningful only for N ≫ 14).
///
/// ⚠ `member_of_count` counts `memberOf`, which **never lists the primary group** — so it is not the
/// number of groups the account is in. It was called `groups_count`, and a service account whose only
/// membership is the default Domain Users primary read `groups_count: 0`, i.e. "in no groups at all",
/// of an account that is in one. `primary_group_rid` is the membership the count cannot see (513 =
/// Domain Users, 515 = Domain Computers, 516 = Domain Controllers); `null` only if the attribute was
/// not returned. Same omission from the other side as `ad-groups`' `member_count`.
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
    // objectSid arrives as a raw byte[], so `P` (which stringifies) would yield 'System.Byte[]'. The
    // SDDL string is what every other surface shows a SID as, and it is the forward direction of
    // `sid-resolve`: given a name, the SID that scheduled tasks, ProfileList and UPD filenames use.
    let project = "$dn=P $x 'distinguishedname'; $uac=0; if($x['useraccountcontrol'].Count){ $uac=[int]$x['useraccountcontrol'][0] }; \
        $nm=(P $x 'displayname'); if(-not $nm){ $nm=(P $x 'cn') }; \
        $sid=''; if($x['objectsid'].Count){ $sb=$x['objectsid'][0]; \
          if($sb -is [byte[]]){ $sid=[string](New-Object System.Security.Principal.SecurityIdentifier($sb,0)).Value } }; \
        [pscustomobject]@{ sam=(P $x 'samaccountname'); name=$nm; upn=(P $x 'userprincipalname'); sid=$sid; \
          enabled=(-not ($uac -band 2)); locked=(($x['lockouttime'].Count -gt 0) -and ([int64]$x['lockouttime'][0] -gt 0)); \
          pwd_last_set=(Fts (P $x 'pwdlastset')); last_logon=(Fts (P $x 'lastlogontimestamp')); \
          expires=(Fts (P $x 'accountexpires')); description=(P $x 'description'); ou=(OUOF $dn); dn=$dn; \
          member_of_count=$x['memberof'].Count; \
          primary_group_rid=$(if($x['primarygroupid'].Count){ [int]$x['primarygroupid'][0] }else{ $null }); \
          _llt=(P $x 'lastlogontimestamp') }";
    let props = ["samaccountname", "cn", "displayname", "userprincipalname", "useraccountcontrol", "lockouttime", "pwdlastset", "lastlogontimestamp", "accountexpires", "description", "distinguishedname", "memberof", "objectsid", "primarygroupid"];
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
/// `offset`, not the cursor, and tags each row `via` = `member` | `primary_group`.
///
/// The list reports membership as three fields because AD stores it in two places: `member_count` is
/// the direct `member` list, `primary_member_count` the principals holding this group as their
/// primary, and `member_count_total` the sum. The last two are `null`, never 0, when that side could
/// not be read — see [`primary_group_tally`] for what reading only `member` got wrong.
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
    let props = ["samaccountname", "cn", "grouptype", "description", "distinguishedname", "managedby", "member", "objectsid"];

    if members {
        // Drill-down: resolve to exactly one group, then page its members with stateless `offset`.
        let project = format!("{PS_SID_FROM_BYTES}; [pscustomobject]@{{ dn=(P $x 'distinguishedname'); sid=$sid; member=@($x['member']) }}");
        let groups = match adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, &project, "") {
            GuardedRows::Failed(e) => return Some(e),
            GuardedRows::Rows(v) => v,
        };
        if groups.is_empty() {
            return Some(json!({ "ok": false, "error": "members:true matched no group" }));
        }
        if groups.len() > 1 {
            return Some(json!({ "ok": false, "error": "members:true matched multiple groups; narrow to one" }));
        }
        let mprops = ["samaccountname", "displayname", "objectclass", "samaccounttype", "objectsid", "primarygroupid"];
        let mut items: Vec<Value> = Vec::new();

        // Enumerate the one group's member DNs → {sam,name,type}.
        let member_dns = groups[0].get("member").and_then(|m| m.as_array()).cloned().unwrap_or_default();
        let list = member_dns.iter().filter_map(|d| d.as_str()).map(ldap_safe).collect::<Vec<_>>();
        if !list.is_empty() {
            let ors = list.iter().map(|d| format!("(distinguishedName={d})")).collect::<String>();
            let mfilter = format!("(|{ors})");
            let mproject = "$ty='user'; if($x['objectclass'] -contains 'group'){ $ty='group' }elseif($x['objectclass'] -contains 'computer'){ $ty='computer' }; \
                [pscustomobject]@{ sam=(P $x 'samaccountname'); name=(P $x 'displayname'); type=$ty; via='member' }";
            match adsi_search(None, &mfilter, &mprops, mproject, "") {
                GuardedRows::Failed(e) => return Some(e),
                GuardedRows::Rows(v) => items.extend(v),
            }
        }

        // ...then the members `member` cannot see. Without this the drill-down answered "no members"
        // for Domain Users — see `primary_group_tally`. `via` keeps the two kinds distinguishable
        // instead of merging them into one indistinguishable list.
        let gsid = groups[0].get("sid").and_then(|v| v.as_str()).unwrap_or("").to_ascii_uppercase();
        let rid = gsid.rsplit('-').next().filter(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit()));
        let mut primary_error: Option<Value> = None;
        match rid {
            Some(rid) => {
                let pfilter = format!("(&(primaryGroupID={rid})(|(objectCategory=person)(objectCategory=computer)))");
                let pproject = format!(
                    "$ty='user'; if($x['objectclass'] -contains 'computer'){{ $ty='computer' }}; \
                     {PS_SID_FROM_BYTES}; \
                     $pg=''; if($sid -and $x['primarygroupid'].Count){{ $pg=($sid -replace '-\\d+$', ('-'+[int]$x['primarygroupid'][0])) }}; \
                     [pscustomobject]@{{ sam=(P $x 'samaccountname'); name=(P $x 'displayname'); type=$ty; via='primary_group'; _pg=$pg }}"
                );
                match adsi_search(None, &pfilter, &mprops, &pproject, "") {
                    GuardedRows::Failed(e) => primary_error = Some(e),
                    GuardedRows::Rows(rows) => {
                        for mut row in rows {
                            // The RID filter is domain-blind; the rebuilt full SID is what actually
                            // proves this principal's primary group is THIS group.
                            let matches = row.get("_pg").and_then(|v| v.as_str()).map(|s| s.eq_ignore_ascii_case(&gsid)).unwrap_or(false);
                            if !matches {
                                continue;
                            }
                            if let Some(o) = row.as_object_mut() {
                                o.remove("_pg");
                            }
                            items.push(row);
                        }
                    }
                }
            }
            // No SID for the group means its primary-group members cannot be found at all. Say so —
            // silently returning only the direct members is the failure this whole change is about.
            None => primary_error = Some(json!({ "error": "group SID unavailable — primary-group members could not be enumerated" })),
        }

        let mut out = paginate(items, params, 300);
        if let Some(e) = primary_error {
            if let Some(o) = out.as_object_mut() {
                o.insert("primary_members_error".into(), e.get("error").cloned().unwrap_or(Value::Null));
            }
        }
        return Some(out);
    }

    let project = format!(
        "$gt=0; if($x['grouptype'].Count){{ $gt=[int64]$x['grouptype'][0] }}; \
         $scope=''; if($gt -band 8){{ $scope='universal' }}elseif($gt -band 4){{ $scope='domainlocal' }}elseif($gt -band 2){{ $scope='global' }}; \
         $ty='distribution'; if($gt -band 2147483648){{ $ty='security' }}; \
         {PS_SID_FROM_BYTES}; \
         [pscustomobject]@{{ name=(P $x 'cn'); sam=(P $x 'samaccountname'); scope=$scope; type=$ty; \
           description=(P $x 'description'); member_count=$x['member'].Count; sid=$sid; \
           dn=(P $x 'distinguishedname'); managed_by=(P $x 'managedby') }}"
    );
    let mut items = match adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, &project, "") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    // `member_count` is the direct `member` list ONLY. Primary-group members are invisible there, so
    // they are counted separately and reported beside it rather than folded in — a caller that wants
    // "who is really in this group" reads `member_count_total`, and one auditing explicit membership
    // still has the number it had before.
    let tally = primary_group_tally();
    for row in &mut items {
        let sid = row.get("sid").and_then(|v| v.as_str()).map(|s| s.to_ascii_uppercase());
        let (primary, total) = match (&tally, &sid) {
            (Ok(m), Some(s)) if !s.is_empty() => {
                let p = m.get(s).copied().unwrap_or(0);
                let direct = row.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0);
                (json!(p), json!(p + direct))
            }
            // The tally read failed, or this group's own SID did not come back. Either way the primary
            // side is UNKNOWN, and a 0 would assert the thing that was wrong before: that it is empty.
            _ => (Value::Null, Value::Null),
        };
        if let Some(o) = row.as_object_mut() {
            o.insert("primary_member_count".into(), primary);
            o.insert("member_count_total".into(), total);
        }
    }
    let mut out = paginate_cursor(items, params, 300);
    if let Err(e) = &tally {
        if let Some(o) = out.as_object_mut() {
            o.insert("primary_member_count_error".into(), e.get("error").cloned().unwrap_or(Value::Null));
        }
    }
    Some(out)
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

/// AD OU tree (role `addc`). `params` `{under:"DN (subtree root; default domain root)", depth:"int
/// (levels below the search root; 0 = the root alone)", limit, offset}`. Reads `gPLink`/`gPOptions`
/// per OU so the operator sees which GPOs link where — the domain-side wiring `rsop` can't show.
/// Stateless `paginate()` (the tree is bounded).
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
          gplinks=$links; blocks_inheritance=[bool]([int]((P $x 'gpoptions')) -band 1) }";
    let props = ["name", "distinguishedname", "description", "gplink", "gpoptions"];
    let items = match adsi_search(p.get("under").and_then(|x| x.as_str()), &filter, &props, project, "") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    // `child_ou_count` used to be a hardcoded 0 — every OU reported childless, which the collector's
    // own output disproved, since the children were right there with this OU as their `parent_dn`.
    // Counted here from the WHOLE result set before pagination, so a page boundary cannot change an
    // OU's count. DNs compare case-insensitively, as AD treats them.
    //
    // ⚠ With a `under` scope the search is narrowed, so this counts children PRESENT IN THE RESULT —
    // exact for the default unscoped listing, a subtree-local count when scoped.
    let mut kids: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for row in &items {
        if let Some(p) = row.get("parent_dn").and_then(|v| v.as_str()) {
            *kids.entry(p.to_ascii_lowercase()).or_insert(0) += 1;
        }
    }
    let mut items = items;
    for row in &mut items {
        let n = row
            .get("dn")
            .and_then(|v| v.as_str())
            .and_then(|d| kids.get(&d.to_ascii_lowercase()).copied())
            .unwrap_or(0);
        if let Some(o) = row.as_object_mut() {
            o.insert("child_ou_count".into(), json!(n));
        }
    }
    // `depth` was documented in the params (and in the API help catalog) and never implemented: the
    // search is always a full subtree, so `{depth:1}` returned the entire tree — measured on a live DC,
    // 16 OUs asked one level deep, 16 OUs returned. A dropped filter is worse than an absent one,
    // because a plausible answer comes back and nothing says the request was ignored.
    //
    // Applied AFTER `child_ou_count`, so a trimmed row still reports how many children it really has
    // rather than how many survived the trim. Level 0 is the search root itself (ADSI subtree scope
    // includes the base object), so `depth:1` is "the root and its immediate children".
    if let Some(d) = p.get("depth").and_then(|x| x.as_i64()).filter(|n| *n >= 0) {
        let base = p
            .get("under")
            .and_then(|x| x.as_str())
            .map(ou_depth_of)
            .unwrap_or(0);
        items.retain(|row| {
            row.get("dn")
                .and_then(|v| v.as_str())
                .map(|dn| (ou_depth_of(dn) as i64 - base as i64) <= d)
                .unwrap_or(true)
        });
    }
    Some(paginate(items, params, 300))
}

/// How many `OU=` components a DN carries — an OU's nesting level, since OUs sit only under other OUs
/// or the domain root. Splits on unescaped commas, so an RDN containing a literal `\,` is one
/// component rather than two.
#[cfg(windows)]
fn ou_depth_of(dn: &str) -> usize {
    // Char-wise rather than a byte slice: an RDN can legitimately start with a multi-byte character,
    // and `&rdn[..3]` would panic mid-codepoint on one.
    fn is_ou_rdn(rdn: &str) -> bool {
        let mut it = rdn.trim_start().chars();
        matches!(
            (it.next(), it.next(), it.next()),
            (Some(o), Some(u), Some('=')) if o.eq_ignore_ascii_case(&'O') && u.eq_ignore_ascii_case(&'U')
        )
    }
    let mut depth = 0usize;
    let mut escaped = false;
    let mut rdn = String::new();
    for c in dn.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            ',' if !escaped => {
                if is_ou_rdn(&rdn) {
                    depth += 1;
                }
                rdn.clear();
            }
            _ => {
                escaped = false;
                rdn.push(c);
            }
        }
    }
    if is_ou_rdn(&rdn) {
        depth += 1;
    }
    depth
}
#[cfg(not(windows))]
fn ad_ous(_params: Option<&str>) -> Option<Value> {
    None
}

/// All GPOs in the domain (role `gpo`) via `Get-GPO -All` (GroupPolicy module). `params` `{name:"glob",
/// limit, offset}`. If the module is absent, returns the runtime sentinel. Paginated.
///
/// `links` names the SOMs linking each GPO. It is not per-GPO work: the whole linkage is read with one
/// query per naming context and joined in memory, so it costs two searches for the entire list rather
/// than a report per policy. `ad-ous`' `gplinks` is the same relation from the other side — that one
/// reports raw GUIDs, this one the GPO's name, and they cross-check each other.
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
         # Links do NOT live on the GPO — `Get-GPO` cannot see them. They live in the `gPLink`
         # attribute of each SOM (the domain root, every OU, and every site), so this reads both
         # naming contexts and joins in memory: one query per NC rather than Get-GPInheritance per OU.
         # Sites are in the CONFIGURATION NC; omitting them would report a site-linked GPO as unlinked,
         # which is the same defect in miniature. `links=@()` used to be hardcoded here, so every GPO
         # read as unlinked — and an unlinked GPO is a deletion candidate, so that was a wrong answer
         # somebody could act on destructively.
         # Best-effort, and it SAYS SO. A `gpo`-role host without the ActiveDirectory module would
         # otherwise fail the whole collector where it previously returned GPOs, so a failed link read
         # sets links_read=$false and omits `links` — never an empty array, which would repeat the
         # original defect. Same shape as process-detail's `signature_checked`.
         $lnk=@{{}}; $linksOk=$false; \
         try {{ \
           $rd=Get-ADRootDSE -ErrorAction Stop; \
           $soms=@(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $rd.defaultNamingContext -Properties gPLink,distinguishedName -ErrorAction Stop) \
                +@(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $rd.configurationNamingContext -Properties gPLink,distinguishedName -ErrorAction Stop); \
           foreach($s in $soms){{ \
             foreach($m in [regex]::Matches([string]$s.gPLink,'cn=\\{{([^}}]+)\\}}')){{ \
               $g=$m.Groups[1].Value.ToLower(); \
               if(-not $lnk.ContainsKey($g)){{ $lnk[$g]=@() }}; \
               $lnk[$g]+=[string]$s.distinguishedName }} }}; \
           $linksOk=$true \
         }} catch {{ $linksOk=$false }}; \
         $Error.Clear(); \
         @($src | ForEach-Object {{ \
           $gid=([string]$_.Id).Trim('{{','}}').ToLower(); \
           $h=[ordered]@{{ name=[string]$_.DisplayName; id=[string]$_.Id; status=[string]$_.GpoStatus; \
             created=[string]$_.CreationTime; modified=[string]$_.ModificationTime; \
             computer_ver=[string]$_.Computer.DSVersion; user_ver=[string]$_.User.DSVersion; \
             wmi_filter=$(if($_.WmiFilter){{ [string]$_.WmiFilter.Name }} else {{ $null }}); \
             links_read=$linksOk }}; \
           if($linksOk){{ $h['links']=@(if($lnk.ContainsKey($gid)){{ $lnk[$gid] }} else {{ @() }}) }}; \
           [pscustomobject]$h \
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
           [pscustomobject]@{{ scope=$(if($anc){{$anc.LocalName}}else{{$null}}); category=[string]$ct.InnerText; \
             setting=[string]$nm.InnerText; state=[string]$st.InnerText; value=$null }} \
         }}); \
         $sec=@($r.SelectNodes('//*[local-name()=\"SecurityOptions\" or local-name()=\"Account\" or local-name()=\"AuditSetting\"]') | ForEach-Object {{ \
           $anc=$_.SelectSingleNode('ancestor::*[local-name()=\"User\" or local-name()=\"Computer\"]'); \
           $ky=$_.SelectSingleNode('*[local-name()=\"KeyName\" or local-name()=\"Name\" or local-name()=\"SubcategoryName\"]'); \
           $vl=$_.SelectSingleNode('*[local-name()=\"SettingNumber\" or local-name()=\"SettingBoolean\" or local-name()=\"SettingString\" or local-name()=\"SettingValue\"]'); \
           if($ky){{ [pscustomobject]@{{ scope=$(if($anc){{$anc.LocalName}}else{{$null}}); category=('Security/'+$_.LocalName); \
             setting=[string]$ky.InnerText; state=$null; value=$(if($vl){{[string]$vl.InnerText}}else{{$null}}) }} }} \
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
           # IntegrationServicesVersion stringifies to '0.0' when it is not reported, and the old
           # fallback published that as if it were a version — every VM on this fleet, running ones
           # included, claimed to be on 0.0. Neither source answering is null, not a version number.
           $isvc=[string]$_.IntegrationServicesState; \
           if(-not $isvc){{ $iv=[string]$_.IntegrationServicesVersion; if($iv -and $iv -ne '0.0'){{ $isvc=$iv }} }}; \
           if(-not $isvc){{ $isvc=$null }}; \
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
         # NOTE: a PowerShell comment line inside this literal must NOT end with a backslash. That is
         # a Rust line-continuation, which strips the newline and pulls the next statement into the
         # comment, silently disabling it.
         # The two sources answer DIFFERENT subsets, so each null below means this source cannot say,
         # never that there is none. Get-RDUserSession knows the deployment (collection, host) but
         # not idle time; quser knows idle time but has no deployment concept. client_ip is emitted
         # by NEITHER - it was a hardcoded empty string in both branches, so every session read as
         # having no client address. Omitted instead; rds-session-events carries the source IP, from
         # the RemoteConnectionManager 1149 event that actually has it.
         if($rd.Count -gt 0){{ $rows=$rd | ForEach-Object {{ [pscustomobject]@{{ user=[string]$_.UserName; \
           session_id=[string]$_.UnifiedSessionId; state=[string]$_.SessionState; collection=[string]$_.CollectionName; \
           host=[string]$_.HostServer; client_name=[string]$_.ClientName; idle_time=$null; \
           logon_time=[string]$_.CreateTime }} }} }} \
         else {{ $rows=@(quser 2>$null | Select-Object -Skip 1 | ForEach-Object {{ \
           $ln=$_ -replace '^>',' '; $u=$ln.Substring(1,22).Trim(); $sn=$ln.Substring(23,18).Trim(); \
           $idp=$ln.Substring(41,4).Trim(); $stt=$ln.Substring(45,8).Trim(); $idl=$ln.Substring(53,11).Trim(); $lt=$ln.Substring(64).Trim(); \
           [pscustomobject]@{{ user=$u; session_id=$idp; state=$stt; collection=$null; host=$null; client_name=$sn; \
             idle_time=$idl; logon_time=$lt }} }}) }}; \
         # Zero rows is ambiguous, so decide WHICH kind of zero it is before reporting.
         # quser writes 'No User exists for *' to stderr when nobody is signed in - that is its EMPTY
         # answer, not a failure. Treating it as one made a quiet session host report the collector as
         # broken, which is the error-vs-absent lie in the other direction: it trains an operator to
         # ignore the collector, and an RDS host is legitimately empty most nights.
         if(@($rows).Count -eq 0){{ \
           if(@($Error | Where-Object {{ [string]$_ -match 'No User exists' }}).Count -gt 0){{ $Error.Clear() }} \
           else {{ Stop-OnError 'sessions' }} }}; \
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
           # An option whose DEFINITION is not registered on this server has no Name, and [string]
           # turns that into '' — a blank label a UI renders as though the option were nameless.
           # null says the name could not be resolved; option_id still identifies it.
           [pscustomobject]@{{ option_id=[int]$_.OptionId; name=$(if($_.Name){{ [string]$_.Name }} else {{ $null }}); \
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
         # VLAN lives on the ADAPTER, not the adapter's switch, and was previously a hardcoded ''.
         # This is the deep read for one VM, so the per-adapter call is affordable here in a way it
         # would not be in the `hyperv-vms` sweep. `vlan` is the access VLAN and is only meaningful
         # in Access mode: a trunk or untagged adapter reports the mode and a null id, rather than a
         # 0 that would read as VLAN zero.
         $nics=@(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {{ \
           $vl=Get-VMNetworkAdapterVlan -VMNetworkAdapter $_ -ErrorAction SilentlyContinue; \
           [pscustomobject]@{{ switch=[string]$_.SwitchName; \
             vlan_mode=$(if($vl){{ [string]$vl.OperationMode }} else {{ $null }}); \
             vlan=$(if($vl -and $vl.OperationMode -eq 'Access'){{ [int]$vl.AccessVlanId }} else {{ $null }}); \
             mac=[string]$_.MacAddress; ip=@($_.IPAddresses) -join ', ' }} }}); \
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
           # No `vlan` here: a VMSwitch has no VLAN of its own — VLAN tagging is a property of each
           # attached ADAPTER. The field was a hardcoded '' describing something that does not exist.
           # `hyperv-vm` reports vlan_mode/vlan per adapter, which is where the answer actually lives.
           [pscustomobject]@{{ name=[string]$_.Name; type=[string]$_.SwitchType; \
             net_adapter=[string]$_.NetAdapterInterfaceDescription; allow_mgmt_os=[bool]$_.AllowManagementOS }} \
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
         $deny=(Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; $Error.Clear(); \
         $cal=Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TSLicenseKeyPack -ErrorAction SilentlyContinue | Select-Object -First 1; \
         $col=@(Get-RDSessionCollection -ErrorAction SilentlyContinue); \
         # max_sessions / connection_broker / gateway / published_apps are NOT emitted. They used to be
         # hardcoded $null, which claims no source could answer about a read that never happened, so
         # a null gateway read as no-gateway-configured on a deployment that has one. Omitting the key
         # says the only true thing: this collector does not produce the field. rds-licensing answers
         # the deployment questions properly, by asking the broker.
         [pscustomobject]@{{ collection=$(if($col.Count -gt 0){{ [string]($col.CollectionName -join ', ') }} else {{ $null }}); \
           per_user_or_per_device_cal=$(if($cal){{ [string]$cal.TypeAndModel }} else {{ $null }}); \
           drain_mode=[int]$ts.SessionBrokerDrainMode; \
           drain_state=$(switch([int]$ts.SessionBrokerDrainMode){{ 0 {{'accepting'}} 1 {{'draining-until-restart'}} 2 {{'draining'}} default {{'unknown'}} }}); \
           logons_enabled=$(if($null -ne $deny){{ -not [bool]$deny }} else {{ $null }}); \
           server_mode=[int]$ts.TerminalServerMode }} \
         | ConvertTo-Json -Depth 4 -Compress"
    );
    ps_json_guarded(&script, "rds-config")
}
#[cfg(not(windows))]
fn rds_config(_params: Option<&str>) -> Option<Value> {
    None
}

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

/// Shared shape for the event-backed RDS collectors: `{since}` days back (default 1, max 90) and a row
/// cap. Kept here so the three collectors cannot drift on how a window is expressed.
#[cfg(windows)]
fn rds_window(p: &Value) -> (i64, i64) {
    let since = p.get("since").and_then(as_i64_loose).unwrap_or(1).clamp(1, 90);
    let max = p.get("max").and_then(as_i64_loose).unwrap_or(500).clamp(1, 2000);
    (since, max)
}

/// Interactive/remote logons on a session host (role `rdsh`) — Security **4624**, the question
/// "who logged on, when, from where". `params` `{since:"days (default 1, max 90)", user:"substring",
/// type:"int (a single LogonType)", max:"int", offset, limit}`.
///
/// Keeps LogonType **10** (RemoteInteractive), **2** (Interactive) and **11** (CachedInteractive), and
/// reports **7** (unlock) separately: an unlock is an activity signal, not a new logon, and counting it
/// as one inflates the daily figure on a host where people lock their screens.
///
/// Returns `{window_days, total, distinct_users, by_type, row_cap_hit, logons:{…page…}}`.
#[cfg(windows)]
fn rds_logons(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let (since, max) = rds_window(&p);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '\\' | '*' | '?')).take(128).collect()
    };
    let user_filter = p
        .get("user")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|u| format!(" | Where-Object {{ $_.user -like '*{}*' }}", safe(u)))
        .unwrap_or_default();
    let type_filter = match p.get("type").and_then(as_i64_loose) {
        Some(t) => format!(" | Where-Object {{ $_.logon_type -eq {} }}", t.clamp(0, 15)),
        None => String::new(),
    };
    let script = format!(
        "{PS_GUARD}\
         $ev=@(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-{since})}} \
           -MaxEvents {max} -ErrorAction SilentlyContinue); \
         Stop-OnError 'security log' -Ignore 'NoMatchingEventsFound'; \
         $rows=@($ev | ForEach-Object {{ \
           $pr=$_.Properties; \
           $u=[string]$pr[5].Value; $d=[string]$pr[6].Value; $lt=[int]$pr[8].Value; \
           if($u -like '*$'){{ return }}; \
           if($u -eq 'SYSTEM' -or $u -eq 'ANONYMOUS LOGON'){{ return }}; \
           if($u -like 'DWM-*' -or $u -like 'UMFD-*'){{ return }}; \
           if($lt -notin @(2,7,10,11)){{ return }}; \
           [pscustomobject]@{{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); user=$u; domain=$d; \
             logon_type=$lt; \
             logon_kind=$(switch($lt){{ 2 {{'interactive'}} 7 {{'unlock'}} 10 {{'remote-interactive'}} 11 {{'cached-interactive'}} default {{'other'}} }}); \
             source_ip=[string]$pr[18].Value; source_host=[string]$pr[11].Value; logon_id=[string]$pr[7].Value }} \
         }}){user_filter}{type_filter}; \
         $logons=@($rows | Where-Object {{ $_.logon_type -ne 7 }}); \
         [pscustomobject]@{{ \
           row_cap_hit=[bool]($ev.Count -ge {max}); \
           distinct_users=@($logons | ForEach-Object {{ $_.domain + '\\' + $_.user }} | Sort-Object -Unique).Count; \
           by_type=[pscustomobject]@{{ \
             interactive=@($rows | Where-Object {{ $_.logon_type -eq 2 }}).Count; \
             remote_interactive=@($rows | Where-Object {{ $_.logon_type -eq 10 }}).Count; \
             cached_interactive=@($rows | Where-Object {{ $_.logon_type -eq 11 }}).Count; \
             unlock=@($rows | Where-Object {{ $_.logon_type -eq 7 }}).Count }}; \
           rows=$rows }} | ConvertTo-Json -Depth 5 -Compress"
    );
    let raw = ps_json_guarded(&script, "rds-logons")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let rows = raw.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    Some(json!({
        "window_days": since,
        "total": rows.len(),
        "distinct_users": raw.get("distinct_users").cloned().unwrap_or_else(|| json!(0)),
        "by_type": raw.get("by_type").cloned().unwrap_or_else(|| json!({})),
        // Newest-first: a cap drops the OLDEST part of the window. Say so — a silently short window
        // reads as a quiet day.
        "row_cap_hit": raw.get("row_cap_hit").cloned().unwrap_or_else(|| json!(false)),
        "logons": paginate(rows, params, 200),
    }))
}
#[cfg(not(windows))]
fn rds_logons(_params: Option<&str>) -> Option<Value> {
    None
}

/// Failed logons on a session host (role `rdsh`) — Security **4625**. The brute-force / password-spray
/// view: nothing else in the console surfaces it. `params` `{since:"days (default 1, max 90)",
/// user:"substring", max:"int", offset, limit}`.
///
/// Returns `{window_days, total, row_cap_hit, by_user, by_source_ip, failures:{…page…}}` — the two
/// roll-ups are the point, since a spray shows as many users from one IP and a brute-force as one user
/// from one IP.
#[cfg(windows)]
fn rds_logon_failures(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let (since, max) = rds_window(&p);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '\\' | '*' | '?')).take(128).collect()
    };
    let user_filter = p
        .get("user")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|u| format!(" | Where-Object {{ $_.user -like '*{}*' }}", safe(u)))
        .unwrap_or_default();
    // 4625 substatus is the useful half: 0xC000006A = bad password, 0xC0000064 = no such user,
    // 0xC0000234 = locked out, 0xC0000072 = disabled. A spray shows as 0xC0000064 across many names.
    let script = format!(
        "{PS_GUARD}\
         $ev=@(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-{since})}} \
           -MaxEvents {max} -ErrorAction SilentlyContinue); \
         Stop-OnError 'security log' -Ignore 'NoMatchingEventsFound'; \
         function ToNtStatus($v){{ if($null -eq $v){{ return '' }}; $i=[int64]$v; if($i -lt 0){{ $i+=4294967296 }}; return ('0x{{0:x8}}' -f $i) }}; \
         $rows=@($ev | ForEach-Object {{ \
           $pr=$_.Properties; \
           # Status/SubStatus surface as a SIGNED Int32, so [string] yields '-1073741718' and every
           # comparison against an NTSTATUS code silently fails. Wrap to unsigned and format as hex.
           $sub=ToNtStatus $pr[9].Value; \
           [pscustomobject]@{{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); \
             user=[string]$pr[5].Value; domain=[string]$pr[6].Value; logon_type=[int]$pr[10].Value; \
             source_ip=[string]$pr[19].Value; source_host=[string]$pr[13].Value; \
             status=(ToNtStatus $pr[7].Value); substatus=$sub; \
             reason=$(switch($sub){{ '0xc000006a' {{'bad password'}} '0xc0000064' {{'no such user'}} \
               '0xc0000022' {{'access denied'}} '0xc000015b' {{'logon type not granted'}} \
               '0xc0000234' {{'account locked out'}} '0xc0000072' {{'account disabled'}} \
               '0xc0000070' {{'workstation restriction'}} '0xc000006f' {{'outside logon hours'}} default {{''}} }}) }} \
         }}){user_filter}; \
         [pscustomobject]@{{ \
           row_cap_hit=[bool]($ev.Count -ge {max}); \
           by_user=@($rows | Group-Object user | Sort-Object Count -Descending | Select-Object -First 25 | \
             ForEach-Object {{ [pscustomobject]@{{ user=$_.Name; count=$_.Count }} }}); \
           by_source_ip=@($rows | Where-Object {{ $_.source_ip -and $_.source_ip -ne '-' }} | Group-Object source_ip | \
             Sort-Object Count -Descending | Select-Object -First 25 | \
             ForEach-Object {{ [pscustomobject]@{{ source_ip=$_.Name; count=$_.Count }} }}); \
           rows=$rows }} | ConvertTo-Json -Depth 5 -Compress"
    );
    let raw = ps_json_guarded(&script, "rds-logon-failures")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let rows = raw.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    Some(json!({
        "window_days": since,
        "total": rows.len(),
        "row_cap_hit": raw.get("row_cap_hit").cloned().unwrap_or_else(|| json!(false)),
        "by_user": raw.get("by_user").cloned().unwrap_or_else(|| json!([])),
        "by_source_ip": raw.get("by_source_ip").cloned().unwrap_or_else(|| json!([])),
        "failures": paginate(rows, params, 200),
    }))
}
#[cfg(not(windows))]
fn rds_logon_failures(_params: Option<&str>) -> Option<Value> {
    None
}

/// The session TIMELINE on a session host (role `rdsh`) — LocalSessionManager/Operational
/// **21/22/23/24/25/40** plus RemoteConnectionManager **1149**, merged newest-first.
/// `params` `{since:"days (default 1, max 90)", user:"substring", max:"int", offset, limit}`.
///
/// This is the collector the operational-channel bug hid: those events are **Informational**, so the
/// old default level filter matched nothing and the channel read as unreadable. 1149 is the pre-auth
/// connection attempt and carries the SOURCE IP, which the LocalSessionManager events do not — pairing
/// them is what turns "someone reconnected" into "someone reconnected from here".
#[cfg(windows)]
fn rds_session_events(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let (since, max) = rds_window(&p);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '\\' | '*' | '?')).take(128).collect()
    };
    let user_filter = p
        .get("user")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|u| format!(" | Where-Object {{ $_.user -like '*{}*' }}", safe(u)))
        .unwrap_or_default();
    let script = format!(
        "{PS_GUARD}\
         $lsm='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; \
         $rcm='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; \
         $a=@(Get-WinEvent -FilterHashtable @{{LogName=$lsm; Id=@(21,22,23,24,25,40); StartTime=(Get-Date).AddDays(-{since})}} \
           -MaxEvents {max} -ErrorAction SilentlyContinue); \
         $b=@(Get-WinEvent -FilterHashtable @{{LogName=$rcm; Id=1149; StartTime=(Get-Date).AddDays(-{since})}} \
           -MaxEvents {max} -ErrorAction SilentlyContinue); \
         if($a.Count -eq 0 -and $b.Count -eq 0){{ Stop-OnError 'terminal-services channels' -Ignore 'NoMatchingEventsFound' }}; \
         $Error.Clear(); \
         $rows=@(); \
         $rows+=@($a | ForEach-Object {{ \
           $x=[xml]$_.ToXml(); $u=[string]($x.Event.UserData.EventXML.User); $sid=[string]($x.Event.UserData.EventXML.SessionID); \
           $addr=[string]($x.Event.UserData.EventXML.Address); \
           [pscustomobject]@{{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id=[int]$_.Id; \
             event=$(switch([int]$_.Id){{ 21 {{'logon'}} 22 {{'shell-start'}} 23 {{'logoff'}} 24 {{'disconnected'}} 25 {{'reconnected'}} 40 {{'disconnect-reason'}} default {{'other'}} }}); \
             user=$u; session_id=$sid; source_ip=$addr; source=  'LocalSessionManager' }} }}); \
         $rows+=@($b | ForEach-Object {{ \
           $x=[xml]$_.ToXml(); $ud=$x.Event.UserData.EventXML; \
           [pscustomobject]@{{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id=1149; event='connection-authenticated'; \
             user=([string]$ud.Param1 + $(if($ud.Param2){{'@' + [string]$ud.Param2}}else{{''}})); session_id=''; \
             source_ip=[string]$ud.Param3; source='RemoteConnectionManager' }} }}); \
         @($rows | Sort-Object time -Descending){user_filter} | ConvertTo-Json -Depth 4 -Compress"
    );
    let items = match ps_rows_guarded(&script, "rds-session-events") {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    Some(json!({ "window_days": since, "total": items.len(), "events": paginate(items, params, 200) }))
}
#[cfg(not(windows))]
fn rds_session_events(_params: Option<&str>) -> Option<Value> {
    None
}

/// Per-SESSION resource attribution on a session host (role `rdsh`) — processes grouped by session id
/// and rolled up to CPU / memory per *user session*. `params` `{min_mb:"int (default 0)",
/// top_n:"int processes per session (default 5, max 20)", user:"substring", offset, limit}`.
///
/// This answers "the RDS is slow — who?", which neither `perf` (top processes, no session mapping) nor
/// `rds-sessions` (sessions, no resource cost) can answer alone. It also surfaces **disconnected
/// sessions still holding memory** — the quiet capacity leak on a session host, where someone closed
/// the window days ago and their profile is still resident.
#[cfg(windows)]
fn rds_session_perf(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let min_mb = p.get("min_mb").and_then(as_i64_loose).unwrap_or(0).clamp(0, 1_000_000);
    let top_n = p.get("top_n").and_then(as_i64_loose).unwrap_or(5).clamp(1, 20);
    let safe = |s: &str| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '\\' | '*' | '?')).take(128).collect()
    };
    let user_filter = p
        .get("user")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|u| format!(" | Where-Object {{ $_.user -like '*{}*' }}", safe(u)))
        .unwrap_or_default();
    // `quser` is the session-id -> user/state join. Get-Process carries SessionId but no user, and
    // asking Get-Process for the owner costs a WMI call per process — far more expensive than one
    // quser parse for the same answer.
    let script = format!(
        "{PS_GUARD}\
         $procs=@(Get-Process); Stop-OnError 'processes'; \
         $sess=@{{}}; \
         foreach($ln in @(quser 2>$null | Select-Object -Skip 1)){{ \
           $l=$ln -replace '^>',' '; \
           $u=$l.Substring(1,22).Trim(); $id=$l.Substring(41,4).Trim(); $st=$l.Substring(45,8).Trim(); $idle=$l.Substring(53,11).Trim(); \
           if($id -match '^\\d+$'){{ $sess[[int]$id]=[pscustomobject]@{{ user=$u; state=$st; idle=$idle }} }} \
         }}; \
         $Error.Clear(); \
         $rows=@($procs | Group-Object SessionId | ForEach-Object {{ \
           $sid=[int]$_.Name; $g=$_.Group; \
           $info=$sess[$sid]; \
           $mem=[math]::Round((($g | Measure-Object WorkingSet64 -Sum).Sum)/1MB,1); \
           $cpu=[math]::Round((($g | Measure-Object CPU -Sum).Sum),1); \
           [pscustomobject]@{{ session_id=$sid; \
             user=$(if($info){{$info.user}}else{{''}}); \
             state=$(if($info){{$info.state}}else{{$(if($sid -eq 0){{'services'}}else{{'unknown'}})}}); \
             idle=$(if($info){{$info.idle}}else{{''}}); \
             process_count=$g.Count; memory_mb=$mem; cpu_seconds=$cpu; \
             top_processes=@($g | Sort-Object WorkingSet64 -Descending | Select-Object -First {top_n} | \
               ForEach-Object {{ [pscustomobject]@{{ name=$_.Name; pid=$_.Id; \
                 memory_mb=[math]::Round($_.WorkingSet64/1MB,1); cpu_seconds=[math]::Round([double]$_.CPU,1) }} }}) }} \
         }} | Where-Object {{ $_.memory_mb -ge {min_mb} }}){user_filter} | Sort-Object memory_mb -Descending; \
         [pscustomobject]@{{ \
           disconnected_holding_mb=[math]::Round((@($rows | Where-Object {{ $_.state -like 'Disc*' }} | \
             Measure-Object memory_mb -Sum).Sum),1); \
           disconnected_sessions=@($rows | Where-Object {{ $_.state -like 'Disc*' }}).Count; \
           rows=$rows }} | ConvertTo-Json -Depth 6 -Compress"
    );
    let raw = ps_json_guarded(&script, "rds-session-perf")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let rows = raw.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    Some(json!({
        "total_sessions": rows.len(),
        // The capacity leak, called out rather than left to be summed by eye.
        "disconnected_sessions": raw.get("disconnected_sessions").cloned().unwrap_or_else(|| json!(0)),
        "disconnected_holding_mb": raw.get("disconnected_holding_mb").cloned().unwrap_or_else(|| json!(0)),
        "sessions": paginate(rows, params, 100),
    }))
}
#[cfg(not(windows))]
fn rds_session_perf(_params: Option<&str>) -> Option<Value> {
    None
}

/// RD licensing posture (role `rdsh`) — the classic silent RDS killer. No params. Single object.
///
/// **The 120-day grace period is the point.** A session host with no reachable licence server keeps
/// working until the grace expires and then refuses connections outright, with nothing in the UI
/// counting down. `grace_days_left` comes from `Win32_TerminalServiceSetting.GetGracePeriodDays()`,
/// which is the same number the OS itself acts on.
///
/// Also reports the configured licence servers and mode (per-user / per-device) from policy and from
/// the service's own parameters, the installed CAL key packs, and recent licensing events
/// (**1128/1130/1136** — licence server discovery + grace warnings).
#[cfg(windows)]
fn rds_licensing(_params: Option<&str>) -> Option<Value> {
    let script = format!(
        "{PS_GUARD}\
         $ts=Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TerminalServiceSetting; \
         Stop-OnError 'terminal-server settings'; \
         $grace=$null; \
         try {{ $grace=[int](Invoke-CimMethod -InputObject $ts -MethodName GetGracePeriodDays -ErrorAction Stop).DaysLeft }} catch {{}}; \
         $Error.Clear(); \
         $pol='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'; \
         $gp=Get-ItemProperty -LiteralPath $pol -ErrorAction SilentlyContinue; $Error.Clear(); \
         $svc=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters' -ErrorAction SilentlyContinue; $Error.Clear(); \
         # CAL key packs live in root\\cimv2, NOT root\\cimv2\\TerminalServices — querying the latter
         # returned an empty list on a server holding real CALs. They exist only where the RD Licensing
         # ROLE runs, which on a small deployment is often the session host itself.
         # [uint32] not [int]: the built-in placeholder pack carries 4294967295, which overflows Int32.
         # 0xFFFFFFFF is the UNLIMITED sentinel, not a count — reported as null so that summing the
         # per-pack rows cannot silently produce four billion. `built_in` is what says the pack is the
         # unlimited placeholder; each field is tested on its own rather than assuming which carry it.
         $packs=@(Get-CimInstance -Namespace root\\cimv2 -ClassName Win32_TSLicenseKeyPack -ErrorAction SilentlyContinue | \
           ForEach-Object {{ [pscustomobject]@{{ type=[string]$_.TypeAndModel; \
             total=$(if ([uint32]$_.TotalLicenses -eq 4294967295) {{ $null }} else {{ [uint32]$_.TotalLicenses }}); \
             issued=$(if ([uint32]$_.IssuedLicenses -eq 4294967295) {{ $null }} else {{ [uint32]$_.IssuedLicenses }}); \
             available=$(if ([uint32]$_.AvailableLicenses -eq 4294967295) {{ $null }} else {{ [uint32]$_.AvailableLicenses }}); \
             product=[string]$_.ProductVersion; expires=[string]$_.ExpirationDate; \
             built_in=[bool]([uint32]$_.TotalLicenses -eq 4294967295) }} }}); $Error.Clear(); \
         $real=@($packs | Where-Object {{ -not $_.built_in }}); \
         $evts=@(Get-WinEvent -FilterHashtable @{{LogName='System'; Id=@(1128,1130,1136); StartTime=(Get-Date).AddDays(-30)}} \
           -MaxEvents 40 -ErrorAction SilentlyContinue | ForEach-Object {{ \
             [pscustomobject]@{{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id=[int]$_.Id; \
               message=(($_.Message -split \"`n\")[0]) }} }}); $Error.Clear(); \
         $mode=[int]$gp.LicensingMode; \
         # A DEPLOYMENT keeps its licensing on the connection broker, not in this host's policy or
         # service keys — which is why reading only those returned 'nothing configured' on a perfectly
         # licensed session host. Ask the deployment too, and record WHY when it cannot be asked
         # rather than letting an unanswerable question look like a negative answer.
         $dok=$false; $derr=$null; $dsrv=$null; $dmode=$null; \
         try {{ \
           $lc=Get-RDLicenseConfiguration -ErrorAction Stop; \
           $dok=$true; \
           $dsrv=@($lc.LicenseServer | Where-Object {{ $_ }}); \
           $dmode=[string]$lc.Mode \
         }} catch {{ $derr=(\"$($_.Exception.Message)\" -replace '\\s+',' ') }}; \
         $Error.Clear(); \
         # Best available answer, most authoritative first. NULL — not [] — when no source could
         # answer at all, so 'undetermined' never renders as 'none'.
         $eff=$(if($dok -and @($dsrv).Count -gt 0){{ $dsrv }} \
           elseif($gp -and $null -ne $gp.LicenseServers){{ @($gp.LicenseServers | Where-Object {{ $_ }}) }} \
           elseif($svc -and $null -ne $svc.LicenseServers){{ @($svc.LicenseServers | Where-Object {{ $_ }}) }} \
           else {{ $null }}); \
         # Re-wrap as a STATEMENT, not inside the $( ) above: a subexpression unwraps a one-element
         # array, so a deployment with a single licence server emitted a bare string here while the
         # sibling field stayed an array — a field whose TYPE depended on how many servers exist.
         if($null -ne $eff){{ $eff=@($eff) }}; \
         [pscustomobject]@{{ \
           terminal_server_mode=[int]$ts.TerminalServerMode; \
           licensing_type=[int]$ts.LicensingType; \
           licensing_mode=$(switch($mode){{ 2 {{'per-device'}} 4 {{'per-user'}} default {{$dmode}} }}); \
           licensing_mode_raw=$(if($gp -and $null -ne $gp.LicensingMode){{ $mode }} else {{ $null }}); \
           # NULL when the value is absent, [] only when it is present and empty. An empty array here
           # previously read as 'no licence server configured' on a deployment that simply keeps the
           # setting somewhere else entirely.
           license_servers_policy=$(if($gp -and $null -ne $gp.LicenseServers){{ @($gp.LicenseServers | Where-Object {{ $_ }}) }} else {{ $null }}); \
           deployment_queried=$dok; \
           deployment_error=$derr; \
           license_servers_deployment=$dsrv; \
           license_servers_effective=$eff; \
           licensing_configured=$(if($null -ne $eff){{ [bool](@($eff).Count -gt 0) }} else {{ $null }}); \
           # grace_days_left is 0 BOTH when grace expired and when grace never applied because the
           # host is licensed — the number alone cannot tell those apart, and alerting on '< 30'
           # would fire on every correctly-licensed server. grace_period_active is the one to gate on.
           grace_period_active=[bool]($grace -gt 0); \
           grace_expiry_events=@($evts | Where-Object {{ $_.id -eq 1128 }}).Count; \
           license_servers_service=@($svc.LicenseServers | Where-Object {{ $_ }}); \
           grace_days_left=$grace; \
           cal_key_packs=$packs; \
           cal_total=$(if(@($real).Count){{ (@($real) | Measure-Object total -Sum).Sum }} else {{ $null }}); \
           cal_issued=$(if(@($real).Count){{ (@($real) | Measure-Object issued -Sum).Sum }} else {{ $null }}); \
           cal_available=$(if(@($real).Count){{ (@($real) | Measure-Object available -Sum).Sum }} else {{ $null }}); \
           recent_events=$evts }} | ConvertTo-Json -Depth 5 -Compress"
    );
    ps_json_guarded(&script, "rds-licensing")
}
#[cfg(not(windows))]
fn rds_licensing(_params: Option<&str>) -> Option<Value> {
    None
}

/// Remote-session transport + link quality (role `rdsh`). No params. Single object.
///
/// Two investigations that each took a manual dig now cost one dispatch: **is UDP actually in use**
/// (RDP falls back to TCP silently, and a TCP-only session is the usual explanation for "it feels
/// laggy but the network is fine"), and **what the measured RTT is**. `udp_disabled_by_policy` is the
/// first thing to check — the fallback is often a policy nobody remembers setting.
///
/// RemoteFX counters exist only while a session is connected; with none, the counter block is `null`
/// rather than zeroed, so "no sessions" cannot read as "no latency".
#[cfg(windows)]
fn rds_connection_quality(_params: Option<&str>) -> Option<Value> {
    let script = format!(
        "{PS_GUARD}\
         $pol='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'; \
         $gp=Get-ItemProperty -LiteralPath $pol -ErrorAction SilentlyContinue; $Error.Clear(); \
         $ws=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue; $Error.Clear(); \
         $ctr=$null; \
         try {{ \
           $s=Get-Counter -Counter '\\RemoteFX Network(*)\\Current TCP RTT','\\RemoteFX Network(*)\\Current UDP RTT',\
'\\RemoteFX Network(*)\\Current TCP Bandwidth','\\RemoteFX Network(*)\\Current UDP Bandwidth' -ErrorAction Stop; \
           $ctr=@($s.CounterSamples | ForEach-Object {{ [pscustomobject]@{{ counter=[string]$_.Path; \
             instance=[string]$_.InstanceName; value=[math]::Round([double]$_.CookedValue,2) }} }}) \
         }} catch {{}}; \
         $Error.Clear(); \
         $udpEvents=@(Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; \
           Id=@(131,140); StartTime=(Get-Date).AddDays(-1)}} -MaxEvents 40 -ErrorAction SilentlyContinue | \
           ForEach-Object {{ [pscustomobject]@{{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id=[int]$_.Id; \
             message=(($_.Message -split \"`n\")[0]) }} }}); $Error.Clear(); \
         [pscustomobject]@{{ \
           udp_disabled_by_policy=$(if($gp -and $null -ne $gp.fClientDisableUDP){{ [bool]$gp.fClientDisableUDP }} else {{ $false }}); \
           # Policy is an OVERRIDE, not the setting. Reporting only the policy key returns null on a
           # host that has an effective value sitting in WinStations — 'no policy set' presented as
           # 'unknown'. Report both, and say which one the listener is actually running with.
           select_transport_policy=$(if($gp -and $null -ne $gp.SelectTransport){{ [int]$gp.SelectTransport }} else {{ $null }}); \
           select_transport_effective=$(if($gp -and $null -ne $gp.SelectTransport){{ [int]$gp.SelectTransport }} \
             elseif($ws -and $null -ne $ws.SelectTransport){{ [int]$ws.SelectTransport }} else {{ $null }}); \
           select_transport_source=$(if($gp -and $null -ne $gp.SelectTransport){{ 'policy' }} \
             elseif($ws -and $null -ne $ws.SelectTransport){{ 'winstation' }} else {{ $null }}); \
           security_layer=$(if($ws -and $null -ne $ws.SecurityLayer){{ [int]$ws.SecurityLayer }} else {{ $null }}); \
           min_encryption_level=$(if($ws -and $null -ne $ws.MinEncryptionLevel){{ [int]$ws.MinEncryptionLevel }} else {{ $null }}); \
           user_authentication=$(if($ws -and $null -ne $ws.UserAuthentication){{ [int]$ws.UserAuthentication }} else {{ $null }}); \
           nla_required=$(if($ws -and $null -ne $ws.UserAuthentication){{ [bool][int]$ws.UserAuthentication }} else {{ $null }}); \
           # A backup value beside a differing live one means something switched NLA deliberately and
           # stashed the prior setting — worth seeing next to the live value rather than inferring.
           user_authentication_backup=$(if($ws -and $null -ne $ws.UserAuthenticationBackup){{ [int]$ws.UserAuthenticationBackup }} else {{ $null }}); \
           remotefx_counters=$ctr; \
           counters_available=[bool]($null -ne $ctr); \
           recent_transport_events=$udpEvents }} | ConvertTo-Json -Depth 5 -Compress"
    );
    ps_json_guarded(&script, "rds-connection-quality")
}
#[cfg(not(windows))]
fn rds_connection_quality(_params: Option<&str>) -> Option<Value> {
    None
}

/// User-profile posture on a session host (role `rdsh`). `params` `{sizes:"bool (default false)",
/// offset, limit}`. Paginated.
///
/// **Temp-profile logons are a top-5 RDS ticket and invisible until a user complains** — the symptom
/// is a `.bak` suffix on the account's `ProfileList` key, which this reports directly as
/// `temp_profile_suspected`. Also reports FSLogix and UPD configuration, since on a host using either,
/// a local profile appearing at all is itself the anomaly.
///
/// `sizes:true` walks each profile directory to total it, which is expensive on a busy host — off by
/// default, and the reason it is a parameter rather than always-on.
#[cfg(windows)]
fn rds_profiles(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let want_sizes = p.get("sizes").and_then(|x| x.as_bool()).unwrap_or(false);
    let size_expr = match want_sizes {
        true => "size_mb=$(try{ [math]::Round((Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum/1MB,1) }catch{ $null });",
        false => "size_mb=$null;",
    };
    let script = format!(
        "{PS_GUARD}\
         $pl='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'; \
         $keys=@(Get-ChildItem -LiteralPath $pl -ErrorAction SilentlyContinue); Stop-OnError 'profile list'; \
         $rows=@($keys | ForEach-Object {{ \
           $sid=$_.PSChildName; $pp=(Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue); \
           $path=[string]$pp.ProfileImagePath; \
           $acct=''; try {{ $acct=(New-Object System.Security.Principal.SecurityIdentifier($sid -replace '\\.bak$','')).Translate([System.Security.Principal.NTAccount]).Value }} catch {{}}; \
           [pscustomobject]@{{ sid=$sid; account=$acct; profile_path=$path; \
             temp_profile_suspected=[bool]($sid -like '*.bak'); \
             state=[int]$pp.State; \
             # Both halves are UInt32 stored in a signed DWORD, so the low word must be widened as
             # UNSIGNED before the OR — sign-extending it corrupts the whole FILETIME. Absent on a
             # profile that has never been unloaded, which is why this is '' rather than a guess.
             last_use=$(if($null -ne $pp.LocalProfileUnloadTimeHigh -and $null -ne $pp.LocalProfileUnloadTimeLow){{ \
               try{{ [datetime]::FromFileTime((([int64][uint32]$pp.LocalProfileUnloadTimeHigh) -shl 32) -bor ([int64][uint32]$pp.LocalProfileUnloadTimeLow)).ToString('yyyy-MM-dd HH:mm:ss') }}catch{{ $null }} }}else{{ '' }}); \
             {size_expr} }} \
         }}); \
         $Error.Clear(); \
         $fsl=Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\FSLogix\\Profiles' -ErrorAction SilentlyContinue; $Error.Clear(); \
         [pscustomobject]@{{ \
           fslogix_enabled=$(if($fsl -and $null -ne $fsl.Enabled){{ [bool]$fsl.Enabled }} else {{ $false }}); \
           fslogix_vhd_locations=@($fsl.VHDLocations | Where-Object {{ $_ }}); \
           temp_profile_count=@($rows | Where-Object {{ $_.temp_profile_suspected }}).Count; \
           rows=$rows }} | ConvertTo-Json -Depth 5 -Compress"
    );
    let raw = ps_json_guarded(&script, "rds-profiles")?;
    if is_collector_error(&raw) {
        return Some(raw);
    }
    let rows = raw.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    Some(json!({
        "total": rows.len(),
        "temp_profile_count": raw.get("temp_profile_count").cloned().unwrap_or_else(|| json!(0)),
        "fslogix_enabled": raw.get("fslogix_enabled").cloned().unwrap_or_else(|| json!(false)),
        "fslogix_vhd_locations": raw.get("fslogix_vhd_locations").cloned().unwrap_or_else(|| json!([])),
        "sizes_included": want_sizes,
        "profiles": paginate(rows, params, 200),
    }))
}
#[cfg(not(windows))]
fn rds_profiles(_params: Option<&str>) -> Option<Value> {
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
    .or_else(|| Some(json!({ "ok": false, "error": "activation produced no parseable output — the read failed" })))
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
# Run a Windows admin tool by NAME, resolved to its System32 .exe by absolute path — never through
# PATHEXT. PATHEXT will happily resolve a bare `wbadmin` to wbadmin.msc when the Windows Server Backup
# feature is absent (the orphan snap-in ships with the OS), and PowerShell hands a .msc to MMC: a GUI
# opens ON THE ENDPOINT'S DESKTOP and never exits, so the collector hangs to timeout and the customer
# watches a management console appear during a read-only audit. Many admin tools have a .msc sibling,
# so this is a general trap, not a wbadmin quirk. A missing .exe throws — an honest error the caller
# reports — rather than silently launching whatever else carries that name.
function Invoke-Native { param([string]$Tool,[string[]]$ToolArgs=@()) $exe=Join-Path $env:SystemRoot "System32\$Tool.exe"; if(-not (Test-Path -LiteralPath $exe)){ throw "native tool not installed: $Tool.exe" }; & { $ErrorActionPreference='Continue'; (& $exe @ToolArgs) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $raw = Invoke-Native 'vssadmin' @('list','writers')
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
    .or_else(|| Some(json!({ "ok": false, "error": "vss-health produced no parseable output — the read failed" })))
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
# Run a Windows admin tool by NAME, resolved to its System32 .exe by absolute path — never through
# PATHEXT. PATHEXT will happily resolve a bare `wbadmin` to wbadmin.msc when the Windows Server Backup
# feature is absent (the orphan snap-in ships with the OS), and PowerShell hands a .msc to MMC: a GUI
# opens ON THE ENDPOINT'S DESKTOP and never exits, so the collector hangs to timeout and the customer
# watches a management console appear during a read-only audit. Many admin tools have a .msc sibling,
# so this is a general trap, not a wbadmin quirk. A missing .exe throws — an honest error the caller
# reports — rather than silently launching whatever else carries that name.
function Invoke-Native { param([string]$Tool,[string[]]$ToolArgs=@()) $exe=Join-Path $env:SystemRoot "System32\$Tool.exe"; if(-not (Test-Path -LiteralPath $exe)){ throw "native tool not installed: $Tool.exe" }; & { $ErrorActionPreference='Continue'; (& $exe @ToolArgs) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $r = [ordered]@{}
  $svc = Get-Service wbengine -ErrorAction SilentlyContinue
  $r.wbengine = if ($svc) { [string]$svc.Status } else { 'absent' }
  # Resolve wbadmin as the EXE, by absolute path. A bare `wbadmin` resolves through PATHEXT, and on a
  # host where the Windows Server Backup FEATURE is not installed the only wbadmin.* left in System32
  # is wbadmin.msc — the MMC snap-in. PowerShell then launches the Server Backup GUI on the endpoint's
  # DESKTOP, where it sits open until someone closes it and this collector hangs until the job times
  # out. Never invoke a Windows admin tool by bare name: many have a .msc sibling.
  $wb = Join-Path $env:SystemRoot 'System32\wbadmin.exe'
  if (-not (Test-Path -LiteralPath $wb)) {
    # A distinct answer from "no backups": the tool is not installed, so there is nothing to ask.
    $r.wbadmin        = 'absent'
    $r.wbadmin_exit   = $null
    $r.backup_count   = $null
    $r.latest_version = $null
  }
  else {
    $ver = Invoke-Native 'wbadmin' @('get','versions')
    $r.wbadmin_exit = $LASTEXITCODE
    $ids = @([regex]::Matches($ver, 'Version identifier:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
    if ($r.wbadmin_exit -ne 0 -and $ids.Count -eq 0 -and $ver -notmatch 'No backup') {
      $tail = @(($ver.Trim() -split "`r?`n") | Where-Object { $_.Trim() })[-1]
      throw "wbadmin exit $($r.wbadmin_exit) : $tail"
    }
    $r.backup_count   = $ids.Count
    $r.latest_version = if ($ids.Count) { $ids[-1] } else { $null }
    # WHERE those backups live, and what they can restore — both from the same listing. A host with
    # backups but no WSB schedule is not necessarily unprotected: something else may be both driving
    # and protecting them. The console cannot judge that without knowing the path, and "Can recover"
    # answers the system-state question directly instead of leaving it undetermined.
    $tg = @([regex]::Matches($ver, 'Backup target:\s*(.+)') | ForEach-Object { $_.Groups[1].Value.Trim() })
    $cr = @([regex]::Matches($ver, 'Can recover:\s*(.+)')   | ForEach-Object { $_.Groups[1].Value.Trim() })
    $r.targets            = @($tg | Select-Object -Unique)
    $r.latest_target      = if ($tg.Count) { $tg[-1] } else { $null }
    $r.latest_can_recover = if ($cr.Count) { $cr[-1] } else { $null }
    # null = the listing never said, which is NOT the same as "system state is missing".
    $r.system_state_in_versions = if ($cr.Count) { [bool]($cr[-1] -match 'System State') } else { $null }
  }
  try {
    $pol = Get-WBPolicy -ErrorAction Stop
    $r.scheduled              = [bool]$pol
    $r.system_state_in_policy = if ($pol) { [bool]$pol.SystemState } else { $false }
  } catch { $r.policy = "unavailable: $($_.Exception.Message)" }
  $r | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#)
    .or_else(|| Some(json!({ "ok": false, "error": "backup-state produced no parseable output — the read failed" })))
}
#[cfg(not(windows))]
fn backup_state(_params: Option<&str>) -> Option<Value> {
    None
}

/// DC health summary (role `addc`) — `dcdiag /q` failure lines plus a passive `_ldap`/`_kerberos`
/// SRV-registration check (`Resolve-DnsName`, never dcdiag's dynamic-update-path probe).
/// `params` JSON `{test:"Replications"}` runs that one named test instead of the full sweep; `/q` is
/// kept either way, so `errors` stays "failure lines only" and `quiet_output_empty` keeps its meaning.
/// The result echoes `test` (null for the full sweep) so a narrowed run can't be read as a whole one.
/// `quiet_output_empty` is a benign-warning-sensitive signal, not a "passed" verdict. `dcdiag` can take
/// tens of seconds — callers should allow a generous wait.
#[cfg(windows)]
fn dcdiag(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    // `test` reaches a command line, so it is VALIDATED, not sanitized: silently stripping a character
    // would run a DIFFERENT test than the caller named and report it under the name they asked for.
    // dcdiag test names are bare identifiers, so anything outside [A-Za-z0-9] is refused outright.
    let test = p.get("test").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let (dc_args, test_lit) = match test {
        None => ("@('/q')".to_owned(), "$null".to_owned()),
        Some(t) => {
            if t.len() > 64 || !t.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Some(json!({ "ok": false, "error": "dcdiag test must be a bare test name, ASCII letters and digits only, max 64 chars (e.g. Connectivity, Replications, Services, DNS)" }));
            }
            // RegisterInDNS probes the DNS dynamic-update path against production even without /fix.
            // This collector is passive by contract, so the test stays unreachable however it is spelled.
            if t.eq_ignore_ascii_case("RegisterInDNS") {
                return Some(json!({ "ok": false, "error": "dcdiag test RegisterInDNS is not permitted: it exercises the DNS dynamic-update path, and this collector is passive/read-only" }));
            }
            (format!("@('/test:{t}','/q')"), format!("'{t}'"))
        }
    };
    ps_json(&format!("$dcArgs={dc_args}\n$dcTest={test_lit}\n{DCDIAG_BODY}"))
    .or_else(|| Some(json!({ "ok": false, "error": "dcdiag produced no parseable output — the read failed" })))
}

/// The `dcdiag` script body. Reads `$dcArgs` (the argument list) and `$dcTest` (the test name, or
/// `$null` for the full sweep), both set by [`dcdiag`] ahead of it.
#[cfg(windows)]
const DCDIAG_BODY: &str = r#"$ErrorActionPreference='Stop'
# Run a Windows admin tool by NAME, resolved to its System32 .exe by absolute path — never through
# PATHEXT. PATHEXT will happily resolve a bare `wbadmin` to wbadmin.msc when the Windows Server Backup
# feature is absent (the orphan snap-in ships with the OS), and PowerShell hands a .msc to MMC: a GUI
# opens ON THE ENDPOINT'S DESKTOP and never exits, so the collector hangs to timeout and the customer
# watches a management console appear during a read-only audit. Many admin tools have a .msc sibling,
# so this is a general trap, not a wbadmin quirk. A missing .exe throws — an honest error the caller
# reports — rather than silently launching whatever else carries that name.
function Invoke-Native { param([string]$Tool,[string[]]$ToolArgs=@()) $exe=Join-Path $env:SystemRoot "System32\$Tool.exe"; if(-not (Test-Path -LiteralPath $exe)){ throw "native tool not installed: $Tool.exe" }; & { $ErrorActionPreference='Continue'; (& $exe @ToolArgs) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $dom = (Get-CimInstance Win32_ComputerSystem).Domain
  $raw = Invoke-Native 'dcdiag' $dcArgs
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
    test               = $dcTest
    quiet_output_empty = [string]::IsNullOrWhiteSpace($raw.Trim())
    errors             = $errLines
    srv_records        = $srv
  } | ConvertTo-Json -Depth 5 -Compress
} catch { @{ ok=$false; error=$_.Exception.Message } | ConvertTo-Json -Compress }"#;
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
# Run a Windows admin tool by NAME, resolved to its System32 .exe by absolute path — never through
# PATHEXT. PATHEXT will happily resolve a bare `wbadmin` to wbadmin.msc when the Windows Server Backup
# feature is absent (the orphan snap-in ships with the OS), and PowerShell hands a .msc to MMC: a GUI
# opens ON THE ENDPOINT'S DESKTOP and never exits, so the collector hangs to timeout and the customer
# watches a management console appear during a read-only audit. Many admin tools have a .msc sibling,
# so this is a general trap, not a wbadmin quirk. A missing .exe throws — an honest error the caller
# reports — rather than silently launching whatever else carries that name.
function Invoke-Native { param([string]$Tool,[string[]]$ToolArgs=@()) $exe=Join-Path $env:SystemRoot "System32\$Tool.exe"; if(-not (Test-Path -LiteralPath $exe)){ throw "native tool not installed: $Tool.exe" }; & { $ErrorActionPreference='Continue'; (& $exe @ToolArgs) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $r = [ordered]@{}
  $source = (Invoke-Native 'w32tm' @('/query','/source')).Trim()
  if ($LASTEXITCODE -eq 0) {
    $r.source         = $source
    $r.vm_ic_provider = ($source -like '*VM IC*')
  } else { $r.source_error = "w32tm /source exit $LASTEXITCODE : $source" }
  $statusRaw = Invoke-Native 'w32tm' @('/query','/status','/verbose')
  if ($LASTEXITCODE -eq 0) {
    $r.stratum      = if ($statusRaw -match 'Stratum:\s*(\d+)')                  { [int]$Matches[1] }   else { $null }
    $r.phase_offset = if ($statusRaw -match 'Phase Offset:\s*(\S+)')             { $Matches[1] }        else { $null }
    $r.last_sync    = if ($statusRaw -match 'Last Successful Sync Time:\s*(.+)') { $Matches[1].Trim() } else { $null }
  } else { $r.status_error = "w32tm /status exit $LASTEXITCODE : $($statusRaw.Trim())" }
  $cfgRaw = Invoke-Native 'w32tm' @('/query','/configuration')
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
    .or_else(|| Some(json!({ "ok": false, "error": "timesync produced no parseable output — the read failed" })))
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
    .or_else(|| Some(json!({ "ok": false, "error": "ldaps-check produced no parseable output — the read failed" })))
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
# Run a Windows admin tool by NAME, resolved to its System32 .exe by absolute path — never through
# PATHEXT. PATHEXT will happily resolve a bare `wbadmin` to wbadmin.msc when the Windows Server Backup
# feature is absent (the orphan snap-in ships with the OS), and PowerShell hands a .msc to MMC: a GUI
# opens ON THE ENDPOINT'S DESKTOP and never exits, so the collector hangs to timeout and the customer
# watches a management console appear during a read-only audit. Many admin tools have a .msc sibling,
# so this is a general trap, not a wbadmin quirk. A missing .exe throws — an honest error the caller
# reports — rather than silently launching whatever else carries that name.
function Invoke-Native { param([string]$Tool,[string[]]$ToolArgs=@()) $exe=Join-Path $env:SystemRoot "System32\$Tool.exe"; if(-not (Test-Path -LiteralPath $exe)){ throw "native tool not installed: $Tool.exe" }; & { $ErrorActionPreference='Continue'; (& $exe @ToolArgs) 2>&1 | ForEach-Object { "$_" } } | Out-String }
try {
  $r = [ordered]@{}
  $r.pending = [ordered]@{
    cbs_reboot   = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    wu_reboot    = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    file_renames = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
  }
  $dism = Invoke-Native 'dism' @('/online','/cleanup-image','/checkhealth')
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
    .or_else(|| Some(json!({ "ok": false, "error": "wu-servicing produced no parseable output — the read failed" })))
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
    .or_else(|| Some(json!({ "ok": false, "error": "device-guard produced no parseable output — the read failed" })))
}
#[cfg(not(windows))]
fn device_guard(_params: Option<&str>) -> Option<Value> {
    None
}

/// Environment variables (read-only). Machine scope from the registry
/// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, user scope from `HKCU\Environment`
/// — NOT a process snapshot, so it reflects the persisted (machine/user) definitions. `params` JSON
/// `{scope:"machine"|"user"|"all" (default "all"), name_filter, offset, limit}` — `name_filter` is a
/// case-insensitive SUBSTRING over the variable name, and `name` is accepted as an alias for it. Returns
/// the standard paginated envelope plus `scope` and `name_filter` echoing what was actually applied.
/// This exposes values, but the collector is admin-gated CONSOLE-SIDE (like fs/wmi) — no redaction here.
/// Reads only.
///
/// **Two refusals, both replacing a false absence.** An unrecognised `scope` and a `name_filter` that
/// sanitises to nothing each return `{ok:false,error}`. Previously the first returned a bare `[]` (so
/// `{"scope":"Machine"}` — just the wrong case — reported that the machine had no environment variables)
/// and the second silently widened to every variable, answering a narrow question with the whole set.
/// Neither failure was visible to the caller; both are the error-vs-absent conflation, one in each
/// direction.
#[cfg(windows)]
fn env_vars(params: Option<&str>) -> Option<Value> {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);

    // An UNRECOGNISED scope is REFUSED, not silently narrowed to nothing. `{"scope":"Machine"}` — the
    // obvious capitalisation — used to fall through both arms, leave `sources` empty and return a bare
    // `[]`, which reads as "this machine has no environment variables". A typo must not be able to
    // manufacture an absence; that is the whole discipline this collector tree was swept for.
    let scope = p.get("scope").and_then(|x| x.as_str()).unwrap_or("all").trim().to_ascii_lowercase();
    if !matches!(scope.as_str(), "machine" | "user" | "all") {
        return Some(json!({
            "ok": false,
            "error": format!("env: unknown scope '{scope}' (expected machine|user|all) — refused rather than \
                              returning an empty list, which would read as 'no variables'"),
        }));
    }
    let want_machine = scope == "machine" || scope == "all";
    let want_user = scope == "user" || scope == "all";

    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' ' | '(' | ')' | '*' | '?'))
            .take(256)
            .collect()
    };
    // `name` is accepted as an alias for `name_filter`. It was previously accepted, echoed back in the
    // dispatched params, and then never read — so `{"scope":"machine","name":"Path"}` returned all 18
    // machine variables while the caller believed it had asked for one. Measured 2026-07-30: name -> 18
    // of 18, name_filter -> 3. A filter that is taken and dropped is worse than one refused, because the
    // caller reads a superset as a match.
    let raw_filter = p
        .get("name_filter")
        .and_then(|x| x.as_str())
        .or_else(|| p.get("name").and_then(|x| x.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let mut applied_filter: Option<String> = None;
    let where_clause = match raw_filter {
        Some(n) => {
            let cleaned = safe(n);
            // A filter that sanitises away to nothing must REFUSE, not widen. Falling back to "no
            // filter" would answer a narrow question with the whole set and call it a match.
            if cleaned.is_empty() {
                return Some(json!({
                    "ok": false,
                    "error": "env: name filter contains no usable characters after sanitising — refused \
                              rather than returning every variable, which would read as a match",
                }));
            }
            applied_filter = Some(cleaned.clone());
            format!(" | Where-Object {{ $_.name -like '*{cleaned}*' }}")
        }
        None => String::new(),
    };

    // Build the (registry-path, scope-label) source list per the requested scope. Each registry key's
    // value names are the variable names; `Get-Item`/`GetValue` only READS — we never write the hive.
    let mut sources: Vec<String> = Vec::new();
    if want_machine {
        sources.push("@{ p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'; s='machine' }".into());
    }
    if want_user {
        // ⚠ `HKCU:` under a SERVICE is the SERVICE's own profile, not any human's.
        //
        // The client runs as SYSTEM, so `HKCU:\Environment` resolved to
        // `C:\Windows\system32\config\systemprofile\...` and the collector reported three
        // service-profile variables as "the user scope". Measured on an RDS host with four people
        // signed in: `scope:"user"` returned 3 variables, while 19 real ones across 4 named accounts
        // sat in loaded hives that SYSTEM could already read. A caller reading "24 environment
        // variables" got the machine's, plus a service account's, and none of the users'.
        //
        // Every signed-in user's hive IS mounted, at `HKU\<SID>`, and the correspondence is exact:
        // 4 logged on -> 4 hives -> 4 readable Environment keys, all 4 SIDs resolvable. So this is a
        // SOURCE LIST change, not new privilege.
        //
        // `_Classes` hives are skipped (they are the per-user COM registrations, not environment), but
        // S-1-5-18 is deliberately NOT skipped: it is what ships today, and dropping it would delete
        // rows an existing caller receives. It is labelled instead, which is the honest fix — every row
        // now carries the `sid` that owns it, so a service-profile row is identifiable rather than
        // disguised as somebody's.
        sources.push(
            "@(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | \
               Where-Object { $_.PSChildName -notlike '*_Classes' } | \
               ForEach-Object { @{ p=\"Registry::HKEY_USERS\\$($_.PSChildName)\\Environment\"; \
                                   s='user'; sid=$_.PSChildName } })"
                .into(),
        );
    }
    // No `sources.is_empty()` guard: the scope refusal above makes an empty source list unreachable, and
    // the guard it replaces is exactly what turned a bad scope into a false absence.

    // No `Select-Object -First 1000` either. That was a SECOND cut, on the PowerShell side, upstream of
    // everything Rust can see — deleting only the Rust-side truncate would have left `paginate` measuring
    // a list PowerShell had already shortened, i.e. the same lie one layer further out and harder to find.
    // `sid` rides on every row. A user-scope row without one is unattributable, and on a host with
    // several people signed in "PATH is wrong" is only answerable if you know WHOSE.
    let script = format!(
        "{PS_GUARD}\
         $srcs=@({}); \
         @($srcs | ForEach-Object {{ $scope=$_.s; $sid=$_.sid; $k=Get-Item -LiteralPath $_.p -ErrorAction SilentlyContinue; \
           if($k){{ foreach($n in $k.GetValueNames()){{ [pscustomobject]@{{ name=[string]$n; value=[string]($k.GetValue($n)); scope=$scope; sid=$sid }} }} }} \
         }}){} | Sort-Object scope,sid,name | ConvertTo-Json -Depth 3 -Compress",
        sources.join(","),
        where_clause
    );
    // The capping array helper keeps an over-long value (e.g. a giant PATH) from blowing the result cap.
    // `what` is the DISPATCH kind: the label reaches the caller in the error text, and "env-vars" is not
    // a kind anything can dispatch, so an operator reading it had nothing to retry.
    let mut out = ps_json_array(&script, 1000, ENV_VALUE_CAP, params, "env")?;
    // Echo what was ACTUALLY applied, so a caller can tell a filter that ran from one this client is too
    // old to have read. Absent echo means old client — never "no filter was applied".
    if let Some(o) = out.as_object_mut() {
        if o.get("ok").and_then(|x| x.as_bool()) != Some(false) {
            o.insert("scope".to_owned(), json!(scope));
            o.insert("name_filter".to_owned(), json!(applied_filter));
            if want_user {
                // WHICH users this answer covers — and, by omission, which it cannot.
                //
                // A hive is mounted at HKU only while its owner is SIGNED IN, so this is a
                // point-in-time answer about the people on the box right now, never the host's user
                // population. Stating the SIDs seen is what stops "24 variables" reading as everyone's:
                // a caller can see it covered four people and ask who else there should be.
                let sids: Vec<String> = out
                    .get("items")
                    .and_then(|v| v.as_array())
                    .map(|rows| {
                        let mut v: Vec<String> = rows
                            .iter()
                            .filter(|r| r.get("scope").and_then(|s| s.as_str()) == Some("user"))
                            .filter_map(|r| r.get("sid").and_then(|s| s.as_str()).map(str::to_owned))
                            .collect();
                        v.sort();
                        v.dedup();
                        v
                    })
                    .unwrap_or_default();
                if let Some(o) = out.as_object_mut() {
                    o.insert("user_hives_read".to_owned(), json!(sids.len()));
                    o.insert("user_sids_read".to_owned(), json!(sids));
                    o.insert(
                        "user_scope_note".to_owned(),
                        json!(
                            "Only users SIGNED IN right now have a loaded HKU hive, so this covers them \
                             and no one else — it is a point-in-time answer, never the host's user list. \
                             A signed-out user's settings live in an NTUSER.DAT this collector does not \
                             load, and on a User-Profile-Disk host that file is inside an unmounted VHDX \
                             and is not on the box at all (see the user-profile-disks collector). Rows \
                             carrying the S-1-5-18 sid are the SYSTEM service profile, which is what this \
                             collector used to return as 'user' — kept and labelled rather than dropped."
                        ),
                    );
                }
            }
        }
    }
    Some(out)
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
# ServerUtil returns as soon as it TRIGGERS the backup - "Running backup X (ID: n)" - so `ok` here can
# only ever mean "the run was started". It is deliberately reported as `dispatched` rather than as a
# result: a caller that reads ok=true as "the backup completed" would be wrong every time, including
# when the run then fails. Unlike the API actions there is no token here to poll the log with, so the
# outcome is deliberately left to be read afterwards rather than guessed at.
[pscustomobject]@{ok=[bool]($p -and $p.Success);dispatched=[bool]($p -and $p.Success);command='run';backup=$b;datafolder=$df;result=$p;raw=$(if($p){$null}else{$raw.Trim()});note='started only - ok means the run was ACCEPTED, not that it finished or succeeded; read duplicati-target-check or duplicati-log for the outcome'}|ConvertTo-Json -Depth 20"#;

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
    .or_else(|| Some(json!({ "ok": false, "error": "duplicati-backups produced no parseable output — the read failed" })))
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
    // A bare `None` here reached the wire as `result: null` alongside `status:"done"` and no error —
    // measured on a live host — which cannot be told from "ran and found nothing". `ps_json` returns
    // None whenever the script produced nothing parseable, which for this collector means the read
    // FAILED. Several Duplicati siblings already convert it; this one and its neighbours did not.
    .or_else(|| Some(json!({ "ok": false, "error": "duplicati-status produced no parseable output" })))
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
    .or_else(|| Some(json!({ "ok": false, "error": "duplicati-vss-test produced no parseable output — the read failed" })))
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
# While a backup runs, the Server API rejects these reads with a bare 400 that is indistinguishable on
# the wire from a broken collector, a stale token or a bad backup id — and the nightly window is exactly
# when an operator investigates a backup. ServerUtil's `status` answers it: it needs no token, keeps
# working throughout a run, and reports `ActiveTask` (an empty STRING when idle, an object carrying
# BackupId + Task during one). Probed at most once per script — several bodies call Invoke-DupApi in a
# poll loop, and one ServerUtil launch per failed call would dominate their runtime.
$dupTaskProbed=$false; $dupActiveTask=$null
# Set only while Wait-DupOutcome is polling for an operation THIS SCRIPT dispatched. There a 400 means
# "our own run is still going", which is the normal path, not a refusal — and the busy branch below
# EXITS the script, so without this the poll loop dies on its first iteration and the action reports
# `busy` naming ITS OWN task as the blocker. Measured on a live host: duplicati-recreate returned
# {ok:false, busy:true, active_task:{BackupId:11,Task:4}} for the recreate it had just started, and
# the rebuild it was reporting on actually SUCCEEDED. Anything slower than the 1.5 s first poll hit
# this, which is every maintenance job worth running. Genuine read collectors leave it false and keep
# the busy envelope they rely on.
$dupPollingOwnRun=$false
function Get-DupActiveTask {
  if($script:dupTaskProbed){ return $script:dupActiveTask }
  $script:dupTaskProbed=$true
  $t=(& $su --json @dfArgs status 2>&1 | Out-String)
  $i=$t.IndexOfAny([char[]]@('{','['))
  if($i -ge 0){ try{ $p=$t.Substring($i)|ConvertFrom-Json; if($p.ActiveTask){ $script:dupActiveTask=$p.ActiveTask } }catch{} }
  return $script:dupActiveTask
}
function Invoke-DupApi([string]$method,[string]$path,$bodyObj){
  if(-not $tok){ return [pscustomobject]@{ok=$false;status=0;error='no Duplicati API token delivered for this device; run the duplicati-token-issue action first'} }
  $h=@{ Authorization="Bearer $tok" }
  $uri="http://127.0.0.1:8200$path"
  try {
    # A STRING body is already JSON and passes through untouched. Piping to ConvertTo-Json unwraps a
    # one-element array to a bare string, and /commandline takes a bare JSON ARRAY - so a command with
    # no arguments would arrive as "list-broken-files" instead of ["list-broken-files"]. Callers that
    # need an exact shape serialise it themselves rather than depending on element count.
    if($null -ne $bodyObj){ $json=$(if($bodyObj -is [string]){ $bodyObj } else { $bodyObj|ConvertTo-Json }); $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -Body $json -ContentType 'application/json' -TimeoutSec $dupTimeout }
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
    # 400 is the measured signature of "a run is in progress" (409 is the other refuse-while-busy code).
    # Written and EXITED here rather than returned, so that `busy` reaches the caller as a DISTINCT state:
    # every calling body reshapes the result into its own envelope, and one that did not carry the flag
    # would hand back an ordinary failure and restore the ambiguity this exists to remove. Probing costs a
    # ServerUtil launch only on a call that already failed, and changes nothing when no task is running.
    # No `retry_after`: ActiveTask carries no duration or progress, and a made-up number would be trusted.
    # Polling a run WE dispatched is excluded: there the active task is our own, so "busy, retry later"
    # would name the caller's own job as the blocker. The bare dispatch path (no trailing segment) is not
    # excluded — a refusal there really is another run holding the server.
    if(($sc -eq 400 -or $sc -eq 409) -and $path -notlike '/api/v1/commandline/*' -and -not $script:dupPollingOwnRun){
      $at=Get-DupActiveTask
      if($at){
        (@{ok=$false;busy=$true;status=$sc;active_task=$at;path=$path;error="Duplicati is busy: task $($at.Task) is running for backup $($at.BackupId), and the Server API refuses this read until it finishes. Transient — NOT a collector, token or backup-id failure. Retry after the run completes; duplicati-status / duplicati-backups / duplicati-target-check stay readable during a run."}|ConvertTo-Json -Depth 10 -Compress); exit
      }
    }
    # A busy server does not always REFUSE — measured on a live DC mid-backup, /filesets did not answer
    # 400 at all: it blocked until the 300s timeout. The operator then got "very large backups can
    # exceed this", which points at the wrong cause and invites raising a timeout that was never the
    # problem. The active task is the discriminator and costs one ServerUtil launch on a call that has
    # already failed. `timed_out` stays separate from `busy` so the two mechanisms remain tellable
    # apart; the operator's action ("retry after the run") is the same for both.
    if($msg -match 'timed out' -and $path -notlike '/api/v1/commandline/*' -and -not $script:dupPollingOwnRun){
      $at=Get-DupActiveTask
      if($at){
        (@{ok=$false;busy=$true;timed_out=$true;status=$sc;active_task=$at;path=$path;error="Duplicati did not answer this read within ${dupTimeout}s, and task $($at.Task) is running for backup $($at.BackupId) — a run in progress is the likely cause, not an undersized timeout. Transient: retry after the run completes. duplicati-status / duplicati-backups / duplicati-target-check stay readable during a run."}|ConvertTo-Json -Depth 10 -Compress); exit
      }
    }
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
const DUP_RECREATE_CALLS: &str = r#"# PRE-FLIGHT, and the only guard that protects the BACKUP rather than the job. deletedb is
# destructive and the Server API does not refuse it while a task is running, so a recreate that gets
# started twice deletes the database out from under its own rebuild. Every scheduler-side guard is
# keyed on job id, and two dispatches mint two ids - so this has to sit here, where the id is
# irrelevant and a scheduled run or a click in Duplicati's own web UI counts too.
# Get-DupActiveTask is used reactively further down (it explains a 400/409 that already came back);
# deletedb needs it asked BEFORE. Refusing on ANY active task, not just this backup's: Duplicati runs
# one task at a time, and ActiveTask.BackupId has no guaranteed comparable form.
$at=Get-DupActiveTask
if($at){
  $whose=$(if(([string]$at.BackupId) -eq ([string]$id)){ "this backup" } else { "backup $($at.BackupId)" })
  [pscustomobject]@{ok=$false;busy=$true;command='recreate';step='preflight';backup=$id;active_task=$at;error="refused: task $($at.Task) is already running for $whose. Recreate DELETES the local database as its first step, so starting it now would delete the database out from under that task. Nothing was changed. Retry once the run finishes."}|ConvertTo-Json -Depth 15
  exit
}
# Clear the probe cache: the helper answers once per script, and a stale 'no task' here would stop
# Invoke-DupApi explaining a later 400/409 as busy. One extra ServerUtil launch, only on a failure.
$script:dupTaskProbed=$false
$d=Invoke-DupApi 'POST' "/api/v1/backup/$id/deletedb" $null
if(-not $d.ok){ [pscustomobject]@{ok=$false;command='recreate';step='deletedb';backup=$id;status=$d.status;error=$d.error}|ConvertTo-Json -Depth 15; exit }
# The rebuild is the part that takes hours and the part that can fail, and the local database has just
# been DELETED - so "did the rebuild work" is the entire question. Reporting the repair's enqueue would
# call a recreate successful the instant it started.
$t0=[int64][double]::Parse((Get-Date -UFormat %s))
$r=Invoke-DupApi 'POST' "/api/v1/backup/$id/repair" $null
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='recreate';step='repair';backup=$id;dispatched=$false;status=$r.status;error=$r.error}|ConvertTo-Json -Depth 15; exit }
$w=Wait-DupOutcome -Id $id -T0 $t0 -TimeoutSec 3600 -Operation 'Repair'
$done=[bool]$w.found
# Through variables, not $( ): a subexpression drops an empty list and unwraps a one-element one to a
# bare string, so the field's type would change with its length.
$errs=$null; $warns=$null; $msgs=$null
if($done){ $errs=@($w.errors); $warns=@($w.warnings); $msgs=@($w.messages) }
[pscustomobject]@{ok=$(if(-not $done){$null}else{[bool]($w.parsed_result -match '^(Success|Warning)$')});
  command='recreate';step='repair';backup=$id;dispatched=$true;outcome_known=$done;
  operation=$(if($done){$w.operation}else{$null});result=$(if($done){$w.parsed_result}else{$null});
  duration=$(if($done){$w.duration}else{$null});errors_total=$(if($done){$w.errors_total}else{$null});
  warnings_total=$(if($done){$w.warnings_total}else{$null});
  messages_total=$(if($done){$w.messages_total}else{$null});errors=$errs;warnings=$warns;messages=$msgs;
  note=$(if($done){$null}else{'the local database was deleted and the rebuild started, but its result could not be read back before the wait expired - it may still be running; do NOT treat this as success'})}|ConvertTo-Json -Depth 15"#;

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

/// Wait for a Duplicati operation dispatched at `$t0` to finish, and return its REAL outcome.
///
/// `POST /backup/{id}/{op}` only ENQUEUES: it answers `{ID,Status:"OK"}` the moment the task is
/// accepted, and that answer is identical whether the operation then succeeds, fails fatally, or
/// deletes remote volumes. Measured on a scratch install: a `verify` the log recorded as **Fatal**
/// with two errors returned `Status:"OK"`, and a `repair` that DELETED an unrecorded remote volume
/// returned a response byte-identical to a repair that did nothing. Reporting the enqueue as the
/// result tells an operator a destructive maintenance action worked when nothing establishes that.
///
/// So poll the backup's own log — the same endpoint and the same `Message` JSON `duplicati-log`
/// already parses — for the first entry stamped at or after dispatch, and report ITS `ParsedResult`
/// plus errors and warnings. On timeout the outcome is reported as **unknown**, never as success:
/// a maintenance action whose result we could not read is exactly the case that must not look fine.
#[cfg(windows)]
const DUP_AWAIT_OUTCOME: &str = r#"
function Wait-DupOutcome { param([string]$Id,[int64]$T0,[int]$TimeoutSec=900,[string]$Operation='')
  $deadline=(Get-Date).AddSeconds($TimeoutSec)
  # While polling, a 400 means OUR OWN operation is still running — the normal case, not a refusal.
  # Invoke-DupApi's busy branch EXITS the script, so without this the loop dies on its first pass and
  # the action reports `busy` against its own task. try/finally: an exception inside the loop must not
  # leave the flag set for whatever runs next in this script.
  $script:dupPollingOwnRun=$true
  try {
  while((Get-Date) -lt $deadline){
    Start-Sleep -Milliseconds 1500
    $lg=Invoke-DupApi 'GET' "/api/v1/backup/$Id/log?pagesize=5" $null
    if($lg.ok){
      foreach($e in @(@($lg.result)|Where-Object{$_})){
        # Timestamps are unix seconds. '>=' not '>': a sub-second operation can land on the same
        # second it was dispatched, and treating that as "not mine yet" would poll until timeout.
        if([int64]$e.Timestamp -ge $T0){
          $m=$null; try{ if($e.Message){ $m=$e.Message|ConvertFrom-Json } }catch{}
          # Timestamp alone is NOT enough to identify our entry. Two operations on one backup inside
          # the same second - a compact and a recreate dispatched together - both satisfy '>= T0', and
          # whichever is seen first gets reported as the other's outcome. Measured: a recreate returned
          # the compact's messages verbatim while its own rebuild went unread. Match the operation the
          # caller actually asked for.
          if($m -and $m.ParsedResult -and ($Operation -eq '' -or [string]$m.MainOperation -eq $Operation)){
            # Messages, not just Errors/Warnings. A repair that DELETES remote volumes logs no error
            # and no warning - it did what it was asked - so on result alone a destructive repair is
            # indistinguishable from a no-op. What it removed is recorded here and nowhere else.
            return [pscustomobject]@{found=$true;operation=[string]$m.MainOperation;
              parsed_result=[string]$m.ParsedResult;interrupted=$m.Interrupted;
              duration=[string]$m.Duration;errors_total=$m.ErrorsActualLength;
              warnings_total=$m.WarningsActualLength;messages_total=$m.MessagesActualLength;
              errors=@(@($m.Errors)|Where-Object{$_}|Select-Object -First 20);
              warnings=@(@($m.Warnings)|Where-Object{$_}|Select-Object -First 20);
              messages=@(@($m.Messages)|Where-Object{$_}|Select-Object -First 30)}
          }
        }
      }
    }
  }
  } finally { $script:dupPollingOwnRun=$false }
  return [pscustomobject]@{found=$false}
}
"#;

/// A single-call API action (`repair`/`verify`/`compact`/`vacuum`) — `POST /backup/{id}/{op}`, then
/// wait for the operation to actually finish and report what it did. See [`DUP_AWAIT_OUTCOME`].
#[cfg(windows)]
fn dup_api_simple(params: Option<&str>, op: &str) -> Value {
    let Some(id) = dup_backup_id(params) else {
        return json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"});
    };
    let Some(tok) = dup_token_line(params) else { return dup_no_token() };
    let body = format!(
        "{tok}\n$id='{id}'\n{await_fn}\n\
         $t0=[int64][double]::Parse((Get-Date -UFormat %s))\n\
         $r=Invoke-DupApi 'POST' \"/api/v1/backup/$id/{op}\" $null\n\
         if(-not $r.ok){{ [pscustomobject]@{{ok=$false;command='{op}';backup=$id;dispatched=$false;status=$r.status;error=$r.error}}|ConvertTo-Json -Depth 15; exit }}\n\
         $w=Wait-DupOutcome -Id $id -T0 $t0 -Operation {expect}\n\
         # `ok` is the OPERATION's verdict, not the request's. Warning counts as ok (it completed and\n\
         # said what it was unhappy about); Fatal/Error does not; an unread outcome is null, not true.\n\
         $done=[bool]$w.found\n\
         $okv=$(if(-not $done){{$null}}else{{[bool]($w.parsed_result -match '^(Success|Warning)$')}})\n\
         # Assign the lists through VARIABLES, never a $( ) subexpression: a subexpression collapses an\n\
         # empty array to nothing and unwraps a single-element one to a bare string, so the field's TYPE\n\
         # would track its length - {{}} at zero, a string at one, a list at two - and zero is the common\n\
         # case. Anything iterating `errors` would break on exactly the results that are fine.\n\
         $errs=$null; $warns=$null; $msgs=$null\n\
         if($done){{ $errs=@($w.errors); $warns=@($w.warnings); $msgs=@($w.messages) }}\n\
         [pscustomobject]@{{ok=$okv;command='{op}';backup=$id;dispatched=$true;outcome_known=$done;\n\
           operation=$(if($done){{$w.operation}}else{{$null}});\n\
           result=$(if($done){{$w.parsed_result}}else{{$null}});\n\
           interrupted=$(if($done){{$w.interrupted}}else{{$null}});\n\
           duration=$(if($done){{$w.duration}}else{{$null}});\n\
           errors_total=$(if($done){{$w.errors_total}}else{{$null}});\n\
           warnings_total=$(if($done){{$w.warnings_total}}else{{$null}});\n\
           messages_total=$(if($done){{$w.messages_total}}else{{$null}});\n\
           errors=$errs;warnings=$warns;messages=$msgs;\n\
           note=$(if($done){{$null}}else{{'the operation was accepted but its result could not be read back before the wait expired - it may still be running, and this says NOTHING about whether it succeeded'}})}}|ConvertTo-Json -Depth 15",
        tok = tok, id = id, op = op, await_fn = DUP_AWAIT_OUTCOME,
        // Duplicati's log names the OPERATION, which is not always the endpoint name: /verify logs as
        // "Test". Without this mapping the wait matches on timestamp alone and can return a different
        // operation's result.
        expect = dup_squote(match op {
            "verify" => "Test",
            "repair" => "Repair",
            "compact" => "Compact",
            "vacuum" => "Vacuum",
            _ => "",
        })
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
    let body = format!(
        "{tok}\n$id='{id}'\n{await_fn}\n{calls}",
        tok = tok, id = id, await_fn = DUP_AWAIT_OUTCOME, calls = DUP_RECREATE_CALLS
    );
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

/// `browse` body — the restore points, PROJECTED rather than passed through.
///
/// `/filesets` reports `FileCount` and `FileSizes` as **-1** for a version whose counts Duplicati has
/// not computed, and returns `IsFullBackup` as 0/1. Handed back raw — which is what this collector did
/// — a restore point reads as containing *minus one* files, a number a caller has no reason to
/// distrust: measured on a live host, a version holding 4 files reported `FileCount: -1`.
#[cfg(windows)]
const DUP_BROWSE_BODY: &str = r#"$r=Invoke-DupApi 'GET' "/api/v1/backup/$id/filesets" $null
# The busy case never reaches here: Invoke-DupApi writes its own {busy:true,active_task} envelope and
# exits, so that state stays distinct rather than collapsing into this generic failure.
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='browse';backup=$id;status=$r.status;error=$r.error}|ConvertTo-Json -Depth 8; exit }
$sets=@(@($r.result)|Where-Object{$_})
$items=@($sets | ForEach-Object {
  [pscustomobject]@{ version=[int]$_.Version; time=[string]$_.Time;
    file_count=$(if($null -ne $_.FileCount -and $_.FileCount -ge 0){ [int64]$_.FileCount } else { $null });
    file_size=$(if($null -ne $_.FileSizes -and $_.FileSizes -ge 0){ [int64]$_.FileSizes } else { $null });
    is_full_backup=[bool]($_.IsFullBackup -eq 1) }
})
[pscustomobject]@{ok=$true;command='browse';backup=$id;count=$items.Count;items=$items}|ConvertTo-Json -Depth 10"#;

/// Read-only: list the backup's restore points / versions (Server API `/filesets`).
///
/// `file_count`/`file_size` are `null` where Duplicati has not computed them — never -1, and never 0,
/// which would claim an empty restore point.
#[cfg(windows)]
fn duplicati_browse(params: Option<&str>) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let body = format!("{tok}\n$id='{id}'\n{DUP_BROWSE_BODY}");
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati browse read produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_browse(_p: Option<&str>) -> Option<Value> { None }

/// `log` body — fetch a few log entries and **project** them. Each entry's `Message` is a complete
/// serialized operation result: filesets, the full `Messages` array, `BackendStatistics`, and every
/// warning. Returning those verbatim does not scale — measured 2026-07-20, `?pagesize=200` against a
/// 2.3M-file backup never completed, because `ConvertTo-Json -Depth 20` over that much data is far
/// slower than the HTTP fetch that produced it. The console caps the stored result (256 KiB —
/// `store::MAX_JOB_RESULT`; it was 64 KiB when this projection was designed, which is what the
/// collector's own `size_ceiling` was sized against), so the old shape built hundreds of MB in order to
/// throw nearly all of it away. The projection is what makes the collector viable at ANY of those
/// figures — it is not a cap workaround.
///
/// What an operator actually needs from this collector is the *warnings* — the EFS `PermissionDenied`
/// lines and missing-fileset errors. So keep the per-run outcome, keep the authoritative
/// `*ActualLength` counts, keep a bounded sample of the warning/error text, and drop the informational
/// `Messages` array and `BackendStatistics` entirely. `warnings_truncated` states plainly when the
/// sample is short of the real count, so a partial list can never be mistaken for a complete one.
///
/// The projection keeps the run's **scalar file statistics** too (added/modified/deleted counts and
/// sizes). Those were never the cost — the arrays were — and without them the console can say a backup
/// ran but not what it did, which is the difference between "ordinary churn" and "something is
/// rewriting the file server". They are emitted uncast so an absent field is `null`, never `0`.
///
/// The projection alone is not a guarantee, so the envelope also measures itself: `entries_bytes`
/// (the serialized payload size), `size_ceiling`, `result_truncated`, `entries_dropped` and
/// `warning_lines_kept`. Sizing this collector by argument has been wrong before, and the correction
/// is precise: **Duplicati 2.3.0.107 clamps `pagesize` to a MINIMUM of 10**, then caps by however
/// many entries exist. Measured on a live host: `1 → 10`, `5 → 10`, `15 → 15`, `50 → 26` (26 being
/// all there were), and the older `2 → 6` reading fits the same rule, 6 being all that existed then.
/// So a request BELOW 10 is silently raised and `count` exceeds what was asked for, while a request
/// above 10 is honoured. That is why the field is emitted as `pagesize_requested`: the requested
/// value is not always the effective one, and beside a larger `count` a bare `pagesize` read as the
/// page size of the answer. The byte-level bound is still `size_ceiling` + `entries_dropped`, which
/// hold regardless. The fleet's largest backup already serializes to
/// tens of KB at defaults, on a warning set that is a fixed ~5,000 EFS exclusions today and could
/// grow. So the result states its own completeness instead of leaving a caller to infer it from the
/// absence of a marker.
#[cfg(windows)]
const DUP_LOG_BODY: &str = r#"$r=Invoke-DupApi 'GET' "/api/v1/backup/$id/log?pagesize=$pagesize" $null
if(-not $r.ok){ ([pscustomobject]@{ok=$false;command='log';backup=$id;status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6); exit }
$entries=@()
# Where-Object, not a bare @(): wrapping $null yields a ONE-element array holding null, so an absent
# result would loop once and emit an entry built from nothing - count 1, for zero log entries. Today
# the API answers [] rather than null so it does not fire, but "no data" must not be able to arrive as
# "one item"; every sibling collector guards the same way.
foreach($e in @(@($r.result)|Where-Object{$_})){
  $m=$null
  try{ if($e.Message){ $m=$e.Message|ConvertFrom-Json } }catch{}
  $o=[ordered]@{id=$e.ID;type=[string]$e.Type;timestamp=$e.Timestamp}
  if($m){
    $o.operation=[string]$m.MainOperation
    # NOT [string]$m.ParsedResult: that casts an absent field to the empty string, so "Duplicati did not
    # tell us" became indistinguishable from a real value - and this field is now what `fatal` is derived
    # from, so an empty string here would silently answer fatal:false for a run we know nothing about.
    $o.parsed_result=$(if($null -ne $m.ParsedResult){[string]$m.ParsedResult}else{$null})
    $o.interrupted=$m.Interrupted
    $o.begin=[string]$m.BeginTime
    $o.end=[string]$m.EndTime
    $o.duration=[string]$m.Duration
    $o.messages_total=$m.MessagesActualLength
    $o.warnings_total=$m.WarningsActualLength
    $o.errors_total=$m.ErrorsActualLength
    # Per-run file statistics. These are already parsed and in memory in $m, so exposing them costs no
    # HTTP and a bounded handful of bytes - unlike the arrays this collector drops, which is where the
    # size problem always was. They answer the one question the outcome fields cannot: whether a run's
    # churn was mass ADDITION (ordinary application/update activity) or mass MODIFICATION of existing
    # paths (the signature of in-place encryption). Transient files that a workload creates and deletes
    # between runs are invisible to any after-the-fact filesystem walk, so the run report is the only
    # instrument that observed them at all.
    #
    # DELIBERATELY UNCAST. `[int]$m.AddedFiles` on an absent property yields 0, and a zeroed count reads
    # as "nothing was added" - a wrong answer, where null is merely no answer. A field the client's
    # Duplicati build does not emit must arrive as null.
    $o.examined_files=$m.ExaminedFiles
    $o.opened_files=$m.OpenedFiles
    $o.added_files=$m.AddedFiles
    $o.modified_files=$m.ModifiedFiles
    $o.deleted_files=$m.DeletedFiles
    $o.added_folders=$m.AddedFolders
    $o.modified_folders=$m.ModifiedFolders
    $o.deleted_folders=$m.DeletedFolders
    $o.added_symlinks=$m.AddedSymlinks
    $o.modified_symlinks=$m.ModifiedSymlinks
    $o.deleted_symlinks=$m.DeletedSymlinks
    $o.size_of_examined_files=$m.SizeOfExaminedFiles
    $o.size_of_opened_files=$m.SizeOfOpenedFiles
    $o.size_of_added_files=$m.SizeOfAddedFiles
    $o.size_of_modified_files=$m.SizeOfModifiedFiles
    # Silent data-exclusion signals: files the run could not read or would not carry. Nothing else in
    # the collector family surfaces them, and a backup that skips files still reports as a backup.
    $o.not_processed_files=$m.NotProcessedFiles
    $o.files_with_error=$m.FilesWithError
    $o.too_large_files=$m.TooLargeFiles
    $o.timestamp_changed_files=$m.TimestampChangedFiles
    $o.partial_backup=$m.PartialBackup
    $o.dryrun=$m.Dryrun
    # DERIVED, not passed through. $m.Fatal is never present: Duplicati marks BasicResults.Fatal
    # [JsonIgnore], so it is absent from the Message JSON this collector parses and the emailed report's
    # "Fatal: False" line comes from the report template, not the API. Measured 36 runs across 6 backups
    # on 3 devices - null every single time. A field that is always null is not a health signal, it is a
    # caller writing if(!fatal) and reading no-answer as not-fatal.
    #
    # ParsedResult recovers it EXACTLY rather than approximately: ParsedResultType's getter returns
    # Fatal whenever the Fatal flag is set, so 'Fatal' in that enum IS the flag, one field over. Null
    # stays null - if ParsedResult is absent we still cannot answer, and we say so instead of guessing
    # false. Do NOT substitute `interrupted` here: it answers "did the run finish", which a fatal run
    # can also do.
    $o.fatal=$(if($null -ne $m.ParsedResult){[bool]([string]$m.ParsedResult -eq 'Fatal')}else{$null})
    # The Duplicati build string, e.g. '2.3.0.107 (2.3.0.107_canary_2026-07-13)' - makes fleet version
    # drift readable from a collector that already runs everywhere.
    $o.version=$m.Version
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
# Explicit truncation, at the envelope. The warning/error samples are the only unbounded part of this
# result and the fleet's largest backup already serializes to tens of KB at DEFAULT pagesize/warning_cap,
# so the envelope MEASURES itself, sheds sample lines when it is over the ceiling, and states that it
# did. `result_truncated` is what a caller checks before reading this as a complete account of the run;
# `entries_bytes` is the measured payload size, so headroom is readable rather than guessed at. The
# per-entry warnings_truncated/errors_truncated flags stay authoritative through a shed because they
# are recomputed against WarningsActualLength, not against whatever survived.
$ceiling=180000
$Measure={ param($x) [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $x -Depth 8 -Compress)) }
$entriesBytes=& $Measure $entries
$shed=$false
$keep=$cap
while($entriesBytes -gt $ceiling -and $keep -gt 1){
  $keep=[int][math]::Floor($keep/2)
  foreach($e in $entries){
    foreach($f in 'warnings','errors'){
      if($e.PSObject.Properties[$f]){ $e.$f=@(@($e.$f)|Select-Object -First $keep) }
    }
    if($e.PSObject.Properties['warnings_truncated']){ $e.warnings_truncated=([int]$e.warnings_total -gt @($e.warnings).Count) }
    if($e.PSObject.Properties['errors_truncated']){ $e.errors_truncated=([int]$e.errors_total -gt @($e.errors).Count) }
  }
  $shed=$true
  $entriesBytes=& $Measure $entries
}
# Still over with the samples down to one line each - drop whole entries, keeping the newest, and count
# them. A dropped RUN is a bigger claim than a dropped warning line, so it gets its own field.
$dropped=0
while($entriesBytes -gt $ceiling -and @($entries).Count -gt 1){
  $n=[int][math]::Floor(@($entries).Count/2)
  $dropped+=(@($entries).Count - $n)
  $entries=@($entries|Select-Object -First $n)
  $shed=$true
  $entriesBytes=& $Measure $entries
}
[pscustomobject]@{ok=$true;command='log';backup=$id;pagesize_requested=$pagesize;warning_cap=$cap;count=@($entries).Count;result_truncated=$shed;entries_bytes=$entriesBytes;entries_dropped=$dropped;warning_lines_kept=$keep;size_ceiling=$ceiling;entries=$entries}|ConvertTo-Json -Depth 8 -Compress"#;

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

/// cli body — run one of Duplicati's own DIAGNOSTIC commands through the server and return its output.
///
/// This is the only route to `list-broken-files` — the "can this backup actually be restored?" check —
/// and to `affected` and `test-filters`. The standalone `Duplicati.CommandLine.exe` takes a
/// `<storage-URL>`, i.e. the credential-bearing target; the server's `/commandline` runs the same
/// commands against a job's own config instead.
///
/// **The target is fetched WITHOUT `export-passwords`.** The UI passes `export-passwords=true` there;
/// this deliberately does not, so the secret is never requested and therefore cannot be echoed into a
/// stored job result. These commands read the local database, so they have no destination to
/// authenticate to — if one ever does need the secret it must FAIL rather than be handed it.
///
/// The command is ALLOW-LISTED. `/commandline` will happily run `delete`, `purge` or `restore`, so an
/// operator-supplied command string is a remote-execution surface, not a convenience.
#[cfg(windows)]
const DUP_CLI_BODY: &str = r#"$allow=@('list-broken-files','affected','test-filters','system-info','list-filesets')
if($allow -notcontains $cmd){ [pscustomobject]@{ok=$false;command='cli';requested=$cmd;error=("not an allowed diagnostic command; permitted: " + ($allow -join ', '))}|ConvertTo-Json -Depth 6; exit }
$e=Invoke-DupApi 'GET' "/api/v1/backup/$id/export-argsonly" $null
if(-not $e.ok){ [pscustomobject]@{ok=$false;command='cli';cli=$cmd;backup=$id;step='export-argsonly';status=$e.status;error=$e.error}|ConvertTo-Json -Depth 6; exit }
$backend=[string]$e.result.Backend
$argv=@($cmd)
if($cmd -ne 'system-info' -and $backend){ $argv += $backend }
foreach($o in @(@($e.result.Options)|Where-Object{$_})){ $argv += [string]$o }
if($extra){ foreach($a in @($extra -split '\s+')){ if($a){ $argv += $a } } }
# Without this the output stops at five files and says "... and 1 more"; the caller then cannot see
# what is actually unrestorable. Our own line cap still bounds the result.
if($cmd -eq 'list-broken-files' -and $argv -notcontains '--full-result'){ $argv += '--full-result' }
# Serialise the array ourselves: /commandline takes a bare JSON array and a one-element one would
# otherwise be unwrapped to a string.
$r=Invoke-DupApi 'POST' '/api/v1/commandline' (ConvertTo-Json -InputObject $argv)
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='cli';cli=$cmd;backup=$id;step='dispatch';status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6; exit }
$runid=[string]$r.result.ID
$lines=@(); $off=0; $fin=$false; $deadline=(Get-Date).AddSeconds($cliTimeout)
while((Get-Date) -lt $deadline){
  $p=Invoke-DupApi 'GET' "/api/v1/commandline/$runid`?pagesize=200&offset=$off" $null
  if(-not $p.ok){ break }
  $items=@(@($p.result.Items)|Where-Object{$null -ne $_})
  if($items.Count){ $lines += $items; $off += $items.Count }
  if($p.result.Finished -and $off -ge [int]$p.result.Count){ $fin=$true; break }
  Start-Sleep -Milliseconds 800
}
# Belt and braces. Nothing here should hold a secret - the export was requested without passwords -
# but the output echoes the command line, so scrub anything credential-shaped before it is stored.
$scrub={ param($t) ($t -replace '://[^@/\s]+@','://***@') -replace '(?i)((?:auth-password|aws-secret-access-key|auth-username|aws-access-key-id)=)[^&\s"]*','$1***' }
$out=@($lines | ForEach-Object { (& $scrub ([string]$_)) })
# `Return code: 0` is NOT the health signal - list-broken-files exits 0 whether it found six
# unrestorable files or none, so a healthy run and a broken one differ only in prose in the middle.
# Anything keying on ok/finished/return-code would call a broken backup fine. Count the filesets and
# the matches so the answer is a value, not something a reader has to notice.
$brokenSets=$null; $brokenFiles=$null; $broken=$null
if($cmd -eq 'list-broken-files'){
  $fs=@($out | Where-Object { $_ -match '^Fileset\s+\d+' })
  $brokenSets=$fs.Count; $n=0
  foreach($l in $fs){ if($l -match '\((\d+)\s+match'){ $n += [int]$Matches[1] } }
  $brokenFiles=$n; $broken=[bool]($brokenSets -gt 0)
}
[pscustomobject]@{ok=$true;command='cli';cli=$cmd;backup=$id;runid=$runid;finished=$fin;
  broken=$broken;broken_filesets=$brokenSets;broken_files=$brokenFiles;
  line_count=$out.Count;lines=@($out|Select-Object -First 400);
  truncated=($out.Count -gt 400);
  note=$(if($fin){$null}else{'the command did not report finished before the wait expired - the lines below may be incomplete'})}|ConvertTo-Json -Depth 8"#;

/// Read-only: one of Duplicati's diagnostic commands, run server-side against a job's own config.
#[cfg(windows)]
fn duplicati_cli(params: Option<&str>) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let cmd = {
        let c = dup_param(params, &["command", "cli", "cmd"]);
        if c.is_empty() { "list-broken-files".to_string() } else { c }
    };
    let extra = dup_param(params, &["args", "extra"]);
    let timeout = dup_param(params, &["timeout"]).parse::<u32>().unwrap_or(300).clamp(30, 1800);
    let body = format!(
        "{tok}\n$id='{id}'\n$cmd={cmd}\n$extra={extra}\n$cliTimeout={timeout}\n{DUP_CLI_BODY}",
        tok = tok, id = id, cmd = dup_squote(&cmd), extra = dup_squote(&extra), timeout = timeout
    );
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati cli run produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_cli(_p: Option<&str>) -> Option<Value> { None }

/// notifications body — Duplicati's OWN warning/error queue, the one its UI shows as alerts.
///
/// Passed through verbatim rather than reshaped into named fields: the record's shape is Duplicati's,
/// not ours, and inventing field names for it would be guessing at a contract we can read directly.
#[cfg(windows)]
const DUP_NOTIFICATIONS_BODY: &str = r#"$r=Invoke-DupApi 'GET' '/api/v1/notifications' $null
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='notifications';status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6; exit }
$items=@(@($r.result)|Where-Object{$_})
[pscustomobject]@{ok=$true;command='notifications';count=$items.Count;items=$items}|ConvertTo-Json -Depth 10"#;

/// Read-only: Duplicati's own notification queue — what IT thinks is wrong, which the console has
/// never asked for. Distinct from a job's log: these are server-level and survive across jobs.
#[cfg(windows)]
fn duplicati_notifications(params: Option<&str>) -> Option<Value> {
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let body = format!("{tok}\n{DUP_NOTIFICATIONS_BODY}");
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati notifications read produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_notifications(_p: Option<&str>) -> Option<Value> { None }

/// files body — what a backup VERSION actually contains, as opposed to what its config says it should.
///
/// `duplicati-sources` answers "what is this job configured to protect"; this answers "what is really
/// in the stored fileset". They are not the same question, and only the second one is evidence.
#[cfg(windows)]
const DUP_FILES_BODY: &str = r#"$r=Invoke-DupApi 'GET' "/api/v1/backup/$id/filesets" $null
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='files';backup=$id;step='filesets';status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6; exit }
$sets=@(@($r.result)|Where-Object{$_})
if(-not $sets.Count){ [pscustomobject]@{ok=$true;command='files';backup=$id;versions=0;time=$null;total=0;truncated=$false;items=@();note='the backup has no stored versions yet'}|ConvertTo-Json -Depth 8; exit }
# Newest fileset unless the caller named a version time. Version 0 IS the newest in Duplicati's order.
$stamp=$(if($time){ $time } else { [string]@($sets|Sort-Object {[int]$_.Version})[0].Time })
$q="/api/v1/backup/$id/files?prefix-only=$prefixOnly&folder-contents=$folderContents&time=" + [uri]::EscapeDataString($stamp)
if($filter){ $q = $q + '&filter=' + [uri]::EscapeDataString($filter) }
$f=Invoke-DupApi 'GET' $q $null
if(-not $f.ok){ [pscustomobject]@{ok=$false;command='files';backup=$id;step='files';time=$stamp;status=$f.status;error=$f.error}|ConvertTo-Json -Depth 6; exit }
$all=@(@($(if($f.result.PSObject.Properties['Files']){ $f.result.Files } else { $f.result }))|Where-Object{$_})
# The SAME response carries a Filesets block holding the version's REAL totals, and this kept only
# .Files and dropped it — so the only count reaching the caller was `total`, which counts returned
# ROWS (4 files + 2 folders = 6) and is not the number of files in the version (4). Measured against
# the raw endpoint on a live host. Reported here as its own fields rather than folded into `total`,
# which keeps its meaning.
$fsblk=@($(if($f.result.PSObject.Properties['Filesets']){ @($f.result.Filesets) } else { @() })|Where-Object{$_})
$ver=@($fsblk|Where-Object{ [string]$_.Time -eq [string]$stamp })[0]
if(-not $ver){ $ver=@($fsblk)[0] }
$vfc=$null; $vfs=$null
if($ver){
  if($null -ne $ver.FileCount -and $ver.FileCount -ge 0){ $vfc=[int64]$ver.FileCount }
  if($null -ne $ver.FileSizes -and $ver.FileSizes -ge 0){ $vfs=[int64]$ver.FileSizes }
}
# A real fileset is far too large to return whole, so cap and SAY the cap was hit rather than quietly
# returning a prefix of the truth.
$items=@($all|Select-Object -First $limit)
# Duplicati writes -1 into Sizes for an entry that HAS no size — every folder row carries it. Passed
# through it reads as a real number, and anything that totals the column gets a smaller answer for
# every directory in the fileset. Unknown/not-applicable is null; `is_folder` says WHY it is null,
# so a caller does not have to infer it from the trailing separator.
$items=@($items | ForEach-Object {
  $p=[string]$_.Path
  [pscustomobject]@{ Path=$p; is_folder=($p.EndsWith('\') -or $p.EndsWith('/'));
    Sizes=@(@($_.Sizes) | ForEach-Object { if($null -ne $_ -and $_ -ge 0){ [int64]$_ } else { $null } }) }
})
[pscustomobject]@{ok=$true;command='files';backup=$id;versions=$sets.Count;time=$stamp;total=$all.Count;
  version_file_count=$vfc;version_size=$vfs;
  truncated=($all.Count -gt $items.Count);count=$items.Count;items=$items}|ConvertTo-Json -Depth 10"#;

/// Read-only: the paths actually present in a stored backup version.
///
/// ⚠ `total` and `count` are ROW counts, and a row can be a folder — a version of 4 files under 2
/// folders reports `total: 6`. `version_file_count` / `version_size` are the version's own totals as
/// Duplicati computed them (`null` if it did not), and are what "how big is this backup version"
/// should read. Unlike `ad-groups`' primary members these were never missing from the response — they
/// arrived in the same payload and were discarded before the wire.
#[cfg(windows)]
fn duplicati_files(params: Option<&str>) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let mut filter = dup_param(params, &["filter", "path", "search"]);
    let time = dup_param(params, &["time", "version"]);
    let limit = dup_param(params, &["limit"]).parse::<usize>().unwrap_or(200).clamp(1, 5000);
    let prefix_only = dup_param(params, &["prefix_only"]) != "false";
    let folder_contents = dup_param(params, &["folder_contents"]) == "true";
    // The API requires a filter once prefix-only is off, and answers a bare 500 without one — an
    // unhelpful reply to a reasonable request. `*` is what the caller meant by "not just prefixes",
    // and it is measurably the working form.
    //
    // ⚠ But NOT with `folder_contents`. That mode lists the children of one named folder, and Duplicati
    // rejects a wildcard for it: "Filter for list-folder-contents must be a path prefix with no
    // wildcards". Substituting `*` therefore turned the documented `{folder_contents:true}` request
    // into a bare HTTP 500 — measured on a live host, where the reason was only visible in the
    // BACKUP'S OWN LOG, not in the reply. A param that cannot be used as advertised must say so
    // itself; guessing a filter that the mode forbids is how it came to fail silently.
    if folder_contents {
        if filter.is_empty() || filter.contains('*') || filter.contains('?') {
            return Some(json!({
                "ok": false,
                "command": "files",
                "backup": id,
                "error": "folder_contents:true lists the children of ONE folder, so it needs `filter` set to that folder's path prefix with no wildcards (e.g. \"C:\\\\Data\\\\\"). Omit folder_contents to list the whole version."
            }));
        }
    } else if !prefix_only && filter.is_empty() {
        filter = "*".to_string();
    }
    let body = format!(
        "{tok}\n$id='{id}'\n$filter={filter}\n$time={time}\n$limit={limit}\n$prefixOnly='{po}'\n$folderContents='{fc}'\n{DUP_FILES_BODY}",
        tok = tok, id = id,
        filter = dup_squote(&filter), time = dup_squote(&time), limit = limit,
        po = if prefix_only { "true" } else { "false" },
        fc = if folder_contents { "true" } else { "false" },
    );
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati files read produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_files(_p: Option<&str>) -> Option<Value> { None }

/// tasks body — the server's task queue, and one task's state when asked for it.
#[cfg(windows)]
const DUP_TASKS_BODY: &str = r#"if($task){
  $r=Invoke-DupApi 'GET' "/api/v1/task/$task" $null
  if(-not $r.ok){ [pscustomobject]@{ok=$false;command='tasks';task=$task;status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6; exit }
  [pscustomobject]@{ok=$true;command='tasks';task=$task;result=$r.result}|ConvertTo-Json -Depth 10; exit
}
$r=Invoke-DupApi 'GET' '/api/v1/tasks' $null
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='tasks';status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6; exit }
$items=@(@($r.result)|Where-Object{$_})
[pscustomobject]@{ok=$true;command='tasks';count=$items.Count;items=$items}|ConvertTo-Json -Depth 10"#;

/// Read-only: what Duplicati is doing right now (queue), or one task's state.
#[cfg(windows)]
fn duplicati_tasks(params: Option<&str>) -> Option<Value> {
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let task = dup_param(params, &["task", "taskid", "id"]);
    let body = format!("{tok}\n$task={t}\n{DUP_TASKS_BODY}", tok = tok, t = dup_squote(&task));
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati tasks read produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_tasks(_p: Option<&str>) -> Option<Value> { None }

/// task-stop body — ask a running operation to end. `stop` lets it finish the file in flight; `abort`
/// cuts it off. Both are reported by re-reading the task, because the POST only says it was accepted.
#[cfg(windows)]
const DUP_TASK_STOP_BODY: &str = r#"$r=Invoke-DupApi 'POST' "/api/v1/task/$task/$mode" $null
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='task-stop';task=$task;mode=$mode;requested=$false;status=$r.status;error=$r.error}|ConvertTo-Json -Depth 6; exit }
Start-Sleep -Seconds 2
$s=Invoke-DupApi 'GET' "/api/v1/task/$task" $null
# The POST answers "asked", not "stopped" - the same distinction the maintenance actions got wrong. A
# task that has not stopped yet is reported as still running, not as a success.
[pscustomobject]@{ok=$true;command='task-stop';task=$task;mode=$mode;requested=$true;
  task_state=$(if($s.ok){$s.result}else{$null});
  note=$(if($s.ok){'requested - read task_state for whether it has actually ended'}else{'requested, but the task could not be re-read: ' + [string]$s.error})}|ConvertTo-Json -Depth 10"#;

/// L2: ask a running Duplicati task to stop (`stop`, graceful) or abort (`abort`, immediate).
#[cfg(windows)]
fn duplicati_task_stop(params: Option<&str>) -> Value {
    let task = dup_param(params, &["task", "taskid", "id"]);
    if task.is_empty() {
        return json!({"ok": false, "error": "provide the task id (from duplicati-tasks)"});
    }
    let Some(tok) = dup_token_line(params) else { return dup_no_token() };
    let mode = if dup_param(params, &["mode"]) == "abort" { "abort" } else { "stop" };
    let body = format!("{tok}\n$task={t}\n$mode='{mode}'\n{DUP_TASK_STOP_BODY}", tok = tok, t = dup_squote(&task), mode = mode);
    ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati task-stop produced no parseable output"}))
}
#[cfg(not(windows))]
fn duplicati_task_stop(_p: Option<&str>) -> Value { json!({"ok": false, "error": "windows only"}) }

/// sources body — every configured backup's SOURCE paths, i.e. what Duplicati protects on this box.
///
/// `Sources` is the only field read out of each record. The per-backup record also carries
/// `TargetURL`, which embeds the backend credential — nothing but `Sources` is read from it and
/// nothing else is emitted, so this collector has no secret to put in a job result.
#[cfg(windows)]
const DUP_SOURCES_BODY: &str = r#"$r=Invoke-DupApi 'GET' '/api/v1/backups' $null
if(-not $r.ok){ [pscustomobject]@{ok=$false;command='sources';status=$r.status;error=$r.error}|ConvertTo-Json -Depth 8; exit }
# Some versions wrap each entry as {Backup:{...},Schedule:{...}} and others return it flat. Accept
# both rather than betting on which one this host runs.
$items=@()
foreach($e in @($r.result)){
  $b=$(if($e.PSObject.Properties['Backup']){ $e.Backup } else { $e })
  if(-not $b){ continue }
  $bid=[string]$b.ID
  # The LIST endpoint does NOT carry Sources — measured on three live servers, every backup on every
  # one came back empty — so it has to be read per backup. $src stays null unless a record actually
  # carried the property: "could not read" and "protects nothing" must not look alike to a rule that
  # decides whether to suppress a backup alert.
  $src=$null; $serr=$null; $dest=$null; $fields=$null
  if(-not $bid){ $serr='backup record carried no id' }
  else{
    $d=Invoke-DupApi 'GET' "/api/v1/backup/$bid" $null
    if(-not $d.ok){ $serr="detail read failed: $($d.error)" }
    else{
      $db=$d.result
      if($db -and $db.PSObject.Properties['data']){ $db=$db.data }
      if($db -and $db.PSObject.Properties['Backup']){ $db=$db.Backup }
      if($db -and $db.PSObject.Properties['Sources']){ $src=@(@($db.Sources) | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
      else {
        $serr='no Sources field on the backup record'
        # Report the record's property NAMES so the next run says what this Duplicati actually
        # returns, instead of another round of guessing at it. Names only - never values, any one of
        # which could be a credential.
        if($db){ $fields=@($db.PSObject.Properties.Name) }
      }
      # WHERE the backup goes, with no way to carry the secret: the credential lives in the query
      # string and in any ://user:pass@ userinfo, and both are stripped in this expression, before the
      # value is ever assigned. Nothing downstream sees the full URL.
      if($db -and $db.PSObject.Properties['TargetURL'] -and $db.TargetURL){
        $dest=((([string]$db.TargetURL) -split '\?')[0] -replace '://[^@/]+@','://***@')
      }
    }
  }
  $items += ,[pscustomobject]@{id=$bid;name=[string]$b.Name;destination=$dest;sources=$src;source_error=$serr;record_fields=$fields}
}
[pscustomobject]@{ok=$true;command='sources';count=$items.Count;backups=$items}|ConvertTo-Json -Depth 8"#;

/// Read-only: what each configured Duplicati backup protects on this box (source paths only).
///
/// Exists so fleet health can tell whether another backup product's output is itself being backed up
/// — a Windows Server Backup run with no WSB schedule is not unprotected if Duplicati sweeps up the
/// folder it writes to nightly.
#[cfg(windows)]
fn duplicati_sources(params: Option<&str>) -> Option<Value> {
    let Some(tok) = dup_token_line(params) else { return Some(dup_no_token()) };
    let body = format!("{tok}\n{DUP_SOURCES_BODY}");
    Some(ps_json(&dup_api_script(&body)).unwrap_or_else(|| json!({"ok": false, "error": "Duplicati sources read produced no parseable output"})))
}
#[cfg(not(windows))]
fn duplicati_sources(_p: Option<&str>) -> Option<Value> { None }

/// target-check body — read the backup's own record (`ServerUtil list-backups`) and report what the
/// NIGHTLY RUN established about the target.
#[cfg(windows)]
const DUP_TARGETCHECK_BODY: &str = r#"$raw=(& $su --json @dfArgs list-backups 2>&1 | Out-String)
$i=$raw.IndexOfAny([char[]]@('{','['));$p=$null;if($i -ge 0){try{$p=$raw.Substring($i)|ConvertFrom-Json}catch{}}
if(-not $p){ [pscustomobject]@{ok=$false;command='target-check';backup=$id;error='could not parse list-backups output';raw=$raw.Trim()}|ConvertTo-Json -Depth 8; exit }
$b=@($p.Backups | Where-Object { [string]$_.Id -eq $id })[0]
if(-not $b){ [pscustomobject]@{ok=$false;command='target-check';backup=$id;error="no backup with id $id on this host (see duplicati-backups)"}|ConvertTo-Json -Depth 8; exit }
$m=$b.Metadata
# Duplicati stamps these compact-UTC ("20260727T035900Z"). A parse failure yields $null, so a field we
# could not read never arrives looking like a date we did read.
$pd={ param($s) $s=[string]$s; if(-not $s){ return $null }
  try { [datetime]::ParseExact($s,'yyyyMMddTHHmmssZ',[Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null } }
$iso={ param($d) if($d){ ([datetime]$d).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
$num={ param($v) $v=[string]$v; if(-not $v){ return $null }; try { [int64]$v } catch { $null } }
$str={ param($v) if($null -eq $v -or "$v" -eq ''){ $null } else { [string]$v } }
# Duplicati writes DateTime.MinValue ("0001-01-01T…") for a schedule that has not computed a next run
# yet - a freshly imported job reports it. Passed through verbatim it reads as a real date in year 1;
# it means "not yet known", so it is null.
$zdt={ param($v) $s=[string]$v; if(-not $s -or $s -like '0001-01-01*'){ $null } else { $s } }
$fin=(& $pd $m.LastBackupFinished)
$errAt=(& $pd $m.LastErrorDate)
# Whose news is newer. An error OLDER than the last completed run has already been answered by a
# success and must not be presented as the backup's current state - both stale jobs on one server here
# carry year-old messages that would otherwise read as today's problem.
$errCurrent=$(if($errAt -and $fin){ $errAt -gt $fin } elseif($errAt){ $true } else { $false })
# The nightly run is the only thing that actually contacts the target, using the real credential, so it
# is the only honest source for "was the target reachable". A completed run PROVES it was, at that
# moment. A current error does NOT prove the converse - it is just as likely a local database or
# source-file fault - so that case reports null and hands over the message instead of inventing an
# attribution. Same discipline as everywhere else here: absence of proof is not proof of absence.
$reachable=$(if($fin -and -not $errCurrent){ $true } else { $null })
$staleDays=$(if($fin){ [int][math]::Floor(([datetime]::UtcNow - $fin).TotalDays) } else { $null })
$sch=$b.Schedule
# A job with NO SCHEDULE is not failing - nothing is driving it, by choice. That is what a decommissioned
# endpoint's config looks like when it is kept for archival: last run long past, last error older still,
# no schedule. Reporting that as 'error' invites someone to fix a backup nobody wants run again, and it
# buries the jobs that ARE broken. The error stays visible in last_error for anyone who wants it.
# Order matters. A job that has NEVER completed a run is 'no-completed-run' whether or not it has a
# schedule: calling an unscheduled one 'retained' claims archival data exists to restore, and a job
# that never ran has none. Only once something HAS been backed up does 'no schedule' mean retained.
$status=$(if(-not $fin){'no-completed-run'} elseif(-not $sch){'retained'} elseif($errCurrent){'error'} else {'ok'})
# No destination field: list-backups carries no TargetURL, and a field that is null on every host in
# every case is worse than an absent one - it reads as "we looked and could not tell" when nothing was
# ever there to look at. Naming the destination would mean going back to the credential-bearing export
# route for a label. `duplicati-sources` reports it, read from the per-backup record and stripped of
# its query string; `duplicati-backups` identifies the job by name.
[pscustomobject]@{ok=$true;command='target-check';backup=$id;name=(& $str $b.Name);
 status=$status;reachable=$reachable;last_success_at=(& $iso $fin);stale_days=$staleDays;
 last_error_at=(& $iso $errAt);last_error=$(if($errCurrent){(& $str $m.LastErrorMessage)}else{$null});
 superseded_error=$(if($errAt -and -not $errCurrent){(& $str $m.LastErrorMessage)}else{$null});
 scheduled=[bool]$sch;schedule_repeat=$(if($sch){(& $str $sch.Repeat)}else{$null});
 allowed_days=$(if($sch -and $sch.AllowedDays){ @(@($sch.AllowedDays)|ForEach-Object{[string]$_}) }else{ $null });
 next_run=$(if($sch){(& $zdt $sch.Time)}else{$null});last_duration=(& $str $m.LastBackupDuration);
 target_files=(& $num $m.TargetFilesCount);target_filesets=(& $num $m.TargetFilesetsCount);
 target_size=(& $str $m.TargetSizeString);source_files=(& $num $m.SourceFilesCount);
 source_size=(& $str $m.SourceSizeString);backup_versions=(& $num $m.BackupListCount)}|ConvertTo-Json -Depth 8"#;

/// Read-only: what the backup's own last run establishes about its remote target — when the target was
/// last successfully written to, how much is there, and whether the newest news is an error.
///
/// ⚠ `schedule_repeat` alone does NOT give the run frequency, and reading it as though it did produces
/// a false staleness alert. Duplicati stores the interval and the permitted weekdays separately: a job
/// measured on a live fileserver carried `Repeat: "1D"` with `AllowedDays: ["sun"]` — a *Sunday-only*
/// job that `1D` describes as daily. Six days since its last run is correct for it and overdue for a
/// genuine daily job, and only `allowed_days` tells the two apart. It is `null` when the schedule sets
/// no restriction, which is not the same as an empty list.
///
/// **It deliberately does not contact the target.** The obvious implementation — `BackendTool LIST` the
/// remote — is what this replaced, and it was worse on every axis. Listing a private bucket or share
/// needs the backup's credential, which meant lifting a live secret out of Duplicati's export and
/// trusting output redaction to keep it out of a stored job result; that redaction had in fact been
/// leaking `auth-password` until it was found. And the probe bought nothing for the risk: the nightly
/// run already contacts the same target with the same credential and records the outcome, so a
/// credential that expired or a destination that vanished shows up here as a failed run. A synthetic
/// LIST at an arbitrary moment is strictly weaker evidence than the real job's own result.
///
/// The one thing an authenticated LIST could uniquely do is cross-check Duplicati's local database
/// against what the remote actually holds — the divergence its own logs report as "remote files not
/// recorded in local storage". That would be worth building; it needs the count compared against
/// `target_files` rather than reported bare, which the LIST version never did.
///
/// Needs no API token, unlike the version it replaces.
#[cfg(windows)]
fn duplicati_target_check(params: Option<&str>) -> Option<Value> {
    let Some(id) = dup_backup_id(params) else {
        return Some(json!({"ok": false, "error": "provide the numeric backup id (from duplicati-backups)"}));
    };
    let body = format!("$id='{id}'\n{DUP_TARGETCHECK_BODY}");
    let mut out = ps_json(&dup_script(&body))
        .unwrap_or_else(|| json!({"ok": false, "error": "Duplicati target-check produced no parseable output"}));
    force_array_field(&mut out, "allowed_days");
    Some(out)
}

/// Make a field that is *conceptually* a list one in the JSON too.
///
/// `ConvertTo-Json` collapses a ONE-element array to a bare scalar, so a Sunday-only schedule
/// returned `"allowed_days": "sun"` where a seven-day one returned a list — both measured on live
/// hosts. The single-element case is precisely the one `allowed_days` exists to report, so the shape
/// a caller has to handle varied exactly where it matters most. Normalized in Rust rather than in the
/// script because it then holds regardless of which PowerShell the endpoint runs. A `null` stays
/// `null`: "no weekday restriction" is not an empty list.
#[cfg(windows)]
fn force_array_field(v: &mut Value, key: &str) {
    let Some(o) = v.as_object_mut() else { return };
    // An OBJECT counts too: a one-element array of rows serializes as a bare `{…}`, which is the same
    // trap one step up — `volumes_without_letter` is a single row on most machines.
    if let Some(lone @ (Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Object(_))) = o.get(key) {
        let one = Value::Array(vec![lone.clone()]);
        o.insert(key.into(), one);
    }
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
try{ Add-Type -TypeDefinition 'using System.Net;using System.Security.Cryptography.X509Certificates;public class STIdracTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp,X509Certificate c,WebRequest r,int p){return true;} }' }catch{}
try{ [System.Net.ServicePointManager]::CertificatePolicy = New-Object STIdracTrust }catch{}
try{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }catch{}
$pair="$($user):$($secret)"
$b64=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
# Accept is REQUIRED, not decorative. Without it .NET sends no Accept header and some iDRAC firmware
# answers Redfish with 406 Not Acceptable - including on /redfish/v1, the unauthenticated service root.
# That 406 was read as a firewall, a credential and a path problem in turn before the header was found
# to be missing: two other iDRACs in this fleet tolerate its absence, so the same code "worked" and the
# odd one out looked like a broken host rather than a stricter one.
$hdr=@{ Authorization = "Basic $b64"; Accept = 'application/json' }
# Candidate order: an explicitly supplied host wins, then the mDNS name the iDRAC publishes for itself,
# then BOTH link-local pass-through addresses. A single hardcoded 169.254.0.1 was wrong on two hosts in
# this fleet - they answer on 169.254.1.1 - and a wrong default is indistinguishable from a dead iDRAC
# in the result. Each candidate is PROVEN by an actual Redfish service-root response before it is used:
# reaching a TCP port is not the same as reaching an iDRAC, and picking on connectivity alone is how the
# 406 on one host would have been reported as a working address.
$idracCandidates=@()
if($idracHost){ $idracCandidates += $idracHost }
$idracCandidates += @('idrac.local','169.254.0.1','169.254.1.1')
$idracTried=@()
$base=$null
foreach($cand in $idracCandidates){
  if(-not $cand){ continue }
  $try="https://$cand"
  try{
    $probe=Invoke-RestMethod -Uri ($try+'/redfish/v1') -Headers $hdr -Method GET -TimeoutSec 15 -EA Stop
    if($probe -and $probe.RedfishVersion){ $base=$try; $idracHost=$cand; break }
    $idratried=$null
    $idracTried += [pscustomobject]@{host=$cand;status=200;error='responded but no RedfishVersion in the service root'}
  }
  catch{
    $sc=0; try{ $sc=[int]$_.Exception.Response.StatusCode }catch{}
    $idracTried += [pscustomobject]@{host=$cand;status=$sc;error=("$($_.Exception.Message)" -replace '\s+',' ')}
  }
}
if(-not $base){
  # Every candidate is listed with its own status. 'Could not reach it' and 'reached it and it refused
  # us' are different problems with different fixes, and a caller cannot tell them apart from a single
  # summary line.
  ([pscustomobject]@{ok=$false;error='no iDRAC Redfish service root answered on any candidate address';tried=$idracTried}|ConvertTo-Json -Depth 6); exit
}
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
# Dell reports **SmartAlertAbsent** on a HEALTHY drive. The previous test flagged any state that was
# merely non-empty and not literally 'No'/'Unknown', so every healthy Dell drive came back as a
# predicted failure - measured: four SSDs, all failure_predicted=false, health=OK, life_left=100%,
# reported as predicted_failure_count=4. Only an alert that is PRESENT counts, and 'no value' means no
# information, not a failure: an unreadable field must not manufacture an alert any more than it may
# manufacture an all-clear.
$predicted=@($drives | Where-Object { $_.failure_predicted -eq $true -or ([string]$_.predictive_failure_state -match '(?i)present|imminent|failing') })
# Drives whose predictive state could not be read at all - neither healthy nor failing, and the caller
# must be told rather than have them silently counted as fine.
$pfUnknown=@($drives | Where-Object { $null -eq $_.failure_predicted -and -not [string]$_.predictive_failure_state })
$unhealthy=@($drives | Where-Object { ($_.health -and $_.health -ne 'OK') -or ($_.raid_status -and $_.raid_status -notmatch '^(Online|Ready|NonRAID|Spare)$') })
$unkH=@(@($drives)+@($controllers) | Where-Object { -not [string]$_.health })
[pscustomobject]@{
  ok=$true; idrac=$idracHost; redfish_version=[string]$root.RedfishVersion
  controllers=$controllers; drives=$drives; volumes=$volumes
  drive_count=@($drives).Count
  predicted_failure_count=@($predicted).Count
  predicted_failures=@($predicted | ForEach-Object { '{0} ({1}) {2}' -f $_.location,$_.id,$_.model })
  predictive_unknown_count=@($pfUnknown).Count
  predictive_unknown=@($pfUnknown | ForEach-Object { '{0} ({1}) {2}' -f $_.location,$_.id,$_.model })
  unhealthy_count=@($unhealthy).Count
  health_unknown_count=@($unkH).Count
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
# A health field that is EMPTY is not a pass. The `-and` guard below skips it, so anything whose
# health could not be read was counted as healthy - two AHCI controllers came back health='' and
# were reported fine. Unknown is its own bucket and is reported as such.
$badT=@($temps | Where-Object { $_.health -and $_.health -ne 'OK' })
$badF=@($fans | Where-Object { $_.health -and $_.health -ne 'OK' })
$unkT=@($temps | Where-Object { -not [string]$_.health })
$unkF=@($fans | Where-Object { -not [string]$_.health })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  temperatures=$temps; fans=$fans
  temp_count=@($temps).Count; fan_count=@($fans).Count
  unhealthy_temp_count=@($badT).Count; unhealthy_fan_count=@($badF).Count
  health_unknown_temp_count=@($unkT).Count; health_unknown_fan_count=@($unkF).Count
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
# A health field that is EMPTY is not a pass. The `-and` guard below skips it, so anything whose
# health could not be read was counted as healthy - two AHCI controllers came back health='' and
# were reported fine. Unknown is its own bucket and is reported as such.
$badP=@($present | Where-Object { $_.health -and $_.health -ne 'OK' })
$badR=@($red | Where-Object { $_.health -and $_.health -ne 'OK' })
$unkP=@($present | Where-Object { -not [string]$_.health })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  supplies=$psus; redundancy=$red
  psu_present=@($present).Count
  consumed_watts=$pc.PowerConsumedWatts
  capacity_watts=$pc.PowerCapacityWatts
  average_watts=$pc.PowerMetrics.AverageConsumedWatts
  unhealthy_psu_count=@($badP).Count
  health_unknown_psu_count=@($unkP).Count
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
# A health field that is EMPTY is not a pass. The `-and` guard below skips it, so anything whose
# health could not be read was counted as healthy - two AHCI controllers came back health='' and
# were reported fine. Unknown is its own bucket and is reported as such.
$bad=@($dimms | Where-Object { $_.health -and $_.health -ne 'OK' })
$unkD=@($dimms | Where-Object { -not [string]$_.health })
$total=0; foreach($d in $dimms){ $total += [int]$d.capacity_mib }
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  dimms=$dimms; dimm_count=@($dimms).Count; total_gib=[math]::Round($total/1024,1)
  unhealthy_count=@($bad).Count
  health_unknown_count=@($unkD).Count
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
# A health field that is EMPTY is not a pass. The `-and` guard below skips it, so anything whose
# health could not be read was counted as healthy - two AHCI controllers came back health='' and
# were reported fine. Unknown is its own bucket and is reported as such.
$bad=@($cpus | Where-Object { $_.health -and $_.health -ne 'OK' })
$unkC=@($cpus | Where-Object { -not [string]$_.health })
[pscustomobject]@{
  ok=$true; idrac=$idracHost
  cpus=$cpus; cpu_count=@($cpus).Count
  unhealthy_count=@($bad).Count
  health_unknown_count=@($unkC).Count
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
///
/// Also backs the `drive_predicted_failure` / `drive_unhealthy` / `drive_predictive_unknown` health
/// alerts: the console registers `idrac-storage` as a health-input COLLECTOR, so a Check dispatches
/// it as a job and the alerts read the stored result. It must stay a job rather than a snapshot —
/// the iDRAC credential is merged in only on the signed params fetch.
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

/// Launch a PowerShell script and capture its stdout/stderr/exit status, terminating it if it outlives
/// [`PS_RUN_CEILING_SECS`].
///
/// `Command::output()` cannot do this: it blocks until the child exits, with no deadline and no way to
/// reach the handle. So the child is spawned, its pipes drained on their own threads, and its exit
/// polled — the interval doubling from 2 ms to 250 ms, so a 200 ms collector pays almost nothing and a
/// long one costs four wakeups a second.
///
/// ⚠ **A timed-out run reports NO stdout**, even when the child wrote some. [`guard_failure`] reads any
/// stdout as a trustworthy answer, so keeping the partial output would turn a killed collector into a
/// confident short one — the failure this whole module is built to prevent.
///
/// ⚠ **The kill reaches the PowerShell process, not its descendants.** A grandchild (`gpresult`,
/// `dcdiag`, …) survives it and can keep the inherited pipe open, so the timeout path abandons the
/// reader threads rather than joining them — joining would wedge exactly where this exists to unwedge.
/// Killing a whole tree needs a Windows job object, which this build does not have.
#[cfg(windows)]
fn ps_capture(script: &str) -> Option<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut child = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(PS_RUN_CEILING_SECS);
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
        hbb_common::log::error!("a collector's PowerShell run passed {PS_RUN_CEILING_SECS}s and was terminated");
        return Some(ps_run_unfinished(&format!(
            "it was still running after {PS_RUN_CEILING_SECS}s, so the PowerShell process was terminated"
        )));
    };
    // The child is gone, so the pipes are at EOF and the readers have finished — unless a descendant
    // inherited one and is still alive, in which case the read never ends.
    let grace = std::time::Duration::from_secs(PS_DRAIN_GRACE_SECS);
    match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(stdout), Ok(stderr)) => Some(std::process::Output { status, stdout, stderr }),
        _ => Some(ps_run_unfinished("a descendant kept its output pipe open after the process exited")),
    }
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

/// Per-field character cap for the cheap metadata collectors. MEASURED across three devices
/// 2026-07-30: it cut NOTHING on two of them, and exactly ONE value on the third — see the note at the
/// truncation site. Kept at 300 for the four short-field kinds, whose natural maxima are 96-125 chars.
#[cfg(windows)]
const FIELD_VALUE_CAP: usize = 300;

/// `env` gets a much larger cap, because it is the ONE field the 300 measurably destroys.
///
/// ⚠ The single cut found across ~2,400 measured values was a machine `PATH` at exactly 301 chars.
/// Seven complete entries survived and the eighth was severed mid-token — and the lost tail is the part
/// that matters: the standard audit question is whether a **user-writable directory** sits on the
/// machine PATH, and the visible head is always the boring system entries. A `PATH` cut at 300 cannot
/// answer the question it exists to answer. The other four collectors return identifier-shaped fields
/// and would not notice either value, so this is raised HERE rather than globally.
#[cfg(windows)]
const ENV_VALUE_CAP: usize = 8000;

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
    // `truncated` is emitted UNCONDITIONALLY, and that is the point: a flag present only when true is
    // unreadable, because absent would mean both "the page is complete" and "this client is too old to
    // say". Its sibling `paginate` has always carried it; the cursor form did not, so an ad-* caller
    // had to infer completeness from `cursor` being present or from count<total — an inference nothing
    // documented and nothing guaranteed. Same condition as the cursor, stated as a fact instead.
    let mut out = json!({ "total": total, "count": page.len(), "truncated": end < total, "items": page });
    if end < total {
        out["cursor"] = json!(end.to_string());
    }
    out
}

/// Run a PowerShell one-liner that emits `ConvertTo-Json` and return its rows as a paginated page, with
/// any over-long string field char-safe-truncated. The shared shape for the read-only list kinds
/// (scheduled tasks / startup / network connections / PnP / env).
///
/// The script is wrapped in [`PS_GUARD`] and checked afterwards, so a read that fails reports
/// `{ok:false,error}` rather than the empty list it used to. And the page comes from `paginate` rather
/// than a bare `truncate`: the old byte guard dropped the tail with no marker at all, so an operator
/// could not tell a complete list from a clipped one — which is the error≠absent problem applied to
/// volume instead of failure. Empty off-Windows.
///
/// **`page_default` is a page size, NOT a collection cap.** It used to be both: the rows were
/// `truncate`d to it BEFORE `paginate` saw them, so `paginate` measured an already-shortened list, fitted
/// it in one page, and reported `truncated:false` on an answer that was not whole. The envelope's own
/// completeness flag asserted the opposite of the truth — worse than the missing marker it replaced,
/// because a caller could read it and be confidently wrong. The truncate is deleted, and the parameter is
/// renamed so it cannot be reflexively restored: `paginate` bounds the page by `limit` AND by
/// [`PAGE_BUDGET`] bytes, so nothing else was holding the size down and page 1 is byte-identical.
///
/// The envelope carries `page_default` back out. That is the only structural way a caller can tell a
/// client that pages honestly from one that silently cut at the same number — `total:400,
/// truncated:false` means CUT on an old client and COMPLETE on a new one, and the field's presence is
/// the discriminator.
#[cfg(windows)]
fn ps_json_array(script: &str, page_default: usize, value_cap: usize, params: Option<&str>, what: &str) -> Option<Value> {
    let guarded = format!("{PS_GUARD}{script}; Stop-OnError '{what}'");
    let mut rows = match ps_rows_guarded(&guarded, what) {
        GuardedRows::Failed(e) => return Some(e),
        GuardedRows::Rows(v) => v,
    };
    // The 300-char VALUE cap. MEASURED 2026-07-30 on two devices: it cut NOTHING — zero values above
    // 300, and zero even in the 200-300 band; the longest value seen anywhere was 128 chars. Left as is.
    // ⚠ That is structural rather than lucky, and it says where to look when it changes: four of the
    // five governed collectors return no field that CAN reach 300 (schtasks has no action field,
    // netconn only IP literals, pnp/startup are path-shaped). `env` is the sole genuine risk — `Path`
    // and `PSModulePath` are the classic >300-char values, and the TAIL is the part that matters — but
    // env is measured on a clean DC here AND only ever reads the SYSTEM profile, so the long per-user
    // values are not collected at all. Re-measure on a workstation, or if any of these gains a
    // long-form field.
    for r in &mut rows {
        if let Some(obj) = r.as_object_mut() {
            for (_k, v) in obj.iter_mut() {
                if let Some(s) = v.as_str() {
                    if s.chars().count() > value_cap {
                        *v = json!(s.chars().take(value_cap).collect::<String>() + "…");
                    }
                }
            }
        }
    }
    let mut out = paginate(rows, params, page_default);
    if let Some(o) = out.as_object_mut() {
        o.insert("page_default".to_owned(), json!(page_default));
    }
    Some(out)
}
#[cfg(not(windows))]
fn ps_json_array(_script: &str, _page_default: usize, _value_cap: usize, _params: Option<&str>, _what: &str) -> Option<Value> {
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

/// Match normalization for a `select` title: trim, collapse whitespace runs to one space, lowercase.
///
/// Deliberately weaker than the console's stored-identity rule — no control-character stripping, no
/// Unicode normalization — because this is a string comparison inside one install run against titles
/// from the same source that produced the snapshot, so its only failure direction is a non-match
/// (nothing installs, and the entry is reported in `not_found`). The comparison itself happens in
/// PowerShell under the same three operations; this copy exists to reject an entry that normalizes
/// to nothing, which would otherwise reach the script as an empty title.
#[cfg(windows)]
fn match_normalize_title(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// Largest base64 `select` blob we'll interpolate. The script rides `powershell.exe -Command`, whose
/// whole command line is capped at 32 767 chars by the OS — a selection large enough to overrun that
/// must be refused here, where the operator gets a reason, rather than truncated into a command line
/// that installs a set nobody chose. 16 KiB of base64 is ~12 KiB of JSON, several times the ~3.4 KiB
/// a full 200-row KB-only selection costs.
#[cfg(windows)]
const SELECT_B64_MAX: usize = 16 * 1024;

/// Validate the `select` param into the canonical entry list the install script is handed: an array
/// of `{"kb":"<digits>"}` / `{"title":"<as sent>"}` objects.
///
/// ANY bad entry rejects the WHOLE selector rather than being dropped. A partially honoured selection
/// installs a set the operator never chose, and the two shapes that could be read charitably are the
/// dangerous ones: an entry carrying both keys has no defined precedence, and an entry carrying
/// neither could be read as matching everything.
///
/// `kb` is reduced to bare digits and `title` is only ever compared, never re-interpolated and never
/// used as a regex — the script receives the list base64-encoded, whose alphabet cannot close the
/// PowerShell string literal it sits in.
#[cfg(windows)]
fn validate_select(v: &Value) -> Result<Vec<Value>, String> {
    let Some(arr) = v.as_array() else {
        return Err("select must be an array".to_owned());
    };
    // Rejected exactly as `kbs: []` is, and for the same reason: an empty selection must never be
    // read as "everything".
    if arr.is_empty() {
        return Err("select is empty".to_owned());
    }
    if arr.len() > 500 {
        return Err("select carries more entries than a device can offer".to_owned());
    }
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        let Some(obj) = e.as_object() else {
            return Err("every select entry must be an object".to_owned());
        };
        if obj.keys().any(|k| k.as_str() != "kb" && k.as_str() != "title") {
            return Err("a select entry carries a key that is neither kb nor title".to_owned());
        }
        let kb = obj.get("kb").and_then(|x| x.as_str()).unwrap_or("").trim();
        let title = obj.get("title").and_then(|x| x.as_str()).unwrap_or("");
        match (kb.is_empty(), match_normalize_title(title).is_empty()) {
            (false, true) => {
                // Same reduction the `kbs` path applies, so both selectors accept the same spellings.
                let digits = kb.trim_start_matches(['K', 'k']).trim_start_matches(['B', 'b']);
                if digits.is_empty() || digits.len() > 12 || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return Err(format!("select entry kb {kb:?} is not a KB number"));
                }
                out.push(json!({ "kb": digits }));
            }
            // The title travels as sent; the script normalizes both sides of the comparison itself.
            (true, false) => out.push(json!({ "title": title })),
            _ => return Err("every select entry needs exactly one of kb or title".to_owned()),
        }
    }
    Ok(out)
}

/// Install Windows updates via the WU COM API (`Microsoft.Update.Session`), run BY the client (no
/// `PSWindowsUpdate` module / resident agent). `params` JSON
/// `{select:[{kb}|{title}], kbs:["KB5000001",…], reboot:false}`.
///
/// **The job must name what it wants, or say "all" and mean it.** `select` is the selection when
/// present and `kbs` is then ignored; a `kbs` digit array is the selection otherwise; `kbs: "all"`
/// resolves from the client's own search. A job carrying NO selector at all is REFUSED rather than
/// silently meaning "everything" — that fall-through is how an unrecognized selector (a newer
/// console's `select` reaching an older client) would turn into a fleet-wide install of every
/// available update, including the optional drivers Windows Update itself declines to install
/// unattended.
///
/// `kbs: "all"` is the pre-`select` contract and keeps working unchanged. Clients self-update on
/// their own schedule, so a new client routinely talks to a console that has not caught up yet, and
/// that console's bulk button still posts `"all"`. Refusing it would break every bulk install on the
/// fleet for no safety gain: it is an explicit documented request, not an unrecognized selector. The
/// console stops emitting it once its `select` builder ships.
///
/// `select` lets a job name an update that has no KB at all — the per-row case that was simply
/// impossible before — and carries titles, which cannot be reduced to a safe literal the way a KB
/// can. So the CLIENT base64-encodes the validated list and the script decodes it, rather than the
/// console sending a blob: the params stay legible in the audit trail for what is an L2 action, and
/// the encoded bytes are well-formed by construction instead of caller-supplied.
///
/// `reboot` (default false, operator-choice-per-job) controls whether the client reboots when an
/// installed update requires it. Always reports `reboot_required`, plus `requested` and `not_found`
/// so a superseded or already-installed selection is distinguishable from nothing-to-do; on reboot
/// opt-in it schedules a 60 s-delayed reboot so the signed result posts first.
#[cfg(windows)]
fn win_update_install(params: Option<&str>) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let reboot = p.get("reboot").and_then(|x| x.as_bool()).unwrap_or(false);
    let (install_all, entries) = match p.get("select") {
        // `select` present is authoritative, and a malformed one fails the job rather than falling
        // back to `kbs` — the console sends both above the floor, so a silent fallback would install
        // the belt's KB subset while reporting against a selection that was never understood.
        Some(v) if !v.is_null() => match validate_select(v) {
            Ok(e) => (false, e),
            Err(why) => return json!({ "ok": false, "error": format!("invalid select: {why}") }),
        },
        _ => match p.get("kbs") {
            // Below-floor path, unchanged: bare KB numbers matched against KBArticleIDs, non-digit
            // input dropped.
            Some(Value::Array(arr)) => {
                let kbs: Vec<Value> = arr
                    .iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().trim_start_matches(['K', 'k']).trim_start_matches(['B', 'b']))
                    .filter(|s| !s.is_empty() && s.len() <= 12 && s.chars().all(|c| c.is_ascii_digit()))
                    .map(|s| json!({ "kb": s }))
                    .collect();
                if kbs.is_empty() {
                    return json!({ "ok": false, "error": "no valid KB ids" });
                }
                (false, kbs)
            }
            // The pre-`select` contract: install whatever the device's own search finds. Matched on
            // the literal word, not on "anything that isn't an array" as it used to be — a caller
            // who asked for everything gets everything, and a caller who asked for nothing
            // intelligible falls through to the refusal below.
            Some(Value::String(s)) if s.trim().eq_ignore_ascii_case("all") => (true, Vec::new()),
            _ => {
                return json!({
                    "ok": false,
                    "error": "win-update-install needs a selection: a 'select' list, a 'kbs' array of KB ids, or kbs:\"all\". \
                              A job naming nothing is refused rather than installing every available update.",
                })
            }
        },
    };
    // base64 is A-Za-z0-9+/= — it cannot close the single-quoted PowerShell literal it lands in, so
    // nothing here needs escaping. Decoded as UTF-8, NOT PowerShell's UTF-16LE `-EncodedCommand`
    // convention, which would mojibake the first localized title.
    let sel_b64 = base64::encode(Value::Array(entries).to_string(), variant());
    if sel_b64.len() > SELECT_B64_MAX {
        return json!({ "ok": false, "error": "the update selection is too large to dispatch; install in smaller batches" });
    }
    let all_lit = if install_all { "$true" } else { "$false" };
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
try {{
  $all = {all_lit}
  $sel = @(); $selKb = @{{}}; $selTitle = @{{}}
  if (-not $all) {{
    # Two steps: PS 5.1 writes the decoded array as ONE pipeline object, so @(... | ConvertFrom-Json)
    # would yield a one-element array holding the whole selection.
    $sel = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{sel_b64}')) | ConvertFrom-Json
    $sel = @($sel)
    if ($sel.Count -eq 0) {{ throw 'empty update selection' }}
    for ($i=0; $i -lt $sel.Count; $i++) {{
      if ($sel[$i].kb) {{ $selKb[$i] = [string]$sel[$i].kb }}
      else {{ $selTitle[$i] = ((([string]$sel[$i].title).Trim()) -replace '\s+',' ').ToLowerInvariant() }}
    }}
  }}
  $session = New-Object -ComObject Microsoft.Update.Session
  $res = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
  $coll = New-Object -ComObject Microsoft.Update.UpdateColl
  $hit = @{{}}
  foreach ($u in $res.Updates) {{
    $match = $all
    if (-not $match) {{
      $ut = ((([string]$u.Title).Trim()) -replace '\s+',' ').ToLowerInvariant()
      $ukb = @(); foreach ($id in $u.KBArticleIDs) {{ $ukb += [string]$id }}
      for ($i=0; $i -lt $sel.Count; $i++) {{
        $one = $false
        if ($selKb.ContainsKey($i)) {{ if ($ukb -contains $selKb[$i]) {{ $one = $true }} }}
        elseif ($ut -eq $selTitle[$i]) {{ $one = $true }}
        if ($one) {{ $match = $true; $hit[$i] = $true }}
      }}
    }}
    if ($match) {{ if (-not $u.EulaAccepted) {{ try {{ $u.AcceptEula() }} catch {{}} }}; [void]$coll.Add($u) }}
  }}
  # requested/not_found describe a NAMED selection; on the "all" path nothing was named, so they are
  # omitted rather than reported as zero-of-nothing.
  $nf = @(); for ($i=0; $i -lt $sel.Count; $i++) {{ if (-not $hit.ContainsKey($i)) {{ $nf += $sel[$i] }} }}
  if ($coll.Count -eq 0) {{
    $out = @{{ ok=$true; installed=0; reboot_required=$false; note='no matching updates' }}
    if (-not $all) {{ $out['requested']=$sel.Count; $out['not_found']=$nf }}
    [PSCustomObject]$out | ConvertTo-Json -Depth 4 -Compress; exit
  }}
  $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
  $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll; $r = $inst.Install()
  $out = @{{ ok=($r.ResultCode -eq 2); installed=$coll.Count; result_code=[int]$r.ResultCode; reboot_required=[bool]$r.RebootRequired }}
  if (-not $all) {{ $out['requested']=$sel.Count; $out['not_found']=$nf }}
  [PSCustomObject]$out | ConvertTo-Json -Depth 4 -Compress
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

/// The registry roots a path may name, paired with the hive the provider knows them by.
#[cfg(windows)]
const REG_HIVES: [(&str, &str); 5] = [
    ("HKLM:\\", "HKEY_LOCAL_MACHINE"),
    ("HKCU:\\", "HKEY_CURRENT_USER"),
    ("HKCR:\\", "HKEY_CLASSES_ROOT"),
    ("HKU:\\", "HKEY_USERS"),
    ("HKCC:\\", "HKEY_CURRENT_CONFIG"),
];

/// Validate a registry path (F11): a known hive root + no characters that could break out of the
/// single-quoted PowerShell literal it's interpolated into. Conservative — rare paths with quotes
/// are rejected rather than risk injection.
///
/// `..` segments are refused outright: the provider resolves them, so `HKU:\..\..\SAM` would walk
/// out of the hive the caller named and past [`reg_path_denied`], which matches on the literal.
#[cfg(windows)]
fn valid_reg_path(path: &str) -> bool {
    REG_HIVES.iter().any(|(r, _)| path.starts_with(r))
        && path.len() <= 512
        && !path.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`'))
        && !path.split(|c| c == '\\' || c == '/').any(|seg| seg == "..")
}

/// Rewrite a validated PS-drive path onto the provider (`HKU:\.DEFAULT` →
/// `Registry::HKEY_USERS\.DEFAULT`), which is what actually reaches PowerShell.
///
/// PowerShell auto-creates only the `HKLM:` and `HKCU:` registry drives, so `HKCR:`, `HKU:` and
/// `HKCC:` do not exist in a fresh session and `Get-Item` on them failed with "Cannot find drive"
/// even though the path was well-formed and documented. Naming the hive directly needs no drive —
/// and unlike creating the drives on demand, it adds no session state and no failure of its own.
/// The drive form stays the only accepted spelling on the wire.
#[cfg(windows)]
fn reg_provider_path(path: &str) -> String {
    for (drive, hive) in REG_HIVES {
        if let Some(rest) = path.strip_prefix(drive) {
            let rest = rest.trim_end_matches('\\');
            return if rest.is_empty() { format!("Registry::{hive}") } else { format!("Registry::{hive}\\{rest}") };
        }
    }
    path.to_string()
}

/// The SAM and SECURITY hives hold password material and are never a legitimate diagnostic read; this
/// mirrors the backend's dispatch-time denylist client-side so no path to a `reg-read` job can reach
/// them. Normalises case, `/` → `\` and repeated separators, and matches both the drive and hive
/// spellings, so the path that reaches the provider is the path that was checked.
#[cfg(windows)]
fn reg_path_denied(path: &str) -> bool {
    let mut norm = path.trim().replace('/', "\\").to_ascii_uppercase();
    while norm.contains("\\\\") {
        norm = norm.replace("\\\\", "\\");
    }
    let norm = norm.trim_start_matches("REGISTRY::").trim_end_matches('\\');
    ["HKLM:\\SAM", "HKLM:\\SECURITY", "HKEY_LOCAL_MACHINE\\SAM", "HKEY_LOCAL_MACHINE\\SECURITY"]
        .iter()
        .any(|d| norm == *d || norm.starts_with(format!("{d}\\").as_str()))
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

/// A `reg-read` result that is NOT a key read — a malformed path, a refused hive, or a read that
/// failed (the missing-key case arrives here as the provider's own stderr text). Carries `ok:false`
/// alongside `error` so [`is_collector_error`] recognizes it; see [`wmi_error`] for why the flag lives
/// in the body while the dispatch `status` stays `done`. `reg-read` is the collector most often used
/// to prove a key is ABSENT, so a refusal that reads as data is the same error≠absent conflation the
/// rest of this file exists to undo.
#[cfg(windows)]
fn reg_error(why: impl Into<String>) -> Value {
    json!({ "ok": false, "error": why.into() })
}

/// The per-value byte cap for a `REG_BINARY` value, and the caller-facing `max_bytes` ceiling.
///
/// ⚠ A BYTE cap, not a character one, because the encoding below is fixed-ratio — 2 characters per
/// byte — so a character bound no longer says anything a caller can act on. 16 KiB comfortably clears
/// the value that motivated this: a printer's `Default DevMode` measured **10,392 bytes**, of which the
/// old 1000-*character* cap carried 453 (4.4%), because rendering bytes as space-separated decimal
/// costs 2.2-3.3 characters each.
#[cfg(windows)]
const REG_BIN_BYTE_CAP: usize = 16 * 1024;

/// Total binary bytes one `reg-read` may return across ALL of a key's values.
///
/// The per-value cap alone does not bound the result: a key with forty binary values (the shell's
/// `*MRU` keys are shaped exactly like that) would multiply out past `store::MAX_JOB_RESULT` = 256 KiB,
/// where an over-cap result is **replaced wholesale** with a failure notice rather than clipped — so
/// raising the per-value ceiling without a pool would trade a truncated answer for no answer at all.
/// 48 KiB of bytes is 96 KiB of hex, which leaves the subkey list and the string values better than
/// half the cap. The budget is spent device-side, in value order, and a value that gets none of it
/// still reports its true `bytes`.
#[cfg(windows)]
const REG_BIN_BUDGET: usize = 48 * 1024;

/// The character cap for a `reg-read` **string** value. Unchanged at 1000 — the measured problem was
/// binary — but an over-cap value now says so (`truncated`) and states its true length (`chars`)
/// instead of leaving a bare ellipsis to be sniffed for.
#[cfg(windows)]
const REG_VALUE_CHAR_CAP: usize = 1000;

/// The per-KEY character budget for `reg-read` **string** values, the string half of what
/// [`REG_BIN_BUDGET`] does for binary. Spent in value order.
///
/// A per-value cap alone does not bound a result: binary learned this already, which is why it has both
/// bounds. A key holding hundreds of long `REG_SZ` values could grow past `store::MAX_JOB_RESULT`, and
/// an over-cap result is **replaced wholesale** with a failure notice rather than clipped — so the
/// failure mode is losing the entire answer, not losing its tail.
///
/// Sized so the two budgets cannot collude: 48 KiB binary + 32 KiB string = 80 KiB of value payload
/// against a 256 KiB cap, leaving room for names, subkeys and hex's 2 chars/byte expansion.
///
/// ⚠ **This does NOT make `reg-read` bounded.** Value *names*, the *subkey list*, and the number of
/// values are all still ungoverned, and `reg-read` has no pagination — so a starved tail is
/// unrecoverable rather than fetchable on a second page. Do not read this constant as "reg-read is safe
/// now"; read it as "the value payload is bounded".
#[cfg(windows)]
const REG_STR_BUDGET: usize = 32 * 1024;

/// How many entries of one `REG_MULTI_SZ` come back by default, and the ceiling a caller may raise it
/// to with `max_entries`.
///
/// The character cap was the wrong UNIT for this type and the measurement is what proves it:
/// `PendingFileRenameOperations` holds 56 paths of ~62 characters, and a 1000-character per-VALUE cap
/// returned **16 of 56** — under a third of a value someone reads precisely when they suspect
/// something. Entries are the unit of meaning, so the character cap now bounds one ENTRY and this
/// bounds how many.
///
/// 256 is >4x the measured worst case, so it does not bind on real data; and unlike the character cap
/// it is **caller-raisable**, which is the property that made 16-of-56 terminal rather than merely
/// tight. Raising it cannot escape [`REG_STR_BUDGET`] — the per-key budget still bounds the total, so
/// the ceiling here is a convenience bound, not the safety one.
#[cfg(windows)]
const REG_MULTI_ENTRY_CAP: usize = 256;
#[cfg(windows)]
const REG_MULTI_ENTRY_MAX: usize = 4096;

/// `reg-read` pagination. The two value budgets bound `data` ONLY — the SUBKEY list and the value
/// NAME list were completely ungoverned, and that is not theoretical: measured on live devices,
/// `HKLM:\SOFTWARE\Classes\Interface` serializes to **1,174,314 characters against a 262,144 cap**
/// (448%) and is REPLACED WHOLESALE at ingest, so reading it returns nothing at all. Nine such keys
/// were found on one ordinary Windows box, the worst at 577%.
///
/// The old error even told the caller to "page it with offset/limit" — on a collector that had no
/// pagination at all. These are that pagination.
///
/// Two corrections worth keeping, because both are counter-intuitive:
/// - **`HKLM:\SOFTWARE\Classes` is NOT the problem key** (5,565 direct subkeys, ~50% of the cap, fits
///   fine). The killers are `Classes\Interface` at 28,689 subkeys and `SideBySide\Winners`.
/// - **Value NAMES dominate, not subkeys.** `Installer\Folders` holds ~11,900 values whose NAMES total
///   ~916,000 characters against ~2,200 characters of DATA — the string budget governs 0.15% of that
///   payload and never fires. A subkey-only fix would leave that key just as lost.
///
/// The bound that matters is the CHAR BUDGET, not the item limit: 5,000 GUID-shaped subkeys already
/// serialize to ~205,000 chars. `limit` is caller-controlled, so it can never be the safety bound.
#[cfg(windows)]
const REG_SUBKEY_PAGE_DEFAULT: usize = 5_000;
#[cfg(windows)]
const REG_SUBKEY_PAGE_MAX: usize = 50_000;
/// Serialized characters of ONE subkey page — the same 48 KiB the rest of the collector tree pages at.
#[cfg(windows)]
const REG_SUBKEY_BUDGET: usize = 48 * 1024;
#[cfg(windows)]
const REG_VALUE_PAGE_DEFAULT: usize = 500;
#[cfg(windows)]
const REG_VALUE_PAGE_MAX: usize = 5_000;
/// Per value NAME. Windows permits a 16,383-character value name, so one pathological name can outrun
/// any list-level budget on its own.
#[cfg(windows)]
const REG_NAME_CHAR_CAP: usize = 512;
/// Value names across ONE page.
#[cfg(windows)]
const REG_NAME_BUDGET: usize = 16 * 1024;

/// The `reg-read` one-liner, built separately so the encoding contract is testable without a device.
///
/// ⚠ **WIRE FORMAT.** A `REG_BINARY` value's `data` is **lowercase hex**, no separators — it was
/// space-separated *decimal* bytes (`"75 0 121 0 …"`), which is what `[string]` does to a `byte[]`.
/// Hex over base64 (2.0 chars/byte against 1.33) is a deliberate trade of ~33% density for two
/// properties this data needs: it is **byte-aligned**, so a truncated blob's visible prefix decodes
/// exactly and offset *n* in the value is always at character *2n* (reading a `DEVMODEW` header, or
/// UTF-16LE text out of a task's `Triggers`, is a fixed-width slice); and it is **greppable**, so a
/// known byte pattern can be matched in the value as returned. Base64 has neither — a 3-byte group
/// spans 4 characters, so a slice is only decodable after realignment, and the same bytes encode
/// differently at three different offsets.
///
/// The value is cut BEFORE it is encoded, per value at `bin_cap` and across the key at `budget`, so a
/// 10 MB blob never becomes a 20 MB string on its way to being thrown away.
///
/// ⚠ **A `REG_MULTI_SZ` is emitted as real entries.** It arrives from `GetValue` as a `System.String[]`,
/// and `[string]` on a PowerShell array joins it with `$OFS` — a single space — which DESTROYS the
/// separator on the device, before any JSON exists. Nothing downstream can recover it. Three distinct
/// registry states collapsed into one shape: N entries vs. one entry containing spaces; an EMPTY entry,
/// which vanished into an extra space; and a zero-entry value, which rendered `""` — identical to an
/// empty `REG_SZ` and to a value the collector failed to read. Measured cost:
/// `PendingFileRenameOperations` carries 58 entries of which **29 are the empty string**, and an empty
/// destination entry is exactly how a pending DELETE is encoded — so 29 security-relevant facts were
/// being erased into whitespace.
///
/// So the arm emits `count` (the true entry count, always) and `items` (the entries), keeping `data` a
/// string for compatibility. Two details are load-bearing:
/// - **`[char]10`, not a literal newline.** The script must stay a one-liner, and `data` joined with
///   newlines round-trips: `reg_write` splits MultiString input on `'\n'`, so read→paste-back through
///   the console used to collapse a multi-entry value into one. An old console renders `\n` as a space
///   in HTML, i.e. exactly what it renders today.
/// - **`-Depth 4` is now load-bearing.** `items` needs depth ≥ 3; at `-Depth 2` `ConvertTo-Json`
///   silently space-joins the array back into the defect shape, with no error. Do not add a nesting
///   level without raising it.
#[cfg(windows)]
fn reg_read_script(
    path: &str,
    bin_cap: usize,
    budget: usize,
    sub_offset: usize,
    sub_limit: usize,
    val_offset: usize,
    val_limit: usize,
) -> String {
    format!(
        "$ErrorActionPreference='Stop'; $k=Get-Item -LiteralPath '{path}'; $cap={bin_cap}; $left={budget}; \
         $sn=[string[]]$k.GetSubKeyNames(); [Array]::Sort($sn,[StringComparer]::OrdinalIgnoreCase); \
         $vn=[string[]]$k.GetValueNames(); [Array]::Sort($vn,[StringComparer]::OrdinalIgnoreCase); \
         $vals=foreach($n in @($vn|Select-Object -Skip {val_offset} -First {val_limit})){{ \
           $t=$k.GetValueKind($n).ToString(); $v=$k.GetValue($n); \
           if($v -is [byte[]]){{ \
             $len=$v.Length; $take=[Math]::Min($len,$cap); if($take -gt $left){{$take=$left}}; $left=$left-$take; \
             $hex=''; if($take -gt 0){{$hex=[System.BitConverter]::ToString($v,0,$take).Replace('-','').ToLowerInvariant()}}; \
             $o=[ordered]@{{name=$n;type=$t;encoding='hex';bytes=$len;data=$hex}}; \
             if($take -lt $len){{$o['truncated']=$true;$o['data_bytes']=$take}}; \
             [pscustomobject]$o \
           }} elseif($v -is [string[]]){{ \
             [pscustomobject]@{{name=$n;type=$t;count=$v.Count;items=@($v);data=($v -join [char]10)}} \
           }} else {{ [pscustomobject]@{{name=$n;type=$t;data=[string]$v}} }} \
         }}; \
         [pscustomobject]@{{key=$k.Name;subkey_total=@($sn).Count;value_total=@($vn).Count;\
           subkeys=@($sn|Select-Object -Skip {sub_offset} -First {sub_limit});values=@($vals)}}\
           |ConvertTo-Json -Compress -Depth 4"
    )
}

/// Char-cap the STRING values of a `reg-read` result — per value at `char_cap`, and across the whole key
/// at `budget`, spent in value order. Returns whether the KEY budget (rather than the per-value cap) cut
/// anything, so the envelope can say which bound fired.
///
/// A binary value is left alone: it was encoded and byte-capped device-side, carries its own
/// `bytes`/`data_bytes`, and re-cutting it here would sever a hex pair.
///
/// The true length is the point. A cut value used to lose its size entirely, so "this value is short"
/// and "we hid 96% of this value" arrived in the same shape, and the only difference — a trailing
/// ellipsis — is a character a real value may end with.
///
/// **A `REG_MULTI_SZ` is charged ONCE, against its entries, and its `data` is REBUILT from what
/// survived.** Cutting `items` and `data` independently would leave two representations of one value
/// disagreeing about what it contains — a new error-vs-absent bug manufactured out of two fixes for it.
/// Entries are kept WHOLE and in order, so every entry present is exact and `items.len() < count` is
/// itself the declaration that the list was clipped; only a lone entry longer than the whole allowance
/// is sliced, and it is stamped so it can never be read as that entry's real text. An EMPTY entry costs
/// nothing and is always kept — that is the pending-delete case.
#[cfg(windows)]
/// Trim a subkey page to `budget` SERIALIZED characters, measuring each item the way [`paginate`] does
/// (`to_string().len() + 1`) so the quotes and the comma are inside the bound. Returns how many were
/// dropped; always keeps at least one, because a page of nothing answers nothing.
///
/// The item limit cannot be the safety bound — it is caller-controlled, and 5,000 GUID-shaped names
/// already serialize to ~205,000 characters. This is the bound that actually holds.
#[cfg(windows)]
fn trim_subkey_page(subkeys: &mut Vec<Value>, budget: usize) -> usize {
    let mut used = 0usize;
    let mut keep = 0usize;
    for sk in subkeys.iter() {
        let sz = sk.to_string().len() + 1;
        if keep > 0 && used + sz > budget {
            break;
        }
        used += sz;
        keep += 1;
    }
    let dropped = subkeys.len().saturating_sub(keep);
    subkeys.truncate(keep);
    dropped
}

/// Cap value NAMES, per name and across the page. Returns `(names_truncated, name_budget_hit)`.
///
/// The names were the ungoverned term that actually blew the cap in the measured cases, and a name is
/// not like a value: it is the value's IDENTITY, so a silently shortened one points at a value that
/// does not exist. A cut name therefore states its true length in `name_chars`, same contract as `data`.
#[cfg(windows)]
fn cap_reg_value_names(values: &mut [Value], char_cap: usize, budget: usize) -> (usize, bool) {
    let mut left = budget;
    let (mut cut_count, mut budget_hit) = (0usize, false);
    for v in values.iter_mut() {
        let Some(obj) = v.as_object_mut() else { continue };
        let Some(name) = obj.get("name").and_then(|x| x.as_str()).map(str::to_owned) else { continue };
        let chars = name.chars().count();
        let take = char_cap.min(left);
        if chars > take {
            budget_hit |= take < char_cap;
            let cut: String = name.chars().take(take.saturating_sub(1)).collect();
            obj.insert("name".to_owned(), json!(cut + "\u{2026}"));
            obj.insert("name_chars".to_owned(), json!(chars));
            obj.insert("name_truncated".to_owned(), json!(true));
            cut_count += 1;
        }
        left -= chars.min(take);
    }
    (cut_count, budget_hit)
}

fn cap_reg_string_values(values: &mut [Value], char_cap: usize, budget: usize, entry_cap: usize) -> bool {
    let mut left = budget;
    let mut budget_hit = false;
    for v in values.iter_mut() {
        let Some(obj) = v.as_object_mut() else { continue };
        // ONLY the hex arm is pre-encoded and byte-capped device-side. This used to skip on the mere
        // PRESENCE of `encoding`, which would have let the new MULTI_SZ arm through uncapped had it set
        // one — the reason that arm deliberately does not.
        if obj.get("encoding").and_then(|x| x.as_str()) == Some("hex") {
            continue;
        }

        if let Some(items) = obj.get("items").and_then(|x| x.as_array()).cloned() {
            // `char_cap` bounds ONE ENTRY here, not the whole value — that re-scoping is the fix for
            // the measured 16-of-56 case. Entries are this type's unit of meaning, so spending a
            // whole-value character budget on the first few and stopping answers a different question
            // than the caller asked: `PendingFileRenameOperations` is 56 ~62-char paths, and a
            // per-value cap of 1000 returned 16 of them. Per entry, all 56 fit in ~3.5 KB.
            //
            // What still bounds it: `entry_cap` (caller-settable, so it is never terminal the way the
            // character cap was) and `left`, the per-key budget, which every branch below charges.
            let mut used = 0usize;
            let mut kept: Vec<Value> = Vec::with_capacity(items.len().min(entry_cap));
            let mut sliced = 0usize;
            let mut entry_cap_hit = false;
            for it in &items {
                if kept.len() >= entry_cap {
                    entry_cap_hit = true;
                    break;
                }
                let s = it.as_str().unwrap_or("");
                let n = s.chars().count();
                let room = left.saturating_sub(used);
                if room == 0 {
                    break;
                }
                // An entry longer than its own cap (or than the budget left) is SLICED and the slice is
                // CHARGED — both were bugs. `used` was only advanced on the whole-entry path, so this
                // branch spent nothing and a key of over-cap values walked straight past the key budget
                // (measured: 100,100 chars against a 32,768 budget). And `clipped` was
                // `kept.len() < items.len()`, which is `1 < 1` for a single-entry value, so a sliced
                // lone entry set no `truncated` at all and left the trailing ellipsis as its only
                // marker — the one marker this collector tells callers never to test for.
                // `room - 1` because the ellipsis we append is itself an emitted character. Charging
                // only the slice let the budget drift over by one per slice — small, but the budget's
                // whole job is to be an upper bound, and a bound that leaks is a bound you cannot cite.
                let per_entry = char_cap.min(room.saturating_sub(1));
                if n > per_entry {
                    if per_entry == 0 {
                        break;
                    }
                    kept.push(json!(s.chars().take(per_entry).collect::<String>() + "…"));
                    used += per_entry + 1;
                    sliced += 1;
                    continue;
                }
                if used + n > left {
                    break;
                }
                used += n;
                kept.push(it.clone());
            }
            // ANY loss counts: entries dropped, or an entry's text shortened. Reporting only the first
            // is what let a sliced value read as whole.
            let dropped = kept.len() < items.len();
            let lost = dropped || sliced > 0;
            budget_hit |= dropped && !entry_cap_hit && used >= left;
            let joined = kept.iter().map(|i| i.as_str().unwrap_or("")).collect::<Vec<_>>().join("\n");
            obj.insert("items".to_owned(), Value::Array(kept));
            obj.insert("data".to_owned(), json!(joined));
            if lost {
                obj.insert("truncated".to_owned(), json!(true));
            }
            if sliced > 0 {
                // How many entries kept their position but lost text. `items.len()` vs `count` says how
                // many vanished; this says how many of the survivors are shorter than they look.
                obj.insert("entries_sliced".to_owned(), json!(sliced));
            }
            if entry_cap_hit {
                // Distinguishes the RAISABLE bound from the key budget. A caller that hits this can pass
                // a larger `max_entries`; one that hits the budget cannot.
                obj.insert("entry_cap_hit".to_owned(), json!(true));
            }
            left -= used.min(left);
            // `data` is DERIVED here — never fall through and re-cut it as a plain string.
            continue;
        }

        let Some(s) = obj.get("data").and_then(|x| x.as_str()) else { continue };
        let chars = s.chars().count();
        let take = char_cap.min(left);
        if chars > take {
            budget_hit |= take < char_cap;
            // A STARVED value is exactly `""`, never `"…"` — matching the binary arm's empty `$hex`, so
            // "we returned none of it" and "here is the start of it" stay different shapes.
            let cut = match take {
                0 => String::new(),
                n => s.chars().take(n).collect::<String>() + "…",
            };
            obj.insert("data".to_owned(), json!(cut));
            obj.insert("chars".to_owned(), json!(chars));
            obj.insert("data_chars".to_owned(), json!(take));
            obj.insert("truncated".to_owned(), json!(true));
        }
        left -= chars.min(take);
    }
    budget_hit
}

/// Read a registry key's values + immediate subkey names (F11, read-only). `params` is a PS-drive
/// path like `HKLM:\SOFTWARE\Microsoft\Windows`, or `{path, max_bytes, max_entries}`. Returns
/// `{key, subkeys:[…], values:[{name,type,data,…}], binary_encoding, binary_byte_cap,
/// binary_budget_bytes, value_char_cap}`. A path that is invalid, denied, or cannot be read returns
/// [`reg_error`]'s `{ok:false, error}`.
///
/// **A `REG_BINARY` value is hex, byte-capped, and states its true size** — see [`reg_read_script`] for
/// the encoding and why, and [`REG_BIN_BYTE_CAP`]/[`REG_BIN_BUDGET`] for the two bounds. Such a value
/// carries `encoding:"hex"` and `bytes` (the value's REAL length in bytes, always, cut or not); a cut
/// one adds `truncated:true` and `data_bytes` (how many bytes `data` actually holds). A string value
/// keeps the 1000-character cap and gains the same self-declaration ([`cap_reg_string_values`]).
/// `max_bytes` raises or lowers the per-value BYTE cap and `max_entries` the per-value MULTI_SZ ENTRY
/// count (default 256, ceiling 4096); the per-key budgets are not caller-settable,
/// because it is what keeps the whole result under `store::MAX_JOB_RESULT`.
#[cfg(windows)]
fn reg_read(params: Option<&str>) -> Option<Value> {
    // Accept a bare `HKLM:\…` string (console UI) or a `{"path":"HKLM:\\…"}` object (/api/diag body).
    let path_owned = json_field_or_raw(params.unwrap_or(""), &["path"]);
    let path = path_owned.trim();
    if !valid_reg_path(path) {
        return Some(reg_error("invalid registry path (expected HKLM:\\, HKCU:\\, HKCR:\\, HKU:\\ or HKCC:\\ …)"));
    }
    // Checked in both spellings — the drive form the caller sent and the hive form that reaches the
    // provider — so a translation change can never open a door the check doesn't cover.
    let path = reg_provider_path(path);
    if reg_path_denied(path_owned.trim()) || reg_path_denied(&path) {
        return Some(reg_error("reading the SAM / SECURITY credential hives is not permitted"));
    }
    // Only ever reachable when the params arrived as an object; a bare path string leaves the default.
    // (The F11 registry browser posts a bare path, so neither knob is reachable from the console UI —
    // the same limitation `max_bytes` has always had. The route is /api/diag or the job API.)
    let pobj = params.and_then(|s| serde_json::from_str::<Value>(s).ok());
    let bin_cap = pobj
        .as_ref()
        .and_then(|v| v.get("max_bytes"))
        .and_then(as_i64_loose)
        .map(|n| n.clamp(16, REG_BIN_BUDGET as i64) as usize)
        .unwrap_or(REG_BIN_BYTE_CAP);
    let entry_cap = pobj
        .as_ref()
        .and_then(|v| v.get("max_entries"))
        .and_then(as_i64_loose)
        .map(|n| n.clamp(1, REG_MULTI_ENTRY_MAX as i64) as usize)
        .unwrap_or(REG_MULTI_ENTRY_CAP);
    let num = |k: &str, dflt: usize, max: usize| -> usize {
        pobj.as_ref()
            .and_then(|v| v.get(k))
            .and_then(as_i64_loose)
            .map(|n| n.clamp(0, max as i64) as usize)
            .unwrap_or(dflt)
    };
    // Two independent cursors: a key can be huge in subkeys, in values, or in both, and making one
    // offset drive both would mean paging past 28,000 subkeys to reach the values behind them.
    let sub_offset = num("subkey_offset", 0, usize::MAX);
    let sub_limit = num("subkey_limit", REG_SUBKEY_PAGE_DEFAULT, REG_SUBKEY_PAGE_MAX).max(1);
    let val_offset = num("offset", 0, usize::MAX);
    let val_limit = num("limit", REG_VALUE_PAGE_DEFAULT, REG_VALUE_PAGE_MAX).max(1);
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = reg_read_script(&path, bin_cap, REG_BIN_BUDGET, sub_offset, sub_limit, val_offset, val_limit);
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    // The provider's own text, passed through — this is the MISSING-KEY case ("Cannot find path …"),
    // which is the answer a caller most often wants and must not read as an empty key.
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err: String = err.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect();
        return Some(reg_error(match err.is_empty() {
            true => format!("reg-read failed (exited {})", out.status.code().unwrap_or(-1)),
            false => err,
        }));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parsed: Value = serde_json::from_str(text.trim()).ok()?;
    let mut string_budget_hit = false;
    let mut values_truncated = 0usize;
    let (mut names_truncated, mut name_budget_hit) = (0usize, false);
    if let Some(vals) = parsed.get_mut("values").and_then(|v| v.as_array_mut()) {
        string_budget_hit = cap_reg_string_values(vals, REG_VALUE_CHAR_CAP, REG_STR_BUDGET, entry_cap);
        let (n, nb) = cap_reg_value_names(vals, REG_NAME_CHAR_CAP, REG_NAME_BUDGET);
        names_truncated = n;
        name_budget_hit = nb;
        values_truncated = vals.iter().filter(|v| v.get("truncated").and_then(|t| t.as_bool()) == Some(true)).count();
    }
    // The subkey page is trimmed by BYTES after the device's item limit — the limit is caller-controlled
    // and so can never be the safety bound.
    let mut subkeys_dropped_for_size = 0usize;
    if let Some(sk) = parsed.get_mut("subkeys").and_then(|v| v.as_array_mut()) {
        subkeys_dropped_for_size = trim_subkey_page(sk, REG_SUBKEY_BUDGET);
    }
    let (sub_count, val_count) = (
        parsed.get("subkeys").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
        parsed.get("values").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
    );
    let sub_total = parsed.get("subkey_total").and_then(|v| v.as_u64()).unwrap_or(sub_count as u64) as usize;
    let val_total = parsed.get("value_total").and_then(|v| v.as_u64()).unwrap_or(val_count as u64) as usize;
    // The bounds travel with the answer, like the deep-read companions' `value_char_cap`: a caller can
    // tell "the whole value" from "as much of it as this read carries" without knowing the build's
    // constants, and can raise `max_bytes` knowing what it was.
    //
    // Every one of these is emitted UNCONDITIONALLY. A field present only when it fired cannot be read:
    // absent would mean both "did not happen" and "this client is too old to tell you", and those are
    // the two answers a caller most needs to separate.
    if let Some(o) = parsed.as_object_mut() {
        o.insert("binary_encoding".to_owned(), json!("hex"));
        o.insert("binary_byte_cap".to_owned(), json!(bin_cap));
        o.insert("binary_budget_bytes".to_owned(), json!(REG_BIN_BUDGET));
        o.insert("value_char_cap".to_owned(), json!(REG_VALUE_CHAR_CAP));
        o.insert("value_char_budget".to_owned(), json!(REG_STR_BUDGET));
        // The entry cap ACTUALLY APPLIED, so a caller can tell it was honoured. Its ABSENCE is the only
        // structural signal that a client is too old to read `max_entries` — an unknown param key is
        // silently ignored, so without this the caller raises the cap, gets the old behaviour, and has
        // no way to know the request never applied.
        o.insert("multi_string_entry_cap".to_owned(), json!(entry_cap));
        o.insert("string_budget_hit".to_owned(), json!(string_budget_hit));
        // Presence of this key is ALSO how a caller knows the client separates MULTI_SZ entries at all.
        o.insert("multi_string_items".to_owned(), json!(true));
        o.insert("values_truncated".to_owned(), json!(values_truncated));
        // DERIVED, because it was documented, read by the console's banner, and never emitted by any
        // client — so "absent means old client" was asserted about a field absent everywhere, and the
        // UI's binary-budget warning was dead code. A hex value cut below its own per-value cap can only
        // have been cut by the key budget. ⚠ Exact for today's script, where `$cap` and `$left` are the
        // only two reasons a blob is shortened; add a third and this must be revisited.
        let bin_hit = parsed
            .get("values")
            .and_then(|v| v.as_array())
            .is_some_and(|vals| {
                vals.iter().any(|v| {
                    v.get("encoding").and_then(|e| e.as_str()) == Some("hex")
                        && v.get("data_bytes").and_then(|d| d.as_u64()).is_some_and(|d| (d as usize) < bin_cap)
                })
            });
        if let Some(o) = parsed.as_object_mut() {
            o.insert("binary_budget_hit".to_owned(), json!(bin_hit));
        }
    }
    // Pagination, emitted unconditionally so ABSENCE means "this client does not page and the arrays
    // ARE the whole key" — never "page 1 of 1", and never that an ignored offset was honoured.
    if let Some(o) = parsed.as_object_mut() {
        o.insert("subkeys_page".to_owned(), json!({
            "total": sub_total,
            "offset": sub_offset,
            "count": sub_count,
            "truncated": sub_offset + sub_count < sub_total,
            "next_offset": (sub_offset + sub_count < sub_total).then_some(sub_offset + sub_count),
            "dropped_for_size": subkeys_dropped_for_size,
            // Hive enumeration order is NOT sorted (measured: `.bashrc` before `.bash_login`), and
            // offset paging over an undefined order is not a contract, so the collector imposes one.
            "order": "ordinal-ci",
        }));
        o.insert("values_page".to_owned(), json!({
            "total": val_total,
            "offset": val_offset,
            "count": val_count,
            "truncated": val_offset + val_count < val_total,
            "next_offset": (val_offset + val_count < val_total).then_some(val_offset + val_count),
            "order": "ordinal-ci",
        }));
        o.insert("value_name_char_cap".to_owned(), json!(REG_NAME_CHAR_CAP));
        o.insert("names_truncated".to_owned(), json!(names_truncated));
        o.insert("name_budget_hit".to_owned(), json!(name_budget_hit));
        // The device already emitted these inside the page objects; drop the duplicates.
        o.remove("subkey_total");
        o.remove("value_total");
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
    let requested = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    let name = p.get("name").and_then(|x| x.as_str()).unwrap_or("").trim();
    let rtype = p.get("type").and_then(|x| x.as_str()).unwrap_or("String").trim();
    let data = p.get("data").and_then(|x| x.as_str()).unwrap_or("");
    if !valid_reg_path(requested) {
        return json!({ "ok": false, "error": "invalid registry path" });
    }
    // As in `reg_read`: address the hive through the provider so the drive-less roots work, and
    // check the denylist against both the requested and the translated spelling.
    let path = reg_provider_path(requested);
    if reg_path_denied(requested) || reg_path_denied(&path) {
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
    match crate::post_request_timeout(url, body, "", crate::API_TIMEOUT_DATA).await {
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
mod wmi_gate_tests {
    // The SELECT-only gate has to stay closed AND has to say which rule closed it: one shared
    // "disallowed token (method call / write / chaining)" message answered every refusal, so a query
    // rejected for its `__` class name sent the caller hunting for a semicolon that was not there.
    // And the three event-subscription classes are the only WMI-persistence read the console has, so
    // the carve-out is pinned in both directions — allowed where it belongs, refused everywhere else.
    use super::{is_collector_error, wmi_error, wmi_ns_key, wmi_refusal, wmi_system_class_refs};

    const CIMV2: &str = "root\\cimv2";
    const SUB: &str = "root\\subscription";

    /// A refusal must be recognizable as a failure by the predicate this file already uses for that
    /// question. Without `ok:false` a bare `{error}` matches nothing, so a caller running the repo's
    /// own check on a refused query reads it as an answer — the `status:"done"` contract is
    /// deliberately unchanged, which makes the body the only thing that can carry the verdict.
    #[test]
    fn every_error_result_is_recognizable_as_one() {
        for q in [
            "DELETE FROM Win32_Process",
            "SELECT * FROM A;",
            "SELECT * FROM A INVOKE B",
            "SELECT Name FROM __EventFilter",  // right classes, wrong namespace
            "SELECT Name FROM __Namespace",    // wrong class
        ] {
            let why = wmi_refusal(CIMV2, q).expect("must be refused");
            let v = wmi_error(CIMV2, q, why);
            assert!(is_collector_error(&v), "a refusal must satisfy is_collector_error: {q}");
            assert!(v.get("error").and_then(|x| x.as_str()).is_some(), "and must still carry the reason: {q}");
            assert!(v.get("rows").is_none(), "and must not carry a rows key a caller could read as data: {q}");
        }
        // A query that RAN and failed is no more an answer than a refused one, so it carries the flag
        // too — a caller must not have to know which error paths in one collector are marked.
        assert!(is_collector_error(&wmi_error(CIMV2, "SELECT * FROM Nope", "Invalid class ")));
    }

    #[test]
    fn ordinary_selects_pass_and_writes_do_not() {
        assert_eq!(wmi_refusal(CIMV2, "SELECT Name FROM Win32_Process"), None);
        // A zero-row query is a query, not a refusal — the gate has no opinion on how many rows match.
        assert_eq!(wmi_refusal(CIMV2, "SELECT Name FROM Win32_Process WHERE Name='nope-zzz.exe'"), None);
        assert!(wmi_refusal(CIMV2, "DELETE FROM Win32_Process").unwrap().contains("must start with SELECT"));
        for q in [
            "SELECT * FROM Win32_Process; SELECT * FROM Win32_Service",
            "SELECT * FROM Win32_Service WHERE Name='x' INVOKE StopService",
            "SELECT * FROM Win32_Process DeleteInstance",
        ] {
            assert!(wmi_refusal(CIMV2, q).is_some(), "{q} must be refused");
        }
    }

    #[test]
    fn each_refusal_names_the_rule_that_fired() {
        // The regression this pins: the `__` refusal claimed a method call / write / chaining, and the
        // query had none of the three.
        let m = wmi_refusal(CIMV2, "SELECT Name FROM __EventFilter").unwrap();
        assert!(m.contains("'__' rule"), "must name the __ rule: {m}");
        assert!(m.contains("root\\subscription"), "must say where it IS readable: {m}");
        let m = wmi_refusal(CIMV2, "SELECT Name FROM __Namespace").unwrap();
        assert!(m.contains("__Namespace") && m.contains("'__' rule"), "must quote the class + rule: {m}");
        // The other rules keep naming themselves, in their own words.
        assert!(wmi_refusal(CIMV2, "SELECT * FROM A;").unwrap().contains("chaining"));
        assert!(wmi_refusal(CIMV2, "SELECT * FROM A INVOKE B").unwrap().contains("method invocation"));
    }

    #[test]
    fn the_three_persistence_classes_are_readable_in_root_subscription_only() {
        for q in [
            "SELECT Name, Query FROM __EventFilter",
            "SELECT * FROM __EventConsumer",
            "SELECT Filter, Consumer FROM __FilterToConsumerBinding",
            "select name from __eventfilter", // WQL is case-insensitive; so is the carve-out
        ] {
            assert_eq!(wmi_refusal(SUB, q), None, "{q} must be readable in root\\subscription");
            assert!(wmi_refusal(CIMV2, q).is_some(), "{q} must stay refused outside root\\subscription");
        }
        // Namespace spelling is not a loophole in either direction.
        for ns in ["ROOT/Subscription", "root\\Subscription\\", "\\root\\subscription"] {
            assert_eq!(wmi_refusal(ns, "SELECT * FROM __EventFilter"), None, "{ns}");
        }
    }

    #[test]
    fn the_carve_out_does_not_relax_double_underscore_generally() {
        // Every other system class stays refused, in the persistence namespace too.
        for q in [
            "SELECT * FROM __Namespace",
            "SELECT * FROM __Win32Provider",
            "SELECT * FROM __InstanceCreationEvent",
            "SELECT * FROM __EventFilterExtra",     // a longer name is a different class
            "SELECT * FROM __EventFilter, __Namespace", // one bad reference refuses the whole query
        ] {
            assert!(wmi_refusal(SUB, q).is_some(), "{q} must stay refused");
            assert!(wmi_refusal(CIMV2, q).is_some(), "{q} must stay refused");
        }
        // A `__` that is not the head of an identifier is not a class name the gate can rule on, so it
        // stays refused rather than being waved through by a prefix match.
        assert!(wmi_refusal(SUB, "SELECT * FROM Win32__EventFilter").is_some());
        assert!(wmi_refusal(SUB, "SELECT * FROM __EventFilter WHERE Name='a__b'").is_some());
    }

    #[test]
    fn helpers_agree_on_what_a_system_class_reference_is() {
        assert_eq!(wmi_system_class_refs("SELECT * FROM __EventFilter"), vec!["__EventFilter".to_owned()]);
        assert_eq!(
            wmi_system_class_refs("SELECT * FROM __EventFilter, __Namespace"),
            vec!["__EventFilter".to_owned(), "__Namespace".to_owned()]
        );
        assert!(wmi_system_class_refs("SELECT * FROM Win32_Process").is_empty());
        // Not a leading `__`, so not a reference this can name — the count mismatch is what refuses it.
        assert!(wmi_system_class_refs("SELECT * FROM Win32__Process").is_empty());
        assert_eq!(wmi_ns_key("ROOT/Subscription\\"), "root\\subscription");
        assert_eq!(wmi_ns_key("root\\CIMV2"), "root\\cimv2");
    }

    /// The row builder RUN against live WMI, because the defect this pins is invisible to a parse
    /// check: the script was always valid PowerShell, it just cast `$null` to `""`.
    ///
    /// WMI does not honour a `SELECT a,b` projection by narrowing the row — it returns the class's
    /// whole property set with the unselected ones null. `[string]$null` is `""`, so every unselected
    /// property arrived as an empty string that a caller could not tell apart from a selected field
    /// that is genuinely empty. Both halves are asserted here, on one query, so a "simplification"
    /// that drops the null filter cannot pass by satisfying only one of them.
    #[test]
    fn a_row_omits_what_wmi_returned_no_value_for_but_keeps_a_real_empty_string() {
        let params = r#"{"namespace":"root\\cimv2","query":"SELECT Caption,Description FROM Win32_OperatingSystem"}"#;
        let out = super::wmi_query(Some(params)).expect("wmi_query returns a result on Windows");
        assert!(out.get("error").is_none(), "the query must succeed: {out}");
        let row = out
            .pointer("/rows/items/0")
            .and_then(|r| r.as_object())
            .cloned()
            .unwrap_or_else(|| panic!("expected one Win32_OperatingSystem row: {out}"));

        // ABSENT. `Win32_OperatingSystem` has ~64 readable properties; two were selected. Before the
        // fix all 64 came back, 62 of them `""`. Asserted by name AND by count: a name-only check
        // passes if the filter is narrowed to a hardcoded list instead of keyed off null.
        for unselected in ["BuildNumber", "SerialNumber", "Version", "InstallDate"] {
            assert!(
                !row.contains_key(unselected),
                "`{unselected}` was not selected, so WMI returned no value for it — it must be OMITTED, \
                 not rendered as \"\" (which is indistinguishable from a genuinely empty value): {row:?}"
            );
        }
        assert!(row.len() <= 8, "an unprojected row is back (~64 keys); got {}: {row:?}", row.len());

        // EMPTY. `Description` is the computer description — selected, and on a host that never set
        // one it is a real empty STRING, not null. It must survive as a value. This is the assertion
        // that stops the fix from being "drop anything falsy".
        assert!(
            row.contains_key("Description"),
            "`Description` was selected and WMI returned a value for it (empty string on an unset host) \
             — an empty value is DATA and must not be dropped with the absent ones: {row:?}"
        );
        assert!(row.get("Caption").and_then(|c| c.as_str()).is_some_and(|s| !s.is_empty()), "{row:?}");
    }

    /// The one PowerShell fact the projection filter rests on, pinned deterministically rather than
    /// inferred from the live-WMI test above — where `Description` merely *happens* to be empty on
    /// this host. If `$null -ne ''` were false, the filter would silently discard every genuinely
    /// empty value and the live test would still pass on a host whose description is set.
    #[test]
    fn powershell_distinguishes_null_from_the_empty_string() {
        let out = super::ps_json(
            "ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ \
               empty_is_kept=($null -ne ''); zero_is_kept=($null -ne 0); false_is_kept=($null -ne $false); \
               null_is_dropped=($null -ne $null); empty_casts_like_null=([string]$null -eq [string]'') })",
        )
        .expect("PowerShell produced JSON");
        assert_eq!(out["empty_is_kept"], serde_json::json!(true), "the filter must keep '': {out}");
        assert_eq!(out["zero_is_kept"], serde_json::json!(true), "{out}");
        assert_eq!(out["false_is_kept"], serde_json::json!(true), "{out}");
        assert_eq!(out["null_is_dropped"], serde_json::json!(false), "{out}");
        // …and the reason the bug existed: the cast the filter now runs AHEAD of erases the difference.
        assert_eq!(out["empty_casts_like_null"], serde_json::json!(true), "{out}");
    }
}

#[cfg(all(test, windows))]
mod refusal_shape_tests {
    //! Every in-band refusal must be recognizable as one by the predicate this file already uses for
    //! that question, and must still say why.
    //!
    //! A refusal returns `status:"done"` — deliberately, because the job DID run and DID produce a
    //! result, and `status:"error"` means *no result at all*. That leaves the body as the only place
    //! the verdict can live, and a bare `{error}` satisfies no predicate in this file: a caller running
    //! [`super::is_collector_error`] on a refused read got `false` and read the refusal as data. `wmi`
    //! was fixed first; these are its siblings, and they are pinned per collector so a later arm added
    //! by copying a neighbour inherits the shape rather than the gap.
    use super::{firewall_rule, fs_error, fs_list, is_collector_error, reg_error, reg_read};
    use serde_json::Value;

    /// `{ok:false}` AND a non-empty reason. Both halves matter: a flag with no reason sends the caller
    /// back to the console, and a reason with no flag is the defect being fixed.
    fn assert_refusal(v: &Value, what: &str) {
        assert!(is_collector_error(v), "{what}: a refusal must satisfy is_collector_error: {v}");
        assert!(
            v.get("error").and_then(|x| x.as_str()).is_some_and(|s| !s.trim().is_empty()),
            "{what}: and must still carry its reason: {v}"
        );
    }

    #[test]
    fn firewall_rule_refuses_a_selectorless_call_as_an_error() {
        // A full-detail dump of every rule is never allowed, so "no selector" is the one refusal this
        // collector has — and the deep-read is exactly where a caller must not mistake it for "no
        // matching rules", which is the same shape a real empty match returns.
        for p in [None, Some("{}"), Some(r#"{"direction":"Inbound","action":"Allow"}"#)] {
            let v = firewall_rule(p).expect("firewall-rule returns a result on Windows");
            assert_refusal(&v, "firewall-rule");
            assert!(v.get("items").is_none(), "a refusal must not carry an items key a caller could page: {v}");
        }
        // …and a selector that IS given is not refused by this arm (it goes on to run).
        let v = firewall_rule(Some(r#"{"name":"__no_such_rule_zzz__"}"#)).expect("runs");
        assert!(!is_collector_error(&v), "a named selector must not hit the refusal arm: {v}");
    }

    #[test]
    fn every_fs_failure_arm_is_recognizable_as_one() {
        // `fs` is the collector used to prove something is NOT on a box, so each of these used to be
        // byte-identical to a real but empty directory. Reached through the collector rather than the
        // constructor wherever a test can reach them, so the arms themselves are pinned.
        for (params, what) in [
            (r#"{}"#, "no path"),
            (r#"{"path":"  "}"#, "blank path"),
            (r#"{"path":"C:\\Windows\\System32\\config"}"#, "sensitive-store denylist"),
            (r#"{"path":"C:/Windows/System32/config/RegBack"}"#, "denylist, forward slashes"),
            (r#"{"path":"C:\\Windows\\System32\\drivers\\etc\\hosts"}"#, "not a directory"),
            (r#"{"path":"C:\\__no_such_dir_zzz__\\nope"}"#, "not found"),
        ] {
            let v = fs_list(Some(params)).expect("fs returns a result on Windows");
            assert_refusal(&v, what);
            assert!(v.get("entries").is_none(), "{what}: a failure must not carry an entries page: {v}");
        }
        // The mid-walk arm — the root's `metadata` succeeded but `read_dir` did not — cannot be
        // provoked from a test without a hostile ACL, so its constructor stands in.
        assert_refusal(&fs_error("C:\\x", "path could not be listed: os error 5"), "could not list");
        // A path that IS readable must not trip any of it.
        let ok = fs_list(Some(r#"{"path":"C:\\Windows"}"#)).expect("runs");
        assert!(!is_collector_error(&ok), "a readable directory is not an error: {ok}");
    }

    #[test]
    fn every_reg_read_failure_arm_is_recognizable_as_one() {
        assert_refusal(&reg_read(Some("not-a-registry-path")).expect("result"), "invalid path");
        assert_refusal(&reg_read(Some(r"HKEY_LOCAL_MACHINE\SOFTWARE")).expect("result"), "non-drive spelling");
        assert_refusal(&reg_read(Some(r"HKLM:\SAM")).expect("result"), "SAM hive");
        assert_refusal(&reg_read(Some(r"HKLM:\SECURITY\Policy")).expect("result"), "SECURITY hive");
        assert_refusal(&reg_error("Cannot find path … because it does not exist."), "stderr passthrough");
        // The missing-key case, through the provider: a key that is not there is an ERROR, never an
        // empty `{subkeys:[],values:[]}` — which is what "is this persistence key present?" would
        // otherwise read as a clean answer.
        let missing = reg_read(Some(r"HKLM:\SOFTWARE\__no_such_key_zzz__")).expect("result");
        assert_refusal(&missing, "missing key");
        assert!(missing.get("subkeys").is_none() && missing.get("values").is_none(), "{missing}");
        // A key that exists still reads as data.
        let ok = reg_read(Some(r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")).expect("result");
        assert!(!is_collector_error(&ok), "a readable key is not an error: {ok}");
    }
}

#[cfg(all(test, windows))]
mod companion_tests {
    //! The deep-read companions, pinned on the three properties that make the split safe.
    //!
    //! The REQUIRED SELECTOR is the load-bearing one. These collectors return the content the cheap
    //! metadata kinds deliberately omit — command lines, task actions, autostart payloads — and a
    //! companion that could be called with no selector would be exactly the "dump every command line on
    //! the box" read the split exists to avoid, on a whole-fleet sweep, with the expensive per-item
    //! calls attached. A refusal here is also a refusal a caller must be able to SEE, so it carries
    //! `ok:false` like every other in-band refusal in this file.
    use super::{
        cap_detail_strings, netconn_owner, parse_uvhd_name, process_detail, schtask_detail, startup_detail,
        user_profile_disks, is_collector_error, DETAIL_VALUE_CAP,
    };
    use serde_json::json;

    #[test]
    fn no_companion_answers_without_a_selector() {
        for (v, what) in [
            (process_detail(None), "process-detail/none"),
            (process_detail(Some("{}")), "process-detail/empty"),
            // A param that only narrows is not a selector: "signature-check every process" is not a
            // bounded question, and neither is "every established connection".
            (process_detail(Some(r#"{"signature":true}"#)), "process-detail/signature only"),
            (schtask_detail(None), "schtask-detail/none"),
            (schtask_detail(Some(r#"{"limit":5}"#)), "schtask-detail/limit only"),
            (netconn_owner(None), "netconn-owner/none"),
            (netconn_owner(Some(r#"{"state":"established"}"#)), "netconn-owner/state only"),
            (startup_detail(None), "startup-detail/none"),
            (startup_detail(Some(r#"{"name":"*"}"#)), "startup-detail/name only"),
            (user_profile_disks(None), "user-profile-disks/none"),
            (user_profile_disks(Some(r#"{"unused_days":90}"#)), "user-profile-disks/no path"),
        ] {
            let v = v.expect("a companion returns a result on Windows");
            assert!(is_collector_error(&v), "{what} must refuse with ok:false: {v}");
            assert!(
                v.get("error").and_then(|x| x.as_str()).is_some_and(|s| !s.trim().is_empty()),
                "{what} must say why: {v}"
            );
        }
    }

    #[test]
    fn startup_detail_rules_on_the_surface_it_was_given() {
        // An unknown surface is refused BY NAME rather than quietly reading nothing — a typo'd surface
        // that returned an empty list would read as "nothing persists there".
        let v = startup_detail(Some(r#"{"surface":"registry"}"#)).expect("result");
        assert!(is_collector_error(&v), "{v}");
        let msg = v["error"].as_str().unwrap_or_default();
        assert!(msg.contains("registry") && msg.contains("winlogon"), "must name the bad surface and the valid set: {msg}");
        // A valid one runs, and every row it returns names the surface it came from.
        let ok = startup_detail(Some(r#"{"surface":"winlogon"}"#)).expect("result");
        assert!(!is_collector_error(&ok), "{ok}");
        assert_eq!(ok["surfaces"], json!(["winlogon"]));
        assert!(ok["errors"].is_array(), "a per-surface error list is always present: {ok}");
        if let Some(items) = ok.pointer("/entries/items").and_then(|x| x.as_array()) {
            for row in items {
                assert_eq!(row.get("surface").and_then(|x| x.as_str()), Some("winlogon"), "{row}");
            }
        }
    }

    /// The whole point of the split is the content, so a value that was CUT must say so. A caller
    /// cannot tell a truncated command line from a whole one by looking at it.
    #[test]
    fn a_shortened_value_declares_itself_and_a_whole_one_does_not() {
        let long = "A".repeat(DETAIL_VALUE_CAP + 50);
        let mut rows = vec![
            json!({ "command_line": long, "name": "x.exe", "actions": [{ "arguments": long }] }),
            json!({ "command_line": "short", "name": "y.exe" }),
        ];
        cap_detail_strings(&mut rows);
        let cut: Vec<&str> = rows[0]["truncated_fields"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert!(cut.contains(&"command_line"), "{cut:?}");
        // Nested values are capped and named by path, not skipped because they are not top-level.
        assert!(cut.contains(&"actions[0].arguments"), "{cut:?}");
        assert!(!cut.contains(&"name"), "a value that fit must not be listed: {cut:?}");
        assert_eq!(rows[0]["command_line"].as_str().unwrap().chars().count(), DETAIL_VALUE_CAP);
        assert!(rows[1].get("truncated_fields").is_none(), "an untouched row must carry no key: {}", rows[1]);
    }

    /// A UPD filename is the only identifier an unresolvable profile has, so the parse has to hold: the
    /// SID and the RID come out of the NAME, which is why a disk whose SID will not translate is still
    /// a complete row rather than a dropped one.
    #[test]
    fn a_profile_disk_filename_yields_its_sid_and_rid() {
        assert_eq!(
            parse_uvhd_name("UVHD-S-1-5-21-1111111111-2222222222-3333333333-1103.vhdx"),
            Some(("S-1-5-21-1111111111-2222222222-3333333333-1103".to_owned(), 1103))
        );
        // Case is the filesystem's business, not the parser's.
        assert!(parse_uvhd_name("uvhd-S-1-5-21-1-2-3-500.VHDX").is_some());
        // The template disk and anything else are NOT profile disks — they are counted separately, and
        // mapping one to a user would invent a profile that does not exist.
        assert_eq!(parse_uvhd_name("UVHD-template.vhdx"), None);
        assert_eq!(parse_uvhd_name("UVHD-S-1-5-18.vhdx"), None); // a well-known SID, not a user profile
        assert_eq!(parse_uvhd_name("UVHD-S-1-5-21-1-2-3-4-1103.vhdx"), None); // one sub-authority too many
        assert_eq!(parse_uvhd_name("S-1-5-21-1-2-3-1103.vhdx"), None);
        assert_eq!(parse_uvhd_name("UVHD-S-1-5-21-1-2-3-1103.vhd"), None);
        assert_eq!(parse_uvhd_name(""), None);
    }
}

#[cfg(all(test, windows))]
mod bare_param_tests {
    // Scalar collector params arrive in three shapes depending on the surface: a bare string from the
    // console UI, a JSON string, or a JSON object from the REST route. Each has silently regressed a
    // collector at least once — an unwrapped body reaches the filesystem as a literal filename — so the
    // three shapes and every accepted alias are pinned here.
    use super::{json_field_or_raw, reg_path_denied, reg_provider_path, valid_reg_path};

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
        // The provider resolves `..`, so a path containing one does not read the subtree it names.
        assert!(!valid_reg_path(r"HKLM:\SOFTWARE\..\SAM"));
        assert!(!valid_reg_path(r"HKU:\S-1-5-18\..\..\SAM"));
        assert!(!valid_reg_path(r"HKU:\S-1-5-18/../../SAM"));
        // A key whose name merely contains dots is not traversal.
        assert!(valid_reg_path(r"HKU:\.DEFAULT\Software"));
        assert!(valid_reg_path(r"HKCR:\...foo"));
    }

    /// Every documented root must reach the provider, not just the two PowerShell mounts as drives:
    /// `HKCR:`, `HKU:` and `HKCC:` do not exist as PSDrives in a fresh session, so a path under them
    /// died with "Cannot find drive" until it was addressed by hive name instead.
    #[test]
    fn every_documented_root_translates_to_a_hive() {
        assert_eq!(reg_provider_path(r"HKLM:\SOFTWARE"), r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE");
        assert_eq!(reg_provider_path(r"HKCU:\Environment"), r"Registry::HKEY_CURRENT_USER\Environment");
        assert_eq!(reg_provider_path(r"HKCR:\.txt"), r"Registry::HKEY_CLASSES_ROOT\.txt");
        assert_eq!(reg_provider_path(r"HKU:\.DEFAULT"), r"Registry::HKEY_USERS\.DEFAULT");
        assert_eq!(reg_provider_path(r"HKCC:\System"), r"Registry::HKEY_CURRENT_CONFIG\System");
        // The operational case this exists for: a logged-on user's mapped drives, read from a service.
        assert_eq!(
            reg_provider_path(r"HKU:\S-1-5-21-1-1-1-1000\Network\Z"),
            r"Registry::HKEY_USERS\S-1-5-21-1-1-1-1000\Network\Z"
        );
        // A bare root enumerates the hive itself — no dangling separator for the provider to chew on.
        assert_eq!(reg_provider_path(r"HKU:\"), "Registry::HKEY_USERS");
        assert_eq!(reg_provider_path(r"HKLM:\SOFTWARE\"), r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE");
        // Translation never crosses hives, so an HKU path can't come out addressing HKLM.
        for p in [r"HKU:\", r"HKU:\.DEFAULT", r"HKCC:\System", r"HKCR:\.txt"] {
            assert!(!reg_provider_path(p).contains("HKEY_LOCAL_MACHINE"), "{p} must stay in its own hive");
        }
    }

    #[test]
    fn credential_hives_are_refused_at_the_root_and_below() {
        assert!(reg_path_denied(r"HKLM:\SAM"));
        assert!(reg_path_denied(r"hklm:\sam\SAM\Domains"));
        assert!(reg_path_denied(r"HKLM:\SECURITY\Policy"));
        // Spellings the provider treats as the same path must not walk past the check.
        assert!(reg_path_denied(r"HKLM:\SAM\"));
        assert!(reg_path_denied("HKLM:\\\\SECURITY"));
        assert!(reg_path_denied(r"HKLM:\SAM/Domains"));
        // The hive form is what actually reaches PowerShell, so it is checked too.
        assert!(reg_path_denied(r"Registry::HKEY_LOCAL_MACHINE\SAM"));
        assert!(reg_path_denied(r"Registry::HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets"));
        // A key that merely starts with the same letters is a different key.
        assert!(!reg_path_denied(r"HKLM:\SAMPLE"));
        assert!(!reg_path_denied(r"HKLM:\SOFTWARE"));
        // The credential hives live only under HKLM — no detour reaches them through another root,
        // and the users' hives themselves stay readable.
        for p in [r"HKU:\.DEFAULT", r"HKU:\S-1-5-18\Network", r"HKCC:\System", r"HKCR:\.txt"] {
            assert!(!reg_path_denied(p), "{p} must stay readable");
            assert!(!reg_path_denied(&reg_provider_path(p)), "{p} must stay readable once translated");
        }
    }
}

#[cfg(all(test, windows))]
mod env_scope_tests {
    //! `env` had no test coverage at all — not here, not in the backend, not in the console — which was
    //! one of the two reasons this collector's fix was deferred. These cover the two refusals shipped in
    //! 0.63.0 (previously unguarded) and the user-scope change.
    use super::env_vars;
    use serde_json::{json, Value};

    fn run(params: &str) -> Value {
        env_vars(Some(params)).expect("env_vars returns on windows")
    }
    fn count(v: &Value) -> usize {
        v["items"].as_array().map_or(0, |a| a.len())
    }

    /// An unrecognised scope REFUSES. It used to fall through both arms, leave the source list empty and
    /// return a bare `[]` — so a merely mis-typed scope reported that the machine had NO environment
    /// variables. A typo must not be able to manufacture an absence.
    #[test]
    fn an_unknown_scope_refuses_rather_than_returning_an_empty_list() {
        let v = run(r#"{"scope":"bogus"}"#);
        assert_eq!(v["ok"], json!(false));
        assert!(v["error"].as_str().unwrap_or_default().contains("unknown scope"), "{v}");
        assert!(v.get("items").is_none(), "a refusal must not also look like an empty result");
    }

    /// ...but the obvious capitalisation must WORK rather than refuse, or we trade a false absence for
    /// a false failure.
    #[test]
    fn a_mis_cased_scope_is_accepted_and_normalised() {
        let v = run(r#"{"scope":"Machine"}"#);
        assert_ne!(v["ok"], json!(false), "Machine is machine: {v}");
        assert_eq!(v["scope"], json!("machine"));
    }

    /// A filter that sanitises to nothing REFUSES rather than widening to everything — answering a
    /// narrow question with the whole set and calling it a match.
    #[test]
    fn an_unusable_filter_refuses_rather_than_widening() {
        let v = run(r#"{"scope":"machine","name":"!!!"}"#);
        assert_eq!(v["ok"], json!(false));
        assert!(v["error"].as_str().unwrap_or_default().contains("no usable characters"), "{v}");
    }

    /// `name` aliases `name_filter`. It was accepted, echoed in the dispatched params, and never read,
    /// so a caller asking for one variable silently received every one and read the superset as a match.
    #[test]
    fn name_is_an_alias_for_name_filter_and_actually_narrows() {
        let all = run(r#"{"scope":"machine"}"#);
        let one = run(r#"{"scope":"machine","name":"Path"}"#);
        assert!(count(&all) > 0, "the machine scope must return something to compare against");
        assert!(count(&one) < count(&all), "name= must narrow: {} vs {}", count(&one), count(&all));
        assert_eq!(one["name_filter"], json!("Path"), "and the echo states what was applied");
    }

    /// The user scope reads LOADED USER HIVES, not the service profile. Under SYSTEM `HKCU:` is the
    /// service's own profile, so this used to report a handful of systemprofile variables as "user".
    /// Every row now carries the SID that owns it, and the envelope states how many hives were read —
    /// because only a signed-in user has one, and a bare count reads as the host's user list.
    #[test]
    fn the_user_scope_attributes_every_row_to_a_sid() {
        let v = run(r#"{"scope":"user"}"#);
        assert_ne!(v["ok"], json!(false), "{v}");
        assert!(v.get("user_hives_read").is_some(), "the envelope must say how many hives it saw");
        let note = v["user_scope_note"].as_str().unwrap_or_default();
        assert!(note.contains("SIGNED IN"), "and that only signed-in users have one: {note}");
        for row in v["items"].as_array().expect("items") {
            assert!(
                row.get("sid").and_then(|s| s.as_str()).is_some_and(|s| !s.is_empty()),
                "an unattributable user row is the defect this closes: {row}"
            );
        }
    }
}

#[cfg(all(test, windows))]
mod value_cap_tests {
    //! The two per-value caps that were measured to hide real data, and the shapes that replaced them.
    //!
    //! `reg-read` rendered a `REG_BINARY` value as space-separated DECIMAL bytes at 2.2-3.3 characters
    //! per byte, so its 1000-character cap carried ~300-450 real bytes — 4.4% of a measured 10,392-byte
    //! printer `Default DevMode`. `wmi`'s 500 cut 23% of the process rows on an RDS host, and the
    //! distribution is bimodal, so no single replacement number exists. Both fixes are about the SHAPE:
    //! a fixed-ratio encoding capped in bytes, and a caller-set cap — with the true size stated either
    //! way, because a bare ellipsis cannot distinguish a short value from a 96%-hidden one.
    use super::{
        cap_reg_string_values, cap_reg_value_names, cap_wmi_row, reg_read_script, trim_subkey_page, wmi_value_cap,
        DETAIL_VALUE_CAP, PAGE_BUDGET, REG_BIN_BUDGET, REG_NAME_BUDGET, REG_NAME_CHAR_CAP, REG_SUBKEY_BUDGET,
        REG_VALUE_PAGE_DEFAULT,
        REG_BIN_BYTE_CAP, REG_MULTI_ENTRY_CAP, REG_MULTI_ENTRY_MAX, REG_STR_BUDGET, REG_VALUE_CHAR_CAP,
        WMI_VALUE_CAP_DEFAULT, WMI_VALUE_CAP_MAX,
    };
    use serde_json::{json, Value};

    /// The encoding is the fix, and it has to happen device-side BEFORE the bytes become a string —
    /// hex at a fixed 2.0 characters per byte, cut per value and per key first, never `[string]` over a
    /// `byte[]` (which is what produced `"75 0 121 0 …"` in the first place).
    #[test]
    fn binary_is_hex_and_is_cut_before_it_is_encoded() {
        let s = reg_read_script(r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE", REG_BIN_BYTE_CAP, REG_BIN_BUDGET, 0, 5000, 0, 500);
        assert!(s.contains("$v -is [byte[]]"), "binary must be detected by TYPE, so REG_NONE/Unknown are covered too");
        assert!(s.contains("[System.BitConverter]::ToString($v,0,$take)"), "{s}");
        assert!(s.contains(".Replace('-','').ToLowerInvariant()"), "hex is unseparated + lowercase: {s}");
        assert!(s.contains("encoding='hex'"), "the row must name its own encoding: {s}");
        // The cut precedes the encode — both bounds — so a 10 MB blob never becomes a 20 MB string.
        assert!(s.contains("$take=[Math]::Min($len,$cap)"), "{s}");
        assert!(s.contains("if($take -gt $left){$take=$left}"), "the per-key budget must bind too: {s}");
        assert!(s.contains(&format!("$cap={REG_BIN_BYTE_CAP}")) && s.contains(&format!("$left={REG_BIN_BUDGET}")), "{s}");
        // The true length is emitted whether or not anything was cut; `data_bytes` says how much of it
        // the row actually carries. Without `bytes` a truncated value loses its size entirely.
        assert!(s.contains("bytes=$len"), "{s}");
        assert!(s.contains("$o['truncated']=$true;$o['data_bytes']=$take"), "{s}");
        // The old shape must be gone: `[string]` over a byte[] is the decimal renderer.
        assert!(!s.contains("data=[string]($k.GetValue($n))"), "the decimal byte rendering is the defect: {s}");
        // Built as ONE line, like every other collector script here.
        assert!(!s.contains('\n'), "the script must stay a one-liner");
    }

    /// `max_bytes` is a per-value knob only. The per-key budget is what holds the whole result under
    /// `store::MAX_JOB_RESULT`, so the cap can never be asked to exceed it.
    #[test]
    fn the_per_value_cap_can_never_outrun_the_per_key_budget() {
        assert!(REG_BIN_BYTE_CAP <= REG_BIN_BUDGET);
        // 16 KiB per value clears the value that motivated this whole change, whole.
        assert!(REG_BIN_BYTE_CAP >= 10_392, "a measured printer DevMode must fit without raising max_bytes");
        // Hex is 2 chars/byte, so the budget's worst case is double — still under half of 256 KiB.
        assert!(REG_BIN_BUDGET * 2 < 256 * 1024 / 2, "the budget must leave the subkeys + strings room");
        // The two budgets are additive against ONE result cap, so they must be bounded TOGETHER. This is
        // the test that fires if someone later raises either constant in isolation.
        assert!(REG_VALUE_CHAR_CAP <= REG_STR_BUDGET, "a single value must not be able to spend the whole key budget");
        assert!(
            REG_BIN_BUDGET * 2 + REG_STR_BUDGET * 2 < 256 * 1024 * 3 / 4,
            "binary (hex-doubled) + strings must still leave room for value names and the subkey list"
        );
    }

    #[test]
    fn a_cut_registry_string_states_its_true_length() {
        let long = "a".repeat(1500);
        let mut vals = vec![
            json!({ "name": "Long", "type": "String", "data": long }),
            json!({ "name": "Short", "type": "String", "data": "abc" }),
        ];
        let budget_hit = cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        assert!(!budget_hit, "the PER-VALUE cap cut this, not the key budget — the two must be tellable apart");
        assert_eq!(vals[0]["data"].as_str().unwrap().chars().count(), 1001); // 1000 + the ellipsis
        assert_eq!(vals[0]["chars"], json!(1500), "the size a cut value used to lose entirely");
        assert_eq!(vals[0]["data_chars"], json!(1000), "how much of it actually came back");
        assert_eq!(vals[0]["truncated"], json!(true));
        // A value that fit carries none of them — "short" and "hidden" must not be the same shape.
        assert!(
            vals[1].get("truncated").is_none() && vals[1].get("chars").is_none() && vals[1].get("data_chars").is_none(),
            "{}",
            vals[1]
        );
    }

    /// A binary value is byte-capped and encoded device-side. Re-cutting it here by characters would
    /// sever a hex pair — the value would stop decoding at the very point it was cut.
    #[test]
    fn an_encoded_binary_value_is_not_re_cut_by_characters() {
        let hex = "ab".repeat(2000); // 2000 bytes → 4000 hex characters
        let mut vals = vec![
            json!({ "name": "Default DevMode", "type": "Binary", "encoding": "hex", "bytes": 2000, "data": hex.clone() }),
            // A string AFTER it, to prove the binary value spent nothing from the string pool: the two
            // budgets are separate, and a big blob must not starve the strings that follow it.
            json!({ "name": "Long", "type": "String", "data": "a".repeat(1500) }),
        ];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        assert_eq!(vals[0]["data"].as_str().unwrap(), hex);
        assert!(vals[0].get("truncated").is_none(), "the device already said whether it was cut");
        assert_eq!(vals[0]["data"].as_str().unwrap().len() % 2, 0, "hex must stay byte-aligned");
        assert_eq!(vals[1]["data_chars"], json!(1000), "the string got its full per-value allowance");
    }

    /// A MULTI_SZ must arrive as ENTRIES. The device-side join is where the separator was destroyed, so
    /// this asserts on the script: no downstream fix can recover what PowerShell already flattened.
    #[test]
    fn a_multi_sz_is_emitted_as_entries_not_a_joined_string() {
        let s = reg_read_script(r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE", REG_BIN_BYTE_CAP, REG_BIN_BUDGET, 0, 5000, 0, 500);
        assert!(s.contains("$v -is [string[]]"), "detect by TYPE, like the byte[] arm: {s}");
        assert!(s.contains("count=$v.Count") && s.contains("items=@($v)"), "{s}");
        assert!(s.contains("-join [char]10"), "join with a real newline, written as [char]10: {s}");
        // ⚠ Depth is load-bearing. `items` needs >= 3; at -Depth 2 ConvertTo-Json SILENTLY space-joins
        // the array back into the exact defect shape, with no error and nothing in the output to see.
        assert!(s.contains("-Depth 4"), "the MULTI_SZ arm needs depth >= 3 to survive serialization: {s}");
        // The script must stay a one-liner — a literal newline would break the -Command invocation.
        assert!(!s.contains('\n'), "reg_read_script must remain a single line");
    }

    /// A zero-entry MULTI_SZ and an empty REG_SZ used to be the same bytes on the wire. They are
    /// different answers and must be different shapes.
    #[test]
    fn an_empty_multi_sz_is_not_an_empty_string() {
        let mut vals = vec![
            json!({ "name": "Empty", "type": "MultiString", "count": 0, "items": [], "data": "" }),
            json!({ "name": "Blank", "type": "String", "data": "" }),
        ];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        assert_eq!(vals[0]["count"], json!(0));
        assert!(vals[0].get("truncated").is_none(), "a genuinely empty list was not clipped");
        assert!(vals[1].get("count").is_none(), "a REG_SZ carries no entry count at all");
    }

    /// The pending-delete case: an EMPTY entry is a fact, not padding. PendingFileRenameOperations
    /// encodes a queued delete as an empty destination entry — 29 of them on a measured host.
    #[test]
    fn an_empty_entry_survives_the_items_cap() {
        let mut vals = vec![json!({ "name": "PFRO", "type": "MultiString", "count": 3, "items": ["a", "", "b"], "data": "a\n\nb" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        let items = vals[0]["items"].as_array().expect("items");
        assert_eq!(items.len(), 3, "an empty entry costs nothing and must never be dropped");
        assert_eq!(items[1], json!(""));
    }

    /// THE case the entry cap exists for, and this test used to assert the opposite.
    ///
    /// 60 entries of 50 characters is 3,000 characters. Under the old per-VALUE character cap of 1,000
    /// that clipped to 20 — and this test asserted the clip as correct. It is not: the caller asked for
    /// a list and got a third of it because a character budget was being spent on a value whose unit is
    /// entries. That is the measured `PendingFileRenameOperations` failure in miniature (56 -> 16).
    /// The cap is now per ENTRY, so all 60 arrive whole and nothing is declared lost.
    #[test]
    fn a_short_entry_list_now_arrives_whole() {
        let entries: Vec<String> = (0..60).map(|i| format!("{i:0>50}")).collect(); // 60 x 50 chars
        let mut vals = vec![json!({ "name": "Many", "type": "MultiString", "count": 60, "items": entries, "data": "" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        let items = vals[0]["items"].as_array().expect("items").clone();
        assert_eq!(items.len(), 60, "60 entries of 50 chars fit easily once the cap is per ENTRY");
        assert!(vals[0].get("truncated").is_none(), "nothing was lost, so nothing may claim it was");
        for it in &items {
            assert_eq!(it.as_str().unwrap().chars().count(), 50, "and every entry is whole");
        }
    }

    /// The measured case, end to end: a 56-entry `PendingFileRenameOperations` of ~62-character paths
    /// returned 16 of 56 before the cap was re-scoped. It must now return all 56.
    #[test]
    fn the_measured_pfro_value_now_returns_every_entry() {
        let entries: Vec<String> =
            (0..56).map(|i| format!("*1\\??\\C:\\Windows\\System32\\spool\\drivers\\x64\\3\\New\\FILE{i:0>4}.DLL")).collect();
        let mut vals = vec![json!({ "name": "PendingFileRenameOperations", "type": "MultiString", "count": 56, "items": entries, "data": "" })];
        cap_reg_string_values(&mut vals, REG_VALUE_CHAR_CAP, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        assert_eq!(vals[0]["items"].as_array().unwrap().len(), 56, "the value that motivated this change");
        assert!(vals[0].get("truncated").is_none());
    }

    /// Entries are still bounded — by the ENTRY cap now, which is caller-raisable, and it declares
    /// itself distinctly from the key budget so a caller knows which bound it hit.
    #[test]
    fn the_entry_cap_bounds_the_list_and_says_it_is_raisable() {
        let entries: Vec<String> = (0..500).map(|i| format!("e{i}")).collect();
        let mut vals = vec![json!({ "name": "Many", "type": "MultiString", "count": 500, "items": entries, "data": "" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, 256);
        assert_eq!(vals[0]["items"].as_array().unwrap().len(), 256);
        assert_eq!(vals[0]["count"], json!(500), "count is the TRUE total and never moves");
        assert_eq!(vals[0]["truncated"], json!(true));
        assert_eq!(vals[0]["entry_cap_hit"], json!(true), "the RAISABLE bound, distinct from the budget");
        // Raising it recovers the rest — the property the character cap could never offer.
        let entries: Vec<String> = (0..500).map(|i| format!("e{i}")).collect();
        let mut vals = vec![json!({ "name": "Many", "type": "MultiString", "count": 500, "items": entries, "data": "" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_MAX);
        assert_eq!(vals[0]["items"].as_array().unwrap().len(), 500);
        assert!(vals[0].get("entry_cap_hit").is_none());
    }

    /// A sliced entry keeps its position but loses text, and `entries_sliced` counts exactly those —
    /// `items.len()` vs `count` says how many VANISHED, which is a different fact.
    #[test]
    fn a_sliced_entry_is_counted_separately_from_a_dropped_one() {
        let mut vals = vec![json!({
            "name": "Mixed", "type": "MultiString", "count": 3,
            "items": ["short", "z".repeat(5000), "also short"], "data": ""
        })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        assert_eq!(vals[0]["items"].as_array().unwrap().len(), 3, "a long entry no longer ends the list");
        assert_eq!(vals[0]["entries_sliced"], json!(1), "exactly one entry lost text");
        assert_eq!(vals[0]["truncated"], json!(true), "and losing text is a loss");
    }

    /// `data` is DERIVED from the entries that survived. Cutting the two independently would leave one
    /// value describing itself two different ways.
    #[test]
    fn the_multi_sz_join_matches_the_entries_that_survived() {
        let entries: Vec<String> = (0..60).map(|i| format!("{i:0>50}")).collect();
        let mut vals = vec![json!({ "name": "Many", "type": "MultiString", "count": 60, "items": entries, "data": "stale" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        let items: Vec<String> =
            vals[0]["items"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_owned()).collect();
        assert_eq!(vals[0]["data"].as_str().unwrap(), items.join("\n"), "data must equal the surviving entries");
    }

    /// A MULTI_SZ the KEY budget starves is `items:[]` — the same shape as a genuine zero-entry value
    /// but for the flag. Without `truncated` the console would render a real 58-entry value as empty.
    #[test]
    fn a_starved_multi_sz_is_not_a_zero_entry_one() {
        let entries: Vec<String> = (0..58).map(|i| format!("entry{i}")).collect();
        let mut vals = vec![json!({ "name": "PFRO", "type": "MultiString", "count": 58, "items": entries, "data": "" })];
        // Budget 0: nothing may be spent at all.
        let hit = cap_reg_string_values(&mut vals, 1000, 0, REG_MULTI_ENTRY_CAP);
        assert!(hit, "the KEY budget is what cut this, and the envelope must be able to say so");
        assert_eq!(vals[0]["items"].as_array().unwrap().len(), 0);
        assert_eq!(vals[0]["count"], json!(58), "the true count survives being starved");
        assert_eq!(vals[0]["truncated"], json!(true), "this is what separates starved from genuinely empty");
    }

    /// The budget is charged ONCE, against the entries — not again for the derived join.
    #[test]
    fn a_multi_sz_is_charged_against_the_budget_once() {
        // Two values of 400 chars each against a 1000 budget. Charged once, both fit; charged twice
        // (entries + join), the second would be starved.
        let mk = |n: &str| json!({ "name": n, "type": "MultiString", "count": 1, "items": [ "x".repeat(400) ], "data": "" });
        let mut vals = vec![mk("A"), mk("B")];
        cap_reg_string_values(&mut vals, 1000, 1000, REG_MULTI_ENTRY_CAP);
        assert_eq!(vals[1]["items"].as_array().unwrap().len(), 1, "the second value must not have been starved");
        assert!(vals[1].get("truncated").is_none(), "{}", vals[1]);
    }

    /// reg-read paginates BOTH lists, and the script must page the value loop BEFORE the budget loop.
    ///
    /// That ordering is load-bearing: the binary and string budgets are spent in value order, so a loop
    /// that still walked every name would hand page 2 a budget already spent on values that are not
    /// even in the payload. Same reason `paginate` bounds a page and not a collection.
    #[test]
    fn reg_read_pages_both_lists_and_imposes_an_order() {
        let s = reg_read_script(r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE", REG_BIN_BYTE_CAP, REG_BIN_BUDGET, 10, 20, 30, 40);
        assert!(s.contains("Select-Object -Skip 10 -First 20"), "subkey page: {s}");
        assert!(s.contains("Select-Object -Skip 30 -First 40"), "value page: {s}");
        assert!(s.contains("$vals=foreach($n in @($vn|Select-Object -Skip 30"), "the VALUE LOOP itself must be paged: {s}");
        assert!(s.contains("subkey_total=@($sn).Count") && s.contains("value_total=@($vn).Count"), "true totals: {s}");
        // Hive order is not sorted, so offset paging needs an imposed one or the pages overlap/skip.
        assert!(s.contains("[Array]::Sort($sn,[StringComparer]::OrdinalIgnoreCase)"), "subkeys must be sorted: {s}");
        assert!(s.contains("[Array]::Sort($vn,[StringComparer]::OrdinalIgnoreCase)"), "value names must be sorted: {s}");
        assert!(!s.contains('\n'), "still a one-liner");
    }

    /// The subkey page is bounded by BYTES, not by the caller's item limit — 5,000 GUID-shaped names
    /// already serialize to ~205,000 characters against a 262,144 cap, so a limit bounds nothing.
    #[test]
    fn the_subkey_page_is_bounded_by_bytes_not_by_the_item_limit() {
        let mut sk: Vec<Value> = (0..5000).map(|i| json!(format!("{{{i:0>8}-1234-5678-9abc-def012345678}}"))).collect();
        let dropped = trim_subkey_page(&mut sk, REG_SUBKEY_BUDGET);
        let bytes: usize = sk.iter().map(|k| k.to_string().len() + 1).sum();
        assert!(bytes <= REG_SUBKEY_BUDGET, "page must fit its budget: {bytes}");
        assert!(dropped > 0, "and it must report what it dropped to get there");
        assert!(!sk.is_empty(), "a page of nothing answers nothing");
    }

    /// A value NAME is the value's IDENTITY, so a silently shortened one points at a value that does not
    /// exist. Names were also the term that actually blew the cap in the measured cases — one key holds
    /// ~916,000 characters of NAMES against ~2,200 of data, which the string budget never touches.
    #[test]
    fn an_over_long_value_name_is_cut_and_states_its_true_length() {
        let mut vals = vec![
            json!({ "name": "x".repeat(2000), "type": "String", "data": "v" }),
            json!({ "name": "short", "type": "String", "data": "v" }),
        ];
        let (cut, _) = cap_reg_value_names(&mut vals, REG_NAME_CHAR_CAP, REG_NAME_BUDGET);
        assert_eq!(cut, 1);
        assert_eq!(vals[0]["name_chars"], json!(2000), "the TRUE length survives the cut");
        assert_eq!(vals[0]["name_truncated"], json!(true));
        assert!(vals[0]["name"].as_str().unwrap().chars().count() <= REG_NAME_CHAR_CAP);
        assert!(vals[1].get("name_truncated").is_none(), "a name that fit carries nothing");
    }

    /// One page's worst case must fit under the store cap with headroom. This is the test that fires if
    /// anyone raises one of these constants in isolation.
    #[test]
    fn one_reg_read_page_fits_the_store_cap() {
        let worst = REG_BIN_BUDGET * 2      // hex is 2 chars/byte
            + REG_STR_BUDGET * 2            // items + the derived data join
            + REG_SUBKEY_BUDGET
            + REG_NAME_BUDGET
            + REG_VALUE_PAGE_DEFAULT * 64;  // per-row JSON structure
        assert!(worst < 262_144, "one page's worst case must fit the 256 KiB store cap: {worst}");
    }

    /// ⚠ A lone entry longer than the whole allowance is SLICED, and that slice must declare itself.
    /// It did not: `clipped` was `kept.len() < items.len()`, which is `1 < 1` for a single-entry value,
    /// so `truncated` was never set and the only marker left was the trailing ellipsis — the one marker
    /// this collector tells callers never to test for. The previous test passed *because* it asserted
    /// exactly that ellipsis, so the suite encoded the bug rather than catching it.
    #[test]
    fn a_sliced_lone_entry_declares_itself() {
        let mut vals = vec![json!({ "name": "One", "type": "MultiString", "count": 1, "items": [ "z".repeat(5000) ], "data": "" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        assert_eq!(vals[0]["truncated"], json!(true), "a sliced entry is a loss and must say so: {}", vals[0]);
    }

    /// ⚠ The slicing path charged NOTHING against the per-key budget: `used` is only incremented on the
    /// whole-entry path, so `left -= used.min(left)` subtracted zero every time. A key full of
    /// over-cap single-entry values therefore walked straight past `REG_STR_BUDGET` — the exact failure
    /// the budget exists to prevent, reachable through the one path that bypassed it.
    #[test]
    fn the_slicing_path_is_charged_against_the_key_budget() {
        let mut vals: Vec<Value> = (0..100)
            .map(|i| json!({ "name": format!("V{i}"), "type": "MultiString", "count": 1, "items": [ "z".repeat(5000) ], "data": "" }))
            .collect();
        let hit = cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        let emitted: usize = vals
            .iter()
            .map(|v| v["items"].as_array().map_or(0, |a| a.iter().map(|i| i.as_str().unwrap_or("").chars().count()).sum()))
            .sum();
        assert!(
            emitted <= REG_STR_BUDGET,
            "the key budget must bound the sliced path too: emitted {emitted} against a {REG_STR_BUDGET} budget"
        );
        assert!(hit, "and the envelope must be able to say the key budget fired");
    }

    /// The guard narrowed from "has an `encoding` key" to "is hex". A MULTI_SZ must still be capped —
    /// it carries `items` and would otherwise be the one unbounded value shape.
    #[test]
    fn a_multi_sz_is_still_character_capped() {
        let mut vals = vec![json!({ "name": "Huge", "type": "MultiString", "count": 1, "items": [ "z".repeat(5000) ], "data": "" })];
        cap_reg_string_values(&mut vals, 1000, REG_STR_BUDGET, REG_MULTI_ENTRY_CAP);
        let only = vals[0]["items"].as_array().unwrap()[0].as_str().unwrap().to_owned();
        assert!(only.chars().count() <= 1001, "a lone over-cap entry is sliced and stamped: {}", only.chars().count());
        assert!(only.ends_with('…'), "and it must be marked so it cannot read as the entry's real text");
    }

    /// The budget is spent in value order and the tail is starved — with the starved values still
    /// stating their TRUE length, so "short" and "we returned none of it" stay different.
    #[test]
    fn the_string_budget_is_spent_in_value_order_and_starves_the_tail() {
        // 1200 chars each, so every value genuinely EXCEEDS the 1000 per-value cap. (A value sitting
        // exactly ON the cap is not cut and carries no declaration at all — which is correct, and is
        // why this fixture has to overshoot to exercise the budget.)
        let mut vals: Vec<Value> =
            (0..40).map(|i| json!({ "name": format!("V{i}"), "type": "String", "data": "q".repeat(1200) })).collect();
        let hit = cap_reg_string_values(&mut vals, 1000, 3500, REG_MULTI_ENTRY_CAP);
        assert!(hit, "the key budget fired");
        // Values 0-2 spend a full 1000 each; value 3 gets the remaining 500; the rest get nothing.
        assert_eq!(vals[0]["data_chars"], json!(1000));
        assert_eq!(vals[3]["data_chars"], json!(500));
        assert_eq!(vals[39]["data_chars"], json!(0));
        assert_eq!(vals[39]["chars"], json!(1200), "a starved value still states its TRUE length");
        assert_eq!(vals[39]["data"].as_str().unwrap(), "", "starved is empty, NOT an ellipsis");
        assert_eq!(vals[39]["truncated"], json!(true));
    }

    #[test]
    fn the_wmi_value_cap_defaults_then_clamps() {
        assert_eq!(wmi_value_cap(&json!({})), WMI_VALUE_CAP_DEFAULT);
        assert_eq!(wmi_value_cap(&json!({ "query": "SELECT * FROM Win32_Process" })), WMI_VALUE_CAP_DEFAULT);
        // The two measured shapes: command lines want ~1,500-2,500; Description wants ~520.
        assert_eq!(wmi_value_cap(&json!({ "max_value_len": 2500 })), 2500);
        assert_eq!(wmi_value_cap(&json!({ "max_value_len": 520 })), 520);
        // The /api/diag route can deliver a number as a string.
        assert_eq!(wmi_value_cap(&json!({ "max_value_len": "2500" })), 2500);
        // Out of range in either direction is clamped, never taken literally.
        assert_eq!(wmi_value_cap(&json!({ "max_value_len": 0 })), 1);
        assert_eq!(wmi_value_cap(&json!({ "max_value_len": -5 })), 1);
        assert_eq!(wmi_value_cap(&json!({ "max_value_len": 999_999 })), WMI_VALUE_CAP_MAX);
        assert_eq!(WMI_VALUE_CAP_MAX, DETAIL_VALUE_CAP, "one ceiling for the file, not two that drift");
    }

    #[test]
    fn a_cut_wmi_value_names_itself() {
        let mut row = json!({ "Name": "chrome.exe", "CommandLine": "x".repeat(900), "ProcessId": "1234" });
        cap_wmi_row(&mut row, WMI_VALUE_CAP_DEFAULT, PAGE_BUDGET);
        assert_eq!(row["CommandLine"].as_str().unwrap().chars().count(), WMI_VALUE_CAP_DEFAULT + 1);
        let cut: Vec<&str> = row["truncated_fields"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(cut, vec!["CommandLine"], "only the field that lost something is named");
        assert_eq!(row["Name"].as_str().unwrap(), "chrome.exe");

        // A row that lost nothing carries NO key — the absence is the "returned whole" signal.
        let mut whole = json!({ "Name": "svchost.exe", "CommandLine": "y".repeat(260) });
        cap_wmi_row(&mut whole, WMI_VALUE_CAP_DEFAULT, PAGE_BUDGET);
        assert!(whole.get("truncated_fields").is_none(), "{whole}");

        // The point of the param: the same row, read at a cap the measurement supports, survives whole.
        let mut raised = json!({ "CommandLine": "z".repeat(2000) });
        cap_wmi_row(&mut raised, 2500, PAGE_BUDGET);
        assert_eq!(raised["CommandLine"].as_str().unwrap().chars().count(), 2000);
        assert!(raised.get("truncated_fields").is_none());
    }

    /// The encoding contract, through the real collector against the real registry — the script is
    /// assembled, PowerShell runs it, and the rows come back parsed. The pure tests above pin the
    /// shape; this one pins that a live `REG_BINARY` read actually produces it.
    #[test]
    fn a_live_binary_read_comes_back_as_decodable_hex() {
        let v = super::reg_read(Some(r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")).expect("result");
        assert!(!super::is_collector_error(&v), "{v}");
        // The bounds travel with the answer.
        assert_eq!(v["binary_encoding"], json!("hex"));
        assert_eq!(v["binary_byte_cap"], json!(REG_BIN_BYTE_CAP));
        assert_eq!(v["binary_budget_bytes"], json!(REG_BIN_BUDGET));
        let vals = v["values"].as_array().expect("values");
        let mut seen_binary = false;
        for val in vals {
            if val.get("encoding").and_then(|e| e.as_str()) != Some("hex") {
                // A non-binary value must NOT have grown a binary field.
                assert!(val.get("bytes").is_none() && val.get("data_bytes").is_none(), "{val}");
                continue;
            }
            seen_binary = true;
            let data = val["data"].as_str().expect("data");
            let bytes = val["bytes"].as_u64().expect("every binary value states its true byte length") as usize;
            assert!(data.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "unseparated lowercase hex: {val}");
            assert_eq!(data.len() % 2, 0, "byte-aligned: {val}");
            match val.get("truncated").and_then(|t| t.as_bool()) {
                // Cut: `data_bytes` says how much of `bytes` came back, and the hex is exactly that.
                Some(true) => {
                    let got = val["data_bytes"].as_u64().expect("a cut value states how much it carries") as usize;
                    assert!(got < bytes, "{val}");
                    assert_eq!(data.len(), got * 2, "{val}");
                }
                // Whole: 2 characters per byte, the fixed ratio the whole change rests on.
                _ => assert_eq!(data.len(), bytes * 2, "{val}"),
            }
        }
        // Not an assertion about Windows — just a signal, since a run that saw no binary value proved
        // nothing about the encoding.
        assert!(seen_binary, "expected at least one REG_BINARY value under CurrentVersion (DigitalProductId)");
    }

    /// `max_value_len` through the real collector: the param has to survive the JSON body, reach the
    /// capping pass, and show up in the envelope — with real WMI rows, not a hand-built one. Forced at
    /// 1 character so the assertion does not depend on this host owning a long value.
    #[test]
    fn a_live_wmi_read_honours_the_value_cap_param() {
        let q = r#"{"namespace":"root\\cimv2","query":"SELECT Caption FROM Win32_OperatingSystem","max_value_len":1}"#;
        let out = super::wmi_query(Some(q)).expect("wmi_query returns a result on Windows");
        assert!(!super::is_collector_error(&out), "{out}");
        assert_eq!(out["value_char_cap"], json!(1));
        let row = out.pointer("/rows/items/0").expect("one row");
        assert_eq!(row["Caption"].as_str().unwrap().chars().count(), 2, "1 character + the ellipsis: {row}");
        let cut: Vec<&str> = row["truncated_fields"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(cut, vec!["Caption"], "{row}");

        // Unset, the default is the shipped 500 and a short value keeps its whole self.
        let plain = r#"{"namespace":"root\\cimv2","query":"SELECT Caption FROM Win32_OperatingSystem"}"#;
        let out = super::wmi_query(Some(plain)).expect("result");
        assert_eq!(out["value_char_cap"], json!(WMI_VALUE_CAP_DEFAULT));
        let row = out.pointer("/rows/items/0").expect("one row");
        assert!(row.get("truncated_fields").is_none(), "{row}");
    }

    /// `paginate` always emits at least one item, so ONE row bypasses the page byte budget. At the
    /// 8000 ceiling a ~45-property class would be 360 KB — past the 256 KiB result cap, where the whole
    /// result is replaced by a failure notice. The per-row pool is what makes the raised ceiling safe.
    #[test]
    fn one_row_cannot_outgrow_the_page_budget_it_bypasses() {
        let mut obj = serde_json::Map::new();
        for i in 0..45 {
            obj.insert(format!("Prop{i:02}"), json!("q".repeat(9000)));
        }
        let mut row = Value::Object(obj);
        cap_wmi_row(&mut row, WMI_VALUE_CAP_MAX, PAGE_BUDGET);
        let strings: usize = row
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(_, v)| v.as_str())
            .map(|s| s.chars().count())
            .sum();
        // The pool bounds the row's content; the slack is one ellipsis per cut field.
        assert!(strings <= PAGE_BUDGET + 64, "a single row spent {strings} characters against a {PAGE_BUDGET} pool");
        assert!(serde_json::to_string(&row).unwrap().len() < 256 * 1024, "one row must never approach MAX_JOB_RESULT");
        // Every field that lost something says so, including the ones the pool cut to nothing — a
        // budget-exhausted field is still a truncated field, not an empty one.
        let cut = row["truncated_fields"].as_array().unwrap().len();
        assert_eq!(cut, 45, "all 45 were over the cap");
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
        let src = include_str!("console_jobs.rs");
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

#[cfg(all(test, windows))]
mod force_array_field_tests {
    use super::force_array_field;
    use serde_json::json;

    /// A list-shaped field must not change JSON TYPE with the data. `ConvertTo-Json` collapses a
    /// one-element array to a scalar, and for `allowed_days` that is the single-day schedule — the
    /// exact case the field was added to report.
    #[test]
    fn a_lone_scalar_becomes_a_one_element_array() {
        let mut v = json!({ "allowed_days": "sun", "other": "untouched" });
        force_array_field(&mut v, "allowed_days");
        assert_eq!(v["allowed_days"], json!(["sun"]));
        assert_eq!(v["other"], json!("untouched"), "only the named field is rewritten");
    }

    #[test]
    fn a_real_array_and_a_null_are_left_alone() {
        let mut v = json!({ "allowed_days": ["mon", "tue"] });
        force_array_field(&mut v, "allowed_days");
        assert_eq!(v["allowed_days"], json!(["mon", "tue"]));

        // null means "no weekday restriction", which is NOT an empty list — wrapping it would
        // manufacture a restriction that does not exist.
        let mut v = json!({ "allowed_days": null });
        force_array_field(&mut v, "allowed_days");
        assert_eq!(v["allowed_days"], json!(null));
    }

    #[test]
    fn an_absent_field_is_not_invented() {
        let mut v = json!({ "ok": true });
        force_array_field(&mut v, "allowed_days");
        assert!(v.get("allowed_days").is_none(), "absent must stay absent, never become []");
    }
}

#[cfg(all(test, windows))]
mod ad_ou_depth_tests {
    use super::ou_depth_of;

    /// `ad-ous`' `depth` filter is only as good as this count — it decides which OUs a caller asked
    /// for. The param was documented and unimplemented, so `{depth:1}` returned the whole tree.
    #[test]
    fn counts_ou_components_not_commas() {
        assert_eq!(ou_depth_of("DC=example,DC=com"), 0, "the domain root is not an OU");
        assert_eq!(ou_depth_of("OU=Staff,DC=example,DC=com"), 1);
        assert_eq!(ou_depth_of("OU=Servers,OU=Computers,OU=Staff,DC=example,DC=com"), 3);
        // A CN container is not an OU level either — `CN=Users` is a container, not an OU.
        assert_eq!(ou_depth_of("CN=Guest,CN=Users,DC=example,DC=com"), 0);
        assert_eq!(ou_depth_of("ou=lower,Ou=Mixed,DC=example,DC=com"), 2, "DN attribute types are case-insensitive");
    }

    #[test]
    fn an_escaped_comma_does_not_split_an_rdn() {
        // `OU=Legal\, Tax` is ONE component. Splitting on the escaped comma would read this as two
        // levels and drop the OU from a `depth:1` answer that should contain it.
        assert_eq!(ou_depth_of(r"OU=Legal\, Tax,DC=example,DC=com"), 1);
        assert_eq!(ou_depth_of(r"OU=Sub,OU=Legal\, Tax,DC=example,DC=com"), 2);
    }

    #[test]
    fn a_multibyte_rdn_does_not_panic() {
        // Guards the byte-slice form of the prefix check, which would panic mid-codepoint here.
        assert_eq!(ou_depth_of("OU=日本,DC=example,DC=com"), 1);
        assert_eq!(ou_depth_of("日本語=x,DC=example,DC=com"), 0);
        assert_eq!(ou_depth_of(""), 0);
    }
}
