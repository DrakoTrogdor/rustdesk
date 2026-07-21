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
    let Some(settings) = verify_policy(sig) else {
        hbb_common::log::warn!("console policy: signature invalid; ignoring");
        return; // fail-safe: a forged/corrupt blob never changes locks
    };

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
        "schtasks" => spawn_blocking(|| ps_json_array(
            "Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Sort-Object TaskPath,TaskName | ConvertTo-Json -Compress",
            400,
        )).await.ok().flatten(),
        "startup" => spawn_blocking(|| ps_json_array(
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress",
            200,
        )).await.ok().flatten(),
        "netconn" => spawn_blocking(|| ps_json_array(
            "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress",
            300,
        )).await.ok().flatten(),
        "pnp" => spawn_blocking(|| ps_json_array(
            "Get-PnpDevice | Select-Object FriendlyName,Class,Status,InstanceId | Sort-Object Class,FriendlyName | ConvertTo-Json -Compress",
            600,
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

/// Recent Windows event-log entries via PowerShell `Get-WinEvent` — System + Application at
/// Critical/Error/Warning by default, newest first, bounded so the signed result stays under the
/// console's 64 KB cap. Optional `params` JSON `{log:"System,Application", level:3, since:"yyyy-MM-dd"|days-int, max:60}`
/// overrides the defaults (`level` = max severity: 1 crit, 2 +err, 3 +warn; `since` bounds the window —
/// integer OR an all-digit string = N days back, any other string = a date literal, omitted = newest
/// `max` with no lower bound). Returns `[]` when the filter genuinely matched nothing, but
/// `{ok:false,error}` when the query itself failed — the two are NOT the same and must never both be `[]`.
/// Empty off-Windows.
#[cfg(windows)]
fn eventlog(params: Option<&str>) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let logs = p.get("log").and_then(|x| x.as_str()).unwrap_or("System,Application");
    let level = p.get("level").and_then(|x| x.as_i64()).unwrap_or(3).clamp(1, 5);
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
    // Sanitize the log names (single-quoted, strip embedded quotes) and build the level list.
    let log_arr = logs
        .split(',')
        .map(|l| format!("'{}'", l.trim().replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",");
    let levels = (1..=level).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let script = format!(
        "Get-WinEvent -FilterHashtable @{{LogName=@({log_arr}); Level=@({levels}){start_clause}}} -MaxEvents {max} -ErrorAction SilentlyContinue | \
         Select-Object @{{n='time';e={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}},@{{n='log';e={{$_.LogName}}}},@{{n='id';e={{$_.Id}}}},@{{n='level';e={{$_.LevelDisplayName}}}},@{{n='provider';e={{$_.ProviderName}}}},@{{n='message';e={{$_.Message}}}} | \
         ConvertTo-Json -Compress -Depth 3"
    );
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let trimmed = text.trim();
    // A filter matching nothing (e.g. a tight `since` window) yields empty stdout — that's a valid
    // empty result, not a failure. Return [] rather than erroring the whole job. But empty stdout ALSO
    // means "the script blew up", and reporting THAT as `[]` reads as "the log is clean" — the worst
    // possible lie for an audit. Distinguish the two on stderr / exit status, and return the collector
    // error shape (`{ok:false,error}`, as `gpo-list` and friends do) so the failure is visible.
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
        return Some(json!([]));
    }
    let parsed: Value = serde_json::from_str(trimmed).ok()?;
    let rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v], // ConvertTo-Json emits a bare object for a single row
        _ => return Some(json!([])),
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
    Some(json!(entries))
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
        "$ErrorActionPreference='SilentlyContinue'; \
         $profiles=@(Get-NetFirewallProfile | ForEach-Object {{ [pscustomobject]@{{ name=[string]$_.Name; enabled=[bool]$_.Enabled }} }}); \
         $rules=@(Get-NetFirewallRule{where_clause} | Select-Object -First 2000 | ForEach-Object {{ \
           $pf=$_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; \
           $af=$_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue; \
           [pscustomobject]@{{ name=[string]$_.Name; display=[string]$_.DisplayName; direction=[string]$_.Direction; action=[string]$_.Action; enabled=[string]$_.Enabled; profile=[string]$_.Profile; protocol=[string]$pf.Protocol; local_port=([string]($pf.LocalPort -join ',')); program=[string]$af.Program }} \
         }}); \
         [pscustomobject]@{{ profiles=$profiles; rules=$rules }} | ConvertTo-Json -Depth 4 -Compress"
    );
    let raw = ps_json(&script)?;
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-NetFirewallRule{where_clause} | Select-Object -First 400 | ForEach-Object {{ \
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
    let rows = ps_json_as_array(&script)?;
    let items = rows.as_array().cloned().unwrap_or_default();
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
$ErrorActionPreference='SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
$cpu = @(Get-CimInstance Win32_Processor)[0]
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
    ps_json(SCRIPT)
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
$ErrorActionPreference='SilentlyContinue'
$disks = @(Get-Disk | ForEach-Object {
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
$bl = @{}
try { Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { $bl[[string]$_.MountPoint] = [string]$_.ProtectionStatus } } catch {}
$volumes = @(Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
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
    ps_json(SCRIPT)
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
        "$ErrorActionPreference='SilentlyContinue'; \
         $admins=@(); $resolved=$false; \
         try {{ $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {{ [string]$_.SID }}); $resolved=$true }} catch {{}}; \
         if(-not $resolved){{ try {{ \
           $g=Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=True' -ErrorAction Stop | Where-Object {{ $_.SID -eq 'S-1-5-32-544' }}; \
           $admins=@(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser -ErrorAction Stop | ForEach-Object {{ [string]$_.SID }}); \
           $resolved=$true \
         }} catch {{}} }}; \
         @(Get-LocalUser{where_clause} | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; enabled=[bool]$_.Enabled; \
             is_admin=$(if($resolved){{ [bool]($admins -contains [string]$_.SID) }} else {{ $null }}); \
             last_logon=if($_.LastLogon){{$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}}else{{''}}; \
             password_expires=if($_.PasswordExpires){{$_.PasswordExpires.ToString('yyyy-MM-dd')}}else{{'never'}}; \
             password_last_set=if($_.PasswordLastSet){{$_.PasswordLastSet.ToString('yyyy-MM-dd')}}else{{''}}; \
             description=[string]$_.Description }} \
         }}) | ConvertTo-Json -Depth 3 -Compress"
    );
    ps_json_as_array(&script)
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
        r#"
$ErrorActionPreference='SilentlyContinue'
$start = {start_expr}
$max = {max}
$fmt = {{ param($e) [pscustomobject]@{{ time=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); log=[string]$e.LogName; id=[int]$e.Id; level=[string]$e.LevelDisplayName; provider=[string]$e.ProviderName; message=(($e.Message -split "`n")[0]) }} }}
$crashes = @(Get-WinEvent -FilterHashtable @{{ LogName='Application'; ProviderName=@('Application Error','Windows Error Reporting','Application Hang'); StartTime=$start }} -MaxEvents $max -ErrorAction SilentlyContinue | ForEach-Object {{ & $fmt $_ }})
$shutdowns = @(Get-WinEvent -FilterHashtable @{{ LogName='System'; Id=@(41,1001,6008,6005,6006); StartTime=$start }} -MaxEvents $max -ErrorAction SilentlyContinue | ForEach-Object {{ & $fmt $_ }})
$dmpdir = Join-Path $env:SystemRoot 'Minidump'
$minidumps = @()
if (Test-Path $dmpdir) {{ $minidumps = @(Get-ChildItem -LiteralPath $dmpdir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First $max | ForEach-Object {{ [pscustomobject]@{{ name=$_.Name; size=[int64]$_.Length; modified=$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }} }}) }}
[pscustomobject]@{{ crashes=$crashes; shutdowns=$shutdowns; minidumps=$minidumps }} | ConvertTo-Json -Depth 4 -Compress
"#
    );
    // Collapse + cap the per-event message so the combined result stays under the console's 64 KB cap.
    let mut v = ps_json(&script)?;
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
/// returns only the expired+expiring set. Returns `{now, expiring_days, certs:[…]}`, capped at 800 certs.
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
        r#"
$ErrorActionPreference='SilentlyContinue'
$now = Get-Date
$soon = $now.AddDays({days})
@(Get-ChildItem -Path '{path}' -Recurse -ErrorAction SilentlyContinue | Where-Object {{ $_.PSIsContainer -eq $false -and $_.Thumbprint }} | Select-Object -First 800 | ForEach-Object {{
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
    Some(json!({ "expiring_days": days, "certs": ps_json_as_array(&script)? }))
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
$ErrorActionPreference='SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
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
    ps_json(SCRIPT)
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
    audit=[pscustomobject]@{
      logon=[int]$ea['AuditLogonEvents']; account_logon=[int]$ea['AuditAccountLogon']
      policy_change=[int]$ea['AuditPolicyChange']; privilege_use=[int]$ea['AuditPrivilegeUse']
      object_access=[int]$ea['AuditObjectAccess']
    }
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
        "$ErrorActionPreference='SilentlyContinue'; \
         $roots=@( \
           @{{ p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s='machine' }}, \
           @{{ p='HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s='machine-wow64' }}, \
           @{{ p='HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; s='user' }} \
         ); \
         @($roots | ForEach-Object {{ $scope=$_.s; Get-ItemProperty -Path $_.p -ErrorAction SilentlyContinue | \
           Where-Object {{ $_.DisplayName -and -not ($_.SystemComponent -eq 1) }} | ForEach-Object {{ \
             [pscustomobject]@{{ name=[string]$_.DisplayName; version=[string]$_.DisplayVersion; publisher=[string]$_.Publisher; install_date=[string]$_.InstallDate; scope=$scope }} \
           }} }}){where_clause} | Sort-Object name | Select-Object -First 1000 | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object {{ $_.DeviceName }} | ForEach-Object {{ \
           [pscustomobject]@{{ device=[string]$_.DeviceName; version=[string]$_.DriverVersion; provider=[string]$_.DriverProviderName; \
             date=if($_.DriverDate){{([datetime]$_.DriverDate).ToString('yyyy-MM-dd')}}else{{''}}; class=[string]$_.DeviceClass; \
             signed=[bool]$_.IsSigned; inf=[string]$_.InfName }} \
         }}){where_clause} | Sort-Object device -Unique | Select-Object -First 1000 | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
            break;
        }
    }
    Some(json!(rows))
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
        "$ErrorActionPreference='SilentlyContinue'; \
         $def=@{{}}; Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue | ForEach-Object {{ if($_.Default){{ $def[[string]$_.Name]=$true }} }}; \
         @(Get-Printer -ErrorAction SilentlyContinue | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; driver=[string]$_.DriverName; port=[string]$_.PortName; \
             shared=[bool]$_.Shared; share_name=[string]$_.ShareName; status=[string]$_.PrinterStatus; \
             type=[string]$_.Type; default=[bool]($def.ContainsKey([string]$_.Name)) }} \
         }}){where_clause} | Sort-Object name | Select-Object -First 500 | ConvertTo-Json -Depth 3 -Compress"
    );
    ps_json_as_array(&script)
}
#[cfg(not(windows))]
fn printers(_params: Option<&str>) -> Option<Value> {
    None
}

// ── Server-role deep-read collectors (docs/PLAN-role-collectors.md). Each is read-only, gated
// CONSOLE-SIDE on the device's `roles` fingerprint (the fork just serves the data). All follow the
// existing collector shape: a PowerShell/ADSI/WMI one-liner → `ps_json_as_array` → `paginate`. ──

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
        "$ErrorActionPreference='SilentlyContinue'; $sys={SHARE_SYS_NAMES_PS}; \
         @(Get-SmbShare -ErrorAction SilentlyContinue{name_filter} | ForEach-Object {{ \
           $sp=[bool]$_.Special; $st=[string]$_.ShareType; \
           $admin=($sp -or ($st -ne 'FileSystemDirectory') -or ($sys -contains $_.Name)); \
           $aces=@(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue); \
           [pscustomobject]@{{ name=[string]$_.Name; path=[string]$_.Path; description=[string]$_.Description; \
             share_type=$st; scope_name=[string]$_.ScopeName; admin=$admin; special_flag=$sp; \
             ace_count=$aces.Count; {acl_field} caching=[string]$_.CachingMode; \
             encrypt_data=[bool]$_.EncryptData; current_users=[int]$_.CurrentUsers }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 4 -Compress"
    );
    let items: Vec<Value> = ps_json_as_array(&script)?
        .as_array()
        .cloned()
        .unwrap_or_default()
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-Printer -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           $st=[string]$_.PrinterStatus; \
           [pscustomobject]@{{ name=[string]$_.Name; shared=[bool]$_.Shared; share_name=[string]$_.ShareName; \
             driver=[string]$_.DriverName; port=[string]$_.PortName; status=$st; \
             jobs_queued=@(Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue).Count; \
             published_ad=[bool]$_.Published; comment=[string]$_.Comment; location=[string]$_.Location }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    let items: Vec<Value> = ps_json_as_array(&script)?
        .as_array()
        .cloned()
        .unwrap_or_default()
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-DnsServerZone -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           [pscustomobject]@{{ zone=[string]$_.ZoneName; type=[string]$_.ZoneType; \
             ds_integrated=[bool]$_.IsDsIntegrated; dynamic_update=[string]$_.DynamicUpdate; \
             replication_scope=[string]$_.ReplicationScope; is_reverse=[bool]$_.IsReverseLookupZone; \
             is_signed=[bool]$_.IsSigned }} \
         }}) | Sort-Object zone | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-DnsServerResourceRecord -ZoneName '{zone}'{type_arg} -ErrorAction SilentlyContinue{name_filter} | ForEach-Object {{ \
           $d=$_.RecordData; \
           $v=@($d.IPv4Address,$d.IPv6Address,$d.HostNameAlias,$d.NameServer,$d.DomainName,$d.PtrDomainName,$d.MailExchange,$d.PrimaryServer,$d.DescriptiveText,$d.StringData,$d.Text) | Where-Object {{ $_ }} | Select-Object -First 1; \
           [pscustomobject]@{{ name=[string]$_.HostName; type=[string]$_.RecordType; \
             ttl=[string]$_.TimeToLive; data=[string]$v }} \
         }}) | Sort-Object name,type | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-DhcpServerv4Scope -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           $s=Get-DhcpServerv4ScopeStatistics -ScopeId $_.ScopeId -ErrorAction SilentlyContinue; \
           $f=Get-DhcpServerv4Failover -ScopeId $_.ScopeId -ErrorAction SilentlyContinue; \
           [pscustomobject]@{{ scope_id=[string]$_.ScopeId; name=[string]$_.Name; state=[string]$_.State; \
             start_range=[string]$_.StartRange; end_range=[string]$_.EndRange; subnet_mask=[string]$_.SubnetMask; \
             lease_duration=[string]$_.LeaseDuration; pct_in_use=[double]$s.PercentageInUse; free=[int]$s.Free; \
             in_use=[int]$s.InUse; reserved=[int]$s.Reserved; failover_relationship=[string]$f.Name }} \
         }}) | Sort-Object scope_id | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-DhcpServerv4Lease -ScopeId '{scope}' -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           $ty='dhcp'; if($_.AddressState -like '*Reservation*'){{ $ty='reservation' }}; \
           [pscustomobject]@{{ ip=[string]$_.IPAddress; mac=[string]$_.ClientId; hostname=[string]$_.HostName; \
             state=[string]$_.AddressState; lease_expiry=[string]$_.LeaseExpiryTime; type=$ty }} \
         }}) | Sort-Object ip | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
/// the collectors' JSON array via `ps_json_as_array`. `filter` is the LDAP filter, `props`/`project` the
/// property loads + the `[pscustomobject]` body, `ou` the optional search-base DN.
#[cfg(windows)]
fn adsi_search(ou: Option<&str>, filter: &str, props: &[&str], project: &str, extra_where: &str) -> Option<Value> {
    let root_expr = match ou.map(ldap_safe).filter(|s| !s.is_empty()) {
        Some(dn) => format!("[adsi]('LDAP://{dn}')"),
        None => "[adsi]''".to_string(),
    };
    let loads = props.iter().map(|p| format!("'{p}'")).collect::<Vec<_>>().join(",");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         $root={root_expr}; \
         $ds=New-Object System.DirectoryServices.DirectorySearcher($root,'{filter}'); \
         $ds.PageSize=1000; \
         foreach($pp in @({loads})){{ [void]$ds.PropertiesToLoad.Add($pp) }}; \
         function Fts($v){{ if($v -and $v -gt 0 -and $v -lt 9223372036854775807){{ [datetime]::FromFileTimeUtc([int64]$v).ToString('yyyy-MM-dd HH:mm:ss') }} else {{ '' }} }}; \
         function P($x,$n){{ if($x[$n].Count -gt 0){{ [string]$x[$n][0] }} else {{ '' }} }}; \
         function OUOF($dn){{ if($dn -match '^(?:[^,]+,)(.*)$'){{ $Matches[1] }} else {{ '' }} }}; \
         @($ds.FindAll() | ForEach-Object {{ $x=$_.Properties; {project} }}){extra_where} | ConvertTo-Json -Depth 3 -Compress"
    );
    ps_json_as_array(&script)
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
    let mut items = adsi_search(ou, &filter, &props, project, &extra_where)?.as_array().cloned().unwrap_or_default();
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
        let groups = adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, project, "")?.as_array().cloned().unwrap_or_default();
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
        let items = adsi_search(None, &mfilter, &mprops, mproject, "")?.as_array().cloned().unwrap_or_default();
        return Some(paginate(items, params, 300));
    }

    let project = "$gt=0; if($x['grouptype'].Count){ $gt=[int64]$x['grouptype'][0] }; \
        $scope=''; if($gt -band 8){ $scope='universal' }elseif($gt -band 4){ $scope='domainlocal' }elseif($gt -band 2){ $scope='global' }; \
        $ty='distribution'; if($gt -band 2147483648){ $ty='security' }; \
        [pscustomobject]@{ name=(P $x 'cn'); sam=(P $x 'samaccountname'); scope=$scope; type=$ty; \
          description=(P $x 'description'); member_count=$x['member'].Count; \
          dn=(P $x 'distinguishedname'); managed_by=(P $x 'managedby') }";
    let items = adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, project, "")?.as_array().cloned().unwrap_or_default();
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
    let mut items = adsi_search(p.get("ou").and_then(|x| x.as_str()), &filter, &props, project, &extra_where)?.as_array().cloned().unwrap_or_default();
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
    let items = adsi_search(p.get("under").and_then(|x| x.as_str()), &filter, &props, project, "")?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         if(-not (Get-Module -ListAvailable -Name GroupPolicy)){{ '{{\"ok\":false,\"error\":\"GroupPolicy module not available\"}}' }} else {{ \
         @(Get-GPO -All -ErrorAction SilentlyContinue{name_filter} | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.DisplayName; id=[string]$_.Id; status=[string]$_.GpoStatus; \
             created=[string]$_.CreationTime; modified=[string]$_.ModificationTime; \
             computer_ver=[string]$_.Computer.DSVersion; user_ver=[string]$_.User.DSVersion; \
             wmi_filter=[string]$_.WmiFilter.Name; links=@() }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress }}"
    );
    // Single PS run: a `{ok:false}` sentinel object passes through; an array/object paginates.
    match ps_json(&script) {
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
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         if(-not (Get-Module -ListAvailable -Name GroupPolicy)){{ '{{\"ok\":false,\"error\":\"GroupPolicy module not available\"}}' }} else {{ \
         $g={resolve}; if(-not $g){{ '{{\"ok\":false,\"error\":\"no such GPO\"}}' }} else {{ \
         [xml]$r=Get-GPOReport -Guid $g.Id -ReportType Xml; \
         @($r.SelectNodes('//*[local-name()=\"Policy\"]') | ForEach-Object {{ \
           $nm=$_.SelectSingleNode('*[local-name()=\"Name\"]'); $st=$_.SelectSingleNode('*[local-name()=\"State\"]'); \
           $ct=$_.SelectSingleNode('*[local-name()=\"Category\"]'); \
           $anc=$_.SelectSingleNode('ancestor::*[local-name()=\"User\" or local-name()=\"Computer\"]'); \
           [pscustomobject]@{{ scope=$(if($anc){{$anc.LocalName}}else{{''}}); category=[string]$ct.InnerText; \
             setting=[string]$nm.InnerText; state=[string]$st.InnerText; value='' }} \
         }}){section_where} | ConvertTo-Json -Depth 3 -Compress }} }}"
    );
    match ps_json(&script) {
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-VM -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           $isvc=[string]$_.IntegrationServicesState; if(-not $isvc){{ $isvc=[string]$_.IntegrationServicesVersion }}; \
           [pscustomobject]@{{ name=[string]$_.Name; state=[string]$_.State; uptime=[string]$_.Uptime; \
             cpu_usage=[int]$_.CPUUsage; assigned_mem_mb=[int64]($_.MemoryAssigned/1MB); \
             demand_mem_mb=[int64]($_.MemoryDemand/1MB); gen=[int]$_.Generation; version=[string]$_.Version; \
             integration_svcs=$isvc; replication_state=[string]$_.ReplicationState; \
             checkpoint_count=@(Get-VMSnapshot -VM $_ -ErrorAction SilentlyContinue).Count }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
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
         @($rows) | ConvertTo-Json -Depth 3 -Compress"
    );
    let mut items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
/// addresses. Single object (no pagination). No params.
#[cfg(windows)]
fn dns_health(_params: Option<&str>) -> Option<Value> {
    // `Get-DnsServerSetting` is used for listen addresses instead of the heavy full-config `Get-DnsServer`
    // (which times out / fails on a live server).
    let script = "$ErrorActionPreference='SilentlyContinue'; \
         $fwd=Get-DnsServerForwarder -ErrorAction SilentlyContinue; \
         $sc=Get-DnsServerScavenging -ErrorAction SilentlyContinue; \
         $set=Get-DnsServerSetting -ErrorAction SilentlyContinue; \
         [pscustomobject]@{ forwarders=@($fwd.IPAddress | ForEach-Object { [string]$_ }); \
           use_root_hints=[bool]$fwd.UseRootHint; scavenging_enabled=[bool]$sc.ScavengingState; \
           scavenging_interval=[string]$sc.ScavengingInterval; \
           listen_addresses=@($set.ListeningIpAddress | ForEach-Object { [string]$_ }) } \
         | ConvertTo-Json -Depth 4 -Compress";
    ps_json(script)
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-DhcpServerv4OptionValue{arg} -ErrorAction SilentlyContinue | ForEach-Object {{ \
           [pscustomobject]@{{ option_id=[int]$_.OptionId; name=[string]$_.Name; \
             value=[string]($_.Value -join ', '); scope='{scope_label}' }} \
         }}) | Sort-Object option_id | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-SmbSession -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           [pscustomobject]@{{ client_ip=[string]$_.ClientComputerName; client_user=[string]$_.ClientUserName; \
             num_open_files=[int]$_.NumOpens; session_time=[string]$_.SecondsExists }} \
         }}) | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-PrintJob -PrinterName '{queue}' -ErrorAction SilentlyContinue | ForEach-Object {{ \
           [pscustomobject]@{{ id=[int]$_.Id; document=[string]$_.DocumentName; owner=[string]$_.UserName; \
             status=[string]$_.JobStatus; pages=[int]$_.PagesPrinted; size=[int64]$_.Size; \
             submitted=[string]$_.SubmittedTime }} \
         }}) | Sort-Object id | ConvertTo-Json -Depth 3 -Compress"
    );
    let items = ps_json_as_array(&script)?.as_array().cloned().unwrap_or_default();
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
        "$ErrorActionPreference='SilentlyContinue'; \
         $vm=Get-VM -Name '{name}' -ErrorAction SilentlyContinue; \
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
    ps_json(&script)
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
        "$ErrorActionPreference='SilentlyContinue'; \
         @(Get-VMSwitch -ErrorAction SilentlyContinue{where_clause} | ForEach-Object {{ \
           [pscustomobject]@{{ name=[string]$_.Name; type=[string]$_.SwitchType; \
             net_adapter=[string]$_.NetAdapterInterfaceDescription; allow_mgmt_os=[bool]$_.AllowManagementOS; vlan='' }} \
         }}) | Sort-Object name | ConvertTo-Json -Depth 3 -Compress"
    );
    // Small bounded list → return the bare array directly (no pagination envelope).
    ps_json_as_array(&script)
}
#[cfg(not(windows))]
fn hyperv_switches(_params: Option<&str>) -> Option<Value> {
    None
}

/// Hyper-V host capacity (role `hyperv`, optional) via `Get-VMHost` + a VM state roll-up. Single object.
#[cfg(windows)]
fn hyperv_host(_params: Option<&str>) -> Option<Value> {
    let script = "$ErrorActionPreference='SilentlyContinue'; \
         $h=Get-VMHost -ErrorAction SilentlyContinue; \
         $vms=@(Get-VM -ErrorAction SilentlyContinue); \
         $byState=@{}; $vms | Group-Object State | ForEach-Object { $byState[[string]$_.Name]=$_.Count }; \
         [pscustomobject]@{ logical_processors=[int]$h.LogicalProcessorCount; \
           total_memory_gb=[int64]($h.MemoryCapacity/1GB); vm_count=$vms.Count; \
           vm_count_by_state=[pscustomobject]$byState; default_vm_path=[string]$h.VirtualMachinePath; \
           default_vhd_path=[string]$h.VirtualHardDiskPath; \
           live_migration=[bool]$h.VirtualMachineMigrationEnabled } \
         | ConvertTo-Json -Depth 4 -Compress";
    ps_json(script)
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
    let script = "$ErrorActionPreference='SilentlyContinue'; \
         $ts=Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TerminalServiceSetting -ErrorAction SilentlyContinue; \
         $cal=Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TSLicenseKeyPack -ErrorAction SilentlyContinue | Select-Object -First 1; \
         $col=@(Get-RDSessionCollection -ErrorAction SilentlyContinue); \
         [pscustomobject]@{ collection=[string]($col.CollectionName -join ', '); \
           max_sessions=''; per_user_or_per_device_cal=[string]$cal.TypeAndModel; \
           drain_mode=[int]$ts.SessionBrokerDrainMode; connection_broker=''; gateway=''; \
           server_mode=[int]$ts.TerminalServerMode; published_apps=@() } \
         | ConvertTo-Json -Depth 4 -Compress";
    ps_json(script)
}
#[cfg(not(windows))]
fn rds_config(_params: Option<&str>) -> Option<Value> {
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
        "$ErrorActionPreference='SilentlyContinue'; \
         $srcs=@({}); \
         @($srcs | ForEach-Object {{ $scope=$_.s; $k=Get-Item -LiteralPath $_.p -ErrorAction SilentlyContinue; \
           if($k){{ foreach($n in $k.GetValueNames()){{ [pscustomobject]@{{ name=[string]$n; value=[string]($k.GetValue($n)); scope=$scope }} }} }} \
         }}){} | Sort-Object scope,name | Select-Object -First 1000 | ConvertTo-Json -Depth 3 -Compress",
        sources.join(","),
        where_clause
    );
    // Use the capping array helper so an over-long value (e.g. a giant PATH) can't blow the 64 KB cap.
    ps_json_array(&script, 1000)
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
// `gpllp-ad` really is configured as `--server-datafolder="E:\Duplicati\"`. That survived every
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
#[cfg(windows)]
fn dup_param(params: Option<&str>, keys: &[&str]) -> String {
    let raw = params.unwrap_or("").trim();
    if raw.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            for k in keys {
                if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
                    return s.trim().to_string();
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

/// PowerShell helpers (appended after `DUP_PRELUDE`): `Get-DupToken` (cached forever-token, minted via
/// ServerUtil on miss) and `Invoke-DupApi` (Bearer call to the local server API; clears the cache on a
/// 401 so the next call re-mints). Windows PowerShell 5.1: `Invoke-RestMethod` throws on non-2xx, so
/// the status is read from the exception.
#[cfg(windows)]
const DUP_API_HELPER: &str = r#"function Invoke-DupApi([string]$method,[string]$path,$bodyObj){
  if(-not $tok){ return [pscustomobject]@{ok=$false;status=0;error='no Duplicati API token delivered for this device; run the duplicati-token-issue action first'} }
  $h=@{ Authorization="Bearer $tok" }
  $uri="http://127.0.0.1:8200$path"
  try {
    if($null -ne $bodyObj){ $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -Body ($bodyObj|ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 60 }
    # A bodyless POST carries no Content-Type, and endpoints that accept an optional DTO (repair takes
    # RepairInputDto) reject that with 415 — while ones taking no body at all (verify/compact/vacuum) are
    # fine either way. Send an empty JSON object so both shapes work (2026-07-20: repair returned 415,
    # which also broke recreate, since its second step is /repair).
    elseif($method -eq 'POST'){ $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -Body '{}' -ContentType 'application/json' -TimeoutSec 60 }
    else { $res=Invoke-RestMethod -Uri $uri -Method $method -Headers $h -TimeoutSec 60 }
    return [pscustomobject]@{ok=$true;status=200;result=$res}
  } catch {
    $sc=0; try{ $sc=[int]$_.Exception.Response.StatusCode }catch{}
    return [pscustomobject]@{ok=$false;status=$sc;error=("$($_.Exception.Message)")}
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
///   is then unterminated, so anything appended after it is swallowed into that argument: the new flag
///   would be silently ignored *and* the datafolder value corrupted. gpllp-ad's datafolder is exactly
///   `E:\Duplicati\`, so this is not hypothetical — strip those separators before appending. (Same
///   family as the 0.12.1 trailing-quote bug and DUP_PRELUDE's `TrimEnd('\')`.)
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
# Strip separators immediately before a closing quote (see doc comment) then append the flag.
$new=($orig -replace '(--server-datafolder="[^"]*[^"\\])\\+"','$1"')
$normalized=($new -ne $orig)
$new=$new.TrimEnd()+' '+$flag
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

/// Read-only: the backup job's own log — per-run messages incl. warnings/errors (Server API `/log`).
/// Surfaces the EFS `PermissionDenied` / missing-fileset entries we otherwise dig for by hand.
#[cfg(windows)]
fn duplicati_log(params: Option<&str>) -> Option<Value> {
    dup_api_get(params, "log", "log", "?pagesize=200")
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

fn ps_json_as_array(script: &str) -> Option<Value> {
    match ps_json(script) {
        Some(Value::Array(a)) => Some(Value::Array(a)),
        Some(v @ Value::Object(_)) => Some(json!([v])),
        Some(Value::Null) | None => Some(json!([])),
        Some(other) => Some(json!([other])),
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

/// Run a PowerShell one-liner that emits `ConvertTo-Json` and return its rows as a JSON array,
/// capped to `max_entries` and with any over-long string field char-safe-truncated so the signed
/// result stays under the console's 64 KB cap. The shared shape for the read-only list kinds
/// (scheduled tasks / startup / network connections). Empty off-Windows.
#[cfg(windows)]
fn ps_json_array(script: &str, max_entries: usize) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let trimmed = text.trim();
    // No rows (e.g. a filter matching nothing) → empty stdout, a valid empty result, not a failure.
    // Return [] rather than erroring the job.
    if trimmed.is_empty() {
        return Some(json!([]));
    }
    let parsed: Value = serde_json::from_str(trimmed).ok()?;
    let mut rows = match parsed {
        Value::Array(a) => a,
        v @ Value::Object(_) => vec![v], // ConvertTo-Json emits a bare object for a single row
        _ => return Some(json!([])),
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
    // Final size guard: keep only the leading rows that fit the byte budget, so a wide list (e.g. many
    // PnP devices) can't overflow the 64 KB result cap even after the count + per-field caps above.
    let mut used = 0usize;
    let keep = rows
        .iter()
        .take_while(|r| {
            used += serde_json::to_string(r).map(|s| s.len() + 1).unwrap_or(0);
            used <= PAGE_BUDGET
        })
        .count();
    rows.truncate(keep);
    Some(json!(rows))
}
#[cfg(not(windows))]
fn ps_json_array(_script: &str, _max_entries: usize) -> Option<Value> {
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
    run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], ok_label)
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

/// Extract a scalar collector param that may arrive as a **bare string** (the console UI sends it raw)
/// OR **wrapped in a JSON object** by the `/api/diag` route (which serializes its request body). Returns
/// the named field for an object, the string for a JSON string, else the raw input. This is what fixes
/// the collectors that expected a raw scalar (`reg-read` = a path, `client-log` = a filename) but were
/// handed a JSON body over the API.
#[cfg(windows)]
fn json_field_or_raw(raw: &str, key: &str) -> String {
    let raw = raw.trim();
    if raw.starts_with('{') || raw.starts_with('"') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(o) = v.as_object() {
                return o.get(key).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
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
    let path_owned = json_field_or_raw(params.unwrap_or(""), "path");
    let path = path_owned.trim();
    if !valid_reg_path(path) {
        return Some(json!({ "error": "invalid registry path (expected HKLM:\\, HKCU:\\, HKCR:\\, HKU:\\ or HKCC:\\ …)" }));
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
    let path = params.unwrap_or("").trim();
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
        return run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], &format!("downloaded to {path}"));
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
        return run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], &format!("moved to {target}"));
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
    run_action(&["powershell", "-NonInteractive", "-NoProfile", "-Command", &script], &format!("{op} {user}"))
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
    match crate::post_request(url, body, "").await {
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
    let rsp = crate::post_request(url, body, "").await.ok()?;
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
