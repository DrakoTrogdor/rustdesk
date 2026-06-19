//! Client-native job channel (EXTENSION-PLAN D). The patched client:
//!   1. enrolls an Ed25519 public key (trust-on-first-use) so the console can verify its results;
//!   2. receives queued jobs in the `/api/heartbeat` response (`{"jobs":[{id,kind,params}, …]}`);
//!   3. runs the read-only kinds natively and POSTs a **signed** result to
//!      `/api/client/jobs/{id}/result` — the signature covers `device_id\njob_id\nstatus\nresult`.
//!
//! No shared secret: the signature (verified against the pinned key) is what the server trusts,
//! replacing the retired `CONSOLE_AGENT_TOKEN` + `jobs.ps1` path. Read-only kinds only today
//! (inventory / processes / services, reusing the existing native collectors); anything else posts
//! an error result. Action/write kinds are gated on the broader security model and stay future work.

use hbb_common::config::{self, Config, LocalConfig};
use hbb_common::sodiumoxide::{base64, crypto::sign};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::RwLock;

/// LocalConfig key holding the base64 Ed25519 secret key (seed‖pub), generated once per machine.
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
const SENSITIVE_KINDS: &[&str] = &["script", "file-push", "deploy", "ad"];

#[inline]
fn variant() -> base64::Variant {
    // Standard base64 + padding — matches the backend's base64 STANDARD engine.
    base64::Variant::Original
}

/// Load (or first-time generate + persist) this machine's signing keypair.
fn keypair() -> (sign::PublicKey, sign::SecretKey) {
    let stored = LocalConfig::get_option(KEY_OPT);
    if let Ok(bytes) = base64::decode(&stored, variant()) {
        if let Some(sk) = sign::SecretKey::from_slice(&bytes) {
            // The Ed25519 secret key is `seed[32] ‖ pubkey[32]`; the trailing 32 bytes are the pub.
            if let Some(pk) = sign::PublicKey::from_slice(&sk.as_ref()[32..]) {
                return (pk, sk);
            }
        }
    }
    let (pk, sk) = sign::gen_keypair();
    LocalConfig::set_option(KEY_OPT.to_owned(), base64::encode(sk.as_ref(), variant()));
    (pk, sk)
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
    Config::path("console-policy.json")
}

/// mtime (secs; 0 = missing) of the policy file at the last `load_persisted_policy`, so the UI's
/// periodic reload is a cheap stat until the file actually changes.
static PERSISTED_MTIME: AtomicI64 = AtomicI64::new(i64::MIN);
/// The locked `(key, value)` set last written to the file — lets the server skip rewriting it (and
/// thus every UI re-reading it) when a heartbeat re-delivers an unchanged policy.
static LAST_PERSISTED: RwLock<Vec<(String, String)>> = RwLock::new(Vec::new());

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

/// Run the jobs the heartbeat delivered, each on its own task, posting a signed result.
pub fn run(heartbeat_url: String, id: String, jobs: Value) {
    let Ok(jobs) = serde_json::from_value::<Vec<Value>>(jobs) else {
        return;
    };
    for job in jobs {
        let job_id = job.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let kind = job.get("kind").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let params = job.get("params").and_then(|x| x.as_str()).map(str::to_owned);
        if job_id.is_empty() {
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

/// Execute one read-only kind → (status, result-json-or-message). Registry/SMBIOS/process work runs
/// on a blocking thread so it can't stall the async runtime.
async fn run_kind(kind: &str, params: Option<String>) -> (&'static str, String) {
    use hbb_common::tokio::task::spawn_blocking;
    let value: Option<Value> = match kind {
        "inventory" => spawn_blocking(crate::console_inventory::collect).await.ok(),
        "processes" => spawn_blocking(|| crate::console_snapshot::collect("processes")).await.ok().flatten(),
        "services" => spawn_blocking(|| crate::console_snapshot::collect("services")).await.ok().flatten(),
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
        // Action kinds (admin-only, console-confirmed). A short delay lets the signed result post
        // before the OS goes down.
        "reboot" => spawn_blocking(|| power_action("/r")).await.ok(),
        "shutdown" => spawn_blocking(|| power_action("/s")).await.ok(),
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
        "file-push" => spawn_blocking(move || file_push(params.as_deref())).await.ok(),
        "deploy" => spawn_blocking(move || deploy(params.as_deref())).await.ok(),
        "ad" => spawn_blocking(move || ad_action(params.as_deref())).await.ok(),
        "wol" => spawn_blocking(move || wol(params.as_deref())).await.ok(),
        _ => None,
    };
    match value {
        Some(v) => ("done", v.to_string()),
        None => ("error", format!("job kind not supported by this client: {kind}")),
    }
}

/// Recent Windows event-log entries via PowerShell `Get-WinEvent` — System + Application at
/// Critical/Error/Warning by default, newest first, bounded so the signed result stays under the
/// console's 64 KB cap. Optional `params` JSON `{log:"System,Application", level:3, count:60}`
/// overrides the defaults (`level` = max severity: 1 crit, 2 +err, 3 +warn). Empty off-Windows.
#[cfg(windows)]
fn eventlog(params: Option<&str>) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let logs = p.get("log").and_then(|x| x.as_str()).unwrap_or("System,Application");
    let level = p.get("level").and_then(|x| x.as_i64()).unwrap_or(3).clamp(1, 5);
    let count = p.get("count").and_then(|x| x.as_i64()).unwrap_or(60).clamp(1, 200);
    // Sanitize the log names (single-quoted, strip embedded quotes) and build the level list.
    let log_arr = logs
        .split(',')
        .map(|l| format!("'{}'", l.trim().replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",");
    let levels = (1..=level).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    let script = format!(
        "Get-WinEvent -FilterHashtable @{{LogName=@({log_arr}); Level=@({levels})}} -MaxEvents {count} -ErrorAction SilentlyContinue | \
         Select-Object @{{n='time';e={{$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}}},@{{n='log';e={{$_.LogName}}}},@{{n='id';e={{$_.Id}}}},@{{n='level';e={{$_.LevelDisplayName}}}},@{{n='provider';e={{$_.ProviderName}}}},@{{n='message';e={{$_.Message}}}} | \
         ConvertTo-Json -Compress -Depth 3"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(text.trim()).ok()?;
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

/// Run a PowerShell one-liner that emits `ConvertTo-Json` and return its rows as a JSON array,
/// capped to `max_entries` and with any over-long string field char-safe-truncated so the signed
/// result stays under the console's 64 KB cap. The shared shape for the read-only list kinds
/// (scheduled tasks / startup / network connections). Empty off-Windows.
#[cfg(windows)]
fn ps_json_array(script: &str, max_entries: usize) -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: Value = serde_json::from_str(text.trim()).ok()?;
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
    Some(json!(rows))
}
#[cfg(not(windows))]
fn ps_json_array(_script: &str, _max_entries: usize) -> Option<Value> {
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

/// Run an operator-supplied PowerShell script (admin-gated, params delivered over the SIGNED
/// `/params` channel — never the unauthenticated heartbeat). Captures stdout+stderr+exit and
/// char-safe-truncates the combined output to stay under the console's 64 KB result cap. Returns
/// `{ok, exit, output}` (or `{ok:false, error}` if the shell couldn't launch).
#[cfg(windows)]
fn run_script(params: Option<&str>) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = params.unwrap_or("").trim();
    if script.is_empty() {
        return json!({ "ok": false, "error": "no script provided" });
    }
    let out = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let combined: String = format!("{stdout}{stderr}").chars().take(60_000).collect();
            json!({ "ok": o.status.success(), "exit": o.status.code(), "output": combined })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
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

/// Read a registry key's values + immediate subkey names (F11, read-only). `params` is a PS-drive
/// path like `HKLM:\SOFTWARE\Microsoft\Windows`. Returns `{key, subkeys:[…], values:[{name,type,data}]}`;
/// each value's data is char-capped so the signed result stays under the console's 64 KB cap.
#[cfg(windows)]
fn reg_read(params: Option<&str>) -> Option<Value> {
    let path = params.unwrap_or("").trim();
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
    let out = std::process::Command::new("powershell")
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
    let out = std::process::Command::new("powershell")
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
    let out = std::process::Command::new("powershell")
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
