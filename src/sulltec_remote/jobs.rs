//! Client-native job channel.

mod command_argv;
mod command_powershell;

mod adopt;

mod client_log;
mod client_logs;
mod disconnect;
mod file_pull;
mod file_push;
mod fs;
pub(crate) mod inventory;
mod perf;
mod runs;
mod script;
mod services;
mod wol;

#[cfg(windows)]
const SENSITIVE_PATHS: &[&str] = &[
    "\\windows\\system32\\config",
    "\\windows\\ntds",
    "\\microsoft\\protect",
    "\\microsoft\\credentials",
    "\\microsoft\\crypto",
];

#[cfg(windows)]
pub(super) const SENSITIVE_DENIED: &str =
    "path is in the sensitive-store denylist (SAM/SECURITY/NTDS/DPAPI); refused";

/// `\Microsoft\Protect` exists under both a user's AppData and `System32`.
#[cfg(windows)]
pub(super) fn sensitive_path(p: &str) -> bool {
    let norm = p.replace('/', "\\").to_lowercase();
    SENSITIVE_PATHS.iter().any(|d| norm.contains(d))
}

use adopt::{settle_child, ChildVerdict};
use command_argv::exec_native;
use command_powershell::exec_powershell;

use client_log::client_log_pull;
use client_logs::client_logs_list;
use disconnect::disconnect_sessions;
use file_pull::file_pull;
use file_push::file_push;
use fs::fs_list;
use perf::perf;
use script::{discard_settled, run_script, settle_script};
use services::services;
use wol::wol;

use hbb_common::config::{self, Config, LocalConfig};
use hbb_common::sodiumoxide::{base64, crypto::sign};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::RwLock;

const KEY_OPT: &str = "console-job-key";
static ENROLLED: AtomicBool = AtomicBool::new(false);
static WARNED: AtomicBool = AtomicBool::new(false);
static LOGON_TRUSTED: RwLock<Option<String>> = RwLock::new(None);
const MAX_CHAIN: usize = 256;
const LOGON_TRUST_OPT: &str = "console-logon-trust";


/// Kept in memory only — a backend that stops signing reverts the
/// fleet to observe (jobs keep running) instead of bricking them, and a fresh signed beat re-arms it.
static JOBS_ENFORCE: AtomicBool = AtomicBool::new(false);
const JOBS_FRESH_SECS: i64 = 300;
const JOBS_SEEN_OPT: &str = "console-jobs-seen";

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Absolute path to the system PowerShell, so a hijacked PATH can't substitute a rogue
/// `powershell.exe` for these SYSTEM-context collectors/actions.
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

fn keypair() -> (sign::PublicKey, sign::SecretKey) {
    static SK_BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = SK_BYTES.get_or_init(resolve_key_bytes);
    let sk = sign::SecretKey::from_slice(bytes).expect("resolved console-job key is a valid ed25519 secret");
    let pk = sign::PublicKey::from_slice(&sk.as_ref()[32..]).expect("an ed25519 secret embeds its public key");
    (pk, sk)
}

fn resolve_key_bytes() -> Vec<u8> {
    let valid = |b: &Vec<u8>| sign::SecretKey::from_slice(b).is_some();
    if let Some(b) = read_machine_key_bytes().filter(valid) {
        return b;
    }
    let bytes = local_key_bytes()
        .filter(valid)
        .unwrap_or_else(|| sign::gen_keypair().1.as_ref().to_vec());
    write_machine_key_bytes(&bytes);
    LocalConfig::set_option(KEY_OPT.to_owned(), base64::encode(&bytes, variant()));
    bytes
}

fn local_key_bytes() -> Option<Vec<u8>> {
    base64::decode(LocalConfig::get_option(KEY_OPT), variant()).ok().filter(|b| !b.is_empty())
}

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

fn write_machine_key_bytes(bytes: &[u8]) {
    let Some(path) = machine_key_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, base64::encode(bytes, variant()));
}

/// Canonical message — MUST match the backend's `client_api::sysinfo` verifier exactly.
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

/// The console verifies the signature over the *exact received bytes* against the
/// device's pinned key. Sign the exact bytes
/// that are sent: build the body string once and pass it to both.
pub fn sign_header(body: &str) -> String {
    let (_, sk) = keypair();
    format!("X-ST-Sig: {}", base64::encode(sign::sign_detached(body.as_bytes(), &sk).as_ref(), variant()))
}

pub fn baked_logon_pubkey() -> &'static str {
    option_env!("ST_LOGON_PUBKEY").unwrap_or("")
}

pub fn current_logon_pubkey() -> String {
    if let Ok(g) = LOGON_TRUSTED.read() {
        if let Some(k) = g.as_ref() {
            return k.clone();
        }
    }
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

pub async fn fetch_logon_grant(console_url: &str, token: &str, device_id: &str, challenge: &str) -> Vec<u8> {
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

/// Mirrors the backend's `sign_logon_rotate`
/// and the logon-challenge scheme (sodiumoxide's `Signature` has no `from_slice` for detached verify).
fn verify_rotate(prev_pub_b64: &str, new_pub_b64: &str, sig_b64: &str) -> bool {
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(prev_pub_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return false;
    };
    // Attached sig is `sig(64)‖msg`.
    if attached.len() < 64 || attached.len() > 64 + 4096 {
        return false;
    }
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let expected = format!("CONSOLE-LOGON-ROTATE\n{new_pub_b64}");
    matches!(sign::verify(&attached, &pk), Ok(m) if m == expected.as_bytes())
}

fn resolve_trusted(anchor: &str, entries: &[Value], prev: Option<(&str, &str)>) -> String {
    // A nested fn (not a closure) so the returned &str borrows from the argument via normal lifetime
    // elision — a `let` closure can't express that higher-ranked relationship.
    fn pub_at(e: &Value) -> Option<&str> {
        e.get("pub").and_then(|x| x.as_str())
    }
    let floor = prev.and_then(|(pa, pt)| (pa == anchor).then_some(pt));

    let Some(start_idx) = entries.iter().position(|e| pub_at(e) == Some(anchor)) else {
        return floor.unwrap_or(anchor).to_owned();
    };

    let mut trusted = anchor.to_owned();
    let mut trusted_idx = start_idx;
    for (off, e) in entries[start_idx + 1..].iter().take(MAX_CHAIN).enumerate() {
        let (Some(new_pub), Some(sig)) = (pub_at(e), e.get("sig").and_then(|x| x.as_str())) else {
            break;
        };
        if new_pub.is_empty() || sig.is_empty() || !verify_rotate(&trusted, new_pub, sig) {
            break;
        }
        trusted = new_pub.to_owned();
        trusted_idx = start_idx + 1 + off;
    }

    match floor {
        Some(f) => match entries.iter().position(|e| pub_at(e) == Some(f)) {
            Some(f_idx) if trusted_idx >= f_idx => trusted,
            _ => f.to_owned(),
        },
        None => trusted,
    }
}

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

/// Kept OUTSIDE the OVERWRITE_* maps that `policy_release_all` clears,
/// so a MITM that merely drops the policy push can't downgrade enforce→observe once a device has
/// latched.
const UPDATE_ENFORCE_LATCH_OPT: &str = "console-update-enforce-latched";
const UPDATE_HWM_OPT: &str = "console-update-hwm";
const UPDATE_REQUIRE_SIG_KEY: &str = "update.require_sig";

/// A rotated-*out* key is intentionally NOT accepted, so a
/// rotation revokes a compromised key; the backend re-signs hosted packages under the current key
/// on rotation.
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
    if attached.len() < 64 || attached.len() > 64 + 4096 {
        return false;
    }
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    let expected = format!("CONSOLE-PKG\n{version}\n{sha256_hex}\n{size}");
    matches!(sign::verify(&attached, &pk), Ok(m) if m == expected.as_bytes())
}

pub fn update_sig_enforced() -> bool {
    if option_env!("ST_UPDATE_ENFORCE") == Some("1") {
        return true;
    }
    LocalConfig::get_option(UPDATE_ENFORCE_LATCH_OPT) == "1"
}

pub fn update_hwm() -> String {
    LocalConfig::get_option(UPDATE_HWM_OPT)
}

pub fn advance_update_hwm(token: &str) {
    if token.is_empty() {
        return;
    }
    let cur = LocalConfig::get_option(UPDATE_HWM_OPT);
    if cur.is_empty() || crate::sulltec_remote::update::version_key(token) > crate::sulltec_remote::update::version_key(&cur) {
        LocalConfig::set_option(UPDATE_HWM_OPT.to_owned(), token.to_owned());
    }
}

fn apply_update_require_sig(value: &str) {
    let truthy = matches!(value.trim(), "1" | "true" | "yes" | "on");
    if truthy {
        LocalConfig::set_option(UPDATE_ENFORCE_LATCH_OPT.to_owned(), "1".to_owned());
    } else if option_env!("ST_UPDATE_ENFORCE") != Some("1") {
        LocalConfig::set_option(UPDATE_ENFORCE_LATCH_OPT.to_owned(), "0".to_owned());
    }
}

static POLICY_LOCKED: RwLock<Vec<String>> = RwLock::new(Vec::new());

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

fn verify_policy(sig_b64: &str) -> Option<Vec<(String, String, bool)>> {
    let pk_b64 = current_logon_pubkey();
    if pk_b64.is_empty() {
        return None;
    }
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(&pk_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return None;
    };
    if attached.len() < 64 || attached.len() > 64 + 65536 {
        return None;
    }
    let pk = sign::PublicKey::from_slice(&pk_bytes)?;
    let msg = sign::verify(&attached, &pk).ok()?;
    let msg = String::from_utf8(msg).ok()?;
    let mut parts = msg.splitn(3, '\n');
    if parts.next() != Some("CONSOLE-POLICY") {
        return None;
    }
    if parts.next() != Some(Config::get_id().as_str()) {
        return None;
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

/// Since we don't know a key's store, we force/release it in ALL
/// THREE maps (an entry in a non-owning map is inert — only that map's getter reads it) and apply
/// unlocked values via all three setters.
pub fn apply_policy(policy: Option<Value>) {
    let sig = match policy.as_ref().and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            policy_release_all();
            sync_policy_file(&[]);
            return;
        }
    };
    let Some(mut settings) = verify_policy(sig) else {
        hbb_common::log::warn!("console policy: signature invalid; ignoring");
        return;
    };

    if let Some(pos) = settings.iter().position(|(k, _, _)| k == UPDATE_REQUIRE_SIG_KEY) {
        let (_, value, _) = settings.remove(pos);
        apply_update_require_sig(&value);
    }

    let now_locked: Vec<String> = settings.iter().filter(|(_, _, l)| *l).map(|(k, _, _)| k.clone()).collect();
    let prev_locked: Vec<String> = POLICY_LOCKED.read().map(|g| g.clone()).unwrap_or_default();

    // BEFORE any `set_option` below — that re-reads
    // OVERWRITE_SETTINGS and would DEADLOCK if this still held the lock.
    apply_overwrite(&config::OVERWRITE_SETTINGS, &settings, &prev_locked, &now_locked);
    apply_overwrite(&config::OVERWRITE_DISPLAY_SETTINGS, &settings, &prev_locked, &now_locked);
    apply_overwrite(&config::OVERWRITE_LOCAL_SETTINGS, &settings, &prev_locked, &now_locked);
    if let Ok(mut g) = POLICY_LOCKED.write() {
        *g = now_locked;
    }

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
    // this the value is forced but the control never disables.
    let locked_kv: Vec<(String, String)> = settings
        .iter()
        .filter(|(_, _, l)| *l)
        .map(|(k, v, _)| (k.clone(), v.clone()))
        .collect();
    sync_policy_file(&locked_kv);
}

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

fn policy_file_path() -> std::path::PathBuf {
    // The file must be reachable by BOTH its writer and its reader, which on a SERVICE install are
    // DIFFERENT Windows accounts. `Config::path()` resolves PER-IDENTITY (SYSTEM →
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

static PERSISTED_MTIME: AtomicI64 = AtomicI64::new(i64::MIN);
static LAST_PERSISTED: RwLock<Vec<(String, String)>> = RwLock::new(Vec::new());
static POLICY_VERSION: AtomicI64 = AtomicI64::new(0);

pub fn policy_version() -> i64 {
    POLICY_VERSION.load(Ordering::Relaxed)
}

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
        return;
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
    POLICY_VERSION.fetch_add(1, Ordering::Relaxed);
}

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

enum JobsVerdict {
    Valid { enforce: bool, jobs: Vec<Value> },
    Invalid,
    Absent,
}

pub fn poll(heartbeat_url: String, id: String) {
    hbb_common::tokio::spawn(async move {
        let Some(mut rsp) = fetch_jobs(&heartbeat_url, &id).await else { return };
        // FIRST, and deliberately not behind the dispatch below. A device whose only open work is a
        // run the console can no longer offer gets an EMPTY `items`, so anything sequenced after
        // that early return would never see the question at all.
        settle_started(&heartbeat_url, &id, rsp.get("started")).await;
        let Some(items) = rsp.get_mut("items").map(Value::take) else { return };
        // The CONSOLE declares the claim route, never the device. `false` here is not a default: it
        // is the whole safety of this client against a console without that route, which answers the
        // claim POST with a bare 404 and an empty body — indistinguishable from a refusal once
        // `post_request_timeout` drops the status. Absent flag ⇒ do not fail closed.
        let claims = rsp.get("claims").and_then(Value::as_bool).unwrap_or(false);
        run(
            heartbeat_url,
            id,
            items,
            rsp.get("jobs_sig").cloned(),
            rsp.get("jobs_ts").cloned(),
            claims,
        );
    });
}

async fn fetch_jobs(heartbeat_url: &str, device_id: &str) -> Option<Value> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let msg = format!("CONSOLE-DEVICE-JOBS\n{device_id}\n{ts}");
    let body = json!({ "device_id": device_id, "ts": ts, "sig": sign_device_msg(&msg) }).to_string();
    let url = format!("{}/api/device/jobs/list", origin_of(heartbeat_url));
    let rsp = crate::post_request_timeout(url, body, "", crate::sulltec_remote::http::API_TIMEOUT_DATA)
        .await
        .ok()?;
    serde_json::from_str::<Value>(&rsp).ok()
}

/// Each caller supplies its own
/// domain-separated message, so a signature captured for the queue read can never be replayed as a
/// claim.
fn sign_device_msg(msg: &str) -> String {
    let (_, sk) = keypair();
    base64::encode(sign::sign_detached(msg.as_bytes(), &sk).as_ref(), variant())
}

fn origin_of(heartbeat_url: &str) -> String {
    match heartbeat_url.find("/api/") {
        Some(i) => heartbeat_url[..i].to_owned(),
        None => heartbeat_url.trim_end_matches('/').to_owned(),
    }
}

pub fn run(
    heartbeat_url: String,
    id: String,
    jobs: Value,
    jobs_sig: Option<Value>,
    jobs_ts: Option<Value>,
    claims: bool,
) {
    let Ok(wire_jobs) = serde_json::from_value::<Vec<Value>>(jobs) else {
        return;
    };
    if wire_jobs.is_empty() {
        return;
    }
    let run_jobs: Vec<Value> = match verify_jobs(&wire_jobs, jobs_sig.as_ref(), jobs_ts.as_ref()) {
        JobsVerdict::Valid { enforce, jobs } => {
            JOBS_ENFORCE.store(enforce, Ordering::Relaxed);
            jobs
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
            wire_jobs
        }
    };
    for job in run_jobs {
        let job_id = job.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let op = job.get("op").and_then(|x| x.as_str()).unwrap_or_default().to_owned();
        let params = job.get("params").and_then(|x| x.as_str()).map(str::to_owned);
        if job_id.is_empty() {
            continue;
        }
        let Some(in_flight) = in_flight_acquire(&job_id) else {
            continue;
        };
        match mark_job_seen(&job_id) {
            JobGate::Run => {}
            JobGate::Skip => continue,
            JobGate::AlreadyRan => {
                hbb_common::log::warn!(
                    "console job {job_id}: already ran to completion here; its result never reached \
                     the console. Reporting that instead of running it again."
                );
                let url = heartbeat_url.clone();
                let id = id.clone();
                hbb_common::tokio::spawn(async move {
                    let _in_flight = in_flight;
                    post_result(&url, &id, &job_id, "error", RESULT_LOST).await;
                });
                continue;
            }
        }
        let url = heartbeat_url.clone();
        let id = id.clone();
        hbb_common::tokio::spawn(async move {
            let _in_flight = in_flight;
            // Inside the future rather than in the
            // loop because `run` is not async: awaiting per job up there would serialise the claims
            // and let one slow claim delay every other job in the same dispatch.
            if claims && !claim_job(&url, &id, &job_id).await {
                return;
            }
            // Id and OPERATION only — params can carry a registry path, a
            // file path or credentials merged in at delivery, and this log gets pulled off devices.
            match op.is_empty() {
                true => hbb_common::log::info!("console job {job_id} starting"),
                false => hbb_common::log::info!("console job {job_id} starting ({op})"),
            }
            let Some((status, result)) = run_job(params, job_id.clone()).await else {
                hbb_common::log::warn!(
                    "console job {job_id}: passed the bound it was given and is still running. Left \
                     alone; its answer follows when it ends."
                );
                return;
            };
            mark_job_done(&job_id, RunRecord::Spent);
            post_result(&url, &id, &job_id, status, &result).await;
        });
    }
}

fn verify_jobs(wire_jobs: &[Value], sig: Option<&Value>, ts: Option<&Value>) -> JobsVerdict {
    let sig_b64 = match sig.and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return JobsVerdict::Absent,
    };
    let pk_b64 = current_logon_pubkey();
    if pk_b64.is_empty() {
        return JobsVerdict::Invalid;
    }
    let (Ok(pk_bytes), Ok(attached)) =
        (base64::decode(&pk_b64, variant()), base64::decode(sig_b64, variant()))
    else {
        return JobsVerdict::Invalid;
    };
    if attached.len() < 64 || attached.len() > 64 + 256 * 1024 {
        return JobsVerdict::Invalid;
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
    let mut parts = msg.splitn(5, '\n');
    if parts.next() != Some("CONSOLE-JOBS") {
        return JobsVerdict::Invalid;
    }
    if parts.next() != Some(Config::get_id().as_str()) {
        return JobsVerdict::Invalid;
    }
    let Some(signed_ts) = parts.next().and_then(|s| s.parse::<i64>().ok()) else {
        return JobsVerdict::Invalid;
    };
    let enforce = parts.next() == Some("1");
    let Some(jobs_json) = parts.next() else {
        return JobsVerdict::Invalid;
    };
    if (now_secs() - signed_ts).abs() > JOBS_FRESH_SECS {
        return JobsVerdict::Invalid;
    }
    if let Some(adv) = ts.and_then(|v| v.as_i64()) {
        if adv != signed_ts {
            return JobsVerdict::Invalid;
        }
    }
    let Ok(signed_jobs) = serde_json::from_str::<Vec<Value>>(jobs_json) else {
        return JobsVerdict::Invalid;
    };
    if signed_jobs != *wire_jobs {
        return JobsVerdict::Invalid;
    }
    JobsVerdict::Valid { enforce, jobs: signed_jobs }
}

/// Release builds set `panic = 'abort'`; a Windows service has no stderr, so the panic message must
/// be logged before the process aborts.
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

/// `Vec` rather than `HashSet`: `HashSet::new()` is not const, and `once_cell::Lazy` is not available
/// here — once_cell is an optional dependency gated on `unix-file-copy-paste`, so it is absent from
/// the Windows build. Only a handful of ids are ever in flight, so the linear scan is free.
static JOBS_IN_FLIGHT: std::sync::RwLock<Vec<String>> = std::sync::RwLock::new(Vec::new());

/// Acquired in [`run`] and **moved into** the spawned
/// future, so the insert and the obligation to release are the same object — constructing it inside
/// the future instead would leak the id for the life of the process if that future were ever dropped
/// before its first poll, leaving the job permanently un-runnable with nothing logged.
struct InFlight(String);

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut ids = JOBS_IN_FLIGHT.write().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = ids.iter().position(|x| *x == self.0) {
            ids.swap_remove(i);
        }
    }
}

pub(crate) fn any_job_in_flight() -> bool {
    !JOBS_IN_FLIGHT.read().unwrap_or_else(|e| e.into_inner()).is_empty()
}

/// ⚠ Membership is NOT "has a process to see or to end". An id being settled holds it, an id whose
/// only work is reporting a lost result holds it, and every procedure that runs inside this client
/// holds it — [`runs::job_runs`] itself included. So it fills a row's `in_flight` field and never
/// decides which rows there are.
#[cfg(windows)]
fn jobs_in_flight() -> Vec<String> {
    JOBS_IN_FLIGHT.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub(crate) fn any_run_in_progress() -> bool {
    any_job_in_flight() || adopt::any_adopted()
}

fn in_flight_acquire(job_id: &str) -> Option<InFlight> {
    let mut ids = JOBS_IN_FLIGHT.write().unwrap_or_else(|e| e.into_inner());
    if ids.iter().any(|x| x == job_id) {
        return None;
    }
    ids.push(job_id.to_owned());
    Some(InFlight(job_id.to_owned()))
}

/// This is independent of [`JOBS_FRESH_SECS`], the dispatch-signature anti-replay window that mirrors
/// the backend's ±300-second check.
const JOBS_SEEN_TTL_SECS: i64 = 300;

const JOB_POISON_TTL_SECS: i64 = 7 * 24 * 3600;

/// Every other writer runs on the heartbeat's
/// single-threaded runtime; [`mark_job_child`] runs on the blocking pool, where an interleaved
/// `get_option`/`set_option` pair drops whichever update lost the race — and a lost seen entry means
/// completed work can be run a second time.
static SEEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const JOBS_SEEN_MAX: usize = 256;

fn seen_entry(v: &Value) -> Option<(i64, bool, bool)> {
    if let Some(t) = v.as_i64() {
        return Some((t, false, false));
    }
    let t = v.get("t")?.as_i64()?;
    Some((
        t,
        v.get("d").and_then(|x| x.as_bool()).unwrap_or(false),
        v.get("r").and_then(|x| x.as_bool()).unwrap_or(false),
    ))
}

/// `x` alone counts: a run-as script has a directory before it has a pid, and may never get one. The
/// bound stamp alone counts too: an executor whose `adopt::record` could not tokenise the pid records
/// neither, and the run is still going.
fn records_a_run(v: &Value) -> bool {
    v.get("p").is_some() || v.get("x").is_some() || v.get(SEEN_OVER_TIME).is_some()
}

#[cfg(windows)]
fn run_is_live(job_id: &str, v: &Value) -> bool {
    if let Some((pid, created)) = child_of(v) {
        return adopt::alive(pid, created);
    }
    v.get("x").is_some() && script::still_running(job_id)
}

#[cfg(not(windows))]
fn run_is_live(_job_id: &str, _v: &Value) -> bool {
    false
}

#[cfg(windows)]
fn job_run_is_live(job_id: &str) -> bool {
    match seen_child(job_id) {
        Some((pid, created)) => adopt::alive(pid, created),
        None => script::still_running(job_id),
    }
}

#[cfg(not(windows))]
fn job_run_is_live(_job_id: &str) -> bool {
    false
}

enum JobGate {
    Run,
    Skip,
    AlreadyRan,
}

const RESULT_LOST: &str = "this job already ran to completion on this device; its result was lost \
     when the client restarted before it could be posted. It was NOT run a second time. Dispatch it \
     again if the work needs repeating.";

const RESULT_ABANDONED: &str = "this device took this job up and cannot say how it ended: the client \
     stopped between starting the work and reporting on it, so no result was ever produced. How far \
     it got is unknown — it may have completed, made a partial change, or done nothing. It was NOT \
     re-run. Check the machine before dispatching it again.";

const RESULT_KILLED: &str = "this run was ended on this device at an operator's request while it \
     was going. It did not finish, and what it had already changed on this machine stands — a kill \
     ends the process, not the work it had already done. ⚠ Only the process this device started was \
     ended; anything IT had launched is still running.";

fn adopted_exit_result(job_id: &str, code: u32) -> String {
    let code = code as i32;
    let how = if seen_flag(job_id, SEEN_KILLED).is_some() {
        "this device ended this job's process on request and watched it exit. The exit code below \
         is the one termination gave it, not one the run chose"
    } else if seen_flag(job_id, SEEN_OVER_TIME).is_some() {
        "this job's process passed the bound it was given. This device stopped WAITING for it \
         without killing it, kept a handle on it, and watched it exit"
    } else {
        "this job's process outlived the client that started it: the client stopped mid-run, this \
         device re-attached to the process it had launched and watched it exit"
    };
    let lost = match seen_job_dir(job_id).is_some() {
        true => "its output was written to a file this device can no longer read",
        false => "the job's output went to pipes nothing was reading by then",
    };
    format!(
        "{how}. Its exit code was {code}. THAT EXIT CODE IS ALL THAT SURVIVED — {lost} — so this is \
         NOT the job's answer, and an exit code of 0 here is not a reported success. What it changed \
         on this machine is unknown. Dispatch it again if the answer is needed."
    )
}

enum RunRecord {
    /// A settlement that believed the removed `p`/`c`/`x` would take
    /// the tidied-up directory for a swept one and publish [`adopted_exit_result`] — which asserts the
    /// output is unrecoverable — over a run whose output had already been read and posted.
    Spent,
    /// Dropping `x`
    /// makes [`settle_script`] answer `None` for the rest of this row's life, which is the recovered
    /// output unreachable for good.
    Kept,
}

fn mark_job_done(job_id: &str, record: RunRecord) {
    seen_merge(job_id, Absent::Create, |e| {
        e.insert("d".into(), json!(true));
        if matches!(record, RunRecord::Spent) {
            e.remove("p");
            e.remove("c");
            e.remove("x");
        }
    });
}

fn mark_job_reported(job_id: &str) {
    seen_merge(job_id, Absent::Ignore, |e| {
        e.insert("r".into(), json!(true));
    });
}

/// On its own
/// thread rather than the caller's: it enumerates `C:\Windows\Temp`, and the caller is the heartbeat.
pub fn sweep_job_temp() {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(|| {
        std::thread::spawn(|| loop {
            script::sweep_job_dirs();
            // ⚠ REPEATEDLY: what this collects only becomes collectible with age, so a single pass
            // at start-up skips exactly the residue it exists for.
            std::thread::sleep(std::time::Duration::from_secs(3600));
        });
    });
}

pub fn sweep_orphaned_results(heartbeat_url: &str, id: &str) {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    if id.is_empty() {
        return;
    }
    SWEPT.call_once(|| {
        let orphans: Vec<String> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|(k, v)| match seen_entry(v) {
                Some((_, true, false)) => Some(k.clone()),
                _ => None,
            })
            .collect();
        if orphans.is_empty() {
            return;
        }
        let url = heartbeat_url.to_owned();
        let id = id.to_owned();
        hbb_common::tokio::spawn(async move {
            for job_id in orphans {
                hbb_common::log::warn!(
                    "console job {job_id}: ran to completion here and its result never reached the \
                     console. Reporting that now; it was NOT run a second time."
                );
                post_result(&url, &id, &job_id, "error", RESULT_LOST).await;
            }
        });
    });
}

async fn settle_started(heartbeat_url: &str, device_id: &str, started: Option<&Value>) {
    let Some(ids) = started.and_then(Value::as_array) else {
        return;
    };
    for entry in ids {
        let Some(job_id) = entry.as_str().filter(|s| !s.is_empty()) else {
            continue;
        };
        // Holding the guard for the settlement also stops a dispatch of
        // this same id from starting underneath it.
        let Some(_in_flight) = in_flight_acquire(job_id) else {
            continue;
        };
        // ⚠ A script run is asked about first in BOTH settling arms: `adopted_exit_result` states the
        // output cannot be recovered, which is false for the one executor that redirects to a file.
        match settle_child(job_id) {
            ChildVerdict::Running => continue,
            ChildVerdict::Exited(code) => {
                if let Some((status, answer, dir)) = settle_script(job_id, Some(code)) {
                    hbb_common::log::warn!(
                        "console job {job_id}: the script process this device re-attached to has \
                         exited {code}. Reporting what the run left on disk as its answer."
                    );
                    // Before the post: an unfinished entry is retained away in 300 s, taking the
                    // guard that stops the work being done twice.
                    mark_job_done(job_id, RunRecord::Kept);
                    if post_result(heartbeat_url, device_id, job_id, status, &answer).await {
                        discard_settled(&dir);
                    }
                    continue;
                }
                hbb_common::log::warn!(
                    "console job {job_id}: the process this device re-attached to has exited \
                     {code}. Settling it as an exit code with no output."
                );
                mark_job_done(job_id, RunRecord::Kept);
                post_result(heartbeat_url, device_id, job_id, "error", &adopted_exit_result(job_id, code)).await;
                continue;
            }
            ChildVerdict::None => {
                if let Some((status, answer, dir)) = settle_script(job_id, None) {
                    hbb_common::log::warn!(
                        "console job {job_id}: nothing is running it here and the run recorded its \
                         own completion. Settling it from what it wrote to disk."
                    );
                    mark_job_done(job_id, RunRecord::Kept);
                    if post_result(heartbeat_url, device_id, job_id, status, &answer).await {
                        discard_settled(&dir);
                    }
                    continue;
                }
                if script::still_running(job_id) {
                    continue;
                }
            }
        }
        // ⚠ NEVER SETTLE A RUN THAT MAY STILL BE GOING.
        // `settle_child` answers nothing when no handle was ever taken, and `adopt::hold` can fail
        // at the moment a bound elapses; an over-time run is exactly where the process outlives
        // everything watching it.
        if job_run_is_live(job_id) {
            continue;
        }
        // ⚠ The kill is asked FIRST. A wrapper this device terminated never reaches its `finally`,
        // so it writes no completion marker and arrives here looking exactly like one that was
        // abandoned — and "we do not know how it ended" would be false of the one ending this device
        // performed itself.
        let killed = seen_flag(job_id, SEEN_KILLED).is_some();
        let finished = matches!(seen_state(job_id), Some((_, true, _)));
        let result = if killed {
            RESULT_KILLED
        } else if finished {
            RESULT_LOST
        } else {
            RESULT_ABANDONED
        };
        hbb_common::log::warn!(
            "console job {job_id}: the console is still waiting on it and nothing is running it \
             here. Settling it as {}.",
            match (killed, finished) {
                (true, _) => "ended-on-request",
                (false, true) => "finished-with-the-result-lost",
                (false, false) => "abandoned",
            }
        );
        post_result(heartbeat_url, device_id, job_id, "error", result).await;
    }
}

#[cfg(windows)]
fn mark_job_child(job_id: &str, pid: Option<u32>, created: Option<u64>, dir: Option<&str>) {
    seen_merge(job_id, Absent::Ignore, |e| {
        if let Some(p) = pid {
            e.insert("p".into(), json!(p));
        }
        // The creation time goes down as text: it is a raw FILETIME tick count compared for exact
        // equality, and nothing downstream may round it.
        if let Some(c) = created {
            e.insert("c".into(), json!(c.to_string()));
        }
        if let Some(x) = dir {
            e.insert("x".into(), json!(x));
        }
    });
}

enum Absent {
    Ignore,
    /// A job that outran
    /// [`JOBS_SEEN_TTL_SECS`] has had its entry retained away by some later dispatch, and forgetting
    /// that it finished is how the work gets done a second time.
    Create,
}

/// ⚠ MERGE-PRESERVING. Independent writers stamp this entry — the
/// process pair, the temp directory, the moment a run passed its bound, the completion, the
/// acknowledgement — and on the run-as path they fire in sequence against the same id. Rebuilding the
/// entry from `(t, done, reported)` plus only the keys one call was given would erase whatever the
/// others had put there, and a lost `x` is a recoverable answer silently downgraded to abandoned.
fn seen_merge(job_id: &str, absent: Absent, set: impl FnOnce(&mut serde_json::Map<String, Value>)) {
    let _seen = SEEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut map: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let (t, done, reported) = match (map.get(job_id).and_then(seen_entry), absent) {
        (Some(state), _) => state,
        (None, Absent::Create) => (now_secs(), false, false),
        (None, Absent::Ignore) => return,
    };
    let mut entry: serde_json::Map<String, Value> =
        map.get(job_id).and_then(|v| v.as_object().cloned()).unwrap_or_default();
    entry.insert("t".into(), json!(t));
    entry.insert("d".into(), json!(done));
    entry.insert("r".into(), json!(reported));
    set(&mut entry);
    map.insert(job_id.to_owned(), Value::Object(entry));
    LocalConfig::set_option(JOBS_SEEN_OPT.to_owned(), Value::Object(map).to_string());
}

const SEEN_OVER_TIME: &str = "o";

const SEEN_KILLED: &str = "k";

#[cfg(windows)]
fn mark_job_stamp(job_id: &str, key: &'static str) {
    seen_merge(job_id, Absent::Ignore, |e| {
        e.insert(key.to_owned(), json!(now_secs()));
    });
}

fn seen_flag(job_id: &str, key: &str) -> Option<i64> {
    serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()?
        .get(job_id)?
        .get(key)?
        .as_i64()
}

#[cfg(windows)]
fn child_of(entry: &Value) -> Option<(u32, u64)> {
    let pid = u32::try_from(entry.get("p")?.as_u64()?).ok()?;
    let created = entry.get("c")?.as_str()?.parse::<u64>().ok()?;
    Some((pid, created))
}

#[cfg(windows)]
fn seen_child(job_id: &str) -> Option<(u32, u64)> {
    let map = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT)).ok()?;
    child_of(map.get(job_id)?)
}

#[cfg(windows)]
fn seen_job_dir(job_id: &str) -> Option<std::path::PathBuf> {
    let entry = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT)).ok()?;
    let dir = entry.get(job_id)?.get("x")?.as_str()?;
    Some(std::path::PathBuf::from(dir))
}

fn seen_state(job_id: &str) -> Option<(i64, bool, bool)> {
    serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()?
        .get(job_id)
        .and_then(seen_entry)
}

/// ⚠ Callers MUST take the in-flight guard first, so a dispatch that guard is about to decline does
/// not rewrite the record on its way past.
fn mark_job_seen(job_id: &str) -> JobGate {
    let _seen = SEEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_secs();
    let mut map: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    map.retain(|_, v| match seen_entry(v) {
        Some((t, done, reported)) => {
            // ⚠ AGE DECIDES A DEDUP STAMP AND NOTHING ELSE. A record the console has not been told
            // about still carries the pid a kill aims by, the directory an answer is read out of,
            // and the guard that stops the work running twice — and since nothing ends a run at its
            // bound, outliving any age this could name is an ordinary outcome rather than an
            // impossible one.
            if !reported && (done || records_a_run(v)) {
                return true;
            }
            let ttl = if done { JOB_POISON_TTL_SECS } else { JOBS_SEEN_TTL_SECS };
            (now - t).abs() <= ttl
        }
        None => false,
    });
    let run = match map.get(job_id).and_then(seen_entry) {
        Some((_, true, _)) => JobGate::AlreadyRan,
        Some((t, _, _)) if (now - t).abs() <= JOBS_SEEN_TTL_SECS => JobGate::Skip,
        // ⚠ A started run outlives the dedup window and lands here. Settling it belongs to adoption;
        // the arm below would re-run it AND erase the record.
        _ if map.get(job_id).is_some_and(records_a_run) => JobGate::Skip,
        _ => {
            map.insert(job_id.to_owned(), json!({ "t": now }));
            JobGate::Run
        }
    };
    if map.len() > JOBS_SEEN_MAX {
        let mut by_age: Vec<(String, u8, i64)> = map
            .iter()
            // Never the id being dispatched right now. Its entry was written three statements ago and
            // carries no child record yet — `adopt::record` stamps that seconds later, once the
            // process exists — so it ranks lowest, and on a device already at the cap it would be the
            // one evicted: the dispatch would forget the job it is in the middle of starting.
            .filter(|(k, _)| k.as_str() != job_id)
            .map(|(k, v)| {
                let (t, done, reported) = seen_entry(v).unwrap_or((0, false, false));
                // The liveness probe sits HERE and not in the retain above: it
                // opens a handle per entry, and this runs only at the cap.
                let rank = match (reported, done, records_a_run(v)) {
                    (true, _, _) => 0,
                    (false, true, _) => 1,
                    (false, false, true) if !run_is_live(k, v) => 2,
                    (false, false, true) => 3,
                    _ => 0,
                };
                (k.clone(), rank, t)
            })
            .collect();
        by_age.sort_by_key(|(_, rank, t)| (*rank, *t));
        for (k, _, _) in by_age.into_iter().take(map.len() - JOBS_SEEN_MAX) {
            map.remove(&k);
        }
    }
    LocalConfig::set_option(JOBS_SEEN_OPT.to_owned(), Value::Object(map).to_string());
    run
}



async fn run_job(params: Option<String>, job_id: String) -> Option<(&'static str, String)> {
    use hbb_common::tokio::task::spawn_blocking;
    // ⚠ An ask carrying an `exec` runs through [`keyset_exec`]; one carrying none is refused,
    // because the backend has not hosted that ask yet — and answering it from a compiled-in arm
    // would make an unhosted ask indistinguishable from a hosted one on both sides at once.
    if keyset_requested(params.as_deref()) {
        return match spawn_blocking(move || keyset_exec(params.as_deref(), &job_id)).await {
            Ok(Settled::OverTime) => None,
            Ok(Settled::Result(v)) => Some(job_answer(v)),
            Err(_) => Some(job_answer(None)),
        };
    }
    Some((
        "error",
        "this job carried no command to run: the client runs what the dispatch brings with it, so \
         an ask arriving without one has not been hosted by the backend yet"
            .to_string(),
    ))
}

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

/// The `/api/diag` route delivers a filter body whose values may
/// arrive as strings, so a param that means "a number" has to accept both spellings or it silently
/// stops filtering.
#[cfg(windows)]
fn as_i64_loose(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
}































const SERVICE_CAP: usize = 3000;

const SERVICE_ORDER: &str = "display asc";






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
        assert!(m.get("display").is_none() && m.get("state").is_none() && m.get("start").is_none(), "{m}");
    }
}



































































/// Both streams must drain while the exit is being polled —
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


#[cfg(windows)]
enum PsRun {
    Done(std::process::Output),
    OverTime { killed: bool },
}


#[cfg(windows)]
enum NativeRun {
    /// `drained` is false when the output pipes could not be read to the end. The process still
    /// exited on its own and `code` is its real one — but the output is not the command's, so a
    /// zero here does not mean the run answered anything.
    Done { code: i32, stdout: String, stderr: String, drained: bool },
    OverTime { killed: bool },
}





/// A distinct type
/// rather than a `Value`, because the list collectors feed their rows straight into `paginate` — and
/// an error object there would `unwrap_or_default()` into an empty page, re-hiding the failure the
/// guard exists to surface.
#[cfg(windows)]
enum GuardedRows {
    Rows(Vec<Value>),
    Failed(Value),
}

/// What the wire's `timeout_s` BOUNDS, which decides what an elapsed bound may do about it.
///
/// ⚠ **The two want opposite things and travel as one wire field.**
#[cfg(windows)]
#[derive(Clone, Copy)]
enum Bound {
    /// A cycle's `Paging::page_timeout_s`. Elapsed, the process is ENDED and the page answers.
    Page,
    /// A `Command::run_timeout_s`, or the device's default. Elapsed, the process is LEFT RUNNING and
    /// nothing is posted.
    Run,
}

#[cfg(windows)]
enum ExecEnd {
    Refused(Value),
    OverTime,
}

/// Uncfg'd so [`run_job`]'s match compiles on both targets; off Windows only `Result` is built.
#[allow(dead_code)]
enum Settled {
    Result(Option<Value>),
    /// The run has NOT ended. Nothing is posted and nothing is marked done: the console's row stays
    /// open and the adoption path answers for it when the process ends.
    OverTime,
}





/// The 48 KiB budget leaves substantial headroom under the 256 KiB result cap, where an over-cap
/// result is replaced wholesale with a failure notice.
#[cfg(windows)]
const PAGE_BUDGET: usize = 48 * 1024;

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



/// The job still reports `done`: it WAS
/// delivered and DID produce an answer, and `status:"error"` means there is no result to read at all.
#[cfg(windows)]
fn keyset_error(why: &str) -> Value {
    json!({ "ok": false, "error": why })
}

fn keyset_requested(params: Option<&str>) -> bool {
    params
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|p| p.get("exec").and_then(|x| x.as_str()).map(|e| !e.trim().is_empty()))
        .unwrap_or(false)
}

#[cfg(windows)]
const JOB_PARAMS_ENV: &str = "SULLTEC_JOB_PARAMS";

/// ⚠ Kept in lockstep with the backend's `HOSTED_WIRE_FIELDS`. A field one half reserves and the
/// other does not is either a wire control a script can read as though it were a selector, or a
/// selector the script is never handed.
#[cfg(windows)]
const HOSTED_WIRE_FIELDS: &[&str] = &["exec", "command", "key", "limit", "timeout_s", "after"];

#[cfg(windows)]
fn hosted_ask(p: &Value) -> String {
    let mut o = p.as_object().cloned().unwrap_or_default();
    for f in HOSTED_WIRE_FIELDS {
        o.remove(*f);
    }
    Value::Object(o).to_string()
}

/// ⚠ **No cursor, no `more` and no page size, and every absence is deliberate.** A bounded ask is
/// one row or a handful — a member's detail read, not a sweep — so there is nothing to resume from
/// and a caller must not be handed an envelope shaped like one that needs paging.
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

#[cfg(windows)]
fn key_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(windows)]
fn keyset_exec(params: Option<&str>, job_id: &str) -> Settled {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let exec = p.get("exec").and_then(|x| x.as_str()).unwrap_or("").trim();
    let command = p.get("command").and_then(|x| x.as_str()).unwrap_or("");
    let key = p.get("key").and_then(|x| x.as_str()).unwrap_or("").trim();
    if command.trim().is_empty() {
        return Settled::Result(Some(keyset_error("a backend-hosted collector needs a command to run")));
    }
    // A backend reading its own `last` back may spell it as a number; both are accepted
    // rather than failing a cycle over a JSON type.
    let after = p.get("after").and_then(key_text);
    let limit = p
        .get("limit")
        .and_then(as_i64_loose)
        .filter(|n| *n > 0)
        .map(|n| n as usize)
        .unwrap_or(usize::MAX);
    let paged = !key.is_empty();
    if !paged && (after.is_some() || p.get("limit").is_some()) {
        return Settled::Result(Some(keyset_error(
            "a paged collector needs the key field that identifies a row; an ask with a cursor or a \
             page limit and no key is neither a cycle nor a bounded read",
        )));
    }
    let timeout_s = p
        .get("timeout_s")
        .and_then(as_i64_loose)
        .filter(|n| *n > 0)
        .map(|n| (n as u64).min(PS_RUN_HARD_MAX_SECS))
        .unwrap_or(PS_RUN_DEFAULT_SECS);
    let bound = match paged {
        true => Bound::Page,
        false => Bound::Run,
    };
    // A set assembled from N pages is N stamped moments, not one, and
    // a reader comparing two rows has to know which moment each came from.
    let collected_at = now_secs();
    let ask = hosted_ask(&p);

    if exec == "builtin" {
        return exec_builtin(command, timeout_s, &ask, job_id);
    }
    let rows = match exec {
        "powershell" => exec_powershell(command, timeout_s, bound, &ask, job_id, "the hosted command"),
        "native" => exec_native(command, timeout_s, bound, &ask, job_id),
        // An executor this client does not have is a REFUSAL. Returning an empty page instead would
        // read as "this machine has nothing", which is the failure the whole guard layer exists for.
        other => Err(ExecEnd::Refused(keyset_error(&format!("this client has no '{other}' executor")))),
    };
    Settled::Result(Some(match rows {
        // A whole RUN only. A page's bound ends its process and answers, so it never arrives here.
        Err(ExecEnd::OverTime) => return Settled::OverTime,
        Err(ExecEnd::Refused(e)) => e,
        Ok(rows) => match paged {
            true => keyset_page(rows, key, after.as_deref(), limit, collected_at),
            false => bounded_answer(rows, collected_at),
        },
    }))
}




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
                        "the hosted command needs '{name}', and the dispatch carried no single \
                         value for it — running with the argument dropped would be a different \
                         command from the one that was sent"
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

#[cfg(windows)]
fn exec_builtin(command: &str, timeout_s: u64, ask: &str, job_id: &str) -> Settled {
    let bound: Value = serde_json::from_str(ask).unwrap_or(Value::Null);
    let argv = match split_argv(command, &bound) {
        Ok(a) => a,
        Err(e) => return Settled::Result(Some(e)),
    };
    let Some((name, args)) = argv.split_first() else {
        return Settled::Result(Some(keyset_error("the hosted procedure is empty")));
    };
    // The unwrap matters: `hosted_params` names a NON-OBJECT ask `ask` so it cannot be dropped on the
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
    if name.as_str() == "script" {
        return run_script(p, timeout_s, job_id);
    }
    Settled::Result(Some(match name.as_str() {
        "disconnect" => disconnect_sessions(),
        "wol" => wol(p),
        "file-pull" => file_pull(p),
        "file-push" => file_push(p),
        "client-log" => client_log_pull(p),
        "client-logs" => client_logs_list(),
        "inventory" => inventory::collect(),
        "perf" => perf(p).unwrap_or_else(|| keyset_error(
            "the 'perf' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "fs" => fs_list(p).unwrap_or_else(|| keyset_error(
            "the 'fs' job produced no result (unsupported on this client/OS, or the collector failed)",
        )),
        "services" => services(),
        "job-runs" => runs::job_runs(),
        "job-kill" => runs::job_kill(p),
        other => keyset_error(&format!("this client has no '{other}' procedure")),
    }))
}


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
    // which `after:"9"` skips every pid from 10 to 99. Per-comparison fallback is not
    // even a total order on a mixed set, and any sort that disagrees with the cursor comparison loses
    // rows at the seam.
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
    // supposed to change.
    let mut h = Sha256::new();
    for (i, (text, _, _)) in keyed.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(text.as_bytes());
    }
    let set_hash = format!("{:x}", h.finalize());
    let after_num = match (numeric, after) {
        (true, Some(a)) => match a.trim().parse::<i128>() {
            Ok(n) => Some(n),
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
fn keyset_exec(_params: Option<&str>, _job_id: &str) -> Settled {
    Settled::Result(None)
}






































const JOB_CLAIM_ATTEMPTS: u32 = 3;

/// The console stops offering a job it has recorded as started, so this is what makes a run
/// at-most-once across a restart. [`JOBS_IN_FLIGHT`] cannot: it is process memory, and a job that
/// kills the client clears it while the row is still queued.
///
/// The claim is idempotent for the owning device: a lost response
/// leaves the row started, and asking again is granted rather than refused.
async fn claim_job(heartbeat_url: &str, device_id: &str, job_id: &str) -> bool {
    let url = format!("{}/api/device/jobs/{job_id}/claim", origin_of(heartbeat_url));
    for _ in 0..JOB_CLAIM_ATTEMPTS {
        // A fresh ts per attempt, so a retry cannot walk out of the console's ±5-minute window.
        let ts = now_secs();
        let msg = format!("CONSOLE-DEVICE-JOB-CLAIM\n{device_id}\n{job_id}\n{ts}");
        let body =
            json!({ "device_id": device_id, "ts": ts, "sig": sign_device_msg(&msg) }).to_string();
        match crate::post_request_timeout(
            url.clone(),
            body,
            "",
            crate::sulltec_remote::http::API_TIMEOUT_CONTROL,
        )
        .await
        {
            Ok(rsp) if rsp.trim() == "JOB_CLAIMED" => return true,
            // The row stopped being runnable: a cancel landed while the dispatch was in flight, or
            // it carries no delivery stamp.
            Ok(rsp) if rsp.trim() == "JOB_CLOSED" => {
                hbb_common::log::info!(
                    "console job {job_id}: the console refused the claim — the job is no longer \
                     runnable. NOT running it."
                );
                return false;
            }
            Ok(rsp) => {
                hbb_common::log::error!(
                    "console job {job_id}: claim refused ({:?}). NOT running it — the console has \
                     not recorded a start, so it still owns the row.",
                    rsp.chars().take(200).collect::<String>()
                );
                return false;
            }
            Err(e) => hbb_common::log::warn!("console job {job_id}: claim did not reach the console: {e}"),
        }
    }
    hbb_common::log::error!(
        "console job {job_id}: the console could not be reached to claim it after \
         {JOB_CLAIM_ATTEMPTS} tries. NOT running it here. The console will offer it again once the \
         hand-over grace expires."
    );
    false
}

/// Returns whether the CONSOLE STORED the answer. A refusal and a transport failure both answer
/// `false`, and they are different: only the refusal stamps the row reported. A caller about to
/// destroy the evidence it just reported needs the stored/not-stored fact, not the stamp.
async fn post_result(heartbeat_url: &str, device_id: &str, job_id: &str, status: &str, result: &str) -> bool {
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
    // Settled and refused both stamp the id as reported: a row the console has answered has nothing
    // left to hear, and leaving it unstamped would have `sweep_orphaned_results` re-post it on every
    // client start for a week. Only a transport failure leaves the stamp unset, because only then is
    // it still true that the console has not been told.
    match crate::post_request_timeout(url, body, "", crate::sulltec_remote::http::API_TIMEOUT_DATA).await {
        Ok(rsp) if rsp.trim() == "JOB_SETTLED" => {
            mark_job_reported(job_id);
            hbb_common::log::info!("console job {job_id} result posted ({status})");
            true
        }
        Ok(rsp) => {
            mark_job_reported(job_id);
            hbb_common::log::error!(
                "console job {job_id} result REFUSED by the console ({status}) — the work is done \
                 here and the console did not take the answer. Response: {:?}",
                rsp.chars().take(200).collect::<String>()
            );
            false
        }
        Err(e) => {
            hbb_common::log::error!("console job {job_id} result post failed: {e}");
            false
        }
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
        let (g, g_sk) = kp();
        let (k1, k1_sk) = kp();
        let (k2, _k2_sk) = kp();
        let s1 = hop(&g_sk, &k1);
        let s2 = hop(&k1_sk, &k2);
        let full = vec![e(&g, ""), e(&k1, &s1), e(&k2, &s2)];

        assert_eq!(resolve_trusted(&g, &full, None), k2);
        assert_eq!(resolve_trusted(&g, &full, Some((g.as_str(), k1.as_str()))), k2);

        let replay = vec![e(&g, ""), e(&k1, &s1)];
        assert_eq!(resolve_trusted(&g, &replay, Some((g.as_str(), k2.as_str()))), k2);

        assert_eq!(resolve_trusted(&g, &full, Some(("OTHER-ANCHOR", k2.as_str()))), k2);

        let bad = hop(&g_sk, &k2);
        let broken = vec![e(&g, ""), e(&k1, &s1), e(&k2, &bad)];
        assert_eq!(resolve_trusted(&g, &broken, None), k1);

        assert_eq!(resolve_trusted("UNSEEN", &full, None), "UNSEEN");
    }
}

#[cfg(test)]
mod package_verify_tests {
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

        assert!(verify_package(version, &sha, size, &sig));
        assert!(!verify_package("0.27.0", &sha, size, &sig));
        assert!(!verify_package(version, &"b".repeat(64), size, &sig));
        assert!(!verify_package(version, &sha, size + 1, &sig));
        assert!(!verify_package("", &sha, size, &sig));
        assert!(!verify_package(version, "", size, &sig));
        assert!(!verify_package(version, &sha, 0, &sig));
        assert!(!verify_package(version, &sha, size, ""));
        let (_pk2, sk2) = sign::gen_keypair();
        let sig2 = sign_pkg(&sk2, version, &sha, size);
        assert!(!verify_package(version, &sha, size, &sig2));

        *LOGON_TRUSTED.write().unwrap() = None;
    }
}








#[cfg(test)]
mod script_lint_tests {
    //! The collector scripts are built as ONE LINE: every line of the Rust literal ends with `\`,
    //! which removes the newline. A PowerShell `#` comment runs to the next newline — so a comment
    //! written with that trailing continuation swallows the entire rest of the script, and the
    //! collector dies with "Missing closing '}'" at runtime.

    #[test]
    fn no_powershell_comment_swallows_its_script() {
        let src = include_str!("jobs.rs");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                let e = l.trim_end();
                t.starts_with("# ") && e.ends_with('\\') && !e.ends_with("\\n\\")
            })
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "PowerShell comment(s) ending in a line-continuation — the comment will swallow the rest \
             of the one-line script. Drop the trailing backslash so the newline survives:\n{offenders:#?}"
        );

        let flags = |l: &str| {
            let (t, e) = (l.trim_start(), l.trim_end());
            t.starts_with("# ") && e.ends_with('\\') && !e.ends_with("\\n\\")
        };
        assert!(flags(r"         # this swallows the next line\"), "a bare trailing continuation MUST be flagged");
        assert!(!flags(r"         # this is fine\n\"), "an explicit \\n before the continuation is safe and must NOT be flagged");
    }
}

#[cfg(all(test, windows))]
mod ps_json_null_tests {
    use super::ps_json_or_none;
    use serde_json::json;

    #[test]
    fn json_null_is_not_a_value() {
        assert_eq!(ps_json_or_none(json!(null)), None);
    }

    #[test]
    fn every_other_shape_survives() {
        for v in [json!({}), json!([]), json!({"ok": false, "error": "x"}), json!(0), json!(false), json!("")] {
            assert_eq!(ps_json_or_none(v.clone()), Some(v.clone()), "{v} must not be swallowed");
        }
    }
}


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

    #[test]
    fn a_top_level_log_is_still_found_when_there_is_no_server_dir() {
        let dir = stage("legacy");
        std::fs::write(dir.join("sulltec-remote_rCURRENT.log"), b"old layout").ok();
        assert_eq!(main_log(&dir).and_then(|p| p.file_name().map(|f| f.to_owned())),
                   Some("sulltec-remote_rCURRENT.log".into()));
        std::fs::remove_dir_all(&dir).ok();
    }

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
    use super::{bounded_answer, key_text, keyset_exec, keyset_page, keyset_requested, Settled, PAGE_BUDGET};
    use serde_json::{json, Value};

    fn rows(pids: &[i64]) -> Vec<Value> {
        pids.iter().map(|p| json!({ "pid": p, "name": format!("p{p}") })).collect()
    }
    fn keys(page: &Value) -> Vec<i64> {
        page["items"].as_array().expect("items").iter().map(|r| r["pid"].as_i64().expect("pid")).collect()
    }

    #[test]
    fn a_numeric_key_sorts_and_resumes_numerically() {
        let page = keyset_page(rows(&[10, 9, 100, 2]), "pid", None, 10, 0);
        assert_eq!(keys(&page), vec![2, 9, 10, 100], "sorted numerically: {page}");
        assert_eq!(page["last"], json!("100"), "last is the final key, rendered: {page}");
        let after_9 = keyset_page(rows(&[10, 9, 100, 2]), "pid", Some("9"), 10, 0);
        assert_eq!(keys(&after_9), vec![10, 100], "after is exclusive AND numeric: {after_9}");
    }

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

    #[test]
    fn a_row_without_the_key_fails_the_page_rather_than_vanishing() {
        let page = keyset_page(vec![json!({ "pid": 1 }), json!({ "name": "orphan" })], "pid", None, 10, 0);
        assert_eq!(page["ok"], json!(false), "{page}");
        assert!(page["error"].as_str().is_some_and(|e| e.contains("pid")), "and it names the key: {page}");
    }

    #[test]
    fn an_empty_set_is_ok_and_complete() {
        let page = keyset_page(Vec::new(), "pid", None, 10, 0);
        assert_eq!(page["ok"], json!(true), "{page}");
        assert_eq!(page["count"], json!(0), "{page}");
        assert_eq!(page["total"], json!(0), "{page}");
        assert_eq!(page["more"], json!(false), "{page}");
        assert!(page.get("last").is_none(), "nothing to resume from: {page}");
    }

    #[test]
    fn only_a_non_empty_exec_selects_the_hosted_path() {
        assert!(!keyset_requested(None));
        assert!(!keyset_requested(Some("{}")));
        assert!(!keyset_requested(Some(r#"{"limit":500}"#)), "the old params must still fall through");
        assert!(!keyset_requested(Some(r#"{"exec":"  "}"#)));
        assert!(!keyset_requested(Some("not json")));
        assert!(keyset_requested(Some(r#"{"exec":"powershell","command":"x","key":"pid"}"#)));
    }

    #[test]
    fn an_unknown_executor_and_a_missing_param_both_refuse() {
        let Settled::Result(Some(v)) = keyset_exec(Some(r#"{"exec":"wmi","command":"select * from x","key":"id"}"#), "")
        else {
            panic!("a result")
        };
        assert_eq!(v["ok"], json!(false), "{v}");
        assert!(v["error"].as_str().is_some_and(|e| e.contains("wmi")), "{v}");
        let Settled::Result(Some(no_cmd)) = keyset_exec(Some(r#"{"exec":"powershell","key":"pid"}"#), "") else {
            panic!("a result")
        };
        assert_eq!(no_cmd["ok"], json!(false), "{no_cmd}");
        for contradiction in [
            r#"{"exec":"powershell","command":"x","after":"9"}"#,
            r#"{"exec":"powershell","command":"x","limit":10}"#,
        ] {
            let Settled::Result(Some(v)) = keyset_exec(Some(contradiction), "") else {
                panic!("a result")
            };
            assert_eq!(v["ok"], json!(false), "{v}");
            assert!(v["error"].as_str().is_some_and(|e| e.contains("key")), "{v}");
        }
    }

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
        let wide: Vec<Value> =
            (1..=200).map(|p| json!({ "pid": p, "blob": "x".repeat(2000) })).collect();
        let cut = bounded_answer(wide, 0);
        assert_eq!(cut["truncated"], json!(true), "{cut}");
        assert_eq!(cut["total"], json!(200), "{cut}");
        assert!(cut["count"].as_u64().is_some_and(|n| n > 0 && n < 200), "{cut}");
    }

    #[test]
    fn a_key_renders_the_way_the_cursor_spells_it() {
        assert_eq!(key_text(&json!(1234)), Some("1234".to_owned()));
        assert_eq!(key_text(&json!("spooler")), Some("spooler".to_owned()));
        assert_eq!(key_text(&json!(null)), None, "null is not an identity");
        assert_eq!(key_text(&json!([1])), None, "nor is a list");
    }
}

/// ⚠ **`None` here means the read FAILED — a caller must never let it reach the wire.** This runner
/// is unguarded, so it cannot distinguish a script that died from one that legitimately produced
/// nothing; either way the output is unparseable, and a collector that returns bare `None` sends
/// `result: null` beside `status:"done"` with no error. Convert it with
/// `.or_else(|| Some(json!({ "ok": false, "error": … })))`.
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

/// `ConvertTo-Json` renders `$null` as the literal `null`, which `serde_json` parses happily into
/// `Some(Value::Null)`. That slips past every `unwrap_or_else(|| error)` a caller wrote — those only
/// fire on `None` — and lands on the wire as `result: null` beside `status:"done"` with no error,
/// incorrectly presenting missing data as success.
#[cfg(windows)]
fn ps_json_or_none(v: Value) -> Option<Value> {
    match v.is_null() {
        true => None,
        false => Some(v),
    }
}

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
            if let Ok(start) = svc.get_value::<u32, _>("Start") {
                let delayed = svc.get_value::<u32, _>("DelayedAutostart").unwrap_or(0) == 1;
                // Windows
                // starts a trigger-start service on demand and lets it idle back to Stopped, so an automatic
                // service sitting Stopped is its designed state, not a failure.
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

/// Despite the `PS_` prefix, this and the max below apply to `native` runs too.
const PS_RUN_DEFAULT_SECS: u64 = 3600;

/// ⚠ Kept in lockstep with the backend's `DEVICE_RUN_HARD_MAX_SECS`, which refuses an
/// over-declaration at mount rather than letting it be truncated here in silence.
const PS_RUN_HARD_MAX_SECS: u64 = 6 * 3600;

/// Normally instant — the
/// readers drain concurrently and EOF arrives with the exit — so this only ever elapses when a
/// descendant inherited a pipe and is still holding it. ⚠ Shared: `run_argv_within` drains on the
/// same grace period, which is the other half of why this is not in `command_powershell`.
const PS_DRAIN_GRACE_SECS: u64 = 30;
