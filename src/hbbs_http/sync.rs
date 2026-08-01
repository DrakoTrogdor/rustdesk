use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(not(any(target_os = "ios")))]
use crate::{ui_interface::get_builtin_option, Connection};
use hbb_common::{
    config::{self, keys, Config, LocalConfig},
    log,
    tokio::{self, sync::broadcast, time::Instant},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const TIME_HEARTBEAT: Duration = Duration::from_secs(15);
const UPLOAD_SYSINFO_TIMEOUT: Duration = Duration::from_secs(120);
const TIME_CONN: Duration = Duration::from_secs(3);

#[cfg(not(any(target_os = "ios")))]
lazy_static::lazy_static! {
    static ref SENDER : Mutex<broadcast::Sender<Vec<i32>>> = Mutex::new(start_hbbs_sync());
    static ref PRO: Arc<Mutex<bool>> = Default::default();
}

#[cfg(not(any(target_os = "ios")))]
pub fn start() {
    let _sender = SENDER.lock().unwrap();
}

#[cfg(not(target_os = "ios"))]
pub fn signal_receiver() -> broadcast::Receiver<Vec<i32>> {
    SENDER.lock().unwrap().subscribe()
}

#[cfg(not(any(target_os = "ios")))]
fn start_hbbs_sync() -> broadcast::Sender<Vec<i32>> {
    let (tx, _rx) = broadcast::channel::<Vec<i32>>(16);
    std::thread::spawn(move || start_hbbs_sync_async());
    return tx;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StrategyOptions {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config_options: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

struct InfoUploaded {
    uploaded: bool,
    url: String,
    last_uploaded: Option<Instant>,
    id: String,
    username: Option<String>,
}

impl Default for InfoUploaded {
    fn default() -> Self {
        Self {
            uploaded: false,
            url: "".to_owned(),
            last_uploaded: None,
            id: "".to_owned(),
            username: None,
        }
    }
}

impl InfoUploaded {
    fn uploaded(url: String, id: String, username: String) -> Self {
        Self {
            uploaded: true,
            url,
            last_uploaded: None,
            id,
            username: Some(username),
        }
    }
}

#[cfg(not(any(target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn start_hbbs_sync_async() {
    let mut interval = crate::rustdesk_interval(tokio::time::interval_at(
        Instant::now() + TIME_CONN,
        TIME_CONN,
    ));
    let mut last_sent: Option<Instant> = None;
    let mut info_uploaded = InfoUploaded::default();
    let mut sysinfo_ver = "".to_owned();
    // SullTec console: consecutive heartbeat POST failures. The heartbeat RESPONSE is the only
    // channel carrying console->client work (`check_update`, `jobs`, snapshot asks, policy), and
    // it runs over the API port (21114) — a different path from rendezvous (21115/21116). So a
    // client that cannot POST goes completely inert while still showing ONLINE in the console,
    // and the operator sees a device that simply ignores every request. Counted here so the log
    // says that out loud instead of leaving it to be inferred.
    let mut heartbeat_failures: u32 = 0;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let url = heartbeat_url();
                let id = Config::get_id();
                if url.is_empty() {
                    *PRO.lock().unwrap() = false;
                    continue;
                }
                if config::option2bool("stop-service", &Config::get_option("stop-service")) {
                    continue;
                }
                let conns = Connection::alive_conns();
                if info_uploaded.uploaded && (url != info_uploaded.url || id != info_uploaded.id) {
                    info_uploaded.uploaded = false;
                    *PRO.lock().unwrap() = false;
                }
                // For Windows:
                // We can't skip uploading sysinfo when the username is empty, because the username may
                // always be empty before login. We also need to upload the other sysinfo info.
                //
                // https://github.com/rustdesk/rustdesk/discussions/8031
                // We still need to check the username after uploading sysinfo, because
                // 1. The username may be empty when logining in, and it can be fetched after a while.
                //    In this case, we need to upload sysinfo again.
                // 2. The username may be changed after uploading sysinfo, and we need to upload sysinfo again.
                //
                // The Windows session will switch to the last user session before the restart,
                // so it may be able to get the username before login.
                // But strangely, sometimes we can get the username before login,
                // we may not be able to get the username before login after the next restart.
                let mut v = crate::get_sysinfo();
                let sys_username = v["username"].as_str().unwrap_or_default().to_string();
                // Though the username comparison is only necessary on Windows,
                // we still keep the comparison on other platforms for consistency.
                let need_upload = (!info_uploaded.uploaded || info_uploaded.username.as_ref() != Some(&sys_username)) &&
                    info_uploaded.last_uploaded.map(|x| x.elapsed() >= UPLOAD_SYSINFO_TIMEOUT).unwrap_or(true);
                if need_upload {
                    // SullTec: report the console-aligned product version so the console UI
                    // shows a number matching its own; the RustDesk protocol version still
                    // rides the heartbeat `ver` field (numeric, below) for hbbs strategy.
                    v["version"] = json!(crate::SULLTEC_VERSION);
                    v["id"] = json!(id);
                    v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                    let ab_name = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NAME);
                    if !ab_name.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_NAME] = json!(ab_name);
                    }
                    let ab_tag = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_TAG);
                    if !ab_tag.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_TAG] = json!(ab_tag);
                    }
                    let ab_alias = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS);
                    if !ab_alias.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS] = json!(ab_alias);
                    }
                    let ab_password = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD);
                    if !ab_password.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_PASSWORD] = json!(ab_password);
                    }
                    let ab_note = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NOTE);
                    if !ab_note.is_empty() {
                        v[keys::OPTION_PRESET_ADDRESS_BOOK_NOTE] = json!(ab_note);
                    }
                    let username = get_builtin_option(keys::OPTION_PRESET_USERNAME);
                    if !username.is_empty() {
                        v[keys::OPTION_PRESET_USERNAME] = json!(username);
                    }
                    let strategy_name = get_builtin_option(keys::OPTION_PRESET_STRATEGY_NAME);
                    if !strategy_name.is_empty() {
                        v[keys::OPTION_PRESET_STRATEGY_NAME] = json!(strategy_name);
                    }
                    let device_group_name = get_builtin_option(keys::OPTION_PRESET_DEVICE_GROUP_NAME);
                    if !device_group_name.is_empty() {
                        v[keys::OPTION_PRESET_DEVICE_GROUP_NAME] = json!(device_group_name);
                    }
                    let device_username = Config::get_option(keys::OPTION_PRESET_DEVICE_USERNAME);
                    if !device_username.is_empty() {
                        v["username"] = json!(device_username);
                    }
                    let device_name = Config::get_option(keys::OPTION_PRESET_DEVICE_NAME);
                    if !device_name.is_empty() {
                        v["hostname"] = json!(device_name);
                    }
                    let note = Config::get_option(keys::OPTION_PRESET_NOTE);
                    if !note.is_empty() {
                        v[keys::OPTION_PRESET_NOTE] = json!(note);
                    }
                    // SullTec: sign the AD identity so the console can bind domain/OU/tenant to this
                    // machine's enrolled key. The ingest tier is unauthenticated, so the console drops
                    // an AD report whose signature doesn't match the pinned key — stopping a rogue that
                    // knows the device id from spoofing its tenant/grouping. No-op off-domain.
                    if let Some(adsig) = crate::console_jobs::sign_sysinfo(&v) {
                        v["adsig"] = json!(adsig);
                    }
                    let v = v.to_string();
                    let mut hash = "".to_owned();
                    if crate::is_public(&url) {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(url.as_bytes());
                        hasher.update(&v.as_bytes());
                        let res = hasher.finalize();
                        hash = hbb_common::base64::encode(&res[..]);
                        let old_hash = config::Status::get("sysinfo_hash");
                        let ver = config::Status::get("sysinfo_ver"); // sysinfo_ver is the version of sysinfo on server's side
                        if hash == old_hash {
                            // When the api doesn't exist, Ok("") will be returned in test.
                            let samever = match crate::post_request(url.replace("heartbeat", "sysinfo_ver"), "".to_owned(), "").await {
                                Ok(x)  => {
                                    sysinfo_ver = x.clone();
                                    *PRO.lock().unwrap() = true;
                                    x == ver
                                }
                                _ => {
                                    false // to make sure Pro can be assigned in below post for old
                                            // hbbs pro not supporting sysinfo_ver, use false for ensuring
                                }
                            };
                            if samever {
                                info_uploaded = InfoUploaded::uploaded(url.clone(), id.clone(), sys_username);
                                log::info!("sysinfo not changed, skip upload");
                                continue;
                            }
                        }
                    }
                    // Data plane: the full sysinfo blob is a bulk upload, not a heartbeat.
                    match crate::post_request_timeout(
                        url.replace("heartbeat", "sysinfo"),
                        v,
                        "",
                        crate::API_TIMEOUT_DATA,
                    )
                    .await
                    {
                        Ok(x)  => {
                            if x == "SYSINFO_UPDATED" {
                                info_uploaded = InfoUploaded::uploaded(url.clone(), id.clone(), sys_username);
                                log::info!("sysinfo updated");
                                if !hash.is_empty() {
                                    config::Status::set("sysinfo_hash", hash);
                                    config::Status::set("sysinfo_ver", sysinfo_ver.clone());
                                }
                                *PRO.lock().unwrap() = true;
                            } else if x == "ID_NOT_FOUND" {
                                info_uploaded.last_uploaded = None; // next heartbeat will upload sysinfo again
                            } else {
                                info_uploaded.last_uploaded = Some(Instant::now());
                            }
                        }
                        _ => {
                            info_uploaded.last_uploaded = Some(Instant::now());
                        }
                    }
                }
                if conns.is_empty() && last_sent.map(|x| x.elapsed() < TIME_HEARTBEAT).unwrap_or(false) {
                    continue;
                }
                last_sent = Some(Instant::now());
                let mut v = Value::default();
                v["id"] = json!(id);
                v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                v["ver"] = json!(hbb_common::get_version_number(crate::VERSION));
                // SullTec D2: report the logon key we currently trust so the console can show whether
                // passwordless logon will actually work for this device (current/stale/no-key).
                v["logon_pub"] = json!(crate::console_jobs::current_logon_pubkey());
                // ...and the anchor COMPILED INTO THIS BUILD, which is a different question. The
                // trusted key moves as the rotation chain is walked forward; the anchor never does.
                // Chain resolution restarts from the anchor every heartbeat, so the anchor — not the
                // trusted key — is what decides whether a device survives the chain being pruned.
                // Without this the console can see what the fleet trusts but not what it can prune.
                v["logon_anchor"] = json!(crate::console_jobs::baked_logon_pubkey());
                if !conns.is_empty() {
                    v["conns"] = json!(conns);
                }
                let modified_at = LocalConfig::get_option("strategy_timestamp").parse::<i64>().unwrap_or(0);
                v["modified_at"] = json!(modified_at);
                // SullTec console (S2 Phase 2): sign the heartbeat body with our pinned device key so
                // the console can verify it (`X-ST-Sig`, the SAME scheme + key as the inventory/snapshot
                // ingest). The identical bytes are signed and sent. Stock servers ignore the header; the
                // console verifies it and — only once enforcement is enabled — withholds queued jobs +
                // pushed policy from an unsigned/forged beat for a device that has signed before.
                let body = v.to_string();
                let sig_header = crate::console_jobs::sign_header(&body);
                let heartbeat = crate::post_request(url.clone(), body, &sig_header).await;
                match &heartbeat {
                    Err(err) => {
                        heartbeat_failures += 1;
                        // First failure, then every 10th, so a long outage does not flood the log
                        // but also never goes fully quiet.
                        if heartbeat_failures == 1 || heartbeat_failures % 10 == 0 {
                            log::warn!(
                                "heartbeat POST failed ({} consecutive): {:?} — console requests \
                                 (update checks, jobs, policy) are NOT being received; rendezvous \
                                 is unaffected so this device still appears online",
                                heartbeat_failures,
                                err
                            );
                        }
                    }
                    Ok(_) if heartbeat_failures > 0 => {
                        log::info!(
                            "heartbeat recovered after {} consecutive failure(s)",
                            heartbeat_failures
                        );
                        heartbeat_failures = 0;
                    }
                    Ok(_) => {}
                }
                if let Ok(s) = heartbeat {
                    if let Ok(mut rsp) = serde_json::from_str::<HashMap::<&str, Value>>(&s) {
                        if rsp.remove("sysinfo").is_some() {
                            info_uploaded.uploaded = false;
                            config::Status::set("sysinfo_hash", "".to_owned());
                            log::info!("sysinfo required to forcely update");
                        }
                        // SullTec console: the server answers the heartbeat with this key
                        // when its stored hw/sw inventory for us is stale (or an operator
                        // pressed Refresh). Stock servers never send it. Upload runs in the
                        // background so a slow collection can't stall the heartbeat loop.
                        if rsp.remove("inventory").is_some() {
                            log::info!("inventory requested by server");
                            crate::console_inventory::upload(url.clone(), id.clone());
                        }
                        // SullTec console: live process/service snapshots, requested only
                        // while an operator is viewing them (cleared after one heartbeat,
                        // re-asked by the console's refresh/timer). Same background upload.
                        if rsp.remove("processes").is_some() {
                            crate::console_snapshot::upload(url.clone(), id.clone(), "processes");
                        }
                        if rsp.remove("services").is_some() {
                            crate::console_snapshot::upload(url.clone(), id.clone(), "services");
                        }
                        // SullTec console: Microsoft Defender status (endpoint security panel).
                        if rsp.remove("defender").is_some() {
                            crate::console_snapshot::upload(url.clone(), id.clone(), "defender");
                        }
                        // SullTec console: Windows Update list (OS patch panel; slow WU search).
                        if rsp.remove("winupdate").is_some() {
                            crate::console_snapshot::upload(url.clone(), id.clone(), "winupdate");
                        }
                        // SullTec console: Group-Policy health (RSoP posture for fleet-health).
                        // NOTE: `policy` is the snapshot REQUEST; the settings-lockdown push is the
                        // separate `policy_push` key below. They collided on `policy` from 0.9.2 (which
                        // added this snapshot kind) until 0.25.0: because this arm removes the key
                        // before the apply arm ever reads it, the push was consumed here — uploading a
                        // snapshot on every heartbeat instead of daily, while the lockdown silently
                        // stopped applying and released its locks every beat. Keep the two keys
                        // distinct, and treat this response as a flat namespace shared by separate
                        // features: a new key must be checked against every existing consumer.
                        if rsp.remove("policy").is_some() {
                            crate::console_snapshot::upload(url.clone(), id.clone(), "policy");
                        }
                        // SullTec console: operator queued a client-update push. Force an
                        // immediate check+install (compares against /version/latest, so it
                        // no-ops unless the console target is newer).
                        if rsp.remove("check_update").is_some() {
                            log::info!("update check requested by server");
                            crate::updater::force_check_update_now();
                        }
                        // SullTec console: client-native job channel (EXTENSION-PLAN D). Pin our
                        // Ed25519 key (once, TOFU), then verify the console's signature over the
                        // delivered jobs (`jobs_sig`/`jobs_ts`, anchored on the logon key) before
                        // running them — each posting a signed result the console verifies against
                        // our pinned key.
                        crate::console_jobs::ensure_enrolled(&url, &id);
                        if let Some(jobs) = rsp.remove("jobs") {
                            crate::console_jobs::run(
                                url.clone(),
                                id.clone(),
                                jobs,
                                rsp.remove("jobs_sig"),
                                rsp.remove("jobs_ts"),
                            );
                        }
                        // SullTec console: key-pair logon rotation chain (§B instant rotation).
                        // Walk it from our baked anchor and adopt the current logon key with no
                        // rebuild; absent (no rotation yet) leaves the baked anchor in force.
                        crate::console_jobs::update_logon_chain(rsp.remove("logon_chain"));
                        // SullTec console: client policy (GPO-style settings lockdown). Apply + lock
                        // the settings the console pushed (verified against our trusted logon key);
                        // an absent/empty policy releases any locks we hold. Reads `policy_push` —
                        // see the note on the `policy` snapshot arm above for why these are separate.
                        crate::console_jobs::apply_policy(rsp.remove("policy_push"));
                        if let Some(conns)  = rsp.remove("disconnect") {
                                if let Ok(conns) = serde_json::from_value::<Vec<i32>>(conns) {
                                    SENDER.lock().unwrap().send(conns).ok();
                                }
                        }
                        if let Some(rsp_modified_at) = rsp.remove("modified_at") {
                            if let Ok(rsp_modified_at) = serde_json::from_value::<i64>(rsp_modified_at) {
                                if rsp_modified_at != modified_at {
                                    LocalConfig::set_option("strategy_timestamp".to_string(), rsp_modified_at.to_string());
                                }
                            }
                        }
                        if let Some(strategy) = rsp.remove("strategy") {
                            if let Ok(strategy) = serde_json::from_value::<StrategyOptions>(strategy) {
                                log::info!("strategy updated");
                                handle_config_options(strategy.config_options);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn heartbeat_url() -> String {
    let url = crate::common::get_api_server(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    );
    if url.is_empty() || crate::is_public(&url) {
        return "".to_owned();
    }
    format!("{}/api/heartbeat", url)
}

fn handle_config_options(config_options: HashMap<String, String>) {
    let mut options = Config::get_options();
    let default_settings = config::DEFAULT_SETTINGS.read().unwrap().clone();
    config_options
        .iter()
        .map(|(k, v)| {
            // Priority: user config > default advanced options.
            // Only when default advanced options are also empty, remove user option (fallback to built-in default);
            // otherwise insert an empty value so user config remains present.
            if v.is_empty() && default_settings.get(k).map_or("", |v| v).is_empty() {
                options.remove(k);
            } else {
                options.insert(k.to_string(), v.to_string());
            }
        })
        .count();
    Config::set_options(options);
}

#[allow(unused)]
#[cfg(not(any(target_os = "ios")))]
pub fn is_pro() -> bool {
    PRO.lock().unwrap().clone()
}
