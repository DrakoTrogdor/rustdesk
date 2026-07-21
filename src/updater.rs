use crate::{common::do_check_software_update, hbbs_http::create_http_client_with_url};
use hbb_common::{bail, config, log, ResultType};
use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    time::{Duration, Instant},
};

enum UpdateMsg {
    CheckUpdate,
    Exit,
}

lazy_static::lazy_static! {
    static ref TX_MSG : Mutex<Sender<UpdateMsg>> = Mutex::new(start_auto_update_check());
}

static CONTROLLING_SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);

const DUR_ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

pub fn update_controlling_session_count(count: usize) {
    CONTROLLING_SESSION_COUNT.store(count, Ordering::SeqCst);
}

#[allow(dead_code)]
pub fn start_auto_update() {
    let _sender = TX_MSG.lock().unwrap();
}

#[allow(dead_code)]
pub fn manually_check_update() -> ResultType<()> {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::CheckUpdate)?;
    Ok(())
}

#[allow(dead_code)]
pub fn stop_auto_update() {
    let sender = TX_MSG.lock().unwrap();
    sender.send(UpdateMsg::Exit).unwrap_or_default();
}

/// SullTec console: force an immediate update check+install, bypassing the auto-update
/// daily interval and the `allow-auto-update` gate (treated as a manual check). Triggered
/// by the console via the `check_update` heartbeat key. `check_update` itself still
/// compares against `/version/latest` (installs only if the console target is newer) and
/// refuses while there are active connections, so this is safe to call unconditionally.
#[allow(dead_code)]
pub fn force_check_update_now() {
    std::thread::spawn(|| {
        if let Err(e) = check_update(true) {
            log::error!("forced update check failed: {e}");
        }
    });
}

#[inline]
fn has_no_active_conns() -> bool {
    let conns = crate::Connection::alive_conns();
    conns.is_empty() && has_no_controlling_conns()
}

#[cfg(any(not(target_os = "windows"), feature = "flutter"))]
fn has_no_controlling_conns() -> bool {
    CONTROLLING_SESSION_COUNT.load(Ordering::SeqCst) == 0
}

#[cfg(not(any(not(target_os = "windows"), feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    let app_exe = format!("{}.exe", crate::get_app_name().to_lowercase());
    for arg in [
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ] {
        if !crate::platform::get_pids_of_process_with_first_arg(&app_exe, arg).is_empty() {
            return false;
        }
    }
    true
}

fn start_auto_update_check() -> Sender<UpdateMsg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || start_auto_update_check_(rx));
    return tx;
}

fn start_auto_update_check_(rx_msg: Receiver<UpdateMsg>) {
    std::thread::sleep(Duration::from_secs(30));
    if let Err(e) = check_update(false) {
        log::error!("Error checking for updates: {}", e);
    }

    const MIN_INTERVAL: Duration = Duration::from_secs(60 * 10);
    const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 30);
    let mut last_check_time = Instant::now();
    let mut check_interval = DUR_ONE_DAY;
    loop {
        let recv_res = rx_msg.recv_timeout(check_interval);
        match &recv_res {
            Ok(UpdateMsg::CheckUpdate) | Err(_) => {
                if last_check_time.elapsed() < MIN_INTERVAL {
                    // log::debug!("Update check skipped due to minimum interval.");
                    continue;
                }
                // Don't check update if there are alive connections.
                if !has_no_active_conns() {
                    check_interval = RETRY_INTERVAL;
                    continue;
                }
                if let Err(e) = check_update(matches!(recv_res, Ok(UpdateMsg::CheckUpdate))) {
                    log::error!("Error checking for updates: {}", e);
                    check_interval = RETRY_INTERVAL;
                } else {
                    last_check_time = Instant::now();
                    check_interval = DUR_ONE_DAY;
                }
            }
            Ok(UpdateMsg::Exit) => break,
        }
    }
}

fn check_update(manually: bool) -> ResultType<()> {
    #[cfg(target_os = "windows")]
    // SullTec: a portable/service install may have no `Uninstall\<app>` registry key, so
    // is_msi_installed() errors (open_subkey on a missing key). Propagating that `?` aborted the
    // ENTIRE update check before it ever queried /version/latest — silently breaking
    // console-driven updates for every such client. Treat an error as "not MSI" (false).
    let update_msi = crate::platform::is_msi_installed().unwrap_or(false) && !crate::is_custom_client();
    if !(manually || config::Config::get_bool_option(config::keys::OPTION_ALLOW_AUTO_UPDATE)) {
        return Ok(());
    }
    if do_check_software_update().is_err() {
        // ignore
        return Ok(());
    }

    let update_url = crate::common::SOFTWARE_UPDATE_URL.lock().unwrap().clone();
    if update_url.is_empty() {
        log::debug!("No update available.");
    } else {
        let download_url = update_url.replace("tag", "download");
        let version = download_url.split('/').last().unwrap_or_default();
        #[cfg(target_os = "windows")]
        let download_url = if cfg!(feature = "flutter") {
            format!(
                "{}/rustdesk-{}-x86_64.{}",
                download_url,
                version,
                if update_msi { "msi" } else { "exe" }
            )
        } else {
            format!("{}/rustdesk-{}-x86-sciter.exe", download_url, version)
        };
        log::debug!("New version available: {}", &version);
        let client = create_http_client_with_url(&download_url);
        let Some(file_path) = get_download_file_from_url(&download_url) else {
            bail!("Failed to get the file path from the URL: {}", download_url);
        };
        // SullTec: ask for the total size FIRST — it decides all three cases (already have it,
        // resume a partial, start fresh). Previously the size was only fetched when a file
        // already existed, and any partial was DELETED, so every retry restarted from zero.
        // On a slow link that meant a transfer interrupted at 23 MB threw away 23 MB, which is
        // why repeated pushes never converged for the WiMAX site.
        let response = client.head(&download_url).send()?;
        if !response.status().is_success() {
            bail!("Failed to get the file size: {}", response.status());
        }
        let total_size = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|ct_len| ct_len.to_str().ok())
            .and_then(|ct_len| ct_len.parse::<u64>().ok());
        let Some(total_size) = total_size else {
            bail!("Failed to get content length");
        };
        let have = std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);
        if have != total_size {
            download_package(&download_url, &file_path, have, total_size)?;
        }
        // We have checked if the `conns` is empty before, but we need to check again.
        // No need to care about the downloaded file here, because it's rare case that the `conns` are empty
        // before the download, but not empty after the download.
        if has_no_active_conns() {
            #[cfg(target_os = "windows")]
            update_new_version(update_msi, &version, &file_path);
        }
    }
    Ok(())
}

/// SullTec: fetch the update package to `file_path`, resuming from `have` bytes if a partial
/// download is already there.
///
/// Two fixes over the original inline code:
///
/// * **Streams to disk** (`std::io::copy` over the `Read` impl) instead of `response.bytes()`,
///   which materialised the whole package in RAM before writing a byte — 24 MB on a domain
///   controller, and the single call whose failure produced the bare `error decoding response
///   body`.
/// * **Resumes** via `Range:` so an interrupted transfer keeps its progress. If the server
///   answers `200` instead of `206` it does not support ranges, so we start over rather than
///   append and corrupt the file.
///
/// Errors carry the URL, the byte counts and the status — the original reported none of them,
/// which is what made this failure invisible on the affected clients.
fn download_package(url: &str, file_path: &PathBuf, have: u64, total: u64) -> ResultType<()> {
    let client = crate::hbbs_http::create_download_client_with_url(url);
    let resume = have > 0 && have < total;
    let mut req = client.get(url);
    if resume {
        req = req.header(reqwest::header::RANGE, format!("bytes={have}-"));
        log::info!("resuming update download at {have}/{total} bytes: {url}");
    } else {
        log::info!("downloading update ({total} bytes): {url}");
    }

    let mut response = req
        .send()
        .map_err(|e| hbb_common::anyhow::anyhow!("update download failed to start ({url}): {e}"))?;
    if !response.status().is_success() {
        bail!(
            "Failed to download the new version file: {} ({url})",
            response.status()
        );
    }

    // 206 = our range was honoured, so append. Anything else is a full body: truncate first,
    // otherwise a resumed request answered with 200 would double-write the file.
    let appending = resume && response.status() == reqwest::StatusCode::PARTIAL_CONTENT;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(appending)
        .truncate(!appending)
        .open(file_path)?;
    let copied = std::io::copy(&mut response, &mut file).map_err(|e| {
        let at = if appending { have } else { 0 };
        hbb_common::anyhow::anyhow!(
            "update download interrupted after {at} + partial of {total} bytes ({url}): {e}"
        )
    })?;
    file.flush()?;
    drop(file);

    let got = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    if got != total {
        // Leave the partial in place: the next attempt resumes from it.
        bail!("update download incomplete: have {got} of {total} bytes ({url}), wrote {copied}");
    }
    log::info!("update package downloaded: {got} bytes");
    Ok(())
}

#[cfg(target_os = "windows")]
fn update_new_version(update_msi: bool, version: &str, file_path: &PathBuf) {
    log::debug!(
        "New version is downloaded, update begin, update msi: {update_msi}, version: {version}, file: {:?}",
        file_path.to_str()
    );
    if let Some(p) = file_path.to_str() {
        if let Some(session_id) = crate::platform::get_current_process_session_id() {
            if update_msi {
                match crate::platform::update_me_msi(p, true) {
                    Ok(_) => {
                        log::debug!("New version \"{}\" updated.", version);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to install the new msi version  \"{}\": {}",
                            version,
                            e
                        );
                        std::fs::remove_file(&file_path).ok();
                    }
                }
            } else {
                let custom_client_staging_dir = if crate::is_custom_client() {
                    let custom_client_staging_dir =
                        crate::platform::get_custom_client_staging_dir();
                    if let Err(e) = crate::platform::handle_custom_client_staging_dir_before_update(
                        &custom_client_staging_dir,
                    ) {
                        log::error!(
                            "Failed to handle custom client staging dir before update: {}",
                            e
                        );
                        std::fs::remove_file(&file_path).ok();
                        return;
                    }
                    Some(custom_client_staging_dir)
                } else {
                    // Clean up any residual staging directory from previous custom client
                    let staging_dir = crate::platform::get_custom_client_staging_dir();
                    hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(
                        &staging_dir
                    ));
                    None
                };
                // Preferred path: launch `--update` into the active interactive session by borrowing
                // winlogon's token (so the update UI/toast can show). This is what desktops use.
                let launched_interactive = match crate::platform::launch_privileged_process(
                    session_id,
                    &format!("{} --update", p),
                ) {
                    Ok(h) if !h.is_null() => {
                        log::debug!("New version \"{}\" is launched.", version);
                        true
                    }
                    Ok(_) => {
                        // Null handle = no winlogon in the target session (headless server, nobody
                        // logged in at the console). Not fatal on a service install — see the fallback.
                        log::error!("Privileged launch returned no handle (no interactive session / winlogon)");
                        false
                    }
                    Err(e) => {
                        log::error!("Failed to run the new version: {}", e);
                        false
                    }
                };
                // Headless-server fallback: when the interactive launch can't land (no console user)
                // BUT we are the LocalSystem service, apply the update directly — its steps
                // (sc stop / taskkill / copy exe / reg / sc start, see `update_me`) are all valid from
                // session 0, and a detached `--update` process survives the service stop+restart, so
                // the self-update completes with no one logged in. Interactive installs (desktops)
                // never reach here — the launch above succeeds — so the working path is unchanged.
                let update_launched = if launched_interactive {
                    true
                } else if crate::platform::is_root() {
                    log::info!("No interactive session for --update; applying update directly from the service (session 0).");
                    match crate::platform::run_exe_direct(p, vec!["--update"], false) {
                        Ok(_) => true,
                        Err(e) => {
                            log::error!("Direct session-0 --update failed: {}", e);
                            false
                        }
                    }
                } else {
                    log::error!("Failed to update to the new version: {}", version);
                    false
                };
                if !update_launched {
                    if let Some(dir) = custom_client_staging_dir {
                        hbb_common::allow_err!(crate::platform::remove_custom_client_staging_dir(
                            &dir
                        ));
                    }
                    std::fs::remove_file(&file_path).ok();
                }
            }
        } else {
            log::error!(
                "Failed to get the current process session id, Error {}",
                std::io::Error::last_os_error()
            );
            std::fs::remove_file(&file_path).ok();
        }
    } else {
        // unreachable!()
        log::error!(
            "Failed to convert the file path to string: {}",
            file_path.display()
        );
    }
}

pub fn get_download_file_from_url(url: &str) -> Option<PathBuf> {
    let filename = url.split('/').last()?;
    Some(std::env::temp_dir().join(filename))
}
