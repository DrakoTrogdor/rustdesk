//! The console-driven update mechanism.
//!
//! Upstream's `updater.rs` decides *when* to check and hands off to the installer; this module
//! owns the parts the fork added around it — the forced check the console triggers over the
//! heartbeat, the resumable streaming download, and the signature/hash verification of the
//! package before it is run.
//!
//! Kept here rather than in `updater.rs` so the upstream file carries call sites and not logic.

use hbb_common::{bail, log, ResultType};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static UPDATE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// SullTec console: force an immediate update check+install, bypassing the auto-update
/// daily interval and the `allow-auto-update` gate (treated as a manual check). Triggered
/// by the console via the `check_update` heartbeat key. `check_update` itself still
/// compares against `/version/latest` (installs only if the console target is newer) and
/// refuses while there are active connections, so this is safe to call unconditionally.
#[allow(dead_code)]
pub fn force_check_update_now() {
    if UPDATE_IN_FLIGHT.swap(true, Ordering::SeqCst) {
        log::debug!("forced update check already in flight; skipping overlapping request");
        return;
    }
    std::thread::spawn(|| {
        if let Err(e) = crate::updater::check_update(true) {
            log::error!("forced update check failed: {e}");
        }
        UPDATE_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
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
pub(crate) fn download_package(url: &str, file_path: &PathBuf, have: u64, total: u64) -> ResultType<()> {
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

/// SullTec (H6): SHA-256 of a file as lowercase hex, streaming (never buffers the whole package).
#[cfg(target_os = "windows")]
fn sha256_file(path: &PathBuf) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher).ok()?;
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// SullTec (H6): the verify gate. Returns `true` if the just-downloaded package may be executed.
///
/// Signature+integrity (`sig_ok`): the response carried a signature, the downloaded bytes match the
/// signed `size` + `sha256`, and the attached Ed25519 signature over `CONSOLE-PKG\n{version}\n
/// {sha256}\n{size}` verifies against the current console logon key. Anti-rollback (`rollback_ok`):
/// the signed version out-ranks both the running build and the persisted high-water mark.
///
/// - both hold → run.
/// - enforce mode → any failure aborts (return false).
/// - observe mode → run anyway (today's behavior), EXCEPT a plaintext origin with no valid signature
///   is refused (§3.5 carve-out closes the sig-strip MITM; a valid-but-rolled-back build still runs
///   in observe, which only enforce closes).
#[cfg(target_os = "windows")]
pub(crate) fn verify_update_package(download_url: &str, file_path: &PathBuf) -> bool {
    let signed_version = crate::common::SOFTWARE_UPDATE_VERSION.lock().unwrap().clone();
    let sig = crate::common::SOFTWARE_UPDATE_SIG.lock().unwrap().clone();
    let exp_sha = crate::common::SOFTWARE_UPDATE_SHA256.lock().unwrap().clone();
    let exp_size = *crate::common::SOFTWARE_UPDATE_SIZE.lock().unwrap();
    let plaintext = download_url.to_ascii_lowercase().starts_with("http://");
    let enforce = crate::sulltec_remote::jobs::update_sig_enforced();

    let actual_size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    let sig_ok = !sig.is_empty()
        && !exp_sha.is_empty()
        && exp_size != 0
        && actual_size == exp_size
        && sha256_file(file_path)
            .map(|h| h.eq_ignore_ascii_case(&exp_sha))
            .unwrap_or(false)
        && crate::sulltec_remote::jobs::verify_package(&signed_version, &exp_sha, exp_size, &sig);

    let hwm = crate::sulltec_remote::jobs::update_hwm();
    let rollback_ok = !signed_version.is_empty()
        && version_key(&signed_version)
            > version_key(crate::SULLTEC_VERSION)
        && (hwm.is_empty()
            || version_key(&signed_version) > version_key(&hwm));

    if sig_ok && rollback_ok {
        return true;
    }
    if enforce {
        log::error!(
            "update refused (enforce): sig_ok={sig_ok} rollback_ok={rollback_ok} version={signed_version}"
        );
        return false;
    }
    if !sig_ok && plaintext {
        log::error!(
            "update refused (observe, plaintext origin, no valid signature): version={signed_version}"
        );
        return false;
    }
    log::warn!(
        "update signature/anti-rollback not satisfied (observe, installing anyway): sig_ok={sig_ok} rollback_ok={rollback_ok} version={signed_version}"
    );
    true
}

/// Headless-server fallback for applying an update.
///
/// The preferred path launches `--update` into the active interactive session by borrowing
/// winlogon's token, so the update UI can show. On a server with nobody logged in at the console
/// there is no such session and that launch returns a null handle.
///
/// When we are the LocalSystem service, apply it directly instead: every step `update_me` performs
/// — `sc stop`, `taskkill`, copy the exe, registry, `sc start` — is valid from session 0, and a
/// detached `--update` process survives the service stop+restart, so the self-update completes with
/// nobody logged in.
///
/// Desktops never reach this: their interactive launch succeeds, so the working path is unchanged.
pub(crate) fn apply_update_from_session_0(exe: &str, version: &str) -> bool {
    if !crate::platform::is_root() {
        log::error!("Failed to update to the new version: {version}");
        return false;
    }
    log::info!("No interactive session for --update; applying update directly from the service");
    match crate::platform::run_exe_direct(exe, vec!["--update"], false) {
        Ok(_) => true,
        Err(e) => {
            log::error!("Direct session-0 --update failed: {e}");
            false
        }
    }
}

/// SullTec (H6): order two SullTec product-version tokens. Compares the FULL product version
/// (SemVer core + build + datetime metadata, see RUST_VERSION_POLICY.md), NOT the RustDesk protocol
/// `VERSION` (which stays 1.4.x). `get_version_number` only parses the SemVer core and ignores
/// everything after `+`, so two builds of the same SemVer would compare equal — we order by
/// `(core, build, datetime)` so same-SemVer rebuilds stay distinguishable. `datetime` carries
/// HH:MM:SS, the real per-build tiebreak when the build counter hasn't moved (dirty rebuilds).
/// Hoisted from `do_check_software_update` so the updater's verify gate and the first-boot hwm
/// hook share one comparator with the update check.
pub fn version_key(v: &str) -> (i64, u64, String) {
    let (core, meta) = v.split_once('+').unwrap_or((v, ""));
    let mut seg = meta.split('.'); // meta = BUILD.DATETIME.COMMIT
    let build = seg.next().unwrap_or("").parse::<u64>().unwrap_or(0);
    let datetime = seg.next().unwrap_or("").to_string();
    (hbb_common::get_version_number(core), build, datetime)
}

/// The console's `/version/latest` URL — never api.rustdesk.com.
///
/// The console dictates what "latest" means and where the package comes from, so a client cannot be
/// talked into pulling a build the console did not publish.
///
/// Falls back to the value baked in at compile time when `api-server` is unset. That covers the one
/// case which empties it: a policy RELEASE, which deletes the baked entry too, since both occupy the
/// same OVERWRITE_SETTINGS key. The fallback is deliberately not routed through `get_api_server` —
/// the `:21114`-stripping guard must not apply to it — and it carries its own scheme, because the
/// console will still be refusing plaintext at the moment this path is needed.
///
/// A build with nothing baked in has nothing to fall back TO, and errors rather than requesting the
/// bare string "/version/latest", which is not a URL and would surface as an update-check failure
/// instead of as a client that was never told where to look.
pub fn version_check_url() -> ResultType<String> {
    let api = crate::ui_interface::get_api_server();
    let api = if api.is_empty() {
        hbb_common::config::ST_API_SERVER.to_string()
    } else {
        api
    };
    if api.is_empty() {
        bail!("no api-server configured and none baked in — cannot check for updates");
    }
    Ok(format!("{}/version/latest", api.trim_end_matches('/')))
}
