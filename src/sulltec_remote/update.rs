//! The console-driven update mechanism.
//!
//! Handles forced checks from the heartbeat, resumable streaming downloads, and package
//! signature and hash verification.

use hbb_common::{bail, log, ResultType};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static UPDATE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Force an immediate update check and installation, bypassing the auto-update
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

/// Fetch the update package to `file_path`, resuming from `have` bytes when a partial download is
/// present. The response streams directly to disk. A `206` response appends to the partial file;
/// other successful responses replace it. Errors include the URL, byte counts, and status.
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

/// Return a file's SHA-256 digest as lowercase hex without buffering the whole package.
#[cfg(target_os = "windows")]
fn sha256_file(path: &PathBuf) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher).ok()?;
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Return whether the downloaded package may be executed.
///
/// Signature+integrity (`sig_ok`): the response carried a signature, the downloaded bytes match the
/// signed `size` + `sha256`, and the attached Ed25519 signature over `CONSOLE-PKG\n{version}\n
/// {sha256}\n{size}` verifies against the current console logon key. Anti-rollback (`rollback_ok`):
/// the signed version out-ranks both the running build and the persisted high-water mark.
///
/// - both hold → run.
/// - enforce mode → any failure aborts (return false).
/// - observe mode → run despite validation failures, except that a plaintext origin without a valid
///   signature is refused; a valid but rolled-back build remains permitted.
#[cfg(target_os = "windows")]
pub(crate) fn verify_update_package(download_url: &str, file_path: &PathBuf) -> bool {
    let signed_version = SOFTWARE_UPDATE_VERSION.lock().unwrap().clone();
    let sig = SOFTWARE_UPDATE_SIG.lock().unwrap().clone();
    let exp_sha = SOFTWARE_UPDATE_SHA256.lock().unwrap().clone();
    let exp_size = *SOFTWARE_UPDATE_SIZE.lock().unwrap();
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
            > version_key(crate::sulltec_remote::SULLTEC_VERSION)
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

/// Order two SullTec product-version tokens by the full product version
/// (SemVer core + build + datetime metadata, see RUST_VERSION_POLICY.md), NOT the RustDesk protocol
/// `VERSION` (which stays 1.4.x). `get_version_number` only parses the SemVer core and ignores
/// everything after `+`, so two builds of the same SemVer would compare equal — we order by
/// `(core, build, datetime)` so same-SemVer rebuilds stay distinguishable. `datetime` carries
/// HH:MM:SS and breaks ties when the build counter has not moved.
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
/// Falls back to the value baked in at compile time when `api-server` is unset. Policy removal can
/// clear the shared `OVERWRITE_SETTINGS` key containing that value. The fallback is deliberately
/// not routed through `get_api_server`: the `:21114`-stripping guard must not apply to it, and its
/// explicit scheme is required when the console refuses plaintext.
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

/// Seed the signed-update anti-rollback floor to the running build's baked version, once per
/// process, before any update decision is taken.
///
/// A fresh install — or one whose `%ProgramData%` was wiped — starts with a high-water mark of 0,
/// which would let an attacker replay any signed build however old. Flooring it at the version
/// actually installed narrows that to replaying something *newer* than what is already running.
///
/// Skipped on a non-release build with no baked token: `SULLTEC_VERSION` then falls back to the
/// protocol version `1.4.x`, whose ordinate outranks every `0.x` console token and would refuse all
/// updates.
pub(crate) fn seed_rollback_floor() {
    static SEEDED: std::sync::Once = std::sync::Once::new();
    SEEDED.call_once(|| {
        if option_env!("SULLTEC_CLIENT_VERSION").is_some() {
            super::jobs::advance_update_hwm(crate::sulltec_remote::SULLTEC_VERSION);
        }
    });
}

/// Make sure the update package is on disk and fit to run. Returns `false` when the package must not
/// be executed, in which case it has already been removed.
///
/// The total size is fetched first to distinguish a complete file, a resumable partial file, and a
/// fresh download.
///
/// Verification runs before the package can be executed as SYSTEM. It binds the console's Ed25519
/// signature over the signed version, sha256 and size, then applies the monotonic anti-rollback
/// rule seeded by [`seed_rollback_floor`].
pub(crate) fn fetch_and_verify(
    client: &reqwest::blocking::Client,
    download_url: &str,
    file_path: &PathBuf,
) -> ResultType<bool> {
    let response = client.head(download_url).send()?;
    if !response.status().is_success() {
        bail!("Failed to get the file size: {}", response.status());
    }
    let Some(total_size) = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|ct_len| ct_len.to_str().ok())
        .and_then(|ct_len| ct_len.parse::<u64>().ok())
    else {
        bail!("Failed to get content length");
    };

    let have = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    if have != total_size {
        download_package(download_url, file_path, have, total_size)?;
    }

    #[cfg(target_os = "windows")]
    if !verify_update_package(download_url, file_path) {
        std::fs::remove_file(file_path).ok();
        return Ok(false);
    }
    Ok(true)
}

hbb_common::lazy_static::lazy_static! {
    /// Package-authenticity state for the pending update, set when the check finds a newer build and
    /// read by the verify gate before the package is executed as SYSTEM.
    ///
    /// The signed version is kept rather than the one parsed from the download URL: the signature and the
    /// monotonic anti-rollback check are both bound to the signed value, so trusting a URL-derived
    /// string here would let a renamed file claim any version it liked.
    static ref SOFTWARE_UPDATE_VERSION: std::sync::Arc<std::sync::Mutex<String>> = Default::default();
    static ref SOFTWARE_UPDATE_SIG: std::sync::Arc<std::sync::Mutex<String>> = Default::default();
    static ref SOFTWARE_UPDATE_SHA256: std::sync::Arc<std::sync::Mutex<String>> = Default::default();
    static ref SOFTWARE_UPDATE_SIZE: std::sync::Arc<std::sync::Mutex<u64>> = Default::default();
}

/// Which version string to trust from a `/version/latest` reply.
///
/// Prefer the explicit signed `version` field. When the backend omits it, the last path segment of
/// the download URL provides an unsigned compatibility value and is not a trusted source.
pub fn pick_version(signed: &str, response_url: &str) -> String {
    if signed.is_empty() {
        response_url.rsplit('/').next().unwrap_or_default().to_string()
    } else {
        signed.to_owned()
    }
}

/// Record the pending package's authenticity fields for the verify gate.
pub fn set_pending_package(version: String, sig: String, sha256: String, size: u64) {
    *SOFTWARE_UPDATE_VERSION.lock().unwrap() = version;
    *SOFTWARE_UPDATE_SIG.lock().unwrap() = sig;
    *SOFTWARE_UPDATE_SHA256.lock().unwrap() = sha256;
    *SOFTWARE_UPDATE_SIZE.lock().unwrap() = size;
}

/// Clear it, so a check that finds nothing newer cannot leave a previous package's fields behind for
/// the verify gate to match against.
pub fn clear_pending_package() {
    set_pending_package(String::new(), String::new(), String::new(), 0);
}

/// Where to save the package named by `url`, or `None` if that URL may not be downloaded.
///
/// Console packages do not use RustDesk's GitHub allow-list, so the origin is deliberately not
/// checked here. Authenticity is carried by the Ed25519 package signature
/// ([`verify_update_package`]), and transport is constrained by the strict HTTPS client.
///
/// What IS checked is the shape, because the last path segment is joined onto the temp directory:
///
/// * it must be a real `http`/`https` URL — splitting on `/` alone treats a bare string with no
///   slashes as its own filename, which let a malformed value reach the join;
/// * the segment must be a plain filename — no separators, no drive letter, no empty segment.
///
pub fn package_file_from_url(url: &str) -> Option<std::path::PathBuf> {
    let parsed = url::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    // path_segments() drops any query and fragment, which splitting on '/' would have kept.
    let filename = parsed.path_segments()?.last()?;
    if !is_plain_filename(filename) {
        return None;
    }
    Some(std::env::temp_dir().join(filename))
}

/// A single path component with nothing that could redirect the temp-dir join.
fn is_plain_filename(filename: &str) -> bool {
    !filename.is_empty()
        && !filename.contains(['/', '\\', ':'])
        && std::path::Path::new(filename)
            .components()
            .next()
            .and_then(|c| match c {
                std::path::Component::Normal(n) => n.to_str(),
                _ => None,
            })
            == Some(filename)
}

#[cfg(test)]
mod resolver_tests {
    use super::package_file_from_url;

    /// Console-hosted packages resolve without RustDesk's GitHub origin restriction.
    #[test]
    fn accepts_a_console_hosted_package_url() {
        let file = package_file_from_url(
            "https://rustdesk.example.com/packages/download/0.87.6/rustdesk-0.87.6-x86_64.exe",
        )
        .expect("a console-hosted package URL must resolve");
        assert_eq!(
            file.file_name().and_then(|n| n.to_str()),
            Some("rustdesk-0.87.6-x86_64.exe")
        );
    }

    /// Permissive about ORIGIN is not permissive about everything: the segment is joined onto the
    /// temp directory, so it still has to be a plain filename.
    #[test]
    fn rejects_anything_that_is_not_a_plain_filename_on_an_http_url() {
        for url in [
            "https://rustdesk.example.com/packages/download/1/", // no filename segment
            "https://rustdesk.example.com/packages/download/1/C:rustdesk.exe", // drive-relative
            "file:///C:/Windows/System32/calc.exe",             // non-http scheme
            "not a url",
        ] {
            assert!(package_file_from_url(url).is_none(), "{url}");
        }
    }

    /// A query string is legal on a package URL and must not end up in the saved filename.
    #[test]
    fn a_query_string_does_not_leak_into_the_filename() {
        let file = package_file_from_url(
            "https://rustdesk.example.com/packages/download/0.87.6/rustdesk-0.87.6-x86_64.exe?t=1",
        )
        .expect("query strings are legal in a package URL");
        assert_eq!(
            file.file_name().and_then(|n| n.to_str()),
            Some("rustdesk-0.87.6-x86_64.exe")
        );
    }
}
