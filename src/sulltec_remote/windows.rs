//! Windows support for portable in-place updates.

#![cfg(windows)]

use crate::platform::windows::{elevate, get_install_info, is_cur_exe_the_installed, is_installed};
use hbb_common::log;
use winapi::um::winuser::*;

/// A modal Yes/No prompt. Used before the Flutter UI exists (e.g. the portable update offer),
/// so it talks straight to `MessageBoxW` instead of routing through the app's dialog system.
/// Returns `true` only when the user picks Yes.
fn message_box_yes_no(caption: &str, text: &str) -> bool {
    let wtext = text
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    let wcaption = caption
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    let ret = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wtext.as_ptr(),
            wcaption.as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND,
        )
    };
    ret == IDYES
}

/// Best-effort read of the installed client's build timestamp via its `--build-date` CLI flag.
/// The command prints `crate::BUILD_DATE`, e.g. "2026-06-15 07:38", then exits early. This is the
/// only locally readable signal that distinguishes SullTec builds: the
/// registry `Version`, the PE version resource, and `--version` all carry the RustDesk *protocol*
/// version (1.4.x), which is identical across SullTec releases. Returns `None` if the value cannot
/// be read; callers then omit the update offer.
fn read_installed_build_date() -> Option<String> {
    let (_, _, _, exe) = get_install_info();
    let out = std::process::Command::new(&exe)
        .arg("--build-date")
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Offer to replace an older installed build with the running portable executable.
///
/// The Flutter runner foregrounds an existing installed instance because the installed and
/// portable builds share a window class and title. This check runs first and offers an in-place
/// update when the portable build is newer. On acceptance, `--update` stops the installed instance,
/// copies the portable executable into the install directory, repairs the uninstall registry
/// entries, and restarts the application.
///
/// Build timestamps determine ordering because the RustDesk protocol `VERSION` is identical across
/// SullTec builds and an arbitrary installed executable does not expose its baked product version.
///
/// Returns `true` if the caller should terminate this instance (the update was launched),
/// `false` to continue the normal startup path.
/// The launch shapes that must never see this offer. `--elevate`, `--run-as-system` and quick-support
/// are internal relaunches, and `--no-server` is the internal headless launch; all of them arrive with
/// their arguments stripped, so `args_empty` alone cannot tell them apart from a real double-click.
pub fn offer_portable_in_place_update(
    args_empty: bool,
    no_server: bool,
    is_quick_support: bool,
    is_elevate: bool,
    is_run_as_system: bool,
) -> bool {
    if !args_empty || no_server || is_quick_support || is_elevate || is_run_as_system {
        return false;
    }
    // Only a portable offers; an installed copy must never self-offer, and there must be an
    // existing install to upgrade.
    if is_cur_exe_the_installed() || !is_installed() {
        return false;
    }
    // Only offer a strict upgrade: our build must be newer than the installed one. BUILD_DATE is
    // "YYYY-MM-DD HH:MM" (fixed width, chronological), so a plain string compare is correct.
    let Some(installed_build) = read_installed_build_date() else {
        return false;
    };
    if crate::BUILD_DATE <= installed_build.as_str() {
        return false;
    }

    // Display the SullTec product SemVer rather than the protocol version.
    let target = crate::sulltec_remote::SULLTEC_VERSION
        .split('+')
        .next()
        .unwrap_or(crate::sulltec_remote::SULLTEC_VERSION);
    let app = crate::get_app_name();
    let prompt = format!(
        "An older {app} is already installed on this computer (built {installed_build}).\n\n\
         Update it to version {target} now? The program will briefly close to apply the update."
    );
    if !message_box_yes_no(&format!("{app} - Update"), &prompt) {
        log::info!("Portable in-place update declined (installed build {installed_build})");
        return false;
    }

    // `update_me` uses the current executable as its source, so this requires no download.
    match elevate("--update") {
        Ok(true) => {
            log::info!(
                "Portable in-place update launched (installed build {installed_build} -> {})",
                crate::BUILD_DATE
            );
            true
        }
        Ok(false) => {
            log::error!("Portable in-place update: elevation declined or failed");
            false
        }
        Err(e) => {
            log::error!("Portable in-place update: elevate error: {e}");
            false
        }
    }
}
