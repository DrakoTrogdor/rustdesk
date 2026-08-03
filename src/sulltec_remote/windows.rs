//! Windows-only fork code lifted out of `platform/windows.rs`.
//!
//! That file is upstream's platform layer and one of the larger fork footprints in the tree. What
//! moves here is the fork's own: the portable in-place update offer and the yes/no prompt it uses.
//! What stays there is everything that reaches into upstream's Windows internals.

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

/// Best-effort read of the installed client's build timestamp via its long-standing
/// `--build-date` CLI flag (prints `crate::BUILD_DATE`, e.g. "2026-06-15 07:38", then exits
/// early). This is the only locally-readable signal that distinguishes SullTec builds: the
/// registry `Version`, the PE version resource, and `--version` all carry the RustDesk *protocol*
/// version (1.4.x), which is identical across every SullTec release. `--build-date` predates the
/// fork, so it also works on already-installed older builds. Returns `None` if the value can't be
/// read (callers treat that as "don't offer" — fail safe).
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

/// SullTec: portable in-place update offer.
///
/// When a *portable* (non-installed) build is double-clicked on a machine that already has an
/// OLDER SullTec Remote installed, the Flutter runner would otherwise just foreground the
/// running install and exit (both share the window class + title), so the newer portable never
/// takes effect — its config/settings are never read. Detect that case and offer to upgrade the
/// install in place from THIS very exe: no download is needed, we ARE the new build. On accept,
/// relaunch elevated with `--update` (-> `update_me`, which stops the old instance, copies us
/// over the install dir, repairs the `Uninstall\SullTec Remote` registry keys, and restarts) —
/// the same proven path the console-pushed update uses.
///
/// "Older" is decided by build timestamp (`crate::BUILD_DATE`, the compile time — monotonic across
/// releases and exposed by `--build-date`), NOT by version label: the RustDesk protocol `VERSION`
/// (1.4.x) is identical across SullTec builds, and the SullTec product version is baked into the
/// lib via `option_env!` with no read path on an arbitrary already-installed exe.
///
/// Returns `true` if the caller should terminate this instance (the update was launched),
/// `false` to continue the normal startup path.
pub fn offer_portable_in_place_update() -> bool {
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

    // Display the SullTec product SemVer (e.g. "0.1.9"), not the protocol VERSION.
    let target = crate::SULLTEC_VERSION
        .split('+')
        .next()
        .unwrap_or(crate::SULLTEC_VERSION);
    let app = crate::get_app_name();
    let prompt = format!(
        "An older {app} is already installed on this computer (built {installed_build}).\n\n\
         Update it to version {target} now? The program will briefly close to apply the update."
    );
    if !message_box_yes_no(&format!("{app} - Update"), &prompt) {
        log::info!("Portable in-place update declined (installed build {installed_build})");
        return false;
    }

    // Relaunch THIS exe elevated with `--update`. `update_me` uses current_exe() (us) as the
    // source, so the newer portable becomes the installed build with no download.
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
