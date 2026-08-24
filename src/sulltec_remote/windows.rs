#![cfg(windows)]

use crate::platform::windows::{elevate, get_install_info, is_cur_exe_the_installed, is_installed};
use hbb_common::log;
use winapi::um::winuser::*;

/// Runs before the Flutter UI exists, so it calls `MessageBoxW` directly rather than routing
/// through the app's dialog system.
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

/// `BUILD_DATE` is the ONLY locally readable signal that tells two SullTec builds apart: the
/// registry `Version`, the PE version resource and `--version` all carry the RustDesk *protocol*
/// version (1.4.x), which is identical across releases.
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

/// Must run BEFORE the Flutter runner, which would otherwise just foreground the installed
/// instance — installed and portable share a window class and title.
///
/// The four flags exist because `--elevate`, `--run-as-system`, quick-support and `--no-server`
/// are internal relaunches that arrive with their arguments stripped, so `args_empty` alone
/// cannot tell them from a real double-click.
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
    if is_cur_exe_the_installed() || !is_installed() {
        return false;
    }
    // `BUILD_DATE` is "YYYY-MM-DD HH:MM" — fixed width and chronological, so a string compare
    // orders builds correctly.
    let Some(installed_build) = read_installed_build_date() else {
        return false;
    };
    if crate::BUILD_DATE <= installed_build.as_str() {
        return false;
    }

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
