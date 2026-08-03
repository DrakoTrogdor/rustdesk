//! The app-naming policy.
//!
//! Three derived forms of the product name, so no call site hand-writes a spaced path:
//! the display name stays `common::get_app_name()` ("SullTec Remote") for anything a user
//! reads, while identifiers, folders, file bases and the exe name each get their own
//! accessor. Upstream gets away with `{app_name}.exe` because "RustDesk"/"rustdesk.exe"
//! differ only by case and NTFS ignores that; a hyphenated rename does not.

/// SullTec: lowercase ASCII-alphanumeric form of the app name
/// ("SullTec Remote" -> "sulltecremote"). Used wherever the app name becomes a machine
/// identifier — the URI scheme, the Windows service name, and the HKCR file-extension /
/// URL-protocol registry keys — none of which tolerate the display name's space.
#[inline]
pub fn get_app_ident() -> String {
    crate::common::get_app_name()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// SullTec naming policy (thin re-exports of the canonical helpers in `hbb_common::config`
/// so call sites read `crate::common::...` uniformly):
///   * folders  -> "SullTecRemote"      (install dir, Start Menu folder, %APPDATA% dir, ...)
///   * file base-> "sulltec-remote"      (config files, temp helper scripts)
///   * exe name -> "sulltec-remote.exe"  (installed binary, service binpath, taskkill, shortcuts)
/// The spaced display name (`get_app_name()`) stays for anything a user reads. Upstream gets
/// away with `{app_name}.exe` because "RustDesk"/"rustdesk.exe" differ only by case (NTFS
/// ignores it); our hyphenated rename does not.
#[inline]
pub fn get_app_dir_name() -> String {
    hbb_common::config::app_dir_name()
}

#[inline]
pub fn get_app_file_base() -> String {
    hbb_common::config::app_file_base()
}

#[inline]
pub fn get_app_exe_name() -> String {
    format!("{}.exe", get_app_file_base())
}
