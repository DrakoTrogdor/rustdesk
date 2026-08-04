//! The app-naming policy.
//!
//! The product name has one form a user reads and four derived forms the machine uses, so that no
//! call site has to hand-write a spaced path. The display name stays `common::get_app_name()`
//! ("SullTec Remote"); identifiers, folders, file bases and the exe name each get an accessor here.
//!
//! Upstream can use `{app_name}` directly almost everywhere because "RustDesk" and "rustdesk.exe"
//! differ only by case and NTFS ignores that. A hyphenated, space-bearing rename does not have that
//! luxury, which is why these forms exist at all.
//!
//! **Every substitution in `platform/windows.rs` is a call to one of these**, and the reason for each
//! is documented on the accessor rather than repeated at the call sites — the call sites live in an
//! upstream file, where a comment costs a merge conflict and buys nothing.

/// Lowercase ASCII-alphanumeric form: "SullTec Remote" -> "sulltecremote".
///
/// This is the form for anything that becomes a machine identifier, none of which tolerates the
/// display name's space:
///   * the **Windows service name** — registered under this, so `sc stop` / `sc delete` and
///     `service_dispatcher::start` must all agree on it;
///   * the **HKCR file-extension and URL-protocol classes** — a space breaks an unquoted `reg add`,
///     and `get_uri_prefix` builds `"{ident}://"`, which would otherwise be an invalid URI scheme;
///   * the **options stash**, which lives under the extension class.
#[inline]
pub fn get_app_ident() -> String {
    crate::common::get_app_name()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Folder form: "SullTec Remote" -> "SullTecRemote".
///
/// The install directory (`Program Files\SullTecRemote`), the Start Menu *group*, and the `%APPDATA%`
/// directory. The `.lnk` files *inside* the Start Menu group keep the readable display name — the
/// group is a path, the shortcuts are labels.
#[inline]
pub fn get_app_dir_name() -> String {
    hbb_common::config::app_dir_name()
}

/// File-stem form: "SullTec Remote" -> "sulltec-remote".
///
/// Config files (`sulltec-remote.toml` and its `_ab` / `_group` siblings) and the temp helper scripts
/// written during install and uninstall.
#[inline]
pub fn get_app_file_base() -> String {
    hbb_common::config::app_file_base()
}

/// The installed binary: `sulltec-remote.exe`. **Never `"{app_name}.exe"`.**
///
/// This one has the sharpest failure mode of the four, because it is what the shortcut targets, the
/// service binpath and `taskkill /IM` all reference. A spaced name here does not fail loudly — it
/// leaves dangling desktop and tray shortcuts, a service whose binpath points at a file that does not
/// exist, and a `taskkill` whose image name matches no running process, so an uninstall reports
/// success while leaving the binary running.
///
/// `rename_exe_cmd` normalizes to this on upgrade for the same reason: everything downstream
/// references the canonical name.
#[inline]
pub fn get_app_exe_name() -> String {
    format!("{}.exe", get_app_file_base())
}
