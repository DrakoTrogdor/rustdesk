//! Compatibility with installs made before `APP_NAME` lost its space.
//!
//! The installed binary used to be `sulltec-remote.exe`, derived from a hyphenated file base.
//! `APP_NAME` is now space-free, so upstream's own `"{app_name}.exe"` derivation produces
//! `sulltecremote.exe` and every naming substitution the fork used to carry is gone.
//!
//! Two things about an old install do NOT move and need no help here: the service is already
//! named `sulltecremote` (`get_app_name().to_lowercase()`), and the install directory is already
//! `SullTecRemote`. Only the executable's filename changes.
//!
//! Without this module a client on the old name never crosses over. `update_me()` computes
//! `InstallLocation + "{app_name}.exe"`, does not find it, and bails `"… is not installed."` —
//! so the update does not half-apply, it does not apply at all, and the device keeps reporting
//! the old version as though the push had been ignored.
//!
//! ## Removal criterion
//!
//! Delete this module and its three hooks once EVERY device in the console reports a client
//! version >= the release that renamed the binary (`GET /api/ro/devices`, `version` field).
//!
//! Deliberately not "after one release". Fleet auto-update is off by policy, so each device
//! crosses when it is pulled; one that was offline through the rollout, restored from an image,
//! or installed from an archived package is still on the old name however many releases later.
//! See also `hbb_common::sulltec_remote::migrate_legacy_config_stems`, which carries the same
//! lifetime for the identity half.

/// The installed executable's name before the rename.
pub const LEGACY_EXE_NAME: &str = "sulltec-remote.exe";

/// The product name before the rename — the SPACED display form.
///
/// Still on disk and in the registry of every pre-rename install: it names the Start Menu
/// shortcuts (`SullTec Remote.lnk`, `Uninstall SullTec Remote.lnk`) and the Add/Remove Programs
/// key (`…\Uninstall\SullTec Remote`). `APP_NAME` no longer produces it, so nothing upstream
/// rebuilds or removes them and they are stranded by the update.
pub const LEGACY_DISPLAY_NAME: &str = "SullTec Remote";

/// The pre-rename executable inside `path`, if that is what is actually installed there.
///
/// Returns `None` when the current-named binary exists (the normal case, and after the first
/// successful crossover) so the fallback costs one `metadata` call and then disappears.
///
/// ⚠ This answers "is something installed here", and NOTHING else. In particular it must never
/// be substituted for the `exe` that `get_install_info` returns: that value is also what
/// `get_create_service` writes into the service binpath, and [`crossover_cleanup_cmds`] deletes the
/// legacy binary during the update. A service pointed at the legacy path would therefore be
/// created against a file that had just been removed — the device would never come back.
pub fn installed_legacy_exe(path: &str, current_exe: &str) -> Option<String> {
    if std::path::Path::new(current_exe).exists() {
        return None;
    }
    let legacy = format!("{}\\{}", path.trim_end_matches('\\'), LEGACY_EXE_NAME);
    std::path::Path::new(&legacy).exists().then_some(legacy)
}

/// Is a client installed at `path` under either the current or the pre-rename name?
///
/// The install check is the only place the legacy name may widen behaviour. Every path that
/// WRITES a location — the service binpath above all — keeps using the current name, so the
/// update converges on it.
pub fn is_installed_either_name(path: &str, current_exe: &str) -> bool {
    std::path::Path::new(current_exe).exists() || installed_legacy_exe(path, current_exe).is_some()
}

/// Shutdown half of the crossover — emitted BEFORE the copy.
///
/// `taskkill` matches by image name, so the running `sulltec-remote.exe` survives a kill aimed at
/// `sulltecremote.exe`, and a surviving process holds its own file open — which is what would make
/// the copy fail. Killing is reversible: the service is restarted at the end of the script either
/// way, so a script that stops here leaves a machine whose client is merely stopped.
///
/// Returns an empty string once nothing legacy is present, so the generated script is unchanged on
/// an already-crossed machine.
pub fn crossover_stop_cmds(path: &str, current_exe: &str) -> String {
    if installed_legacy_exe(path, current_exe).is_none() {
        return String::new();
    }
    format!("\ntaskkill /F /IM \"{LEGACY_EXE_NAME}\"\n")
}

/// Cleanup half of the crossover — emitted AFTER the new binary is in place.
///
/// Deleting the old binary is the one irreversible step in the whole update, so it runs last and
/// only once the replacement provably exists: `if exist <new> if exist <old> del <old>`. Ordered
/// any earlier, every failure between the delete and the copy — a locked file, an AV quarantine,
/// elevation withdrawn, power loss — leaves the machine with no client binary at all and no way
/// to reach it.
///
/// It must still happen: a leftover old binary is what a stale shortcut would launch, giving a
/// second client alongside the real one.
pub fn crossover_cleanup_cmds(path: &str, current_exe: &str) -> String {
    if installed_legacy_exe(path, current_exe).is_none() {
        return String::new();
    }
    let path = path.trim_end_matches('\\');
    let current = std::path::Path::new(current_exe)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_owned();
    format!(
        "
if exist \"{path}\\{current}\" if exist \"{path}\\{LEGACY_EXE_NAME}\" del /f /q \"{path}\\{LEGACY_EXE_NAME}\"
"
    )
}

/// Is a pre-rename Start Menu shortcut still sitting in `start_menu`?
///
/// `start_menu` arrives as an unexpanded `%ProgramData%\...` path because it is destined for a
/// batch script, so the variable is expanded here before testing.
fn legacy_shortcut_present(start_menu: &str) -> bool {
    let expanded = match std::env::var("ProgramData") {
        Ok(pd) => start_menu.replace("%ProgramData%", &pd),
        Err(_) => return false,
    };
    std::path::Path::new(&expanded)
        .join(format!("{LEGACY_DISPLAY_NAME}.lnk"))
        .exists()
}

/// Repair what the rename strands but nothing upstream rebuilds — emitted after the new binary
/// is in place, alongside the cleanup.
///
/// `update_me` rewrites the service and the version registry values, and that is all. Everything
/// else carrying the old identity simply stops resolving:
///
/// * **Start Menu shortcuts** — `SullTec Remote.lnk` and `Uninstall SullTec Remote.lnk` both
///   target the deleted `sulltec-remote.exe`. Measured after a real crossover: both dead, so the
///   client could not be launched or uninstalled from the Start Menu.
/// * **Add/Remove Programs** — the key is named from `APP_NAME`, so the update writes a new
///   `…\Uninstall\SullTecRemote` and leaves `…\Uninstall\SullTec Remote` behind. ARP then lists
///   the product twice, the stale entry pointing at nothing.
///
/// The shortcut payloads are built by the caller: they need `shortcut_bytes` /
/// `embedded_shortcut_commands`, which are private to `platform::windows`. This function owns the
/// decision and the assembly; the caller only hands over bytes.
///
/// Returns an empty string when nothing legacy is present, so an already-crossed machine gets an
/// unchanged script.
pub fn crossover_repair_cmds(
    path: &str,
    current_exe: &str,
    start_menu: &str,
    mk_shortcut_cmds: &str,
    uninstall_shortcut_cmds: &str,
) -> String {
    // Gate on the DAMAGE, not on the crossover. Keying this off "is the legacy binary still
    // here" was wrong: the binary is renamed early in the script and deleted at the end, so a
    // machine that crossed on a build without this repair has stale shortcuts AND no legacy
    // binary — a state the repair could then never reach, leaving it broken permanently.
    // Measured on sulltec-z790, which crossed on 0.89.2 and was still carrying two dead Start
    // Menu shortcuts after 0.89.3.
    if installed_legacy_exe(path, current_exe).is_none() && !legacy_shortcut_present(start_menu) {
        return String::new();
    }
    let arp = |wow: bool| {
        let k = format!(
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{LEGACY_DISPLAY_NAME}"
        );
        if wow {
            k.replace("Microsoft", "Wow6432Node\\Microsoft")
        } else {
            k
        }
    };
    format!(
        "
{mk_shortcut_cmds}
{uninstall_shortcut_cmds}
md \"{start_menu}\"
copy /Y \"%RUSTDESK_OUTPUT_DIR%\\{app}.lnk\" \"{start_menu}\\\"
copy /Y \"%RUSTDESK_OUTPUT_DIR%\\Uninstall {app}.lnk\" \"{start_menu}\\\"
if exist \"{start_menu}\\{LEGACY_DISPLAY_NAME}.lnk\" del /f /q \"{start_menu}\\{LEGACY_DISPLAY_NAME}.lnk\"
if exist \"{start_menu}\\Uninstall {LEGACY_DISPLAY_NAME}.lnk\" del /f /q \"{start_menu}\\Uninstall {LEGACY_DISPLAY_NAME}.lnk\"
reg delete \"{arp}\" /f
reg delete \"{arp_wow}\" /f
",
        app = crate::get_app_name(),
        arp = arp(false),
        arp_wow = arp(true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_legacy_exe_means_no_extra_commands() {
        // Neither file exists: nothing to clean up, and the script must be left alone.
        let dir = std::env::temp_dir().join("stlegacy_none");
        std::fs::create_dir_all(&dir).ok();
        let cur = dir.join("sulltecremote.exe");
        assert!(installed_legacy_exe(dir.to_str().unwrap(), cur.to_str().unwrap()).is_none());
        assert_eq!(crossover_stop_cmds(dir.to_str().unwrap(), cur.to_str().unwrap()), "");
        assert_eq!(crossover_cleanup_cmds(dir.to_str().unwrap(), cur.to_str().unwrap()), "");
    }

    #[test]
    fn current_exe_wins_over_a_leftover_legacy_one() {
        // A machine that already crossed but still has the old file on disk must NOT be treated
        // as a legacy install - otherwise every update would re-run the crossover.
        let dir = std::env::temp_dir().join("stlegacy_both");
        std::fs::create_dir_all(&dir).ok();
        let cur = dir.join("sulltecremote.exe");
        std::fs::write(&cur, b"x").ok();
        std::fs::write(dir.join(LEGACY_EXE_NAME), b"x").ok();
        assert!(installed_legacy_exe(dir.to_str().unwrap(), cur.to_str().unwrap()).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The install check may widen to the legacy name; the path the service is pointed at may
    /// NOT. The crossover deletes the legacy binary, so a service binpath carrying it would be
    /// created against a file that no longer exists and the device would never come back.
    #[test]
    fn a_legacy_install_is_detected_without_yielding_a_path_to_write() {
        let dir = std::env::temp_dir().join("stlegacy_invariant");
        std::fs::create_dir_all(&dir).ok();
        let d = dir.to_str().unwrap().to_string();
        let current = format!("{d}\\sulltecremote.exe");
        std::fs::remove_file(&current).ok();
        std::fs::write(dir.join(LEGACY_EXE_NAME), b"x").ok();

        // Installed: yes. And the crossover will remove the legacy binary...
        assert!(is_installed_either_name(&d, &current));
        assert!(crossover_cleanup_cmds(&d, &current).contains(LEGACY_EXE_NAME));
        // ...so the only path anything may WRITE is the current one, which the update creates.
        assert!(installed_legacy_exe(&d, &current).unwrap() != current);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The delete is the only irreversible step in the update, so it must come AFTER the
    /// replacement exists and must be guarded on it. Both bricking defects found in review were
    /// invisible to helper-level tests and only showed up in the assembled script, so this
    /// asserts on the emitted text rather than on the functions in isolation.
    #[test]
    fn the_delete_is_guarded_on_the_replacement_existing() {
        let dir = std::env::temp_dir().join("stlegacy_order");
        std::fs::create_dir_all(&dir).ok();
        let d = dir.to_str().unwrap().to_string();
        let current = format!("{d}\\sulltecremote.exe");
        std::fs::remove_file(&current).ok();
        std::fs::write(dir.join(LEGACY_EXE_NAME), b"x").ok();

        // The stop half kills, and must NOT delete.
        let stop = crossover_stop_cmds(&d, &current);
        assert!(stop.contains("taskkill"), "{stop}");
        assert!(!stop.contains("del "), "the stop half must not delete: {stop}");

        // The cleanup half deletes, and only if the new binary is there.
        let cleanup = crossover_cleanup_cmds(&d, &current);
        assert!(cleanup.contains("del /f /q"), "{cleanup}");
        assert!(
            cleanup.contains("if exist \"") && cleanup.contains("sulltecremote.exe\""),
            "the delete must be guarded on the replacement: {cleanup}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The repair must rebuild the shortcuts at the NEW name, remove the stale ones, and drop the
    /// orphaned ARP key — and must emit nothing at all once the machine has crossed.
    #[test]
    fn the_repair_rebuilds_shortcuts_and_drops_the_stale_arp_key() {
        let dir = std::env::temp_dir().join("stlegacy_repair");
        std::fs::create_dir_all(&dir).ok();
        let d = dir.to_str().unwrap().to_string();
        let current = format!("{d}\\sulltecremote.exe");
        std::fs::remove_file(&current).ok();
        std::fs::write(dir.join(LEGACY_EXE_NAME), b"x").ok();

        let out = crossover_repair_cmds(&d, &current, "C:\\SM", "MK", "UN");
        assert!(out.contains("MK") && out.contains("UN"), "payloads passed through: {out}");
        // Rebuilt at the current name, stale ones removed.
        assert!(out.contains("Uninstall SullTec Remote.lnk"), "stale shortcut not removed: {out}");
        assert!(out.contains("reg delete"), "orphaned ARP key not removed: {out}");
        assert!(
            out.contains("Wow6432Node"),
            "the 32-bit ARP view must be cleaned too: {out}"
        );

        // Crossed AND repaired (no legacy binary, no stale shortcut) -> script untouched.
        std::fs::write(&current, b"x").ok();
        assert_eq!(crossover_repair_cmds(&d, &current, "C:\\SM", "MK", "UN"), "");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A machine that crossed on a build WITHOUT the repair has no legacy binary but still has
    /// the stale shortcuts. Gating on the binary would strand it there forever, which is exactly
    /// what happened to the first machine across.
    #[test]
    fn a_crossed_but_unrepaired_machine_still_gets_repaired() {
        let dir = std::env::temp_dir().join("stlegacy_stranded");
        let sm = dir.join("startmenu");
        std::fs::create_dir_all(&sm).ok();
        let d = dir.to_str().unwrap().to_string();

        // Crossed: the current binary exists and the legacy one is gone.
        let current = format!("{d}\\sulltecremote.exe");
        std::fs::write(&current, b"x").ok();
        std::fs::remove_file(dir.join(LEGACY_EXE_NAME)).ok();
        assert!(installed_legacy_exe(&d, &current).is_none());

        // ...but the stale shortcut is still there, so the repair must still fire.
        std::fs::write(sm.join(format!("{LEGACY_DISPLAY_NAME}.lnk")), b"x").ok();
        let out = crossover_repair_cmds(&d, &current, sm.to_str().unwrap(), "MK", "UN");
        assert!(!out.is_empty(), "a stranded machine must still be repaired");
        assert!(out.contains("reg delete"), "{out}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_exe_alone_is_detected_and_cleaned() {
        let dir = std::env::temp_dir().join("stlegacy_old");
        std::fs::create_dir_all(&dir).ok();
        let cur = dir.join("sulltecremote.exe");
        std::fs::remove_file(&cur).ok();
        std::fs::write(dir.join(LEGACY_EXE_NAME), b"x").ok();
        let d = dir.to_str().unwrap();
        assert!(installed_legacy_exe(d, cur.to_str().unwrap()).is_some());
        assert!(crossover_stop_cmds(d, cur.to_str().unwrap()).contains("taskkill"));
        assert!(crossover_cleanup_cmds(d, cur.to_str().unwrap()).contains(LEGACY_EXE_NAME));
        std::fs::remove_dir_all(&dir).ok();
    }
}
