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

/// The pre-rename executable inside `path`, if that is what is actually installed there.
///
/// Returns `None` when the current-named binary exists (the normal case, and after the first
/// successful crossover) so the fallback costs one `metadata` call and then disappears.
pub fn installed_legacy_exe(path: &str, current_exe: &str) -> Option<String> {
    if std::path::Path::new(current_exe).exists() {
        return None;
    }
    let legacy = format!("{}\\{}", path.trim_end_matches('\\'), LEGACY_EXE_NAME);
    std::path::Path::new(&legacy).exists().then_some(legacy)
}

/// Extra shutdown + cleanup for an install still on the old executable name.
///
/// Two jobs, both of which the current-named commands miss entirely:
///
/// * `taskkill` matches by image name, so the running `sulltec-remote.exe` survives a kill aimed
///   at `sulltecremote.exe` — and a surviving process holds its own file open, which is what
///   would make the subsequent copy fail.
/// * the old binary is deleted afterwards, so the directory does not end up holding two clients
///   where a stale shortcut could launch the wrong one.
///
/// Returns an empty string once nothing legacy is present, so the generated script is unchanged
/// on an already-crossed machine.
pub fn crossover_cmds(path: &str, current_exe: &str) -> String {
    if installed_legacy_exe(path, current_exe).is_none() {
        return String::new();
    }
    let path = path.trim_end_matches('\\');
    format!(
        "
taskkill /F /IM \"{LEGACY_EXE_NAME}\"
if exist \"{path}\\{LEGACY_EXE_NAME}\" del /f /q \"{path}\\{LEGACY_EXE_NAME}\"
"
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
        assert_eq!(crossover_cmds(dir.to_str().unwrap(), cur.to_str().unwrap()), "");
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

    #[test]
    fn legacy_exe_alone_is_detected_and_cleaned() {
        let dir = std::env::temp_dir().join("stlegacy_old");
        std::fs::create_dir_all(&dir).ok();
        let cur = dir.join("sulltecremote.exe");
        std::fs::remove_file(&cur).ok();
        std::fs::write(dir.join(LEGACY_EXE_NAME), b"x").ok();
        let d = dir.to_str().unwrap();
        assert!(installed_legacy_exe(d, cur.to_str().unwrap()).is_some());
        let cmds = crossover_cmds(d, cur.to_str().unwrap());
        assert!(cmds.contains("taskkill"), "{cmds}");
        assert!(cmds.contains(LEGACY_EXE_NAME), "{cmds}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
