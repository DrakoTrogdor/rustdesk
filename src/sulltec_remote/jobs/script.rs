use super::*;

/// Windows resolves `-ExecutionPolicy Bypass` into the Process scope, which MachinePolicy and
/// UserPolicy both outrank, so the engine is asked what a `-File` run would actually be given
/// rather than assuming the command line won.
#[cfg(windows)]
fn unsigned_file_refused() -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-ExecutionPolicy"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output();
    match out {
        Ok(out) => matches!(decode_ps_bytes(&out.stdout).trim().to_ascii_lowercase().as_str(), "allsigned" | "restricted"),
        Err(_) => false,
    }
}

/// Reads the source rather than being handed it, so a 64K script is not squeezed through the
/// 32767-character command line an `-EncodedCommand` of the source itself would need.
#[cfg(windows)]
fn load_script_expr(path: &std::path::Path) -> String {
    format!("& ([scriptblock]::Create([IO.File]::ReadAllText('{}',[Text.Encoding]::UTF8)))", path.display())
}

/// `Out-String` rather than the host's own renderer: a service has no console to take a width from,
/// and `*>&1` keeps the error and warning streams off the process's stderr, where PowerShell would
/// serialise them as CLIXML.
#[cfg(windows)]
fn encoded_run(ps1: &std::path::Path) -> String {
    let body = format!(
        "$ProgressPreference='SilentlyContinue'\r\n{} *>&1 | Out-String -Stream -Width 512 | Write-Output\r\nexit 0\r\n",
        load_script_expr(ps1)
    );
    encoded_command(&body)
}

#[cfg(windows)]
pub(super) fn encoded_command(body: &str) -> String {
    use hbb_common::sodiumoxide::base64;
    let utf16: Vec<u8> = body.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::encode(&utf16, base64::Variant::Original)
}

#[cfg(windows)]
pub(super) const EXECUTOR_ENCODED: &str =
    "this device's execution policy refuses unsigned script files, so the source was handed to \
     PowerShell as an encoded command rather than run as a .ps1. The exit code is the script's own, \
     but this path renders the error and warning streams differently: an uncaught terminating error \
     arrives as a CLIXML block instead of the plain text a normal run shows, a non-terminating error \
     carries the loader's own line beside it, and output that a native command sent to stderr can \
     land out of order.";

#[cfg(windows)]
const ENCODED_MARKER: &str = "encoded.flag";

#[cfg(windows)]
pub(super) fn run_script(params: Option<&str>, ceiling_secs: u64, job_id: &str) -> Settled {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let raw = params.unwrap_or("").trim();
    if raw.is_empty() {
        return Settled::Result(Some(json!({ "ok": false, "error": "no script provided" })));
    }
    let (script, run_as, username, password) = parse_script_params(raw);
    if run_as == "user" || run_as == "credential" {
        return run_script_as(&script, &run_as, &username, &password, ceiling_secs, job_id);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::path::Path::new(r"C:\Windows\Temp").join(format!("sulltec-job-{}-{}", std::process::id(), nonce));
    if std::fs::create_dir_all(&dir).is_err() {
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to create job temp dir" })));
    }
    let ps1 = dir.join("job.ps1");
    if std::fs::write(&ps1, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to write script" })));
    }
    let out_file = dir.join("out.txt");
    // Handing the child a file rather than a pipe is what keeps native-command output.
    let Ok(sink) = std::fs::OpenOptions::new().create(true).append(true).open(&out_file) else {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job output file" })));
    };
    // A second handle opened for writing keeps its own file pointer and would overwrite what the
    // first wrote.
    let Ok(err_sink) = sink.try_clone() else {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job error file" })));
    };
    let encoded = unsigned_file_refused();
    if encoded {
        let _ = std::fs::write(dir.join(ENCODED_MARKER), EXECUTOR_ENCODED.as_bytes());
    }
    let mut cmd = std::process::Command::new(powershell_exe());
    match encoded {
        true => cmd.args(["-NonInteractive", "-NoProfile", "-EncodedCommand"]).arg(encoded_run(&ps1)),
        false => cmd.args(["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(&ps1),
    };
    let spawned = cmd
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(sink))
        .stderr(std::process::Stdio::from(err_sink))
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Settled::Result(Some(json!({ "ok": false, "error": e.to_string() })));
        }
    };
    adopt::record_run(job_id, child.id(), Some(&dir));
    // No drain: both streams are file handles, so there is no pipe for the child to fill and block on.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ceiling_secs);
    let mut nap = std::time::Duration::from_millis(2);
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(_) => break None,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(std::time::Duration::from_millis(250));
    };
    let Some(status) = finished else {
        adopt::hold(job_id);
        mark_job_stamp(job_id, SEEN_OVER_TIME);
        hbb_common::log::warn!("console job {job_id}: the script passed {ceiling_secs}s and was left running");
        // ⚠ The directory STAYS and nothing is read out of it: a half-written `out.txt` published
        // now would be a live script's last word.
        return Settled::OverTime;
    };
    let captured = read_ps_output(&out_file);
    let _ = std::fs::remove_dir_all(&dir);
    let (captured, read_err) = match captured {
        Ok(s) => (s, String::new()),
        Err(e) => (String::new(), format!("[console: the script ran but its captured output could not be read: {e}]")),
    };
    let combined: String = format!("{captured}{read_err}").chars().take(60_000).collect();
    let mut answer = json!({ "ok": status.success(), "exit": status.code(), "output": combined });
    if encoded {
        answer["executor"] = json!(EXECUTOR_ENCODED);
    }
    if seen_flag(job_id, SEEN_KILLED).is_some() {
        answer["killed"] = json!(RESULT_KILLED);
    }
    Settled::Result(Some(answer))
}

#[cfg(not(windows))]
pub(super) fn run_script(_params: Option<&str>, _ceiling_secs: u64, _job_id: &str) -> Settled {
    Settled::Result(Some(json!({ "ok": false, "error": "Windows-only" })))
}

#[cfg(windows)]
const LAUNCH_GRACE_SECS: i64 = 30;

/// A job directory inherits `C:\Windows\Temp`'s `Users` entry, which is container-inherit only, so
/// the files in it grant SYSTEM, Administrators and the creator alone — and a session launch
/// borrows a UAC-filtered token whose Administrators SID is deny-only. The grant is Modify because
/// the runner creates `pid.txt`, `out.txt` and `done.flag` in the directory. `S-1-5-4` is the
/// interactive logon set, which `Users` on a workstation is not.
#[cfg(windows)]
fn grant_access_to_runner(dir: &std::path::Path, mode: &str, username: &str) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let who = match mode {
        "credential" if !username.is_empty() => username.to_string(),
        _ => "*S-1-5-4".to_string(),
    };
    let args: Vec<String> = vec![
        dir.display().to_string(),
        "/grant".into(),
        format!("{who}:(OI)(CI)M"),
        "/T".into(),
        "/C".into(),
        "/Q".into(),
    ];
    std::process::Command::new("icacls.exe")
        .args(&args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Upstream's `LaunchProcessWin` creates the process with `DETACHED_PROCESS`, which leaves a
/// console program with no console: `powershell.exe` exits 0 before its first statement while
/// `CreateProcessAsUser` reports success, so the caller holds a handle to a process that ran
/// nothing. This is that call with `CREATE_NO_WINDOW` in its place.
#[cfg(windows)]
mod session_launch {
    use std::os::raw::c_void;

    pub type Handle = *mut c_void;

    #[repr(C)]
    pub struct StartupInfoW {
        pub cb: u32,
        pub lp_reserved: *mut u16,
        pub lp_desktop: *mut u16,
        pub lp_title: *mut u16,
        pub dw_x: u32,
        pub dw_y: u32,
        pub dw_x_size: u32,
        pub dw_y_size: u32,
        pub dw_x_count_chars: u32,
        pub dw_y_count_chars: u32,
        pub dw_fill_attribute: u32,
        pub dw_flags: u32,
        pub w_show_window: u16,
        pub cb_reserved2: u16,
        pub lp_reserved2: *mut u8,
        pub h_std_input: Handle,
        pub h_std_output: Handle,
        pub h_std_error: Handle,
    }

    #[repr(C)]
    pub struct ProcessInformation {
        pub h_process: Handle,
        pub h_thread: Handle,
        pub dw_process_id: u32,
        pub dw_thread_id: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn CreateProcessAsUserW(
            h_token: Handle,
            lp_application_name: *const u16,
            lp_command_line: *mut u16,
            lp_process_attributes: *mut c_void,
            lp_thread_attributes: *mut c_void,
            b_inherit_handles: i32,
            dw_creation_flags: u32,
            lp_environment: *mut c_void,
            lp_current_directory: *const u16,
            lp_startup_info: *mut StartupInfoW,
            lp_process_information: *mut ProcessInformation,
        ) -> i32;
    }

    #[link(name = "userenv")]
    extern "system" {
        pub fn CreateEnvironmentBlock(
            lp_environment: *mut *mut c_void,
            h_token: Handle,
            b_inherit: i32,
        ) -> i32;
        pub fn DestroyEnvironmentBlock(lp_environment: *mut c_void) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CloseHandle(h: Handle) -> i32;
    }
}

#[cfg(windows)]
fn launch_in_session(cmd: &str, session_id: u32) -> Result<(), String> {
    use session_launch::*;
    use std::os::windows::ffi::OsStrExt;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
    const SW_HIDE: u16 = 0;

    let token = crate::platform::get_user_token(session_id, true) as Handle;
    if token.is_null() {
        return Err(format!(
            "no interactive token for session {session_id}: that session has no explorer.exe"
        ));
    }
    let mut wcmd: Vec<u16> = std::ffi::OsStr::new(cmd).encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut env: *mut std::os::raw::c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, token, 1) != 0;
        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as _;
        si.dw_flags = STARTF_USESHOWWINDOW;
        si.w_show_window = SW_HIDE;
        let mut pi: ProcessInformation = std::mem::zeroed();
        let flags = CREATE_NO_WINDOW | if have_env { CREATE_UNICODE_ENVIRONMENT } else { 0 };
        let ok = CreateProcessAsUserW(
            token,
            std::ptr::null(),
            wcmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            flags,
            if have_env { env } else { std::ptr::null_mut() },
            std::ptr::null(),
            &mut si,
            &mut pi,
        ) != 0;
        let err = std::io::Error::last_os_error();
        if ok {
            CloseHandle(pi.h_thread);
            CloseHandle(pi.h_process);
        }
        if have_env {
            DestroyEnvironmentBlock(env);
        }
        CloseHandle(token);
        match ok {
            true => Ok(()),
            false => Err(format!("CreateProcessAsUser failed: {err}")),
        }
    }
}

#[cfg(windows)]
pub(super) fn run_script_as(
    script: &str,
    mode: &str,
    username: &str,
    password: &str,
    ceiling_secs: u64,
    job_id: &str,
) -> Settled {
    if mode == "credential" && (username.is_empty() || password.is_empty()) {
        return Settled::Result(Some(json!({ "ok": false, "error": "run-as credential needs a username and password" })));
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::path::Path::new(r"C:\Windows\Temp").join(format!("sulltec-job-{}-{}", std::process::id(), nonce));
    if std::fs::create_dir_all(&dir).is_err() {
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to create job temp dir" })));
    }
    let inner = dir.join("inner.ps1");
    let wrapper = dir.join("wrapper.ps1");
    let out = dir.join("out.txt");
    let flag = dir.join("done.flag");
    let pidfile = dir.join("pid.txt");
    if std::fs::write(&inner, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to write script" })));
    }
    let encoded = unsigned_file_refused();
    if encoded {
        let _ = std::fs::write(dir.join(ENCODED_MARKER), EXECUTOR_ENCODED.as_bytes());
    }
    let invoke = match encoded {
        true => load_script_expr(&inner),
        false => format!("& '{}'", inner.display()),
    };
    // `*>` captures all six PowerShell streams.
    let wrapper_ps = format!(
        "$ErrorActionPreference='Continue'\r\nSet-Content -LiteralPath '{pidfile}' -Value $PID\r\ntry {{ {invoke} *> '{out}' }} catch {{ \"$_\" | Out-File -LiteralPath '{out}' -Append }} finally {{ Set-Content -LiteralPath '{flag}' -Value 'done' }}\r\n",
        pidfile = pidfile.display(),
        out = out.display(),
        flag = flag.display(),
    );
    if std::fs::write(&wrapper, wrapper_ps.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to write wrapper" })));
    }
    if !grant_access_to_runner(&dir, mode, username) {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": format!("run-as ({mode}): could not grant the launching identity read/write access to the job directory") })));
    }
    let ps = powershell_exe();
    let wrapper_str = wrapper.display().to_string();
    let payload = match encoded {
        true => encoded_command(&wrapper_ps),
        false => wrapper_str,
    };
    let launch = if mode == "credential" {
        let arg = match encoded {
            true => format!("-NoProfile -EncodedCommand {payload}"),
            false => format!("-ExecutionPolicy Bypass -NoProfile -File \"{payload}\""),
        };
        crate::platform::create_process_with_logon(username, password, &ps, &arg)
            .map_err(|e| e.to_string())
    } else {
        let session = crate::platform::get_current_session_id(false);
        let args = match encoded {
            true => format!("-NoProfile -EncodedCommand {payload}"),
            false => format!("-ExecutionPolicy Bypass -NoProfile -File \"{payload}\""),
        };
        launch_in_session(&format!("\"{ps}\" {args}"), session)
    };
    if let Err(e) = launch {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": format!("launch failed ({mode}): {e}") })));
    }
    // Recorded before the wait, not after it: a client that dies in the next moment must still
    // leave behind the address of the answer being written.
    adopt::record_dir(job_id, &dir);
    let deadline = now_secs() + ceiling_secs as i64;
    let launch_deadline = now_secs() + LAUNCH_GRACE_SECS.min(ceiling_secs as i64);
    let mut adopted = false;
    while now_secs() < deadline && !flag.exists() {
        if !adopted {
            if let Some(pid) = read_pid_file(&pidfile) {
                // `record` answers false when `OpenProcess` refuses — which a client not running as
                // SYSTEM gets every time for a process it launched under another identity — and
                // treating that as done would leave the run with no pid for its whole life over one
                // failed call.
                adopted = adopt::record(job_id, pid);
            }
        }
        if !pidfile.exists() && now_secs() > launch_deadline {
            let _ = std::fs::remove_dir_all(&dir);
            return Settled::Result(Some(json!({
                "ok": false,
                "error": format!("run-as ({mode}): the wrapper was launched but never started - no pid file after {LAUNCH_GRACE_SECS}s"),
            })));
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    if !flag.exists() {
        adopt::hold(job_id);
        mark_job_stamp(job_id, SEEN_OVER_TIME);
        hbb_common::log::warn!("console job {job_id}: the run-as script passed {ceiling_secs}s and was left running");
        return Settled::OverTime;
    }
    let output: String = read_ps_output(&out)
        .unwrap_or_else(|e| format!("[console: the script's captured output could not be read: {e}]"))
        .chars()
        .take(60_000)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    let mut answer = json!({ "ok": true, "output": output, "run_as": mode });
    if encoded {
        answer["executor"] = json!(EXECUTOR_ENCODED);
    }
    Settled::Result(Some(answer))
}

#[cfg(windows)]
fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    let bytes = std::fs::read(path).ok()?;
    decode_ps_bytes(&bytes).trim().parse::<u32>().ok()
}

/// `code` is DISCARDED for a run-as directory: the adopted process there is the wrapper, whose
/// `finally` always runs, so it exits 0 for a script that threw.
#[cfg(windows)]
pub(super) fn settle_script(job_id: &str, code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    let dir = seen_job_dir(job_id)?;
    // ⚠ BEFORE any read: `read_ps_output` maps NotFound to `Ok("")`, so a swept directory would
    // otherwise be published as the script having answered nothing.
    if !dir.is_dir() {
        return None;
    }
    let run_as = dir.join("wrapper.ps1").exists();
    let code = if run_as { None } else { code };
    let finished = match run_as {
        true => dir.join("done.flag").exists(),
        false => code.is_some(),
    };
    if !finished {
        return None;
    }
    let output: String = match read_ps_output(&dir.join("out.txt")) {
        Ok(s) => s,
        Err(e) => format!("[console: the script ran but its captured output could not be read: {e}]"),
    }
    .chars()
    .take(60_000)
    .collect();
    let mut answer = recovered_answer(job_id, code, &output);
    if dir.join(ENCODED_MARKER).is_file() {
        answer["executor"] = json!(EXECUTOR_ENCODED);
    }
    Some(("done", answer.to_string(), dir))
}

#[cfg(not(windows))]
pub(super) fn settle_script(_job_id: &str, _code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    None
}

/// A pid, once the wrapper has reported one, is the stronger signal and is preferred — a wrapper
/// that died without reaching its `finally` never writes the flag, and waiting on the flag alone
/// would hold the row open for a process that is gone.
#[cfg(windows)]
pub(super) fn still_running(job_id: &str) -> bool {
    let Some(dir) = seen_job_dir(job_id) else {
        return false;
    };
    if !dir.is_dir() || !dir.join("wrapper.ps1").exists() || dir.join("done.flag").exists() {
        return false;
    }
    match seen_child(job_id) {
        Some((pid, created)) => adopt::alive(pid, created),
        None => true,
    }
}

#[cfg(not(windows))]
pub(super) fn still_running(_job_id: &str) -> bool {
    false
}

#[cfg(windows)]
fn recovered_answer(job_id: &str, code: Option<u32>, output: &str) -> Value {
    let began = if seen_flag(job_id, SEEN_KILLED).is_some() {
        "this device ended this script's process on request while it was running"
    } else if seen_flag(job_id, SEEN_OVER_TIME).is_some() {
        "this script passed the bound it was given and this device stopped waiting for it without \
         killing it"
    } else {
        "the client that started this script stopped while it was running"
    };
    let recovered = match code {
        Some(_) => format!(
            "{began}. This device kept a handle on the PowerShell process it had launched, watched it \
             exit, and read the run's output back off the file that process had been writing — so the \
             output and the exit code here are this run's own. What this device cannot tell you is \
             whether that process ended on its own or was cut off, so output that stops mid-line is a \
             truncation and not the script's last word."
        ),
        None => format!(
            "{began}. The script ran under a different identity, outlived the wait, and recorded its \
             own completion; the output here was read back off the file it wrote. There is NO exit \
             code for this run — this executor never produces one — so `ok` means the script reached \
             its end, not that the work it did succeeded."
        ),
    };
    let mut answer = json!({
        "ok": !matches!(code, Some(c) if c != 0),
        "output": output,
        "recovered": recovered,
    });
    // `as i32` is the reinterpretation Windows `ExitStatus::code()` performs, so an access violation
    // serialises as -1073741819 the way every live run reports it.
    if let Some(code) = code {
        answer["exit"] = json!(code as i32);
    }
    answer
}

pub(super) fn discard_settled(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
const JOB_DIR_SWEEP_AGE_SECS: i64 = PS_RUN_HARD_MAX_SECS as i64 + 3600;

#[cfg(windows)]
pub(super) fn sweep_job_dirs() {
    let keep: Vec<String> = serde_json::from_str::<Value>(&LocalConfig::get_option(JOBS_SEEN_OPT))
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
        .values()
        .filter_map(|v| v.get("x").and_then(|x| x.as_str()).map(str::to_lowercase))
        .collect();
    let Ok(entries) = std::fs::read_dir(r"C:\Windows\Temp") else {
        return;
    };
    let mine = format!("sulltec-job-{}-", std::process::id());
    let cutoff = std::time::Duration::from_secs(JOB_DIR_SWEEP_AGE_SECS as u64);
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("sulltec-job-") || name.starts_with(&mine) {
            continue;
        }
        if keep.contains(&path.display().to_string().to_lowercase()) {
            continue;
        }
        let aged = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
            .is_some_and(|age| age > cutoff);
        if aged {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

#[cfg(not(windows))]
pub(super) fn sweep_job_dirs() {}

#[cfg(windows)]
pub(super) fn read_ps_output(path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(decode_ps_bytes(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// `powershell_exe()` is Windows PowerShell 5.1, whose redirect operators default to **UTF-16LE
/// with a `FF FE` BOM** — not UTF-8.
#[cfg(windows)]
pub(super) fn decode_ps_bytes(bytes: &[u8]) -> String {
    let utf16 = |b: &[u8], le: bool| -> String {
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

#[cfg(windows)]
pub(super) fn parse_script_params(raw: &str) -> (String, String, String, String) {
    if raw.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(script) = v.get("script").and_then(|x| x.as_str()) {
                let f = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let run_as = v.get("run_as").and_then(|x| x.as_str()).unwrap_or("system").to_string();
                return (script.to_string(), run_as, f("username"), f("password"));
            }
        }
    }
    (raw.to_string(), "system".to_string(), String::new(), String::new())
}
