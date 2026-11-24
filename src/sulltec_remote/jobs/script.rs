use super::*;

/// Windows resolves `-ExecutionPolicy Bypass` into the Process scope, which MachinePolicy and
/// UserPolicy both outrank.
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

#[cfg(windows)]
const UNSIGNED_REFUSED: &str =
    "this device only runs signed scripts (execution policy AllSigned/Restricted); the script is unsigned";

#[cfg(windows)]
pub(super) const EXECUTOR_SIGNED_FILE: &str = "signed-file";

#[cfg(windows)]
const SIGNED_MARKER: &str = "signed.flag";

#[cfg(windows)]
const SIGNATURE_REFUSALS: &[&str] = &[
    "is not digitally signed",
    "cannot be loaded because running scripts is disabled",
    "does not support user interaction",
];

#[cfg(windows)]
const SHA256_MISMATCH: &str = "script bytes do not match the sha256 the console sent; nothing was run";

#[cfg(windows)]
const WRITTEN_MISMATCH: &str =
    "the script file written to disk does not match the sha256 the console sent; nothing was run";

#[cfg(windows)]
fn signature_refused(output: &str) -> bool {
    SIGNATURE_REFUSALS.iter().any(|s| output.contains(s))
}

#[cfg(windows)]
fn sha256_hex(bytes: &[u8]) -> String {
    use hbb_common::sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

#[cfg(windows)]
fn write_script(path: &std::path::Path, body: &ScriptBody) -> Result<(), &'static str> {
    std::fs::write(path, &body.bytes).map_err(|_| "failed to write script")?;
    let back = std::fs::read(path)
        .map_err(|_| "could not read the script file back to verify its sha256; nothing was run")?;
    match sha256_hex(&back) == body.sha256 {
        true => Ok(()),
        false => Err(WRITTEN_MISMATCH),
    }
}

#[cfg(windows)]
struct Run {
    status: std::process::ExitStatus,
    output: String,
}

#[cfg(windows)]
fn spawn_system_run(
    dir: &std::path::Path,
    ps1: &std::path::Path,
    out_file: &std::path::Path,
    deadline: std::time::Instant,
    ceiling_secs: u64,
    job_id: &str,
) -> Result<Run, Settled> {
    // Handing the child a file rather than a pipe is what keeps native-command output.
    let Ok(sink) = std::fs::OpenOptions::new().create(true).append(true).open(out_file) else {
        let _ = std::fs::remove_dir_all(dir);
        return Err(Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job output file" }))));
    };
    // A second handle opened for writing keeps its own file pointer and would overwrite what the
    // first wrote.
    let Ok(err_sink) = sink.try_clone() else {
        let _ = std::fs::remove_dir_all(dir);
        return Err(Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job error file" }))));
    };
    let args: Vec<std::ffi::OsString> = vec![
        "-NonInteractive".into(),
        "-NoProfile".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-File".into(),
        ps1.into(),
    ];
    let spawned = system_token::spawn(&powershell_exe(), &args, sink, err_sink, job_id);
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            let _ = std::fs::remove_dir_all(dir);
            return Err(Settled::Result(Some(json!({ "ok": false, "error": e.to_string() }))));
        }
    };
    adopt::record_run(job_id, child.id(), Some(dir));
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
        return Err(Settled::OverTime);
    };
    let (captured, read_err) = match read_ps_output(out_file) {
        Ok(s) => (s, String::new()),
        Err(e) => (String::new(), format!("[console: the script ran but its captured output could not be read: {e}]")),
    };
    Ok(Run { status, output: format!("{captured}{read_err}") })
}

#[cfg(windows)]
fn jobs_root() -> Result<std::path::PathBuf, String> {
    match crate::platform::is_root() {
        true => crate::sulltec_remote::system_dir::ensure("jobs"),
        false => Ok(std::path::PathBuf::from(r"C:\Windows\Temp")),
    }
}

#[cfg(windows)]
fn job_dir_path(nonce: u128) -> Result<std::path::PathBuf, Settled> {
    jobs_root()
        .map(|root| root.join(format!("sulltec-job-{}-{}", std::process::id(), nonce)))
        .map_err(|e| Settled::Result(Some(json!({ "ok": false, "error": format!("failed to prepare the job directory: {e}") }))))
}

#[cfg(windows)]
pub(super) fn run_script(params: Option<&str>, ceiling_secs: u64, job_id: &str) -> Settled {
    let raw = params.unwrap_or("").trim();
    if raw.is_empty() {
        return Settled::Result(Some(json!({ "ok": false, "error": "no script provided" })));
    }
    let ScriptParams { body, run_as, username, password, session_id } = match parse_script_params(raw) {
        Ok(p) => p,
        Err(e) => return Settled::Result(Some(json!({ "ok": false, "error": e }))),
    };
    if !body.signed && unsigned_file_refused() {
        return Settled::Result(Some(json!({ "ok": false, "error": UNSIGNED_REFUSED })));
    }
    if run_as == "user" || run_as == "credential" {
        return run_script_as(&body, &run_as, &username, &password, session_id, ceiling_secs, job_id);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = match job_dir_path(nonce) {
        Ok(dir) => dir,
        Err(settled) => return settled,
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to create job temp dir" })));
    }
    let ps1 = dir.join("job.ps1");
    if let Err(e) = write_script(&ps1, &body) {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": e })));
    }
    let out_file = dir.join("out.txt");
    let signed = body.signed;
    if signed {
        let _ = std::fs::write(dir.join(SIGNED_MARKER), EXECUTOR_SIGNED_FILE.as_bytes());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ceiling_secs);
    let run = match spawn_system_run(&dir, &ps1, &out_file, deadline, ceiling_secs, job_id) {
        Ok(run) => run,
        Err(settled) => return settled,
    };
    let refused = signed && !run.status.success() && signature_refused(&run.output);
    let _ = std::fs::remove_dir_all(&dir);
    let combined: String = run.output.chars().take(60_000).collect();
    let mut answer = json!({ "ok": run.status.success(), "exit": run.status.code(), "output": combined });
    if signed {
        answer["executor"] = json!(EXECUTOR_SIGNED_FILE);
    }
    if refused {
        answer["signature_refused"] = json!(true);
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

/// A job directory grants SYSTEM and Administrators alone, and a session launch borrows a
/// UAC-filtered token whose Administrators SID is deny-only.
#[cfg(windows)]
fn grant_access_to_runner(dir: &std::path::Path, who: &str) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let args: Vec<String> = vec![
        dir.display().to_string(),
        "/grant".into(),
        format!("{who}:(OI)(CI)RX"),
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

#[cfg(windows)]
fn session_user_sid(session_id: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    let raw = crate::platform::get_user_token(session_id, true);
    if raw.is_null() {
        return None;
    }
    let token = HANDLE(raw as *mut core::ffi::c_void);
    unsafe {
        let mut len: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
        let read = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
        let _ = CloseHandle(token);
        read.ok()?;
        let user = &*buf.as_ptr().cast::<TOKEN_USER>();
        crate::sulltec_remote::system_dir::sid_string(user.User.Sid)
    }
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
    pub struct StartupInfoExW {
        pub startup_info: StartupInfoW,
        pub lp_attribute_list: *mut c_void,
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
        pub fn LogonUserW(
            lp_username: *const u16,
            lp_domain: *const u16,
            lp_password: *const u16,
            dw_logon_type: u32,
            dw_logon_provider: u32,
            ph_token: *mut Handle,
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
        pub fn SetHandleInformation(h_object: Handle, dw_mask: u32, dw_flags: u32) -> i32;
        pub fn InitializeProcThreadAttributeList(
            lp_attribute_list: *mut c_void,
            dw_attribute_count: u32,
            dw_flags: u32,
            lp_size: *mut usize,
        ) -> i32;
        pub fn UpdateProcThreadAttribute(
            lp_attribute_list: *mut c_void,
            dw_flags: u32,
            attribute: usize,
            lp_value: *const c_void,
            cb_size: usize,
            lp_previous_value: *mut c_void,
            lp_return_size: *mut usize,
        ) -> i32;
        pub fn DeleteProcThreadAttributeList(lp_attribute_list: *mut c_void);
        pub fn WaitForSingleObject(h_handle: Handle, dw_milliseconds: u32) -> u32;
        pub fn GetExitCodeProcess(h_process: Handle, lp_exit_code: *mut u32) -> i32;
    }
}

#[cfg(windows)]
struct RunAsChild {
    process: session_launch::Handle,
    pid: u32,
}

#[cfg(windows)]
impl Drop for RunAsChild {
    fn drop(&mut self) {
        unsafe {
            session_launch::CloseHandle(self.process);
        }
    }
}

#[cfg(windows)]
impl RunAsChild {
    fn try_wait(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        use std::os::windows::process::ExitStatusExt;
        const WAIT_OBJECT_0: u32 = 0;
        const WAIT_TIMEOUT: u32 = 0x0000_0102;
        unsafe {
            match session_launch::WaitForSingleObject(self.process, 0) {
                WAIT_OBJECT_0 => {
                    let mut code: u32 = 0;
                    match session_launch::GetExitCodeProcess(self.process, &mut code) != 0 {
                        true => Ok(Some(std::process::ExitStatus::from_raw(code))),
                        false => Err(std::io::Error::last_os_error()),
                    }
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }
}

#[cfg(windows)]
fn launch_in_session(
    cmd: &str,
    session_id: u32,
    stdout: &std::fs::File,
    stderr: &std::fs::File,
) -> Result<RunAsChild, String> {
    let token = crate::platform::get_user_token(session_id, true) as session_launch::Handle;
    if token.is_null() {
        return Err(format!(
            "no interactive token for session {session_id}: that session has no explorer.exe"
        ));
    }
    launch_with_token(cmd, token, stdout, stderr)
}

/// `CreateProcessWithLogonW` answers `ERROR_ACCESS_DENIED` to a LocalSystem caller — it reads a
/// logon SID out of the caller's token and SYSTEM's does not carry one.
/// ⚠ The logon type must be `BATCH`: an `INTERACTIVE` token creates a process that reports success
/// and then exits without running, the way `DETACHED_PROCESS` does above.
#[cfg(windows)]
fn launch_as_credential(
    cmd: &str,
    username: &str,
    password: &str,
    stdout: &std::fs::File,
    stderr: &std::fs::File,
) -> Result<RunAsChild, String> {
    use session_launch::*;
    use std::os::windows::ffi::OsStrExt;
    const LOGON32_LOGON_BATCH: u32 = 4;
    const LOGON32_PROVIDER_DEFAULT: u32 = 0;
    let wide = |s: &str| -> Vec<u16> { std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect() };

    let (domain, user) = match username.split_once('\\') {
        Some((d, u)) => (Some(wide(d)), wide(u)),
        None => (None, wide(username)),
    };
    let wpwd = wide(password);
    let mut token: Handle = std::ptr::null_mut();
    let ok = unsafe {
        LogonUserW(
            user.as_ptr(),
            domain.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            wpwd.as_ptr(),
            LOGON32_LOGON_BATCH,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        ) != 0
    };
    if !ok {
        return Err(format!("LogonUser failed: {}", std::io::Error::last_os_error()));
    }
    launch_with_token(cmd, token, stdout, stderr)
}

#[cfg(windows)]
fn launch_with_token(
    cmd: &str,
    token: session_launch::Handle,
    stdout: &std::fs::File,
    stderr: &std::fs::File,
) -> Result<RunAsChild, String> {
    use session_launch::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const SW_HIDE: u16 = 0;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

    let stdin = match std::fs::OpenOptions::new().read(true).open("NUL") {
        Ok(f) => f,
        Err(e) => {
            unsafe {
                CloseHandle(token);
            }
            return Err(format!("opening NUL failed: {e}"));
        }
    };
    let handles: [Handle; 3] = [stdin.as_raw_handle(), stdout.as_raw_handle(), stderr.as_raw_handle()];
    let mut wcmd: Vec<u16> = std::ffi::OsStr::new(cmd).encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut env: *mut std::os::raw::c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, token, 1) != 0;
        let mut size: usize = 0;
        let _ = InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let list: *mut std::os::raw::c_void = storage.as_mut_ptr().cast();
        let mut pi: ProcessInformation = std::mem::zeroed();
        let launched = if InitializeProcThreadAttributeList(list, 1, 0, &mut size) == 0 {
            Err(format!("InitializeProcThreadAttributeList failed: {}", std::io::Error::last_os_error()))
        } else {
            let made = if UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_ptr().cast(),
                std::mem::size_of_val(&handles),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                Err(format!("UpdateProcThreadAttribute failed: {}", std::io::Error::last_os_error()))
            } else if handles.iter().any(|h| SetHandleInformation(*h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0) {
                Err(format!("SetHandleInformation failed: {}", std::io::Error::last_os_error()))
            } else {
                let mut si: StartupInfoExW = std::mem::zeroed();
                si.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as _;
                si.startup_info.dw_flags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                si.startup_info.w_show_window = SW_HIDE;
                si.startup_info.h_std_input = handles[0];
                si.startup_info.h_std_output = handles[1];
                si.startup_info.h_std_error = handles[2];
                si.lp_attribute_list = list;
                let flags = CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT
                    | if have_env { CREATE_UNICODE_ENVIRONMENT } else { 0 };
                let ok = CreateProcessAsUserW(
                    token,
                    std::ptr::null(),
                    wcmd.as_mut_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    1,
                    flags,
                    if have_env { env } else { std::ptr::null_mut() },
                    std::ptr::null(),
                    &mut si.startup_info,
                    &mut pi,
                ) != 0;
                match ok {
                    true => Ok(()),
                    false => Err(format!("CreateProcessAsUser failed: {}", std::io::Error::last_os_error())),
                }
            };
            DeleteProcThreadAttributeList(list);
            made
        };
        for h in handles {
            SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
        }
        if have_env {
            DestroyEnvironmentBlock(env);
        }
        CloseHandle(token);
        launched.map(|()| {
            CloseHandle(pi.h_thread);
            RunAsChild { process: pi.h_process, pid: pi.dw_process_id }
        })
    }
}

#[cfg(windows)]
pub(super) fn run_script_as(
    body: &ScriptBody,
    mode: &str,
    username: &str,
    password: &str,
    session_id: Option<u32>,
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
    let dir = match job_dir_path(nonce) {
        Ok(dir) => dir,
        Err(settled) => return settled,
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to create job temp dir" })));
    }
    let ps1 = dir.join("job.ps1");
    if let Err(e) = write_script(&ps1, body) {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": e })));
    }
    let signed = body.signed;
    if signed {
        let _ = std::fs::write(dir.join(SIGNED_MARKER), EXECUTOR_SIGNED_FILE.as_bytes());
    }
    let target_session = session_id.unwrap_or_else(|| crate::platform::get_current_session_id(false));
    let who = match mode {
        "credential" => username.to_string(),
        _ => match session_user_sid(target_session) {
            Some(sid) => format!("*{sid}"),
            None => {
                let _ = std::fs::remove_dir_all(&dir);
                return Settled::Result(Some(json!({ "ok": false, "error": format!("run-as ({mode}): could not read the session user's SID") })));
            }
        },
    };
    if !grant_access_to_runner(&dir, &who) {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": format!("run-as ({mode}): could not grant the launching identity read access to the job directory") })));
    }
    let out_file = dir.join("out.txt");
    let launch = {
        let Ok(sink) = std::fs::OpenOptions::new().create(true).append(true).open(&out_file) else {
            let _ = std::fs::remove_dir_all(&dir);
            return Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job output file" })));
        };
        let Ok(err_sink) = sink.try_clone() else {
            let _ = std::fs::remove_dir_all(&dir);
            return Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job error file" })));
        };
        let cmd = format!(
            "\"{}\" -NonInteractive -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
            powershell_exe(),
            ps1.display()
        );
        match mode {
            "credential" => launch_as_credential(&cmd, username, password, &sink, &err_sink),
            _ => launch_in_session(&cmd, target_session, &sink, &err_sink),
        }
    };
    let child = match launch {
        Ok(child) => child,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Settled::Result(Some(json!({ "ok": false, "error": format!("launch failed ({mode}): {e}") })));
        }
    };
    adopt::record_run(job_id, child.pid, Some(&dir));
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
        hbb_common::log::warn!("console job {job_id}: the run-as script passed {ceiling_secs}s and was left running");
        return Settled::OverTime;
    };
    let output = match read_ps_output(&out_file) {
        Ok(s) => s,
        Err(e) => format!("[console: the script ran but its captured output could not be read: {e}]"),
    };
    let refused = signed && !status.success() && signature_refused(&output);
    let _ = std::fs::remove_dir_all(&dir);
    let combined: String = output.chars().take(60_000).collect();
    let mut answer = json!({ "ok": status.success(), "exit": status.code(), "output": combined, "run_as": mode });
    if signed {
        answer["executor"] = json!(EXECUTOR_SIGNED_FILE);
    }
    if refused {
        answer["signature_refused"] = json!(true);
    }
    if seen_flag(job_id, SEEN_KILLED).is_some() {
        answer["killed"] = json!(RESULT_KILLED);
    }
    Settled::Result(Some(answer))
}

#[cfg(windows)]
pub(super) fn settle_script(job_id: &str, code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    let dir = seen_job_dir(job_id)?;
    // ⚠ BEFORE any read: `read_ps_output` maps NotFound to `Ok("")`, so a swept directory would
    // otherwise be published as the script having answered nothing.
    if !dir.is_dir() {
        return None;
    }
    let code = code?;
    let output: String = match read_ps_output(&dir.join("out.txt")) {
        Ok(s) => s,
        Err(e) => format!("[console: the script ran but its captured output could not be read: {e}]"),
    }
    .chars()
    .take(60_000)
    .collect();
    let mut answer = recovered_answer(job_id, code, &output);
    if dir.join(SIGNED_MARKER).is_file() {
        answer["executor"] = json!(EXECUTOR_SIGNED_FILE);
    }
    Some(("done", answer.to_string(), dir))
}

#[cfg(not(windows))]
pub(super) fn settle_script(_job_id: &str, _code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    None
}

#[cfg(windows)]
pub(super) fn still_running(job_id: &str) -> bool {
    let Some(dir) = seen_job_dir(job_id) else {
        return false;
    };
    if !dir.is_dir() {
        return false;
    }
    match seen_child(job_id) {
        Some((pid, created)) => adopt::alive(pid, created),
        None => false,
    }
}

#[cfg(not(windows))]
pub(super) fn still_running(_job_id: &str) -> bool {
    false
}

#[cfg(windows)]
fn recovered_answer(job_id: &str, code: u32, output: &str) -> Value {
    let began = if seen_flag(job_id, SEEN_KILLED).is_some() {
        "this device ended this script's process on request while it was running"
    } else if seen_flag(job_id, SEEN_OVER_TIME).is_some() {
        "this script passed the bound it was given and this device stopped waiting for it without \
         killing it"
    } else {
        "the client that started this script stopped while it was running"
    };
    let recovered = format!(
        "{began}. This device kept a handle on the PowerShell process it had launched, watched it \
         exit, and read the run's output back off the file that process had been writing — so the \
         output and the exit code here are this run's own. What this device cannot tell you is \
         whether that process ended on its own or was cut off, so output that stops mid-line is a \
         truncation and not the script's last word."
    );
    let mut answer = json!({
        "ok": code == 0,
        "output": output,
        "recovered": recovered,
    });
    // `as i32` is the reinterpretation Windows `ExitStatus::code()` performs, so an access violation
    // serialises as -1073741819 the way every live run reports it.
    answer["exit"] = json!(code as i32);
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
    let Ok(root) = jobs_root() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(root) else {
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
pub(super) struct ScriptParams {
    pub(super) body: ScriptBody,
    pub(super) run_as: String,
    pub(super) username: String,
    pub(super) password: String,
    pub(super) session_id: Option<u32>,
}

#[cfg(windows)]
pub(super) struct ScriptBody {
    bytes: Vec<u8>,
    sha256: String,
    signed: bool,
}

#[cfg(windows)]
pub(super) fn parse_script_params(raw: &str) -> Result<ScriptParams, String> {
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return Err("the script job's params are not JSON; nothing was run".to_string());
    };
    let f = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let Some(b64) = v.get("script_b64").and_then(|x| x.as_str()) else {
        return Err("the script job carries no script_b64; nothing was run".to_string());
    };
    let sha256 = f("sha256").trim().to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("script_b64 needs a sha256 of 64 hex characters beside it; nothing was run".to_string());
    }
    let Ok(bytes) = base64::decode(b64.trim(), variant()) else {
        return Err("script_b64 is not valid base64; nothing was run".to_string());
    };
    if sha256_hex(&bytes) != sha256 {
        return Err(SHA256_MISMATCH.to_string());
    }
    let session_id = match v.get("session_id") {
        None | Some(Value::Null) => None,
        Some(s) => match s.as_u64().or_else(|| s.as_str().and_then(|t| t.trim().parse().ok())).and_then(|n| u32::try_from(n).ok()) {
            Some(n) => Some(n),
            None => return Err(format!("session_id {s} is not a Windows session id; nothing was run")),
        },
    };
    Ok(ScriptParams {
        body: ScriptBody { bytes, sha256, signed: !f("signer_thumbprint").trim().is_empty() },
        run_as: v.get("run_as").and_then(|x| x.as_str()).unwrap_or("system").to_string(),
        username: f("username"),
        password: f("password"),
        session_id,
    })
}
