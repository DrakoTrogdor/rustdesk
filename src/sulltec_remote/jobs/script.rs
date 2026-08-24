use super::*;

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
    // ⚠ `-File`, NOT `-Command "& script *> file"`, and the redirect is a FILE HANDLE rather than
    // PowerShell's `*>`. Under `-Command` the host reports its own success and a script ending
    // `exit 42` answers 1, while appending `; exit $LASTEXITCODE` answers 7 for a script whose
    // mid-way `robocopy` exited 7 and then finished — a lie about a successful run. `-File` reports
    // the script's own `exit` and 0 when it never called one. Handing the child a file rather than a
    // pipe is what keeps native-command output.
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
    let spawned = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&ps1)
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
    Settled::Result(Some(json!({ "ok": status.success(), "exit": status.code(), "output": combined })))
}

#[cfg(not(windows))]
pub(super) fn run_script(_params: Option<&str>, _ceiling_secs: u64, _job_id: &str) -> Settled {
    Settled::Result(Some(json!({ "ok": false, "error": "Windows-only" })))
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
    // `*>` captures all six PowerShell streams.
    let wrapper_ps = format!(
        "$ErrorActionPreference='Continue'\r\nSet-Content -LiteralPath '{pidfile}' -Value $PID\r\ntry {{ & '{inner}' *> '{out}' }} catch {{ \"$_\" | Out-File -LiteralPath '{out}' -Append }} finally {{ Set-Content -LiteralPath '{flag}' -Value 'done' }}\r\n",
        pidfile = pidfile.display(),
        inner = inner.display(),
        out = out.display(),
        flag = flag.display(),
    );
    if std::fs::write(&wrapper, wrapper_ps.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to write wrapper" })));
    }
    let ps = powershell_exe();
    let wrapper_str = wrapper.display().to_string();
    let launch = if mode == "credential" {
        let arg = format!("-ExecutionPolicy Bypass -NoProfile -File \"{wrapper_str}\"");
        crate::platform::create_process_with_logon(username, password, &ps, &arg)
    } else {
        let session = crate::platform::get_current_session_id(false);
        crate::platform::run_exe_in_session(
            &ps,
            vec!["-ExecutionPolicy", "Bypass", "-NoProfile", "-File", wrapper_str.as_str()],
            session,
            false,
        )
        .map(|_| ())
    };
    if let Err(e) = launch {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": format!("launch failed ({mode}): {e}") })));
    }
    // Recorded before the wait, not after it: a client that dies in the next moment must still
    // leave behind the address of the answer being written.
    adopt::record_dir(job_id, &dir);
    // The launchers gave us no handle to wait on.
    let deadline = now_secs() + ceiling_secs as i64;
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
    Settled::Result(Some(json!({ "ok": true, "output": output, "run_as": mode })))
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
    let answer = recovered_answer(job_id, code, &output).to_string();
    Some(("done", answer, dir))
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
