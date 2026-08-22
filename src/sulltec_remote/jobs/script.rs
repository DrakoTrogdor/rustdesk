use super::*;

/// Run an operator-supplied PowerShell script. The operation is admin-gated and its parameters use
/// the signed `/params` channel rather than the unauthenticated heartbeat. Captures stdout, stderr,
/// and exit status, truncating the combined output to 60,000 characters to stay within the result
/// cap. Returns `{ok, exit, output}` (or `{ok:false, error}` if the shell couldn't launch).
///
/// `job_id` is what makes this run recoverable: it names the record the PowerShell process and the
/// directory it is writing into are stamped onto, so a client that replaces this one can re-attach to
/// the process and read the answer back off the file rather than report the run abandoned.
///
/// `ceiling_secs` bounds the WAIT and not the work, exactly as it does for the other two executors:
/// when it elapses this stops waiting, kills nothing, and answers [`Settled::OverTime`].
#[cfg(windows)]
pub(super) fn run_script(params: Option<&str>, ceiling_secs: u64, job_id: &str) -> Settled {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let raw = params.unwrap_or("").trim();
    if raw.is_empty() {
        return Settled::Result(Some(json!({ "ok": false, "error": "no script provided" })));
    }
    // Params are either a bare script, which runs in this process's context,
    // or a JSON envelope `{script, run_as, username, password}` selecting an optional run-as identity.
    // The envelope arrives over the signed `/params` channel because scripts are sensitive,
    // so a credential inside it never rides the unauthenticated heartbeat.
    let (script, run_as, username, password) = parse_script_params(raw);
    if run_as == "user" || run_as == "credential" {
        return run_script_as(&script, &run_as, &username, &password, ceiling_secs, job_id);
    }
    // The default runs PowerShell in the client's service/SYSTEM context. A temporary `.ps1` avoids
    // command-line escaping across Rust, PowerShell, and native tools.
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
    // PowerShell's `*>`. Measured on Win2019Test: under `-Command` the host reports its own success
    // and a script ending `exit 42` answers 1, while appending `; exit $LASTEXITCODE` answers 7 for a
    // script whose mid-way `robocopy` exited 7 and then finished — a lie about a successful run.
    // `-File` reports the script's own `exit` and 0 when it never called one. Handing the child a
    // file rather than a pipe is what keeps native-command output, which is why `*>` was here.
    let Ok(sink) = std::fs::OpenOptions::new().create(true).append(true).open(&out_file) else {
        let _ = std::fs::remove_dir_all(&dir);
        return Settled::Result(Some(json!({ "ok": false, "error": "failed to open the job output file" })));
    };
    // One file, two handles, both APPEND — a second handle opened for writing keeps its own file
    // pointer and would overwrite what the first wrote.
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
    // The same loop the other two executors run, for the same reason and with the same outcome.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ceiling_secs);
    let mut nap = std::time::Duration::from_millis(2);
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            // Treat an unreadable process handle as an unfinished run.
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
        // ⚠ The directory STAYS and nothing is read out of it. It is the only copy of the answer, and
        // `settle_script` reads it back once the process ends; a half-written `out.txt` published now
        // would be a live script's last word.
        return Settled::OverTime;
    };
    let captured = read_ps_output(&out_file);
    let _ = std::fs::remove_dir_all(&dir);
    // Keep capture failures distinct from scripts that produced no output.
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

/// Run a script under a different identity than the service: `"user"` = the active console user
/// (CreateProcessAsUser via `run_exe_in_session`), `"credential"` = a supplied account
/// (CreateProcessWithLogonW). Both launchers are fire-and-forget (no waitable child), so we run a
/// wrapper that redirects every PowerShell stream to a temp file and always drops a `done.flag`, then
/// poll for the flag. Temp script + output live in `C:\Windows\Temp\sulltec-job-…` (writable by the
/// target identity) and are deleted afterward; the password is passed only to the Win32 logon API,
/// never to disk.
///
/// `ceiling_secs` bounds the polling and nothing else: past it this stops watching and answers
/// [`Settled::OverTime`], leaving the wrapper running and its directory intact.
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
    // `*>` captures all six PowerShell streams; `finally` guarantees the flag even if the script throws.
    // The shell reports its own `$PID` before it starts work because the launchers surrender none: it
    // is the only handle a later client can re-attach by, and without it a directory with no flag is
    // indistinguishable from a run that is still going.
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
    // Recorded before the wait, not after it: from here on the launch has happened, and a client that
    // dies in the next moment must still leave behind the address of the answer being written.
    adopt::record_dir(job_id, &dir);
    // Poll for completion — the launchers gave us no handle to wait on. The same loop picks the
    // wrapper's PID up the first time it is readable; if it never appears the path degrades to
    // flag-only, which is exactly the information it had before.
    let deadline = now_secs() + ceiling_secs as i64;
    let mut adopted = false;
    while now_secs() < deadline && !flag.exists() {
        if !adopted {
            if let Some(pid) = read_pid_file(&pidfile) {
                // Only a pid that was actually identified ends the hunt. `record` answers false when
                // `OpenProcess` refuses — which a client not running as SYSTEM gets every time for a
                // process it launched under another identity — and treating that as done would leave
                // the run with no pid for its whole life over one failed call.
                adopted = adopt::record(job_id, pid);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    if !flag.exists() {
        // A wrapper that reported its pid is worth holding a handle on: it keeps `settle_child` from
        // logging that the client restarted, which it did not.
        adopt::hold(job_id);
        mark_job_stamp(job_id, SEEN_OVER_TIME);
        hbb_common::log::warn!("console job {job_id}: the run-as script passed {ceiling_secs}s and was left running");
        // ⚠ The directory STAYS and the half-written `out.txt` is NOT published. There is no completion
        // marker, so nothing in it is the script's answer — and deleting it would take the working
        // directory out from under a live wrapper and disable recovery for good.
        return Settled::OverTime;
    }
    // Same BOM-decode as the SYSTEM path: the wrapper redirects with `*>`, so 5.1 writes UTF-16LE.
    let output: String = read_ps_output(&out)
        .unwrap_or_else(|e| format!("[console: the script's captured output could not be read: {e}]"))
        .chars()
        .take(60_000)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    Settled::Result(Some(json!({ "ok": true, "output": output, "run_as": mode })))
}

/// The PID the wrapper wrote for itself, once it has written it.
#[cfg(windows)]
fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    let bytes = std::fs::read(path).ok()?;
    decode_ps_bytes(&bytes).trim().parse::<u32>().ok()
}

/// What this device can report for a script job it did not run, read off what the run left on disk.
///
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
    // ⚠ PROOF, not inference: with no code and no marker there is NO liveness signal, and answering
    // would publish a half-written `out.txt` and delete the directory under a live script.
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
    // `done` for the same reason the live executor uses it for every script answer whatever the
    // script did: the status says an answer was produced, and `ok` inside it says how the run went.
    Some(("done", answer, dir))
}

#[cfg(not(windows))]
pub(super) fn settle_script(_job_id: &str, _code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    None
}

/// Whether the run-as script recorded for `job_id` is still going, read off what it left on disk.
///
/// The wrapper's `done.flag` is the only completion signal that path has: it surrenders no waitable
/// handle, so a directory with a wrapper and no flag is a run nothing here has seen end. A pid, once
/// the wrapper has reported one, is the stronger signal and is preferred — a wrapper that died without
/// reaching its `finally` never writes the flag, and waiting on the flag alone would hold the row open
/// for a process that is gone.
///
/// ⚠ What this guards is [`settle_started`]'s abandoned answer. Since a bound stopped decapitating the
/// run, a run-as script that passes it is still running on the very next beat, and settling it as
/// abandoned would close the row of a script that is mid-change.
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

/// The answer a recovered run reports, and what about it this device does not know.
///
/// The `recovered` key is mandatory: nothing here was watched from start to finish by the client
/// posting it, and an answer that read like an ordinary one would hide that.
///
/// WHY it was not watched comes off the record and is never guessed: a run this device stopped WAITING
/// for is one it started and is still holding, and calling that a client that stopped would say the
/// client had gone when it is right here.
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

/// ⚠ Callers must have proved BOTH that the run ended and that the console stored the answer —
/// neither is checked here, and until the console has it this directory is the only copy.
pub(super) fn discard_settled(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// How old a directory NAMED BY NO RECORD must be before it is collected. Not a bound on a run —
/// a run that still has a record is kept whatever its age — but on how long a directory nothing
/// refers to is left in case a record is about to refer to it.
#[cfg(windows)]
const JOB_DIR_SWEEP_AGE_SECS: i64 = PS_RUN_HARD_MAX_SECS as i64 + 3600;

/// Delete job temp directories nothing will read: not this client's, named by no record, and past
/// the age at which any record could still settle them. The only owner of what a stopped client left.
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

/// Read and decode a PowerShell output file. A missing file maps to `Ok("")`; other read failures
/// remain errors so callers can distinguish failed capture from an empty script output.
#[cfg(windows)]
pub(super) fn read_ps_output(path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(decode_ps_bytes(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Decode bytes written by PowerShell's `*>` redirect, honouring the BOM. `powershell_exe()` is
/// Windows PowerShell 5.1, whose redirect operators default to **UTF-16LE with a `FF FE` BOM** — not
/// UTF-8. Decode by BOM and fall back to lossy UTF-8 for unmarked output.
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

/// Split remote-script parameters into `(script, run_as, username, password)`. A bare string is the
/// compatibility form for a system-context script; a `{ "script": … }` JSON object carries the
/// optional run-as fields.
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
