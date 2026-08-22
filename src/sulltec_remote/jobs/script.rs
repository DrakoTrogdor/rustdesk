use super::*;

/// Run an operator-supplied PowerShell script. The operation is admin-gated and its parameters use
/// the signed `/params` channel rather than the unauthenticated heartbeat. Captures stdout, stderr,
/// and exit status, truncating the combined output to 60,000 characters to stay within the result
/// cap. Returns `{ok, exit, output}` (or `{ok:false, error}` if the shell couldn't launch).
///
/// `job_id` is what makes this run recoverable: it names the record the PowerShell process and the
/// directory it is writing into are stamped onto, so a client that replaces this one can re-attach to
/// the process and read the answer back off the file rather than report the run abandoned.
#[cfg(windows)]
pub(super) fn run_script(params: Option<&str>, job_id: &str) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let raw = params.unwrap_or("").trim();
    if raw.is_empty() {
        return json!({ "ok": false, "error": "no script provided" });
    }
    // Params are either a bare script, which runs in this process's context,
    // or a JSON envelope `{script, run_as, username, password}` selecting an optional run-as identity.
    // The envelope arrives over the signed `/params` channel because scripts are sensitive,
    // so a credential inside it never rides the unauthenticated heartbeat.
    let (script, run_as, username, password) = parse_script_params(raw);
    if run_as == "user" || run_as == "credential" {
        return run_script_as(&script, &run_as, &username, &password, job_id);
    }
    // The default runs PowerShell in the client's service/SYSTEM context. A temporary `.ps1` avoids
    // command-line escaping across Rust, PowerShell, and native tools.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::path::Path::new(r"C:\Windows\Temp").join(format!("sulltec-job-{}-{}", std::process::id(), nonce));
    if std::fs::create_dir_all(&dir).is_err() {
        return json!({ "ok": false, "error": "failed to create job temp dir" });
    }
    let ps1 = dir.join("job.ps1");
    if std::fs::write(&ps1, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": "failed to write script" });
    }
    // Redirect all PowerShell streams, including native-command stdout, to a file because session-0
    // does not reliably capture unassigned native output through the process stdout pipe. Single-quoted
    // temporary paths prevent Rust argument escaping from changing them.
    let out_file = dir.join("out.txt");
    let invoke = format!("& '{}' *> '{}'", ps1.display(), out_file.display());
    // Spawned rather than `.output()`ed for one reason: `Child::id()`, which is what a later client
    // re-attaches by. `wait_with_output` and the drain inside `output()` are the same code on the
    // (piped, piped) case, so the wait, the concurrent drain and the absence of a timeout are all
    // unchanged.
    //
    // ⚠ The three `Stdio` calls are MANDATORY, not tidiness: `output()` spawns with MakePipe and a
    // null stdin, while a bare `spawn()` defaults to INHERIT — omit them and the child takes the
    // service's own handles, `o.stderr` below goes permanently empty, and the only channel that
    // reports PowerShell failing to launch disappears.
    let spawned = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &invoke])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let out = match spawned {
        Ok(child) => {
            adopt::record_run(job_id, child.id(), Some(&dir));
            child.wait_with_output()
        }
        Err(e) => Err(e),
    };
    // `captured` = the script's own output (all streams, redirected to the file, BOM-decoded); `o.stderr`
    // only catches a failure to launch PowerShell itself.
    let captured = read_ps_output(&out_file);
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) => {
            let ps_err = String::from_utf8_lossy(&o.stderr);
            // Keep capture failures distinct from scripts that produced no output.
            let (captured, read_err) = match captured {
                Ok(s) => (s, String::new()),
                Err(e) => (String::new(), format!("[console: the script ran but its captured output could not be read: {e}]")),
            };
            let combined: String = format!("{captured}{ps_err}{read_err}").chars().take(60_000).collect();
            json!({ "ok": o.status.success(), "exit": o.status.code(), "output": combined })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(not(windows))]
pub(super) fn run_script(_params: Option<&str>, _job_id: &str) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Run a script under a different identity than the service: `"user"` = the active console user
/// (CreateProcessAsUser via `run_exe_in_session`), `"credential"` = a supplied account
/// (CreateProcessWithLogonW). Both launchers are fire-and-forget (no waitable child), so we run a
/// wrapper that redirects every PowerShell stream to a temp file and always drops a `done.flag`, then
/// poll for the flag. Temp script + output live in `C:\Windows\Temp\sulltec-job-…` (writable by the
/// target identity) and are deleted afterward; the password is passed only to the Win32 logon API,
/// never to disk.
#[cfg(windows)]
pub(super) fn run_script_as(script: &str, mode: &str, username: &str, password: &str, job_id: &str) -> Value {
    if mode == "credential" && (username.is_empty() || password.is_empty()) {
        return json!({ "ok": false, "error": "run-as credential needs a username and password" });
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::path::Path::new(r"C:\Windows\Temp").join(format!("sulltec-job-{}-{}", std::process::id(), nonce));
    if std::fs::create_dir_all(&dir).is_err() {
        return json!({ "ok": false, "error": "failed to create job temp dir" });
    }
    let inner = dir.join("inner.ps1");
    let wrapper = dir.join("wrapper.ps1");
    let out = dir.join("out.txt");
    let flag = dir.join("done.flag");
    let pidfile = dir.join("pid.txt");
    if std::fs::write(&inner, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": "failed to write script" });
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
        return json!({ "ok": false, "error": "failed to write wrapper" });
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
        return json!({ "ok": false, "error": format!("launch failed ({mode}): {e}") });
    }
    // Recorded before the wait, not after it: from here on the launch has happened, and a client that
    // dies in the next moment must still leave behind the address of the answer being written.
    adopt::record_dir(job_id, &dir);
    // Poll for completion (10-minute cap) — the launchers gave us no handle to wait on. The same loop
    // picks the wrapper's PID up the first time it is readable; if it never appears the path degrades
    // to flag-only, which is exactly the information it had before.
    let deadline = now_secs() + 600;
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
    let done = flag.exists();
    // Same BOM-decode as the SYSTEM path: the wrapper redirects with `*>`, so 5.1 writes UTF-16LE.
    let output: String = read_ps_output(&out)
        .unwrap_or_else(|e| format!("[console: the script's captured output could not be read: {e}]"))
        .chars()
        .take(60_000)
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    if done {
        json!({ "ok": true, "output": output, "run_as": mode })
    } else {
        json!({ "ok": false, "error": "timed out after 10 minutes", "output": output, "run_as": mode })
    }
}

/// The PID the wrapper wrote for itself, once it has written it.
#[cfg(windows)]
fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    let bytes = std::fs::read(path).ok()?;
    decode_ps_bytes(&bytes).trim().parse::<u32>().ok()
}

/// What this device can report for a script job it did not run, read off what the run left on disk.
///
/// This is the answer, not a substitute for one. The piped executors lose an orphan's output with the
/// client's pipes and can only ever report an exit code; here every stream went to a file, so the run
/// that outlived its client left the thing the operator actually asked for.
///
/// `code` is the exit code of a process this device re-attached to, when there was one. It is
/// DISCARDED for a run-as directory: the process adopted there is the wrapper, whose `finally` runs
/// whatever the script did, so it exits 0 for a script that threw and its code says nothing about the
/// work.
#[cfg(windows)]
pub(super) fn settle_script(job_id: &str, code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    let dir = seen_job_dir(job_id)?;
    // ⚠ BEFORE any read. `read_ps_output` maps NotFound to `Ok("")`, which is right where the run
    // provably created the directory and fatal here: a swept or already-deleted directory would
    // otherwise be reported as the script having answered with nothing.
    if !dir.is_dir() {
        return None;
    }
    let run_as = dir.join("wrapper.ps1").exists();
    let code = if run_as { None } else { code };
    let finished = match run_as {
        true => dir.join("done.flag").exists(),
        false => code.is_some(),
    };
    // ⚠ PROOF, not inference. Without an exit code or a completion marker this device has NO liveness
    // signal for the run — a run-as record carries no pid until the wrapper manages to report one, and
    // may never carry one — so "I cannot see it" would be being read as "it ended". Answering here
    // would publish a half-written `out.txt` as the run's answer and hand the caller a directory to
    // delete out from under a script that is still writing it. Unproven falls through to the
    // abandoned answer, which claims nothing and destroys nothing.
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
    let answer = recovered_answer(code, &output).to_string();
    // `done` for the same reason the live executor uses it for every script answer whatever the
    // script did: the status says an answer was produced, and `ok` inside it says how the run went.
    Some(("done", answer, dir))
}

#[cfg(not(windows))]
pub(super) fn settle_script(_job_id: &str, _code: Option<u32>) -> Option<(&'static str, String, std::path::PathBuf)> {
    None
}

/// The answer a recovered run reports, and what about it this device does not know.
///
/// The `recovered` key is mandatory: nothing here was watched from start to finish by the client
/// posting it, and an answer that read like an ordinary one would hide that.
#[cfg(windows)]
fn recovered_answer(code: Option<u32>, output: &str) -> Value {
    let recovered = match code {
        Some(_) => "the client that started this script stopped while it was running. This \
             device re-attached to the PowerShell process it had launched, watched it exit, and read \
             the run's output back off the file that process had been writing — so the output and \
             the exit code here are this run's own. What this device cannot tell you is whether that \
             process ended on its own or was killed along with the client, so output that stops \
             mid-line is a truncation and not the script's last word.",
        None => "the client that started this script stopped while it was running. The \
             script ran under a different identity, outlived that client, and recorded its own \
             completion; the output here was read back off the file it wrote. There is NO exit code \
             for this run — this executor never produces one — so `ok` means the script reached its \
             end, not that the work it did succeeded.",
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

/// Remove a recovered run's directory once the console has STORED the answer read off it.
///
/// Two things have to be true before this is reached and neither is checked here: the run is over —
/// `settle_script` answers nothing it cannot prove ended — and the console kept the answer, which is
/// what `post_result` returns. A refusal or a dropped connection keeps the directory, because it is
/// still the only copy of what the operator asked for.
#[cfg(windows)]
pub(super) fn discard_settled(_job_id: &str, dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(not(windows))]
pub(super) fn discard_settled(_job_id: &str, _dir: &std::path::Path) {}

/// Delete job temp directories nothing is going to read: not this client's, named by no record, and
/// older than the window in which a run could still be settled.
///
/// Letting a directory outlive its run is what makes this necessary. Every other delete belongs to a
/// run that reached its own end, so this is the only owner of what a stopped client left: a run the
/// console never asked about, one whose answer the console refused, a record aged out, and the
/// residue of the run-as timeout path whose own delete lost to an open `out.txt`.
///
/// The age test reads the directory's mtime, which does not advance while a script appends to an
/// `out.txt` that already exists — so a run still going after seven hours is swept. That is past
/// [`PS_RUN_HARD_MAX_SECS`] and past the point where any record could settle it, and `remove_dir_all`
/// against live handles simply fails, which is the acceptable outcome.
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
    let cutoff = std::time::Duration::from_secs(JOB_CHILD_TTL_SECS as u64);
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
