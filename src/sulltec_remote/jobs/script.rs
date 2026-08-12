use super::*;

/// Run an operator-supplied PowerShell script (admin-gated, params delivered over the SIGNED
/// `/params` channel — never the unauthenticated heartbeat). Captures stdout+stderr+exit and
/// char-safe-truncates the combined output (60,000 chars — sized against a 64 KiB result cap, and so
/// conservative against the real 256 KiB `store::MAX_JOB_RESULT` even after JSON escaping). Returns
/// `{ok, exit, output}` (or `{ok:false, error}` if the shell couldn't launch).
#[cfg(windows)]
pub(super) fn run_script(params: Option<&str>) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let raw = params.unwrap_or("").trim();
    if raw.is_empty() {
        return json!({ "ok": false, "error": "no script provided" });
    }
    // Params are either a bare script (the default — runs in THIS process's own context, unchanged)
    // or a JSON envelope `{script, run_as, username, password}` selecting an optional run-as identity.
    // The envelope only ever arrives over the SIGNED `/params` channel (script is a sensitive kind),
    // so a credential inside it never rides the unauthenticated heartbeat.
    let (script, run_as, username, password) = parse_script_params(raw);
    if run_as == "user" || run_as == "credential" {
        return run_script_as(&script, &run_as, &username, &password);
    }
    // Default: PowerShell in the client's own (service / SYSTEM) context. Run the script from a temp
    // `.ps1` via `-File` rather than inline `-Command`: the inline path pushes the whole script through
    // Rust arg-escaping → PowerShell → the native tool, which mangles quoting and could echo / parse-fail
    // scripts that call native commands (`auditpol`, `reg`, …). A file sidesteps all command-line escaping,
    // and the child's stdout/stderr — including the native command's — is captured normally.
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
    // Invoke the file via the call operator and redirect ALL PowerShell streams (`*>`) — including a
    // native command's stdout (auditpol/reg/etc.) — to a file we read back. A bare `-File` leaves an
    // unassigned native command writing to the host, which the session-0 service context doesn't capture
    // on the stdout pipe (it came back as just the echoed command line). This is the same file-capture
    // the run-as path uses. Both paths are quote-free temp paths, single-quoted so Rust arg-escaping
    // can't mangle them.
    let out_file = dir.join("out.txt");
    let invoke = format!("& '{}' *> '{}'", ps1.display(), out_file.display());
    let out = std::process::Command::new(powershell_exe())
        .args(["-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &invoke])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    // `captured` = the script's own output (all streams, redirected to the file, BOM-decoded); `o.stderr`
    // only catches a failure to launch PowerShell itself.
    let captured = read_ps_output(&out_file);
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) => {
            let ps_err = String::from_utf8_lossy(&o.stderr);
            // Surface a read failure rather than flattening it to "" — an empty `output` must mean the
            // script printed nothing, never "we lost what it printed".
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
pub(super) fn run_script(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Run a script under a DIFFERENT identity than the service: `"user"` = the active console user
/// (CreateProcessAsUser via `run_exe_in_session`), `"credential"` = a supplied account
/// (CreateProcessWithLogonW). Both launchers are fire-and-forget (no waitable child), so we run a
/// wrapper that redirects every PowerShell stream to a temp file and always drops a `done.flag`, then
/// poll for the flag. Temp script + output live in `C:\Windows\Temp\sulltec-job-…` (writable by the
/// target identity) and are deleted afterward; the password is passed only to the Win32 logon API,
/// never to disk.
#[cfg(windows)]
pub(super) fn run_script_as(script: &str, mode: &str, username: &str, password: &str) -> Value {
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
    if std::fs::write(&inner, script.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return json!({ "ok": false, "error": "failed to write script" });
    }
    // `*>` captures all six PowerShell streams; `finally` guarantees the flag even if the script throws.
    let wrapper_ps = format!(
        "$ErrorActionPreference='Continue'\r\ntry {{ & '{inner}' *> '{out}' }} catch {{ \"$_\" | Out-File -LiteralPath '{out}' -Append }} finally {{ Set-Content -LiteralPath '{flag}' -Value 'done' }}\r\n",
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
    // Poll for completion (10-minute cap) — the launchers gave us no handle to wait on.
    let deadline = now_secs() + 600;
    while now_secs() < deadline && !flag.exists() {
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

/// Read + decode a PowerShell-written output file. A MISSING file means the script wrote nothing (or
/// never ran) → `Ok("")`; any other read failure is returned as `Err` so the caller can SAY so rather
/// than pass an empty string off as "the script printed nothing". That distinction matters: `ok`/`exit`
/// come from the PowerShell process, which exits 0 whatever the script did, so `output` is the only
/// evidence a job actually did its work.
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
/// UTF-8. `0xFF` is invalid UTF-8, so `read_to_string` on such a file always `Err`s; paired with
/// `unwrap_or_default()` that silently turned EVERY script job's output into an empty string. Decode
/// by BOM instead, and fall back to a lossy UTF-8 read (bare UTF-8 is what `pwsh` 6+ would write, if
/// this ever stops hard-coding 5.1).
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

/// Split a remote-script param into `(script, run_as, username, password)`. A bare string (the legacy
/// shape) is the script itself with `run_as = "system"`; a `{ "script": … }` JSON object carries the
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
