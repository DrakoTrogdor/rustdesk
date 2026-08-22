use super::*;

/// Spawn a hosted native command as a program and argument vector.
///
/// The command is split into argument elements and passed directly to the process API without a shell,
/// so shell operators and globs are not interpreted.
///
/// `${name}` substitutes one parameter value and must occupy an entire argument element. Embedded
/// substitutions are rejected.
///
/// Missing or empty substitution values are rejected rather than omitted from the command.
#[cfg(windows)]
pub(super) fn exec_native(command: &str, timeout_s: u64, ask: &str, job_id: &str) -> Result<Vec<Value>, Value> {
    let bound: Value = serde_json::from_str(ask).unwrap_or(Value::Null);
    let argv = split_argv(command, &bound)?;
    let Some((program, args)) = argv.split_first() else {
        return Err(keyset_error("the hosted command is empty"));
    };
    match run_argv_within(program, args, timeout_s, job_id) {
        None => Err(keyset_error(&format!("'{program}' could not be started"))),
        // Report timeouts explicitly so they remain distinguishable from queued jobs.
        Some(NativeRun::TimedOut) => Err(json!({
            "ok": false,
            "error": format!("'{program}' timed out after {timeout_s}s"),
            "timed_out": true,
        })),
        // A nonzero process exit is a failed job rather than a successful result row.
        Some(NativeRun::Done { code, stdout, stderr, .. }) if code != 0 => Err(json!({
            "ok": false,
            "error": format!(
                "'{program}' exited {code}: {}",
                first_line(&stderr).or_else(|| first_line(&stdout)).unwrap_or_default()
            ),
            "exit_code": code,
        })),
        // Exited cleanly, but its output was never readable. Reporting the empty stdout as the answer
        // would make an unreadable run indistinguishable from one that printed nothing.
        Some(NativeRun::Done { code, drained: false, .. }) => Err(json!({
            "ok": false,
            "error": format!(
                "'{program}' exited {code} but its output could not be read: a descendant kept the \
                 pipe open after it exited, so nothing it wrote is the command's answer"
            ),
            "exit_code": code,
        })),
        Some(NativeRun::Done { code, stdout, .. }) => Ok(vec![json!({
            "exit_code": code,
            "output": stdout.trim(),
        })]),
    }
}

/// Spawn one program with separate arguments under a wall-clock timeout.
///
/// `std::process::Command` passes `args` as distinct elements without shell parsing. Validation of
/// individual values enforces the invoked program's input requirements.
///
/// Parameter values are substituted into the argument vector before this function is called. The
/// timeout behavior matches [`ps_capture_within`].
#[cfg(windows)]
pub(super) fn run_argv_within(program: &str, args: &[String], ceiling_secs: u64, job_id: &str) -> Option<NativeRun> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().ok()?;
    adopt::record(job_id, child.id());
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
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
        let _ = child.kill();
        hbb_common::log::error!("a hosted '{program}' run passed {ceiling_secs}s and was terminated");
        return Some(NativeRun::TimedOut);
    };
    let grace = std::time::Duration::from_secs(PS_DRAIN_GRACE_SECS);
    let (stdout, stderr, drained) = match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(o), Ok(e)) => (o, e, true),
        // A descendant can keep an inherited pipe open after the command has exited.
        _ => (
            Vec::new(),
            b"a descendant kept its output pipe open after the process exited".to_vec(),
            false,
        ),
    };
    Some(NativeRun::Done {
        // Use `-1` when termination by a signal provides no exit code.
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        drained,
    })
}

/// Return the first nonempty output line, limited to 256 characters for error reporting.
#[cfg(windows)]
pub(super) fn first_line(s: &str) -> Option<String> {
    s.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.chars().take(256).collect())
}
