use super::*;

/// No shell is involved, so shell operators and globs are never interpreted. A `${name}` must
/// occupy a WHOLE argument element — embedded substitutions are refused, as are missing or empty
/// values, which are never silently dropped from the command.
#[cfg(windows)]
pub(super) fn exec_native(
    command: &str,
    timeout_s: u64,
    bound: Bound,
    ask: &str,
    job_id: &str,
) -> Result<Vec<Value>, ExecEnd> {
    let ask_values: Value = serde_json::from_str(ask).unwrap_or(Value::Null);
    let argv = split_argv(command, &ask_values).map_err(ExecEnd::Refused)?;
    let Some((program, args)) = argv.split_first() else {
        return Err(ExecEnd::Refused(keyset_error("the hosted command is empty")));
    };
    match run_argv_within(program, args, timeout_s, bound, job_id) {
        None => Err(ExecEnd::Refused(keyset_error(&format!("'{program}' could not be started")))),
        // Nothing to report: the run is still going. Not an error object, because every one of those
        // says something about how the run CAME OUT.
        Some(NativeRun::OverTime { killed: false }) => Err(ExecEnd::OverTime),
        // A PAGE, and it was ended. The cycle is waiting on this page to decide whether to ask for
        // the next one, so it gets the fact instead of a silence it cannot act on.
        Some(NativeRun::OverTime { killed: true }) => Err(ExecEnd::Refused(json!({
            "ok": false,
            "error": format!("'{program}' timed out after {timeout_s}s and was killed on the device"),
            "timed_out": true,
        }))),
        Some(NativeRun::Done { code, stdout, stderr, .. }) if code != 0 => Err(ExecEnd::Refused(json!({
            "ok": false,
            "error": format!(
                "'{program}' exited {code}: {}",
                first_line(&stderr).or_else(|| first_line(&stdout)).unwrap_or_default()
            ),
            "exit_code": code,
        }))),
        // Exited cleanly, but its output was never readable. Reporting the empty stdout as the answer
        // would make an unreadable run indistinguishable from one that printed nothing.
        Some(NativeRun::Done { code, drained: false, .. }) => Err(ExecEnd::Refused(json!({
            "ok": false,
            "error": format!(
                "'{program}' exited {code} but its output could not be read: a descendant kept the \
                 pipe open after it exited, so nothing it wrote is the command's answer"
            ),
            "exit_code": code,
        }))),
        Some(NativeRun::Done { code, stdout, .. }) => Ok(vec![json!({
            "exit_code": code,
            "output": stdout.trim(),
        })]),
    }
}

/// `${name}` substitution has already happened by the time this is called. Timeout behaviour
/// matches [`ps_capture_within`].
#[cfg(windows)]
pub(super) fn run_argv_within(
    program: &str,
    args: &[String],
    ceiling_secs: u64,
    bound: Bound,
    job_id: &str,
) -> Option<NativeRun> {
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
        let killed = match bound {
            // A PAGE. It is ended here, and nothing about it is recorded for a later settlement:
            // this run is being ANSWERED, and a held handle plus an over-time stamp would have the
            // adoption path come back for a job the console has already settled.
            Bound::Page => {
                let _ = child.kill();
                hbb_common::log::error!("a hosted '{program}' page passed {ceiling_secs}s and was terminated");
                true
            }
            // NOT killed. The handle is re-taken before `child` drops, because the kernel discards
            // the exit code with the last handle on the process.
            Bound::Run => {
                adopt::hold(job_id);
                mark_job_stamp(job_id, SEEN_OVER_TIME);
                hbb_common::log::warn!("a hosted '{program}' run passed {ceiling_secs}s and was left running");
                false
            }
        };
        return Some(NativeRun::OverTime { killed });
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
        // `code()` is None when a signal ended the process, which has no exit code of its own.
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        drained,
    })
}

#[cfg(windows)]
pub(super) fn first_line(s: &str) -> Option<String> {
    s.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.chars().take(256).collect())
}
