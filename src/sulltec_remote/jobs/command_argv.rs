use super::*;

/// The `native` executor: spawn one program with its arguments, and report how it went.
///
/// ⚠ **An ARGV, never a shell string, and that is the whole security property.** The text is split on
/// whitespace into argument elements and handed to the process API as a list, so nothing reparses
/// it: there is no shell to interpret `&`, `|`, `>`, quotes or globs, and a substituted value cannot
/// become a second argument no matter what it contains. The PowerShell executor beside this one has
/// to bind its ask through an environment variable precisely because its input IS a language; this
/// one has no language to escape into.
///
/// **`${name}` takes one value from the ask, and must be a WHOLE element.** `taskkill /F /PID ${pid}`
/// is four arguments, the fourth being the pid as sent. A token embedded in a larger element is
/// REFUSED rather than substituted — such a value would still be a single argument, so this is about
/// keeping the rule one sentence long rather than about closing a hole.
///
/// **A missing or empty value is a refusal, not an empty argument.** `taskkill /F /PID` with the pid
/// silently dropped is a different command from the one the backend authored, and one of the shapes
/// it could take is "kill nothing and exit 0".
///
/// **Spawning an argv list is what a process kill and a session logoff always did here.** What
/// changes is only that the list is now the backend's to state. Starting, stopping and restarting a
/// service are genuinely PowerShell on this device and go through the executor above instead.
#[cfg(windows)]
pub(super) fn exec_native(command: &str, timeout_s: u64, ask: &str) -> Result<Vec<Value>, Value> {
    let bound: Value = serde_json::from_str(ask).unwrap_or(Value::Null);
    let argv = split_argv(command, &bound)?;
    let Some((program, args)) = argv.split_first() else {
        return Err(keyset_error("the hosted command is empty"));
    };
    match run_argv_within(program, args, timeout_s) {
        None => Err(keyset_error(&format!("'{program}' could not be started"))),
        // Same reasoning as the PowerShell executor's: a result rather than a silence, because a job
        // in its timeout and a job never picked up read identically to the console otherwise.
        Some(NativeRun::TimedOut) => Err(json!({
            "ok": false,
            "error": format!("'{program}' timed out after {timeout_s}s"),
            "timed_out": true,
        })),
        // ⚠ A non-zero exit is a FAILED JOB, not a row saying so. The fork's `run_action` reported a
        // fixed label — "killed" — whatever the exit code was, so a `taskkill` that found no such
        // process answered exactly like one that ended it. That is the single worst shape an action
        // result can have: it reads as done.
        Some(NativeRun::Done { code, stdout, stderr }) if code != 0 => Err(json!({
            "ok": false,
            "error": format!(
                "'{program}' exited {code}: {}",
                first_line(&stderr).or_else(|| first_line(&stdout)).unwrap_or_default()
            ),
            "exit_code": code,
        })),
        Some(NativeRun::Done { code, stdout, .. }) => Ok(vec![json!({
            "exit_code": code,
            "output": stdout.trim(),
        })]),
    }
}

/// Spawn one program with its arguments, under the same wall-clock ceiling PowerShell runs under.
///
/// ⚠ **`args` is a LIST and is never joined into a string.** `std::process::Command` passes it to the
/// process API as separate elements, so nothing a substituted value contains can turn into a second
/// argument, a redirect or a command separator. This is why a hosted native command needs no escaping
/// rule and no allow-list on the values it carries — a pid's all-digits check is there because
/// `taskkill` is picky about its argument, not because the spawn was unsafe.
///
/// ⚠ **No environment ask.** The PowerShell executor hands its ask over in `SULLTEC_JOB_PARAMS`
/// because its input is a LANGUAGE and pasting a value into code is how a selector becomes a command.
/// An argv has no such hazard, so the values are already substituted by the time they get here and
/// there is nothing to bind.
///
/// The wait loop is [`ps_capture_within`]'s, deliberately: one timeout discipline for both
/// executors, so a hosted command's budget means the same thing whichever one runs it.
#[cfg(windows)]
pub(super) fn run_argv_within(program: &str, args: &[String], ceiling_secs: u64) -> Option<NativeRun> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().ok()?;
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ceiling_secs);
    let mut nap = std::time::Duration::from_millis(2);
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            // A handle we cannot ask about will not be waited on either — treat it as the timeout case.
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
    let (stdout, stderr) = match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(o), Ok(e)) => (o, e),
        // A descendant inherited a pipe and outlived its parent. The command itself FINISHED, so
        // reporting a timeout would say the wrong thing; the exit status is still true.
        _ => (Vec::new(), b"a descendant kept its output pipe open after the process exited".to_vec()),
    };
    Some(NativeRun::Done {
        // ⚠ A process killed by a signal has no code. `-1` rather than `0`, because the one thing
        // this must never do is report a run it cannot describe as a success.
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// The first non-empty line of a program's output — enough to say WHY it failed without carrying a
/// screenful of untrusted device text onto an error path.
#[cfg(windows)]
pub(super) fn first_line(s: &str) -> Option<String> {
    s.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.chars().take(256).collect())
}
