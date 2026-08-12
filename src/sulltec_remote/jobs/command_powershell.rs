use super::*;

/// The `powershell` executor: run the backend's command under [`PS_GUARD`] with a hard ceiling.
///
/// The prologue is the one every compiled-in collector gets — [`PS_GUARD`] so a hosted command can
/// call `Stop-OnError` and have a failed read reported as a failure rather than as an empty set, and
/// [`PS_ADD_FNS`] so it can project a row the way the compiled-in collectors do, omitting a field
/// the source had no value for instead of rendering it as an empty string. A hosted command that had
/// to carry its own copies of those would be shipping the client's dialect over the wire on every
/// single dispatch.
#[cfg(windows)]
pub(super) fn exec_powershell(command: &str, timeout_s: u64, ask: &str) -> Result<Vec<Value>, Value> {
    let script = format!("{PS_GUARD}{PS_ADD_FNS}{PS_PARAMS_BIND}{command}");
    match ps_capture_within(&script, timeout_s, Some(ask)) {
        None => Err(keyset_error("the collector command failed: PowerShell could not be started")),
        // ⚠ A RESULT, never a silence. A job sitting in its timeout and a job that was never picked up
        // both read `queued` to the console. This says three things a silence cannot: it was
        // delivered, it ran, and it outlasted a budget somebody chose — which is what makes the
        // timeout a probe of the machine rather than only a guardrail.
        Some(PsRun::TimedOut) => Err(json!({
            "ok": false,
            "error": format!("timed out after {timeout_s}s"),
            "timed_out": true,
        })),
        Some(PsRun::Done(out)) => match ps_rows_of(&out, "the collector command") {
            GuardedRows::Rows(rows) => Ok(rows),
            GuardedRows::Failed(e) => Err(e),
        },
    }
}

/// [`ps_capture`] with the wall-clock ceiling supplied by the caller.
#[cfg(windows)]
pub(super) fn ps_capture_within(script: &str, ceiling_secs: u64, ask: Option<&str>) -> Option<PsRun> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new(powershell_exe());
    cmd.args(["-NonInteractive", "-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // ⚠ The ask travels in the ENVIRONMENT, never in the script text. A backend-hosted command has
    // to be able to select the row the address named, and the only two ways to give it a value are
    // to paste the value into the code or to hand it over as data. Pasting is how a selector becomes
    // a command, and no amount of escaping makes that a property of the design rather than of the
    // escaper. This way the command compares against a variable it did not author.
    if let Some(ask) = ask {
        cmd.env(JOB_PARAMS_ENV, ask);
    }
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
        hbb_common::log::error!("a collector's PowerShell run passed {ceiling_secs}s and was terminated");
        return Some(PsRun::TimedOut);
    };
    // The child is gone, so the pipes are at EOF and the readers have finished — unless a descendant
    // inherited one and is still alive, in which case the read never ends. That is a FAILED run rather
    // than a timed-out one: the command itself finished, and a caller told to expect `timed_out` for a
    // command that outlasted its budget would be told the wrong thing.
    let grace = std::time::Duration::from_secs(PS_DRAIN_GRACE_SECS);
    match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(stdout), Ok(stderr)) => Some(PsRun::Done(std::process::Output { status, stdout, stderr })),
        _ => Some(PsRun::Done(ps_run_unfinished(
            "a descendant kept its output pipe open after the process exited",
        ))),
    }
}

/// The row-reading half of [`ps_rows_guarded`], separated so a run captured under a caller-supplied
/// ceiling reads its output through the SAME parse. Split rather than copied: a second reader is how
/// the two paths drift into disagreeing about what an unparseable line means.
#[cfg(windows)]
pub(super) fn ps_rows_of(out: &std::process::Output, what: &str) -> GuardedRows {
    if let Some(e) = guard_failure(out, what) {
        return GuardedRows::Failed(e);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    // Nothing on stdout, having already cleared the failure check above — a genuine empty result.
    if text.is_empty() {
        return GuardedRows::Rows(Vec::new());
    }
    match serde_json::from_str(text) {
        Ok(Value::Array(a)) => GuardedRows::Rows(a),
        Ok(v @ Value::Object(_)) => GuardedRows::Rows(vec![v]), // ConvertTo-Json emits a bare object for one row
        Ok(Value::Null) => GuardedRows::Rows(Vec::new()),
        Ok(other) => GuardedRows::Rows(vec![other]),
        // Output that won't parse is a failure, not an empty list: the script wrote *something*, so
        // whatever it wrote is the closest thing to a reason available.
        Err(e) => GuardedRows::Failed(json!({ "ok": false, "error": format!("{what} returned unreadable output: {e}") })),
    }
}

/// The result a run that could not be finished reports: a failure status, the reason on stderr, and
/// deliberately NO stdout — see [`ps_capture`].
#[cfg(windows)]
pub(super) fn ps_run_unfinished(why: &str) -> std::process::Output {
    use std::os::windows::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(1),
        stdout: Vec::new(),
        stderr: format!(
            "the PowerShell run did not complete: {why}. Whatever it had written is discarded rather \
             than reported as the answer"
        )
        .into_bytes(),
    }
}

/// The collector error for a [`PS_GUARD`] script that failed a read, or `None` when the run is
/// trustworthy. Output on stdout wins: a multi-target read that got rows from one target and an error
/// from another still returns the rows, exactly as the event-log collector does. Empty stdout with a
/// clean exit is a genuine empty result and is left alone — reporting *that* as a failure would train
/// operators to ignore the collector, which is the same lie in the other direction.
#[cfg(windows)]
pub(super) fn guard_failure(out: &std::process::Output, what: &str) -> Option<Value> {
    if !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
        return None;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.trim();
    if err.is_empty() && out.status.success() {
        return None;
    }
    let detail: String = match err.is_empty() {
        true => format!("exited {}", out.status.code().unwrap_or(-1)),
        false => err.chars().take(2000).collect(),
    };
    Some(json!({ "ok": false, "error": format!("{what} failed: {detail}") }))
}

/// Prologue for a collector script that must not report a failed read as an empty one. Defines
/// `Stop-OnError`, which inspects the errors raised since the last checkpoint and — if any are real —
/// writes the first message to stderr and exits 1, which the guarded runners below turn into a
/// collector `{ok:false,error}`. Call it directly after each read, **before** anything derived from
/// that read is used; a read that legitimately returned nothing leaves `$Error` empty and passes.
///
/// `-Ignore` takes `FullyQualifiedErrorId` prefixes, for the cmdlets that raise an error to mean
/// "nothing matched". Matching on the id rather than the message text is what makes this work on a
/// non-English host. `-ErrorAction SilentlyContinue` stays on the reads themselves: a multi-target
/// query has to survive one target failing, and `$Error` still records what did.
///
/// ⚠ A read that is deliberately **best-effort** must be followed by `$Error.Clear()`, not merely
/// wrapped in `try/catch`: PowerShell records a caught exception in `$Error` regardless, so the next
/// `Stop-OnError` would otherwise fail the collector over an optional read that was allowed to fail.
#[cfg(windows)]
pub(super) const PS_GUARD: &str = "$ErrorActionPreference='SilentlyContinue'; $Error.Clear(); \
function Stop-OnError { param([string]$What='',[string[]]$Ignore=@()) \
$real=@($Error | Where-Object { $i=[string]$_.FullyQualifiedErrorId; \
-not (@($Ignore | Where-Object { $i -like ($_ + '*') }).Count) }); \
if ($real.Count -gt 0) { $m=[string]$real[0].Exception.Message; if ($What) { $m=$What + ': ' + $m }; \
[Console]::Error.WriteLine($m); exit 1 }; $Error.Clear() }; ";

/// Row builders every hosted script gets in its prologue ([`exec_powershell`]). `Add-S` / `Add-N` /
/// `Add-D` add a key ONLY when the
/// source had a value: a property PowerShell or WMI returned nothing for is OMITTED, never rendered as
/// `""`, so a caller can tell "no value" from a value that is genuinely empty.
///
/// `Add-D` normalizes a date to one sortable spelling instead of the host's locale format, and drops
/// anything before 2000 — that is not a date, it is a SENTINEL. Task Scheduler reports a task that has
/// never run as `1999-11-30`, and other Windows APIs use `1899-12-30` or the FILETIME epoch; each of
/// them serializes as a perfectly plausible timestamp, and "this task last ran in 1999" is exactly the
/// confident-but-wrong answer this file exists to stop. Absent is the honest rendering of never.
#[cfg(windows)]
pub(super) const PS_ADD_FNS: &str = "function Add-S { param($H,[string]$K,$V) \
if ($null -ne $V) { $s=[string]$V; if ($s.Trim() -ne '') { $H[$K]=$s } } }; \
function Add-N { param($H,[string]$K,$V) \
if ($null -ne $V) { $n=$V -as [long]; if ($null -ne $n) { $H[$K]=$n } } }; \
function Add-D { param($H,[string]$K,$V) \
if ($null -ne $V) { try { $d=[datetime]$V; if ($d -ge [datetime]'2000-01-01') { $H[$K]=$d.ToString('yyyy-MM-dd HH:mm:ss') } } catch { } } }; \
function Add-B { param($H,[string]$K,$V) \
if ($null -ne $V) { $H[$K]=[bool]$V } }; ";

/// The prologue every hosted PowerShell command runs behind — the executor's own dialect.
///
/// `$Params` is the ask: the dispatch's narrowing params, minus the fields the executor reserves.
/// Bound from the environment rather than pasted into the script, so a selector is a VALUE the
/// command compares against and can never be code (see [`ps_capture_within`]). It is `$null` for a
/// command that was sent none, which is the shape a script tests with `$null -ne`.
///
/// The variable is cleared once read: a descendant this command starts inherits the environment,
/// and there is no reason for the ask to travel any further than the script that asked for it.
#[cfg(windows)]
pub(super) const PS_PARAMS_BIND: &str = "$Params=$null; \
if($env:SULLTEC_JOB_PARAMS){ $Params=ConvertFrom-Json $env:SULLTEC_JOB_PARAMS }; \
$env:SULLTEC_JOB_PARAMS=$null; $Error.Clear(); ";
