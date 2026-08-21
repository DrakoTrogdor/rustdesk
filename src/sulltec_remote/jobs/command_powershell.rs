use super::*;

/// Run a hosted PowerShell command with the collector prologue and a wall-clock timeout.
///
/// [`PS_GUARD`] reports failed reads, and [`PS_ADD_FNS`] supplies row projection helpers that omit
/// fields whose sources have no value.
#[cfg(windows)]
pub(super) fn exec_powershell(command: &str, timeout_s: u64, ask: &str) -> Result<Vec<Value>, Value> {
    let script = format!("{PS_GUARD}{PS_ADD_FNS}{PS_PARAMS_BIND}{command}");
    match ps_capture_within(&script, timeout_s, Some(ask)) {
        None => Err(keyset_error("the collector command failed: PowerShell could not be started")),
        // Report timeouts explicitly so they remain distinguishable from queued jobs.
        Some(PsRun::TimedOut) => Err(json!({
            "ok": false,
            "error": format!(
                "timed out after {timeout_s}s — PowerShell was killed on the device; anything it \
                 handed to a Windows service may still be running, so do not re-dispatch without \
                 checking"
            ),
            "timed_out": true,
        })),
        Some(PsRun::Done(out)) => match ps_rows_of(&out, "the collector command") {
            GuardedRows::Rows(rows) => Ok(rows),
            GuardedRows::Failed(e) => Err(e),
        },
    }
}

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
    // Pass parameters as environment data so their values cannot become PowerShell code.
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
        hbb_common::log::error!("a collector's PowerShell run passed {ceiling_secs}s and was terminated");
        return Some(PsRun::TimedOut);
    };
    // A descendant can keep inherited pipes open after the command exits. Failure to drain them is a
    // completed process failure rather than a wall-clock timeout.
    let grace = std::time::Duration::from_secs(PS_DRAIN_GRACE_SECS);
    match (out_rx.recv_timeout(grace), err_rx.recv_timeout(grace)) {
        (Ok(stdout), Ok(stderr)) => Some(PsRun::Done(std::process::Output { status, stdout, stderr })),
        _ => Some(PsRun::Done(ps_run_unfinished(
            "a descendant kept its output pipe open after the process exited",
        ))),
    }
}

/// Parse guarded PowerShell output into collector rows.
#[cfg(windows)]
pub(super) fn ps_rows_of(out: &std::process::Output, what: &str) -> GuardedRows {
    if let Some(e) = guard_failure(out, what) {
        return GuardedRows::Failed(e);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    // Clean, empty stdout represents an empty result.
    if text.is_empty() {
        return GuardedRows::Rows(Vec::new());
    }
    match serde_json::from_str(text) {
        Ok(Value::Array(a)) => GuardedRows::Rows(a),
        Ok(v @ Value::Object(_)) => GuardedRows::Rows(vec![v]), // ConvertTo-Json emits a bare object for one row
        Ok(Value::Null) => GuardedRows::Rows(Vec::new()),
        Ok(other) => GuardedRows::Rows(vec![other]),
        // Nonempty, unparseable output is a collector failure.
        Err(e) => GuardedRows::Failed(json!({ "ok": false, "error": format!("{what} returned unreadable output: {e}") })),
    }
}

/// Build a failed process result with the reason on stderr and no partial stdout.
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

/// Return a collector error when a guarded command produced no rows and failed.
///
/// Nonempty stdout takes precedence over errors so partial multi-target results remain available. A
/// successful command with empty stdout represents an empty result.
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

/// PowerShell prologue that defines `Stop-OnError` for distinguishing failed reads from empty results.
///
/// `Stop-OnError` inspects errors since the previous checkpoint, writes the first applicable error to
/// stderr, exits with failure, and then clears the error list. Call it immediately after each read.
///
/// `-Ignore` accepts `FullyQualifiedErrorId` prefixes for expected no-match errors without depending
/// on localized messages. Reads use `-ErrorAction SilentlyContinue` while `$Error` retains failures.
///
/// Best-effort reads must clear `$Error` because caught PowerShell exceptions remain in that list.
#[cfg(windows)]
pub(super) const PS_GUARD: &str = "$ErrorActionPreference='SilentlyContinue'; $Error.Clear(); \
function Stop-OnError { param([string]$What='',[string[]]$Ignore=@()) \
$real=@($Error | Where-Object { $i=[string]$_.FullyQualifiedErrorId; \
-not (@($Ignore | Where-Object { $i -like ($_ + '*') }).Count) }); \
if ($real.Count -gt 0) { $m=[string]$real[0].Exception.Message; if ($What) { $m=$What + ': ' + $m }; \
[Console]::Error.WriteLine($m); exit 1 }; $Error.Clear() }; ";

/// Row builders included in every hosted PowerShell command prologue.
///
/// `Add-S`, `Add-N`, and `Add-D` omit keys whose sources have no value, preserving the distinction
/// between an absent value and an empty string.
///
/// `Add-D` normalizes dates to `yyyy-MM-dd HH:mm:ss` and omits pre-2000 sentinel dates used by Windows
/// APIs to represent events that never occurred.
#[cfg(windows)]
pub(super) const PS_ADD_FNS: &str = "function Add-S { param($H,[string]$K,$V) \
if ($null -ne $V) { $s=[string]$V; if ($s.Trim() -ne '') { $H[$K]=$s } } }; \
function Add-N { param($H,[string]$K,$V) \
if ($null -ne $V) { $n=$V -as [long]; if ($null -ne $n) { $H[$K]=$n } } }; \
function Add-D { param($H,[string]$K,$V) \
if ($null -ne $V) { try { $d=[datetime]$V; if ($d -ge [datetime]'2000-01-01') { $H[$K]=$d.ToString('yyyy-MM-dd HH:mm:ss') } } catch { } } }; \
function Add-B { param($H,[string]$K,$V) \
if ($null -ne $V) { $H[$K]=[bool]$V } }; ";

/// Bind a hosted command's JSON parameters from the environment into `$Params`.
///
/// `$Params` is `$null` when no parameters were supplied. Environment binding keeps parameter values
/// separate from executable script text.
///
/// The environment variable is cleared after parsing so descendants do not inherit it.
#[cfg(windows)]
pub(super) const PS_PARAMS_BIND: &str = "$Params=$null; \
if($env:SULLTEC_JOB_PARAMS){ $Params=ConvertFrom-Json $env:SULLTEC_JOB_PARAMS }; \
$env:SULLTEC_JOB_PARAMS=$null; $Error.Clear(); ";
