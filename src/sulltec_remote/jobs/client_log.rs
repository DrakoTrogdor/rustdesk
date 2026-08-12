use super::*;

/// Pull the TAIL of one of this client's run logs — written under `Config::log_path()` (machine-wide
/// `%ProgramData%\SullTecRemote\log` for a service install), where the updater + this job channel log
/// their errors, so "didn't update / job failed" is diagnosable from the console without RDP. With no
/// `params` it returns the **main service log**; pass a `name` from `client-logs` to fetch a specific
/// one (confined to the log dir — no traversal). Same `file_pull` shape over the last `CAP` bytes.
///
/// `params` reaches us two ways and BOTH are accepted: the console UI right-click passes a **bare name**
/// (`job_enqueue_h` sends `Option<String>` verbatim), while the REST `/api/diag` path serializes the
/// whole request body to the params string — so `{"name":"foo.log"}` (or `{}` for "no filter", which the
/// MCP bridge sends) arrives as JSON. A real log name always ends in `.log` and never parses as JSON, so
/// the bare form still falls through untouched; a JSON object supplies the name via `name`/`file`/`log`,
/// and an empty/nameless object (or `null`) means "main log".
#[cfg(windows)]
pub(super) fn client_log_pull(params: Option<&str>) -> Value {
    const CAP: usize = 128 * 1024;
    let dir = Config::log_path();
    let want: Option<String> = params.map(str::trim).filter(|s| !s.is_empty()).and_then(|raw| {
        match serde_json::from_str::<Value>(raw) {
            // JSON object (REST body): the name is under `name` (what `client-logs` emits), or
            // `file`/`log` as aliases. `{}` / a nameless object → None → main log.
            Ok(Value::Object(map)) => ["name", "file", "log"]
                .iter()
                .find_map(|k| map.get(*k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()))
                .map(|s| s.to_string()),
            // A JSON string body (`"foo.log"`) — use it directly.
            Ok(Value::String(s)) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            // `null` / number / bool / array carry no name → main log.
            Ok(_) => None,
            // Not JSON → the bare-name form from the console UI; use verbatim.
            Err(_) => Some(raw.to_string()),
        }
    });
    let path = match want.as_deref() {
        Some(name) => {
            // A specific file from the list — confine to the log dir via canonicalized prefix check.
            let candidate = dir.join(name.replace('/', "\\"));
            match candidate.canonicalize().ok().zip(dir.canonicalize().ok()) {
                Some((cp, cdir)) if cp.starts_with(&cdir) && cp.is_file() => cp,
                _ => return json!({ "ok": false, "error": format!("no such log: {name}") }),
            }
        }
        None => match main_log(&dir) {
            Some(p) => p,
            None => return json!({ "ok": false, "error": format!("no .log under {}", dir.display()) }),
        },
    };
    // Seek to the tail rather than reading the log in and slicing it: a log left unrotated (or a path
    // that resolved to something much larger than a log) would otherwise allocate its whole length,
    // and an allocation failure aborts the process rather than failing the job.
    use std::io::{Read, Seek, SeekFrom};
    let read = std::fs::File::open(&path).and_then(|mut f| {
        let file_size = f.metadata()?.len();
        if file_size > CAP as u64 {
            f.seek(SeekFrom::Start(file_size - CAP as u64))?;
        }
        let mut buf: Vec<u8> = Vec::new();
        f.take(CAP as u64).read_to_end(&mut buf)?;
        Ok((file_size, buf))
    });
    match read {
        Ok((size, bytes)) => {
            let truncated = size > CAP as u64;
            // We hold the LAST CAP bytes (recent activity) — drop the leading partial line + lossily
            // decode (a run log is always UTF-8 text, so no base64 fallback needed).
            let mut slice: &[u8] = &bytes;
            if truncated {
                if let Some(nl) = slice.iter().position(|&b| b == b'\n') {
                    slice = &slice[nl + 1..];
                }
            }
            let text = String::from_utf8_lossy(slice);
            json!({ "ok": true, "path": path.display().to_string(), "size": size, "truncated": truncated, "encoding": "text", "content": text.as_ref() })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// The MAIN service log — where the service writes its heartbeat, job-channel and updater-*check*
/// activity, and so the right default when an operator asks for "the log" without naming one.
///
/// That lives in the `server` subdirectory. It is looked up there FIRST, and only then does this
/// fall back to a top-level `*.log` and finally to `newest_log` (anywhere).
///
/// The order used to be the other way round, and it silently rotted. Top-level was preferred to keep
/// short-lived subprocess logs (`update`, `check-hwcodec-config`, …) from winning on mtime — sound
/// when the client wrote its service log at the top level. It no longer does: every component logs
/// into its own subdirectory, so nothing writes a top-level log any more, and the only files still
/// matching are relics left by the pre-subdirectory layout. The default therefore returned a log
/// frozen months earlier — plausible-looking, correctly formatted, and describing a client that no
/// longer exists. That is worse than an error, because nothing about it announces itself as stale.
///
/// The gate was on "does a top-level log exist" when the question is "which log is the service
/// writing NOW". Preferring `server` answers the second one directly.
#[cfg(windows)]
pub(super) fn main_log(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    newest_log_in(&dir.join("server"))
        .or_else(|| newest_log_in(dir))
        .or_else(|| newest_log(dir))
}

/// Newest `*.log` under `dir` (and one level of per-component subdirs flexi_logger may create),
/// by modified time. `None` if the dir is absent or holds no log.
#[cfg(windows)]
pub(super) fn newest_log(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dirs = vec![dir.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path());
            }
        }
    }
    let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("log") {
                continue;
            }
            if let Some(m) = e.metadata().ok().and_then(|md| md.modified().ok()) {
                if best.as_ref().map_or(true, |(bm, _)| m > *bm) {
                    best = Some((m, p));
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Newest `*.log` directly inside `dir` — no recursion, so a caller can ask about one component
/// without a subdirectory's shorter-lived logs outvoting it on mtime.
#[cfg(windows)]
pub(super) fn newest_log_in(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("log"))
        .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()).map(|m| (m, e.path())))
        .max_by_key(|(m, _)| *m)
        .map(|(_, p)| p)
}
