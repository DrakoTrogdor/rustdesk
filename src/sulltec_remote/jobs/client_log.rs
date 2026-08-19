use super::*;

/// Return the tail of a client log under `Config::log_path()`.
///
/// A `name` from `client-logs` selects a specific file and is confined to the log directory. A bare
/// name, JSON string, or JSON object using `name`, `file`, or `log` is accepted. Missing or null names
/// select the main service log. The response uses the `file_pull` shape for the last 128 KiB.
#[cfg(windows)]
pub(super) fn client_log_pull(params: Option<&str>) -> Value {
    const CAP: usize = 128 * 1024;
    let dir = Config::log_path();
    let want: Option<String> = params.map(str::trim).filter(|s| !s.is_empty()).and_then(|raw| {
        match serde_json::from_str::<Value>(raw) {
            // JSON objects accept `name`, `file`, or `log`; a nameless object selects the main log.
            Ok(Value::Object(map)) => ["name", "file", "log"]
                .iter()
                .find_map(|k| map.get(*k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()))
                .map(|s| s.to_string()),
            // Use a JSON string as the log name.
            Ok(Value::String(s)) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            // Other JSON values select the main log.
            Ok(_) => None,
            // Use non-JSON input as a bare log name.
            Err(_) => Some(raw.to_string()),
        }
    });
    let path = match want.as_deref() {
        Some(name) => {
            // Confine named files to the canonical log directory.
            let candidate = dir.join(name.replace('/', "\\"));
            match candidate.canonicalize().ok().zip(dir.canonicalize().ok()) {
                Some((cp, cdir)) if cp.starts_with(&cdir) && cp.is_file() => cp,
                _ => return json!({ "ok": false, "error": format!("no such log: {name}") }),
            }
        }
        None => match main_log(&dir) {
            Some(p) => match stale_against_running_build(&p) {
                Some(err) => return err,
                None => p,
            },
            None => return json!({ "ok": false, "error": format!("no .log under {}", dir.display()) }),
        },
    };
    // Seek before reading so allocation remains bounded by CAP regardless of the file's size.
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
            // Drop a leading partial line from truncated content and decode the log as UTF-8 text.
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

/// `Some(error)` when the log has not been written since the running binary was installed, and so
/// cannot hold a line this build wrote.
#[cfg(windows)]
fn stale_against_running_build(path: &std::path::Path) -> Option<Value> {
    let exe = std::env::current_exe().ok()?;
    let exe_at = std::fs::metadata(exe).ok()?.modified().ok()?;
    let log_at = std::fs::metadata(path).ok()?.modified().ok()?;
    if log_at >= exe_at {
        return None;
    }
    Some(json!({
        "ok": false,
        "error": format!(
            "{} is the newest log this layout offers, and it has not been written since the running \
             build was installed — it predates this client and holds nothing it logged",
            path.display()
        ),
    }))
}

/// Select the newest service log, preferring the `server` subdirectory, then the log root, then any
/// component subdirectory.
#[cfg(windows)]
pub(super) fn main_log(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    newest_log_in(&dir.join("server"))
        .or_else(|| newest_log_in(dir))
        .or_else(|| newest_log(dir))
}

/// Return the newest `*.log` in `dir` or one level of component subdirectories.
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

/// Return the newest `*.log` directly inside `dir` without recursion.
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
