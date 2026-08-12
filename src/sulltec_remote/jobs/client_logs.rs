use super::*;

/// List the client's available log files (`name` relative to the log dir, `size`, local `modified`),
/// newest first — so an operator can see what's there + which is freshest, then fetch a specific one
/// via `client-log` with that `name`. No content; read-only.
#[cfg(windows)]
pub(super) fn client_logs_list() -> Value {
    let dir = Config::log_path();
    let mut dirs = vec![dir.clone()];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                dirs.push(e.path());
            }
        }
    }
    let mut out: Vec<(i64, Value)> = vec![];
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("log") {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            let modified = meta.modified().ok();
            let mtime = modified
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let modified_str = modified
                .map(|m| chrono::DateTime::<chrono::Local>::from(m).format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            // rel path under the log dir (the `name` selector for client-log), forward-slashed.
            let name = p.strip_prefix(&dir).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            out.push((mtime, json!({ "name": name, "size": meta.len(), "modified": modified_str })));
        }
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    Value::Array(out.into_iter().map(|(_, v)| v).collect())
}
