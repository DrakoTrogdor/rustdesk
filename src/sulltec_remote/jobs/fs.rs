use super::*;

#[cfg(windows)]
pub(super) fn fs_list(params: Option<&str>) -> Option<Value> {
    use hbb_common::sha2::{Digest, Sha256};
    const CAP: usize = 1000;
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let root = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if root.is_empty() {
        return Some(fs_error(root, "fs needs a path (root)"));
    }
    if super::sensitive_path(root) {
        return Some(fs_error(root, super::SENSITIVE_DENIED));
    }
    match std::fs::metadata(root) {
        Ok(m) if !m.is_dir() => {
            return Some(fs_error(root, "path exists but is not a directory; fs lists directories"));
        }
        Ok(_) => {}
        Err(e) => {
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => "path not found".to_owned(),
                std::io::ErrorKind::PermissionDenied => "access denied reading the path".to_owned(),
                _ => format!("path could not be opened: {e}"),
            };
            return Some(fs_error(root, reason));
        }
    }
    let recurse = p.get("recurse").and_then(|x| x.as_bool()).unwrap_or(false);
    let max_depth = p.get("depth").and_then(|x| x.as_u64()).map(|d| d as usize).unwrap_or(if recurse { 8 } else { 1 }).min(32);
    let glob = p.get("glob").and_then(|x| x.as_str()).filter(|s| !s.is_empty());
    let min_size = p.get("min_size").and_then(|x| x.as_u64()).unwrap_or(0);
    let want_hidden = p.get("hidden").and_then(|x| x.as_bool()).unwrap_or(false);
    let want_hash = p.get("hash").and_then(|x| x.as_bool()).unwrap_or(false);
    use chrono::TimeZone;
    let since: Option<std::time::SystemTime> = match p.get("modified_since") {
        Some(Value::Number(n)) => n
            .as_i64()
            .map(|d| std::time::SystemTime::now() - std::time::Duration::from_secs((d.max(0) as u64) * 86400)),
        Some(Value::String(s)) => chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .and_then(|dt| chrono::Local.from_local_datetime(&dt).single())
            .map(std::time::SystemTime::from),
        _ => None,
    };

    let fmt_time = |t: std::time::SystemTime| {
        chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M:%S").to_string()
    };
    let mut entries: Vec<Value> = Vec::new();
    let mut truncated = false;
    let mut unreadable_dirs = 0usize;
    const COUNT_SCAN_CAP: usize = 200_000;
    let count_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut matched = 0usize;
    let mut examined = 0usize;
    let mut count_stopped = false;
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(std::path::PathBuf::from(root), 1)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if depth == 1 => {
                return Some(fs_error(root, format!("path could not be listed: {e}")));
            }
            Err(_) => {
                unreadable_dirs += 1;
                continue;
            }
        };
        for ent in rd.flatten() {
            examined += 1;
            if examined > COUNT_SCAN_CAP || (examined % 4096 == 0 && std::time::Instant::now() > count_deadline) {
                count_stopped = true;
                break 'walk;
            }
            let path = ent.path();
            let Ok(meta) = ent.metadata() else { continue };
            let is_dir = meta.is_dir();
            let name = ent.file_name().to_string_lossy().into_owned();
            let attrs = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes()
            };
            let is_hidden = attrs & 0x2 != 0;
            let is_reparse_point = attrs & 0x400 != 0;
            if is_hidden && !want_hidden {
                continue;
            }
            let modified = meta.modified().ok();
            let passes_glob = glob.map_or(true, |g| glob_match(g, &name));
            let passes_size = is_dir || meta.len() >= min_size;
            let passes_since = since.map_or(true, |fl| modified.map_or(false, |m| m >= fl));
            if passes_glob && passes_size && passes_since {
                matched += 1;
                if truncated {
                    if is_dir && recurse && depth < max_depth && !is_reparse_point {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                let mut e = json!({
                    "name": name,
                    "path": path.to_string_lossy(),
                    "is_dir": is_dir,
                    "size": if is_dir { 0 } else { meta.len() },
                    "modified": modified.map(fmt_time).unwrap_or_default(),
                    "attrs": attrs,
                    "is_reparse_point": is_reparse_point,
                });
                if want_hash && !is_dir && meta.len() <= 64 * 1024 * 1024 {
                    if let Ok(bytes) = std::fs::read(&path) {
                        let mut h = Sha256::new();
                        h.update(&bytes);
                        e["sha256"] = json!(format!("{:x}", h.finalize()));
                    }
                }
                entries.push(e);
                if entries.len() >= CAP {
                    truncated = true;
                }
            }
            // A reparse point is LISTED but never followed: Windows ships self-referential
            // junctions (`…\ProgramData\Application Data` → `…\ProgramData` and the per-user
            // equivalent), so following them revisits the same tree and inflates every count with
            // duplicate rows.
            if is_dir && recurse && depth < max_depth && !is_reparse_point {
                stack.push((path, depth + 1));
            }
        }
    }
    Some(json!({
        "path": root,
        "recurse": recurse,
        "row_cap_hit": truncated,
        "unreadable_dirs": unreadable_dirs,
        "matched_at_least": matched,
        "matched_total": if count_stopped { Value::Null } else { json!(matched) },
        "count_stopped": count_stopped,
        "entries": paginate(entries, params, CAP),
    }))
}

#[cfg(not(windows))]
pub(super) fn fs_list(_params: Option<&str>) -> Option<Value> {
    None
}

#[cfg(windows)]
pub(super) fn fs_error(path: &str, why: impl Into<String>) -> Value {
    json!({ "ok": false, "path": path, "error": why.into() })
}

#[cfg(windows)]
pub(super) fn glob_match(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let s: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(windows)]
pub(super) fn paginate(items: Vec<Value>, params: Option<&str>, default_limit: usize) -> Value {
    let p: Value = params.and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
    let total = items.len();
    let offset = p.get("offset").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let limit = p
        .get("limit")
        .and_then(|x| x.as_u64())
        .map(|n| (n as usize).max(1))
        .unwrap_or(default_limit);
    let page = page_within_budget(items.iter().skip(offset), limit);
    let end = offset + page.len();
    let mut out = json!({
        "total": total,
        "offset": offset,
        "count": page.len(),
        "truncated": end < total,
        "items": page,
    });
    if end < total {
        out["next_offset"] = json!(end);
    }
    out
}
