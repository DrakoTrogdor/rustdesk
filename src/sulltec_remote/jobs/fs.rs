use super::*;

/// Filesystem listing at a specified root (read-only). Returns directory entries
/// (name/path/size/modified/attrs/is_reparse_point) and, with `hash`, the SHA-256 of matched files —
/// but not file contents. The console admin-gates this collector.
/// `params` JSON `{path (required root), recurse:bool, depth:N, glob:"*.log", min_size:bytes,
/// modified_since:"yyyy-MM-dd"|days, hidden:bool, hash:bool}`. Walks with `std::fs` (no shell), capped at
/// 1000 entries; the SAM/SECURITY/LSA/DPAPI-equivalent denylist below blocks credential-store paths even
/// though the client runs as SYSTEM. Returns `{path, recurse, row_cap_hit, unreadable_dirs, entries:{…page…}}`.
///
/// A missing or unreadable root is an error rather than an empty listing. Not-found, not-a-directory,
/// and access-denied each return [`fs_error`]'s `{ok:false, path, error}`. A subdirectory that
/// cannot be read mid-walk is counted in `unreadable_dirs` rather than silently skipped, so a
/// partially readable tree returns its accessible entries and reports that it is partial.
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
    // Validate the root before walking so failures remain distinct from an empty directory.
    match std::fs::metadata(root) {
        Ok(m) if !m.is_dir() => {
            return Some(fs_error(root, "path exists but is not a directory; fs lists directories"));
        }
        Ok(_) => {}
        Err(e) => {
            // Preserve OS error text for failures that are neither not-found nor permission-denied.
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
    // modified_since → a SystemTime floor (integer = N days back; string = a date).
    use chrono::TimeZone; // for Local.from_local_datetime
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
    // Continue counting after the materialization cap without allocating more rows. The scan and time
    // bounds set `count_stopped`; when a bound is reached, `matched_total` is null and
    // `matched_at_least` remains the observed floor.
    const COUNT_SCAN_CAP: usize = 200_000;
    let count_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut matched = 0usize;
    let mut examined = 0usize;
    let mut count_stopped = false;
    // Iterative DFS with an explicit (path, depth) stack so a deep tree can't blow the call stack.
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(std::path::PathBuf::from(root), 1)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // A root enumeration failure invalidates the listing. Unreadable subdirectories increment
            // `unreadable_dirs` while the rest of the tree remains available.
            Err(e) if depth == 1 => {
                return Some(fs_error(root, format!("path could not be listed: {e}")));
            }
            Err(_) => {
                unreadable_dirs += 1;
                continue;
            }
        };
        for ent in rd.flatten() {
            // Count every examined entry before filters so nonmatching trees remain bounded. Check the
            // deadline every 4,096 entries.
            examined += 1;
            if examined > COUNT_SCAN_CAP || (examined % 4096 == 0 && std::time::Instant::now() > count_deadline) {
                count_stopped = true;
                break 'walk;
            }
            let path = ent.path();
            let Ok(meta) = ent.metadata() else { continue };
            let is_dir = meta.is_dir();
            let name = ent.file_name().to_string_lossy().into_owned();
            // Hidden filter (Windows FILE_ATTRIBUTE_HIDDEN bit) — skip hidden unless asked.
            let attrs = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes()
            };
            let is_hidden = attrs & 0x2 != 0; // FILE_ATTRIBUTE_HIDDEN
            // Reparse points may represent conditionally mounted trees such as RDS User Profile
            // Disks. Expose the flag so callers can identify virtual trees.
            let is_reparse_point = attrs & 0x400 != 0; // FILE_ATTRIBUTE_REPARSE_POINT
            // Skip hidden entries (and don't descend into hidden dirs) unless hidden was requested.
            if is_hidden && !want_hidden {
                continue;
            }
            // Apply file-only filters (glob/min_size/modified_since) to FILES; dirs are always listed
            // (they're the navigation aid) but still subject to the name glob when one is given.
            let modified = meta.modified().ok();
            let passes_glob = glob.map_or(true, |g| glob_match(g, &name));
            let passes_size = is_dir || meta.len() >= min_size;
            let passes_since = since.map_or(true, |fl| modified.map_or(false, |m| m >= fl));
            if passes_glob && passes_size && passes_since {
                matched += 1;
                // Past the cap, count matching entries without building rows or hashing files.
                if truncated {
                    // Continue descending so the count covers the requested tree.
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
                // SHA-256 of matched FILES on request (size-capped at 64 MB to bound the read).
                if want_hash && !is_dir && meta.len() <= 64 * 1024 * 1024 {
                    if let Ok(bytes) = std::fs::read(&path) {
                        let mut h = Sha256::new();
                        h.update(&bytes);
                        e["sha256"] = json!(format!("{:x}", h.finalize()));
                    }
                }
                entries.push(e);
                if entries.len() >= CAP {
                    // Stop materializing rows while continuing the count.
                    truncated = true;
                }
            }
            // Descend into subdirectories (honouring recurse + depth; hidden dirs already skipped
            // above). A reparse point is LISTED but never followed: Windows ships self-referential
            // junctions (`…\ProgramData\Application Data` → `…\ProgramData` and the per-user
            // equivalent), so following them revisits the same tree and inflates every count with
            // duplicate rows. `is_reparse_point` on the entry is how a caller sees the link is there.
            if is_dir && recurse && depth < max_depth && !is_reparse_point {
                stack.push((path, depth + 1));
            }
        }
    }
    // `row_cap_hit` identifies the materialization cap independently of page truncation.
    Some(json!({
        "path": root,
        "recurse": recurse,
        "row_cap_hit": truncated,
        // Subdirectories the walk could not enumerate. Non-zero means the listing is short of the
        // tree by an unknown amount, which no other field in this envelope can say.
        // This includes unreadable subdirectories encountered after the materialization cap.
        "unreadable_dirs": unreadable_dirs,
        // How many entries MATCHED the filters across the whole walk, not just the ones materialized.
        // `entries.total` keeps the page family's meaning (the rows this envelope pages over) and is
        // still the cap once `row_cap_hit`; these two say what that number cannot:
        //   matched_at_least — the observed floor
        //   matched_total    — the exact count, or null if a bound stopped counting
        "matched_at_least": matched,
        "matched_total": if count_stopped { Value::Null } else { json!(matched) },
        // The count gave up (scan cap or time budget). Distinct from `row_cap_hit`, which is only
        // about how many rows were built.
        "count_stopped": count_stopped,
        "entries": paginate(entries, params, CAP),
        // File contents are not returned; the collector provides listings and optional hashes only.
    }))
}

#[cfg(not(windows))]
pub(super) fn fs_list(_params: Option<&str>) -> Option<Value> {
    None
}

/// An `fs` result that is NOT a listing — a missing path, a refused one, or one that could not be
/// opened or walked. Carries `ok:false` alongside `{path, error}` while the dispatch `status`
/// remains `done`.
/// `path` is echoed on every arm (including the denylist refusal) so one shape answers "which read
/// failed, and why" without the caller re-deriving it from the request.
#[cfg(windows)]
pub(super) fn fs_error(path: &str, why: impl Into<String>) -> Value {
    json!({ "ok": false, "path": path, "error": why.into() })
}

/// `true` if `name` matches a simple `*`/`?` glob (case-insensitive) — `*` any run, `?` one char.
/// Used by `fs_list` for in-collector name filtering without pulling in the `glob` crate.
#[cfg(windows)]
pub(super) fn glob_match(pat: &str, name: &str) -> bool {
    // Classic two-pointer wildcard match with backtracking on `*`.
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

/// Paginate + size-cap a JSON item list for a diag result: apply the optional `{offset, limit}` from
/// `params`, then include items only while the serialized page stays under [`PAGE_BUDGET`] — so a large
/// collection (firewall rules, installed programs, drivers, …) can never SILENTLY overflow the result
/// cap. Returns `{total, offset, count, truncated, next_offset?, items:[…]}`; a caller reads the whole
/// set by re-requesting with `offset = next_offset` until `truncated` is false.
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
