use super::*;

/// Pull a file off the endpoint (F14, admin). Reads via Rust `std::fs` (no shell), size-capped; returns
/// it as `text` when valid UTF-8, else base64. `{ok, path, size, truncated, encoding, content}`.
///
/// Intentionally reads an ARBITRARY path (an operator pulls a log from anywhere), so — unlike
/// `file_push` — it must NOT be constrained to a write-root via `safe_path`; that would break
/// the feature. Its authorization is the signed job channel (R2): once dispatch-signature enforcement
/// is on, only the console can request a pull. Until then (observe) the `CAP` size limit bounds any one
/// read. Don't bolt a path allow-list on here without making it operator-configurable.
#[cfg(windows)]
pub(super) fn file_pull(params: Option<&str>) -> Value {
    // A bare path (console UI) or a `{"path":…}` / `{"file":…}` body (/api/diag). Without the unwrap the
    // JSON text itself was passed to `read`, which failed with a filename-syntax error naming the body.
    let path_owned = json_field_or_raw(params.unwrap_or(""), &["path", "file"]);
    let path = path_owned.trim();
    if path.is_empty() {
        return json!({ "ok": false, "error": "file-pull needs a path" });
    }
    const CAP: usize = 128 * 1024; // 128 KB raw keeps the signed result well within limits.
    // The read is bounded BEFORE it allocates. `std::fs::read` sizes its buffer from the file — and
    // grows it without limit when the size hint is 0, as on a device path — so a pull of a pagefile,
    // a VHDX or `\\.\PhysicalDrive0` allocated proportionally to the target, and an allocation failure
    // aborts the process rather than failing the job. CAP+1 is read so a file of exactly CAP is still
    // reported untruncated, as before.
    use std::io::Read;
    let read = std::fs::File::open(path).and_then(|f| {
        let file_size = f.metadata()?.len();
        let mut buf: Vec<u8> = Vec::new();
        f.take(CAP as u64 + 1).read_to_end(&mut buf)?;
        Ok((file_size, buf))
    });
    match read {
        Ok((file_size, mut bytes)) => {
            let truncated = bytes.len() > CAP;
            if truncated {
                bytes.truncate(CAP);
            }
            // The file's own size, so the caller learns how much it did NOT get. A device path can
            // report 0 there, so never understate it below what was actually read.
            let size = file_size.max(bytes.len() as u64);
            match std::str::from_utf8(&bytes) {
                Ok(text) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "text", "content": text }),
                Err(_) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "base64", "content": base64::encode(&bytes, variant()) }),
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(not(windows))]
pub(super) fn file_pull(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

/// Extract a scalar collector param that may arrive as a **bare string** (the console UI sends it raw)
/// OR **wrapped in a JSON object** by the `/api/diag` route (which serializes its request body). Returns
/// the first matching field for an object, the string for a JSON string, else the raw input. This is
/// what fixes the collectors that expected a raw scalar (`reg-read` = a path, `file-pull` = a path) but
/// were handed a JSON body over the API.
///
/// Several keys are accepted for the same value because callers reasonably spell it differently — a
/// path arrives as `path` from one surface and `file` from another, and reading only the first name
/// silently drops the value rather than failing, which is far harder to notice.
#[cfg(windows)]
pub(super) fn json_field_or_raw(raw: &str, keys: &[&str]) -> String {
    let raw = raw.trim();
    if raw.starts_with('{') || raw.starts_with('"') {
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(o) = v.as_object() {
                return keys
                    .iter()
                    .find_map(|k| o.get(*k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()))
                    .unwrap_or("")
                    .to_string();
            }
            if let Some(s) = v.as_str() {
                return s.trim().to_string();
            }
        }
    }
    raw.to_string()
}
