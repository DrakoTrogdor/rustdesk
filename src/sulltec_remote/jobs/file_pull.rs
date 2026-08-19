use super::*;

/// Read up to 128 KiB from an arbitrary endpoint path without invoking a shell.
///
/// Valid UTF-8 is returned as text and other content as base64. Authorization is provided by the job
/// channel, and the response reports `{ok, path, size, truncated, encoding, content}`.
#[cfg(windows)]
pub(super) fn file_pull(params: Option<&str>) -> Value {
    // Accept a bare path or a JSON object containing `path` or `file`.
    let path_owned = json_field_or_raw(params.unwrap_or(""), &["path", "file"]);
    let path = path_owned.trim();
    if path.is_empty() {
        return json!({ "ok": false, "error": "file-pull needs a path" });
    }
    if super::sensitive_path(path) {
        return json!({ "ok": false, "error": super::SENSITIVE_DENIED });
    }
    const CAP: usize = 128 * 1024; // 128 KB raw keeps the signed result well within limits.
    // Bound allocation independently of the file's reported size. Reading CAP+1 distinguishes an
    // exact-CAP file from truncated content.
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
            // Some device paths report a zero size, so never report less than the bytes read.
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

/// Extract a scalar from a bare value, JSON string, or the first matching field of a JSON object.
///
/// Multiple keys support the parameter names used by different callers, such as `path` and `file`.
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
