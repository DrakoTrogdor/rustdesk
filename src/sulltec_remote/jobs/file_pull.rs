use super::*;

#[cfg(windows)]
pub(super) fn file_pull(params: Option<&str>) -> Value {
    let path_owned = json_field_or_raw(params.unwrap_or(""), &["path", "file"]);
    let path = path_owned.trim();
    if path.is_empty() {
        return json!({ "ok": false, "error": "file-pull needs a path" });
    }
    if super::sensitive_path(path) {
        return json!({ "ok": false, "error": super::SENSITIVE_DENIED });
    }
    if let Some((offset, length)) = window_of(params.unwrap_or("")) {
        return file_pull_window(path, offset, length);
    }
    const CAP: usize = 128 * 1024;
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
            // Some device paths report a zero size from `metadata`.
            let size = file_size.max(bytes.len() as u64);
            match std::str::from_utf8(&bytes) {
                Ok(text) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "text", "content": text }),
                Err(_) => json!({ "ok": true, "path": path, "size": size, "truncated": truncated, "encoding": "base64", "content": base64::encode(&bytes, variant()) }),
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

#[cfg(windows)]
const WINDOW_LENGTH: u64 = 32 * 1024;

#[cfg(windows)]
fn window_of(raw: &str) -> Option<(u64, u64)> {
    let ask: Value = serde_json::from_str(raw.trim()).ok()?;
    let offset = ask.get("offset").and_then(Value::as_u64);
    let length = ask.get("length").and_then(Value::as_u64);
    if offset.is_none() && length.is_none() {
        return None;
    }
    Some((offset.unwrap_or(0), length.unwrap_or(WINDOW_LENGTH)))
}

#[cfg(windows)]
fn file_pull_window(path: &str, offset: u64, length: u64) -> Value {
    use std::io::{Read, Seek, SeekFrom};
    let read = std::fs::File::open(path).and_then(|mut f| {
        let file_size = f.metadata()?.len();
        f.seek(SeekFrom::Start(offset))?;
        let mut buf: Vec<u8> = Vec::new();
        f.take(length.saturating_add(1)).read_to_end(&mut buf)?;
        Ok((file_size, buf))
    });
    let (file_size, mut bytes) = match read {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": e.to_string() }),
    };
    let mut more = bytes.len() as u64 > length;
    bytes.truncate(length as usize);
    if let Some(e) = std::str::from_utf8(&bytes).err() {
        if e.error_len().is_none() && e.valid_up_to() > 0 {
            bytes.truncate(e.valid_up_to());
            more = true;
        }
    }
    let returned = bytes.len() as u64;
    let size = if file_size == 0 && returned > 0 { offset.saturating_add(returned) } else { file_size };
    let next_offset = more.then(|| offset + returned);
    let (encoding, content) = match std::str::from_utf8(&bytes) {
        Ok(text) if !text.chars().any(|c| c.is_ascii_control() && !matches!(c, '\t' | '\n' | '\r')) => {
            ("text", text.to_string())
        }
        _ => ("base64", base64::encode(&bytes, variant())),
    };
    json!({ "ok": true, "path": path, "size": size, "offset": offset, "length": returned, "next_offset": next_offset, "truncated": more, "encoding": encoding, "content": content })
}

#[cfg(not(windows))]
pub(super) fn file_pull(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

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
