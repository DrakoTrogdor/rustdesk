use super::*;

#[cfg(windows)]
pub(super) fn file_push(params: Option<&str>) -> Value {
    use hbb_common::sha2::{Digest, Sha256};
    let Some(p) = params.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return json!({ "ok": false, "error": "file-push needs JSON {path, url|content_b64}" });
    };
    let path = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if !safe_path(path) {
        return json!({ "ok": false, "error": "invalid destination path" });
    }
    if super::sensitive_path(path) {
        return json!({ "ok": false, "error": super::SENSITIVE_DENIED });
    }
    let url = p.get("url").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let b64 = p.get("content_b64").and_then(|x| x.as_str());
    let sha256 = p.get("sha256").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty());
    if sha256.is_some_and(|s| s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit())) {
        return json!({ "ok": false, "error": "sha256 must be 64 hex characters" });
    }
    let sha256 = sha256.map(str::to_ascii_lowercase);
    if let Some(url) = url {
        if !safe_url(url) {
            return json!({ "ok": false, "error": "url must be http(s) with no spaces/quotes" });
        }
        let script = format!("$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{path}' -UseBasicParsing; 'ok'");
        let ps = powershell_exe();
        let out = run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &script], &format!("downloaded to {path}"));
        let Some(expected) = sha256 else {
            return out;
        };
        if out.get("ok").and_then(|x| x.as_bool()) != Some(true) {
            return out;
        }
        let Ok(mut f) = std::fs::File::open(path) else {
            return json!({ "ok": false, "error": format!("downloaded to {path} but could not read it back to verify sha256") });
        };
        let mut h = Sha256::new();
        if std::io::copy(&mut f, &mut h).is_err() {
            return json!({ "ok": false, "error": format!("downloaded to {path} but could not read it back to verify sha256") });
        }
        let computed = format!("{:x}", h.finalize());
        if computed != expected {
            let _ = std::fs::remove_file(path);
            return json!({ "ok": false, "error": format!("sha256 mismatch: computed {computed}; the downloaded file was removed") });
        }
        return out;
    }
    if let Some(b64) = b64 {
        let Ok(bytes) = base64::decode(b64, variant()) else {
            return json!({ "ok": false, "error": "content_b64 is not valid base64" });
        };
        if let Some(expected) = &sha256 {
            let mut h = Sha256::new();
            h.update(&bytes);
            let computed = format!("{:x}", h.finalize());
            if computed != *expected {
                return json!({ "ok": false, "error": format!("sha256 mismatch: computed {computed}") });
            }
        }
        return match std::fs::write(path, &bytes) {
            Ok(_) => json!({ "ok": true, "result": format!("wrote {} bytes to {path}", bytes.len()) }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        };
    }
    json!({ "ok": false, "error": "file-push needs either url or content_b64" })
}

#[cfg(not(windows))]
pub(super) fn file_push(_params: Option<&str>) -> Value {
    json!({ "ok": false, "error": "Windows-only" })
}

#[cfg(windows)]
pub(super) fn run_action(argv: &[&str], ok_label: &str) -> Value {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(argv[0])
        .args(&argv[1..])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) if o.status.success() => json!({ "ok": true, "result": ok_label }),
        Ok(o) => json!({ "ok": false, "error": String::from_utf8_lossy(&o.stderr).trim().chars().take(300).collect::<String>() }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

/// The rejected characters are the ones that would break OUT of a single-quoted PowerShell
/// literal, which is the only context these are interpolated into.
#[cfg(windows)]
pub(super) fn safe_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`'))
}

#[cfg(windows)]
pub(super) fn safe_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s.chars().any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '`'))
}
