use super::*;

/// Push a file to the endpoint from an HTTP(S) URL or base64 content.
///
/// The JSON parameters are `{path, url|content_b64}`. Inline content is limited by the job parameter
/// size, so larger files should use `url`.
#[cfg(windows)]
pub(super) fn file_push(params: Option<&str>) -> Value {
    let Some(p) = params.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return json!({ "ok": false, "error": "file-push needs JSON {path, url|content_b64}" });
    };
    let path = p.get("path").and_then(|x| x.as_str()).unwrap_or("").trim();
    if !safe_path(path) {
        return json!({ "ok": false, "error": "invalid destination path" });
    }
    if let Some(url) = p.get("url").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
        if !safe_url(url) {
            return json!({ "ok": false, "error": "url must be http(s) with no spaces/quotes" });
        }
        let script = format!("$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{url}' -OutFile '{path}' -UseBasicParsing; 'ok'");
        let ps = powershell_exe();
        return run_action(&[ps.as_str(), "-NonInteractive", "-NoProfile", "-Command", &script], &format!("downloaded to {path}"));
    }
    if let Some(b64) = p.get("content_b64").and_then(|x| x.as_str()) {
        let Ok(bytes) = base64::decode(b64, variant()) else {
            return json!({ "ok": false, "error": "content_b64 is not valid base64" });
        };
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

/// Run a sanitized argument vector without a console window and report `{ok, result | error}`.
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

/// Validate a nonempty path or argument for interpolation into a single-quoted PowerShell literal.
#[cfg(windows)]
pub(super) fn safe_path(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(|c| matches!(c, '\'' | '"' | '\n' | '\r' | '`'))
}

/// Validate an HTTP(S) URL for interpolation into a single-quoted PowerShell literal.
#[cfg(windows)]
pub(super) fn safe_url(s: &str) -> bool {
    (s.starts_with("http://") || s.starts_with("https://"))
        && s.len() <= 2048
        && !s.chars().any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '`'))
}
