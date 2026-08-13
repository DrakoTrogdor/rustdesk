use super::*;

/// Logged-on and terminal-server sessions on the box (read-only). Parses `quser` (`query user`),
/// which lists every
/// interactive + RDP session with its state + idle + logon time. No params (an empty params object is
/// accepted + ignored). Returns `[{user,session,id,state,idle,logon_time}, …]`. `quser` exits non-zero
/// with "No User exists for *" when nobody is logged on — that's an empty list, not an error.
#[cfg(windows)]
pub(super) fn sessions() -> Option<Value> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // `quser` is a thin wrapper over WTS APIs with fixed-width columns.
    let out = std::process::Command::new("quser")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Header line + one row per session. The leading column may carry a '>' marker for the current
    // session; SESSIONNAME is blank for a disconnected session. Parse positionally from the right so a
    // username with spaces (rare) or a blank session name doesn't misalign the trailing fixed columns.
    let mut rows: Vec<Value> = Vec::new();
    let mut capped = false;
    for line in text.lines().skip(1) {
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        // The user name is the first token (drop a leading '>' current-session marker).
        let line_no_marker = trimmed.trim_start();
        let line_no_marker = line_no_marker.strip_prefix('>').unwrap_or(line_no_marker);
        let fields: Vec<&str> = line_no_marker.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        // Trailing fields are stable: … ID STATE IDLE LOGON-DATE LOGON-TIME (logon time = last 2 tokens).
        // A disconnected session omits SESSIONNAME, so field count varies (6 connected / 5 disconnected).
        let n = fields.len();
        let (user, session, id, state, idle, logon_time) = if n >= 6 {
            (
                fields[0].to_string(),
                fields[1].to_string(),
                fields[2].to_string(),
                fields[3].to_string(),
                fields[4].to_string(),
                format!("{} {}", fields[n - 2], fields[n - 1]),
            )
        } else if n == 5 {
            // Disconnected: user, id, state, idle, logon-date/time collapsed — session name blank.
            (
                fields[0].to_string(),
                String::new(),
                fields[1].to_string(),
                fields[2].to_string(),
                fields[3].to_string(),
                fields[4].to_string(),
            )
        } else {
            continue;
        };
        rows.push(json!({
            "user": user,
            "session": session,
            "id": id,
            "state": state,
            "idle": idle,
            "logon_time": logon_time,
        }));
        if rows.len() >= 200 {
            capped = true;
            break;
        }
    }
    // Mark the result as truncated when the row cap drops the tail.
    let mut out = json!({ "total": rows.len(), "count": rows.len(), "truncated": capped, "items": rows });
    if capped {
        out["next_offset"] = json!(200);
    }
    Some(out)
}

#[cfg(not(windows))]
pub(super) fn sessions() -> Option<Value> {
    None
}
