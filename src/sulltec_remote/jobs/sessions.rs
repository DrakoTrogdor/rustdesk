use super::*;

/// Logged-on and terminal-server sessions on the box (read-only). Parses `quser` (`query user`),
/// which lists every
/// interactive + RDP session with its state + idle + logon time. No params (an empty params object is
/// accepted + ignored). Returns `[{user,session,id,state,idle,logon_time}, …]`. `quser` exits non-zero
/// with "No User exists for *" when nobody is logged on — that's an empty list, not an error.
/// One fixed-width column of a `quser` row, by CHARACTER offset, trimmed.
///
/// Character rather than byte offsets because a user name is whatever the domain allows, and a
/// non-ASCII one would put a byte slice inside a code point. A row shorter than the column asked
/// for answers empty, which is what a blank SESSIONNAME and a missing logon time both are.
#[cfg(windows)]
fn column(row: &[char], start: usize, len: Option<usize>) -> String {
    if start >= row.len() {
        return String::new();
    }
    let end = len.map_or(row.len(), |n| (start + n).min(row.len()));
    row[start..end].iter().collect::<String>().trim().to_string()
}

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
        if line.trim().is_empty() {
            continue;
        }
        // ⚠ **BY COLUMN, never by whitespace.** Two things move the token count independently: a
        // disconnected session leaves SESSIONNAME blank, and the logon timestamp carries a space in
        // every locale that prints AM/PM. A split-based parse reads either one as a different
        // column — it drops the logon DATE on a connected row and shifts every field by one on a
        // disconnected row. The offsets below are the ones `quser` pads to, and the same ones the
        // PowerShell reader in `roles/rdsh/sessions` uses.
        let row: Vec<char> = line.chars().collect();
        // The '>' marks the caller's own session and occupies column 0. Blanking it rather than
        // trimming it keeps every following column at its declared offset.
        let row: Vec<char> = match row.split_first() {
            Some(('>', rest)) => std::iter::once(' ').chain(rest.iter().copied()).collect(),
            _ => row,
        };
        let user = column(&row, 1, Some(22));
        if user.is_empty() {
            continue;
        }
        let session = column(&row, 23, Some(18));
        let id = column(&row, 41, Some(4));
        let state = column(&row, 45, Some(8));
        let idle = column(&row, 53, Some(11));
        // To the end of the line: the date and the time together, however the host's locale spells
        // them.
        let logon_time = column(&row, 64, None);
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
