//! Connection-path logic the fork adds to `server::connection`.
//!
//! Kept here rather than inline because `connection.rs` is the file upstream churns hardest -
//! over 1,300 lines changed since this fork branched. Logic left in there is logic a future
//! merge can quietly mangle; logic here survives an upstream rewrite of that file untouched,
//! and only the call sites need re-placing.

use hbb_common::config::Config;
use hbb_common::message_proto::{Message, Misc, WindowsSessions};

/// SullTec key-pair logon: true if `sig` is a valid console signature over `CONSOLE-LOGON\n{our
/// device id}\n{our per-connection challenge}`. The controller signs it with the console's private
/// key; we verify against our currently-trusted console key (the baked `ST_LOGON_PUBKEY` advanced
/// by any adopted rotation). Empty key or sig → false (feature unprovisioned → normal password
/// flow). Proves the controller holds the console key without any device password; the challenge
/// stops replay and the device-id bind (D1) stops a signature being reused against another device.
pub(crate) fn verify_console_logon_sig(sig: &[u8], challenge: &str) -> bool {
    use hbb_common::sodiumoxide::{base64, crypto::sign};
    // The currently-trusted console logon key: the baked anchor, advanced by any rotation chain
    // adopted off the heartbeat (§B instant rotation). Empty when the feature isn't provisioned.
    let pubkey_b64 = crate::sulltec_remote::jobs::current_logon_pubkey();
    // An attached Ed25519 sig is `sig(64)‖msg`, so it must be ≥ 64 bytes; cap the upper bound so a
    // bogus oversized blob can't amplify verify work on every connection attempt.
    if pubkey_b64.is_empty() || sig.len() < 64 || sig.len() > 64 + 4096 {
        return false;
    }
    let Ok(pk_bytes) = base64::decode(&pubkey_b64, base64::Variant::Original) else {
        return false;
    };
    let Some(pk) = sign::PublicKey::from_slice(&pk_bytes) else {
        return false;
    };
    // Attached signature (sig‖msg): recover the signed bytes and require they are exactly our
    // challenge bind. D1: the controller binds to OUR device id, so verify against our own id —
    // a signature made for a different device can't authorize this one.
    let expected = format!("CONSOLE-LOGON\n{}\n{}", Config::get_id(), challenge);
    matches!(sign::verify(sig, &pk), Ok(recovered) if recovered == expected.as_bytes())
}

/// The console's session picker sends `SelectedSid(u32::MAX)` as a sentinel meaning "re-enumerate
/// my sessions and push the fresh list back" - so the controller can re-open its picker including
/// anyone who logged on since connect. It is NOT a session switch, and must never reach
/// `connect_to_user_session`.
///
/// Returns the standalone `Misc::windows_sessions` reply, or `None` when this process has no
/// session id to report (in which case upstream sends nothing and the sentinel is simply absorbed).
pub(crate) fn windows_sessions_refresh_msg() -> Option<Message> {
    let current_sid = crate::platform::get_current_process_session_id()?;
    let sessions = crate::platform::get_available_sessions(true);
    let mut misc = Misc::new();
    misc.set_windows_sessions(WindowsSessions {
        sessions,
        current_sid,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_misc(misc);
    Some(msg_out)
}
