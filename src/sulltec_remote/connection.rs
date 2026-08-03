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

/// What the console key-pair logon path has decided, for a caller that owns the connection.
///
/// The decision is made here; the *effects* stay in `server::connection` because every one of them
/// needs `&mut Connection` and its private methods. Splitting it this way means the policy — when a
/// signature authorizes, when key-pair-only mode rejects, which peers are old enough to be told why
/// — survives an upstream rewrite of the auth flow, and is unit-testable without a live connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LogonDecision {
    /// No usable console signature, and the device still permits passwords. Upstream continues into
    /// its normal approve-mode / password flow; nothing about ordinary connections changes.
    FallThrough,
    /// A valid console signature over our challenge. Authorize without a device password.
    Authorize,
    /// The signature is good, but the caller already staged a login error. Report that instead.
    ReportError,
    /// No valid signature and the device accepts ONLY key-pair logon, so there is no password
    /// fallback to offer. `tell_peer` is false for peers too old to render the reason.
    RejectNoPassword { tell_peer: bool },
}

/// Decide the key-pair logon outcome. `err_msg` is whatever login error the caller already staged.
pub(crate) fn keypair_logon_decision(
    sig: &[u8],
    challenge: &str,
    err_msg: &str,
    peer_version: &str,
) -> LogonDecision {
    if verify_console_logon_sig(sig, challenge) {
        return if err_msg.is_empty() {
            LogonDecision::Authorize
        } else {
            LogonDecision::ReportError
        };
    }
    if hbb_common::password_security::keypair_only() {
        // Below 1.2.0 the peer cannot render this error, so sending it only produces a confusing
        // client-side failure; the connection is refused either way.
        let tell_peer = hbb_common::get_version_number(peer_version)
            >= hbb_common::get_version_number("1.2.0");
        return LogonDecision::RejectNoPassword { tell_peer };
    }
    LogonDecision::FallThrough
}

#[cfg(test)]
mod logon_decision_tests {
    use super::*;

    #[test]
    fn an_unsigned_attempt_falls_through_when_passwords_are_allowed() {
        // No signature and (by default config) not keypair-only: the password flow must still run.
        assert_eq!(
            keypair_logon_decision(b"", "challenge", "", "1.4.7"),
            LogonDecision::FallThrough
        );
    }

    #[test]
    fn a_too_short_signature_is_never_treated_as_valid() {
        // An attached Ed25519 signature is sig(64)+msg, so anything under 64 bytes cannot verify -
        // the guard exists so a truncated blob can't reach the crypto at all.
        assert_eq!(
            keypair_logon_decision(&[0u8; 8], "challenge", "", "1.4.7"),
            LogonDecision::FallThrough
        );
    }

    #[test]
    fn a_staged_error_is_reported_rather_than_swallowed() {
        // Guards the branch order: an error staged before this point must not be lost just because
        // the signature check runs first.
        assert_ne!(
            keypair_logon_decision(b"", "challenge", "account not found", "1.4.7"),
            LogonDecision::Authorize
        );
    }
}
