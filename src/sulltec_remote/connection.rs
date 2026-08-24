use hbb_common::config::Config;
use hbb_common::message_proto::{Message, Misc, WindowsSessions};

pub(crate) fn verify_console_logon_sig(sig: &[u8], challenge: &str) -> bool {
    use hbb_common::sodiumoxide::{base64, crypto::sign};
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
    // The controller binds to this device id, so verify against our own id: a signature made for a
    // different device can't authorize this one.
    let expected = format!("CONSOLE-LOGON\n{}\n{}", Config::get_id(), challenge);
    matches!(sign::verify(sig, &pk), Ok(recovered) if recovered == expected.as_bytes())
}

/// The console's session picker sends `SelectedSid(u32::MAX)` as a sentinel meaning "re-enumerate
/// my sessions and push the fresh list back". It is NOT a session switch, and must never reach
/// `connect_to_user_session`.
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LogonDecision {
    FallThrough,
    Authorize,
    ReportError,
    RejectNoPassword { tell_peer: bool },
}

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

pub(crate) fn close_all_authed_conns() -> (usize, usize, Vec<String>) {
    close_conns(crate::server::authed_conns_snapshot())
}

/// Port-forward tunnels run a separate raw forwarding loop that never polls the authed channel, so
/// they are counted as skipped rather than falsely reported closed.
fn close_conns(
    conns: Vec<(
        crate::server::AuthConnType,
        String,
        hbb_common::tokio::sync::mpsc::UnboundedSender<crate::ipc::Data>,
    )>,
) -> (usize, usize, Vec<String>) {
    let mut closed = 0usize;
    let mut skipped = 0usize;
    let mut peers: Vec<String> = Vec::new();
    for (conn_type, peer_id, sender) in conns {
        if conn_type == crate::server::AuthConnType::PortForward {
            skipped += 1;
            continue;
        }
        if sender.send(crate::ipc::Data::Close).is_ok() {
            closed += 1;
            peers.push(peer_id);
        }
    }
    (closed, skipped, peers)
}

#[cfg(test)]
mod force_disconnect_tests {
    use super::*;
    use crate::server::AuthConnType;
    use hbb_common::tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    fn conn(
        kind: AuthConnType,
        peer: &str,
    ) -> (
        (
            AuthConnType,
            String,
            hbb_common::tokio::sync::mpsc::UnboundedSender<crate::ipc::Data>,
        ),
        UnboundedReceiver<crate::ipc::Data>,
    ) {
        let (tx, rx) = unbounded_channel();
        ((kind, peer.to_string(), tx), rx)
    }

    #[test]
    fn a_port_forward_tunnel_is_skipped_not_reported_closed() {
        let (remote, mut rx) = conn(AuthConnType::Remote, "peer-remote");
        let (tunnel, _rx_tunnel) = conn(AuthConnType::PortForward, "peer-tunnel");
        let (closed, skipped, peers) = close_conns(vec![remote, tunnel]);
        assert_eq!((closed, skipped), (1, 1));
        assert_eq!(peers, vec!["peer-remote".to_string()]);
        assert!(matches!(rx.try_recv(), Ok(crate::ipc::Data::Close)));
    }

    #[test]
    fn a_connection_already_tearing_down_is_neither_closed_nor_named() {
        let (remote, rx) = conn(AuthConnType::Remote, "peer-gone");
        drop(rx);
        assert_eq!(close_conns(vec![remote]), (0, 0, Vec::new()));
    }

    #[test]
    fn every_authorized_kind_except_port_forward_is_closed() {
        let mut conns = Vec::new();
        let mut keep = Vec::new();
        for kind in [
            AuthConnType::Remote,
            AuthConnType::FileTransfer,
            AuthConnType::ViewCamera,
            AuthConnType::Terminal,
        ] {
            let (c, rx) = conn(kind, "peer");
            conns.push(c);
            keep.push(rx);
        }
        let (closed, skipped, peers) = close_conns(conns);
        assert_eq!((closed, skipped, peers.len()), (4, 0, 4));
    }
}

#[cfg(test)]
mod logon_decision_tests {
    use super::*;

    #[test]
    fn an_unsigned_attempt_falls_through_when_passwords_are_allowed() {
        assert_eq!(
            keypair_logon_decision(b"", "challenge", "", "1.4.7"),
            LogonDecision::FallThrough
        );
    }

    #[test]
    fn a_too_short_signature_is_never_treated_as_valid() {
        assert_eq!(
            keypair_logon_decision(&[0u8; 8], "challenge", "", "1.4.7"),
            LogonDecision::FallThrough
        );
    }

    #[test]
    fn a_staged_error_is_reported_rather_than_swallowed() {
        assert_ne!(
            keypair_logon_decision(b"", "challenge", "account not found", "1.4.7"),
            LogonDecision::Authorize
        );
    }
}

pub(crate) fn windows_sessions_refresh_request(sid: u32) -> Option<hbb_common::message_proto::Message> {
    use hbb_common::message_proto::{Message, Misc};

    if sid != u32::MAX {
        return None;
    }
    let mut misc = Misc::new();
    misc.set_selected_sid(sid);
    let mut msg = Message::new();
    msg.set_misc(misc);
    Some(msg)
}
