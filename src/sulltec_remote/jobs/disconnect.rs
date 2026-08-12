use super::*;

/// Force-disconnect (S6): close every active incoming session (remote control / file transfer /
/// view camera / terminal). Port-forward tunnels can't be reached this way; they're reported as
/// skipped so the operator isn't told they were closed.
pub(super) fn disconnect_sessions() -> Value {
    let (closed, skipped_port_forward, peers) =
        crate::sulltec_remote::connection::close_all_authed_conns();
    json!({
        "ok": true,
        "closed": closed,
        "peers": peers,
        "skipped_port_forward": skipped_port_forward,
    })
}
