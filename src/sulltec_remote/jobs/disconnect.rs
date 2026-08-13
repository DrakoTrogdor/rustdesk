use super::*;

/// Close active incoming sessions and report unreachable port-forward tunnels as skipped.
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
