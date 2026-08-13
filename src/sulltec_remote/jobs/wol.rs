use super::*;

/// Wake-on-LAN magic packet. `params` is the **target** MAC ("AA:BB:CC:DD:EE:FF" or bare hex; any
/// separators tolerated); this online device broadcasts the packet on its LAN to wake the sleeping
/// target. Cross-platform UDP — sent to the broadcast address on the conventional WoL ports (9 and 7).
pub(super) fn wol(params: Option<&str>) -> Value {
    let raw = params.unwrap_or("").trim();
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return json!({ "ok": false, "error": "MAC must be 6 hex bytes (e.g. AA:BB:CC:DD:EE:FF)" });
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.set_broadcast(true);
            let r1 = sock.send_to(&packet, "255.255.255.255:9");
            let r2 = sock.send_to(&packet, "255.255.255.255:7");
            if r1.is_ok() || r2.is_ok() {
                json!({ "ok": true, "result": format!("magic packet sent to {raw}") })
            } else {
                json!({ "ok": false, "error": "failed to send broadcast" })
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}
