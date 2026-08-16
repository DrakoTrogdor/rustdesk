use super::*;

/// The target MAC out of one ask: the `mac` field of a JSON object, a JSON string, or the text as it
/// arrived.
///
/// ⚠ **An object is read by FIELD, never as text.** The address is recovered below by keeping the
/// hex digits of what is handed over, and a key name is hex too — the `a` and the `c` of `mac` fold
/// straight into the address, so an object read as text yields a wrong MAC rather than a refusal.
fn target_mac(raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => {
            map.get("mac").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
        }
        Ok(Value::String(s)) => s.trim().to_string(),
        // A bare MAC: not JSON at all, or the digits-only form JSON reads as a number.
        _ => raw.to_string(),
    }
}

/// Wake-on-LAN magic packet. The parameters name the **target** MAC — `{"mac": "AA:BB:CC:DD:EE:FF"}`,
/// a JSON string, or a bare one; any separators tolerated. This online device broadcasts the packet
/// on its LAN to wake the sleeping target. Cross-platform UDP — sent to the broadcast address on the
/// conventional WoL ports (9 and 7).
pub(super) fn wol(params: Option<&str>) -> Value {
    let raw = target_mac(params.unwrap_or("").trim());
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
