//! When the console launches a client to connect somewhere, it passes an operator token and a
//! backend URL so the client can ask the console to sign the target's challenge — the console's
//! private key never leaves it.

use hbb_common::log;
use std::path::PathBuf;

pub(crate) struct HandOff {
    pub token: String,
    pub url: String,
}

/// The env vars are the primary channel, but RustDesk's single-instance model can forward
/// `--connect` to an already-running client that never sees the new environment, which is why the
/// files exist at all.
pub(crate) fn resolve_handoff(id: &str, challenge: &str) -> HandOff {
    let mut token = std::env::var("ST_LOGON_TOKEN").unwrap_or_default();
    let mut url = std::env::var("ST_LOGON_URL").unwrap_or_default();
    let from_env = !token.is_empty() && !url.is_empty();
    if token.is_empty() || url.is_empty() {
        for f in handoff_candidates() {
            if token.is_empty() || url.is_empty() {
                if let Ok(s) = std::fs::read_to_string(&f) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                        if token.is_empty() {
                            token = v
                                .get("token")
                                .and_then(|x| x.as_str())
                                .unwrap_or_default()
                                .to_owned();
                        }
                        if url.is_empty() {
                            url = v
                                .get("url")
                                .and_then(|x| x.as_str())
                                .unwrap_or_default()
                                .to_owned();
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&f);
        }
    }
    let src = if from_env {
        "env"
    } else if !token.is_empty() && !url.is_empty() {
        "file"
    } else {
        "none"
    };
    log::info!(
        "console-logon: hand-off source={src} (token={}, url={}, id={}, challenge={})",
        !token.is_empty(),
        !url.is_empty(),
        !id.is_empty(),
        !challenge.is_empty()
    );
    HandOff { token, url }
}

/// MUST mirror the console writer's `logon_handoff_targets`.
pub(crate) fn handoff_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    if let Ok(base) = std::env::var("ProgramData") {
        v.push(
            PathBuf::from(base)
                .join("SullTecRemote")
                .join("console-logon.json"),
        );
    }
    v.push(std::env::temp_dir().join("sulltec-console-logon.json"));
    v
}

/// Attached signature (`sig‖msg`), which is what `decode_id_pk` expects.
pub(crate) fn sign_locally(id: &str, challenge: &str) -> Option<Vec<u8>> {
    use hbb_common::sodiumoxide::{base64, crypto::sign};

    let key_b64 = std::env::var("ST_LOGON_KEY").ok()?;
    let sk_bytes = base64::decode(key_b64.trim(), base64::Variant::Original).ok()?;
    let sk = sign::SecretKey::from_slice(&sk_bytes)?;
    let msg = format!("CONSOLE-LOGON\n{id}\n{challenge}");
    Some(sign::sign(msg.as_bytes(), &sk))
}

pub(crate) struct Grant {
    pub sig: Vec<u8>,
    pub token: String,
    pub url: String,
}

pub(crate) async fn fetch_grant(id: &str, challenge: &str, token: &str, url: &str) -> Grant {
    let (mut token, mut url) = (token.to_owned(), url.to_owned());
    let mut retain = false;

    if token.is_empty() || url.is_empty() {
        let h = resolve_handoff(id, challenge);
        token = h.token;
        url = h.url;
        retain = !token.is_empty() && !url.is_empty();
    }

    let none = Grant {
        sig: Vec::new(),
        token: if retain { token.clone() } else { String::new() },
        url: if retain { url.clone() } else { String::new() },
    };
    if token.is_empty() || url.is_empty() || id.is_empty() || challenge.is_empty() {
        return none;
    }

    let sig = super::jobs::fetch_logon_grant(&url, &token, id, challenge).await;
    Grant { sig, ..none }
}
