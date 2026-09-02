//! When the console launches a client to connect somewhere, it passes an operator token and a
//! backend URL so the client can ask the console to sign the target's challenge — the console's
//! private key never leaves it.

use crate::client::LoginConfigHandler;
use hbb_common::{log, message_proto::Hash};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

pub(crate) struct HandOff {
    pub token: String,
    pub url: String,
    pub password: String,
}

/// The env vars are the primary channel, but RustDesk's single-instance model can forward
/// `--connect` to an already-running client that never sees the new environment, which is why the
/// files exist at all.
pub(crate) fn resolve_handoff(id: &str, challenge: &str) -> HandOff {
    let mut token = std::env::var("ST_LOGON_TOKEN").unwrap_or_default();
    let mut url = std::env::var("ST_LOGON_URL").unwrap_or_default();
    let mut password = env_password(id);
    let from_env = !token.is_empty() && !url.is_empty();
    let mut password_src = if password.is_empty() { "none" } else { "env" };
    let mut cleared = 0usize;
    if from_env && launched_for(id) {
        for f in handoff_candidates() {
            let mine = std::fs::read_to_string(&f)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .map(|v| v.get("id").and_then(|x| x.as_str()) == Some(bare_id(id)))
                .unwrap_or(false);
            if mine && std::fs::remove_file(&f).is_ok() {
                cleared += 1;
            }
        }
    }
    if token.is_empty() || url.is_empty() {
        for f in handoff_candidates() {
            if token.is_empty() || url.is_empty() {
                if let Ok(s) = std::fs::read_to_string(&f) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                        if token.is_empty() {
                            token = field(&v, "token");
                        }
                        if url.is_empty() {
                            url = field(&v, "url");
                        }
                        if password.is_empty() && handoff_is_for(&v, id) {
                            password = field(&v, "password");
                            if !password.is_empty() {
                                password_src = "file";
                            }
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
        "console-logon: hand-off source={src} (token={}, url={}, password={password_src}, cleared={cleared}, id={}, challenge={})",
        !token.is_empty(),
        !url.is_empty(),
        !id.is_empty(),
        !challenge.is_empty()
    );
    HandOff {
        token,
        url,
        password,
    }
}

fn field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_owned()
}

fn bare_id(id: &str) -> &str {
    id.split('@').next().unwrap_or(id)
}

/// The environment outlives the connect it was set for: the launched process stays open as the
/// operator's GUI, and every later session it starts sees the same variables.
fn env_password(id: &str) -> String {
    if !launched_for(id) {
        return String::new();
    }
    std::env::var("ST_CONNECT_PASSWORD").unwrap_or_default()
}

fn launched_for(id: &str) -> bool {
    let bare = bare_id(id);
    std::env::args().skip(1).any(|a| a == bare)
}

fn handoff_is_for(v: &serde_json::Value, id: &str) -> bool {
    match v.get("id").and_then(|x| x.as_str()) {
        Some(file_id) => file_id == bare_id(id),
        None => true,
    }
}

/// `Sha256(password ‖ salt)`, the shape `handle_hash` gives a preset password; empty when the
/// console passed none. The one read of the hand-off deletes the files, so the token and URL it
/// carried are retained here for `fetch_grant`.
pub(crate) fn preset_password(lc: &Arc<RwLock<LoginConfigHandler>>, hash: &Hash) -> Vec<u8> {
    let (id, token, url) = {
        let g = lc.read().unwrap();
        (
            g.get_id().to_owned(),
            g.console_logon_token.clone(),
            g.console_logon_url.clone(),
        )
    };
    let h = if token.is_empty() || url.is_empty() {
        resolve_handoff(&id, &hash.challenge)
    } else {
        HandOff {
            token,
            url,
            password: env_password(&id),
        }
    };
    if !h.token.is_empty() && !h.url.is_empty() {
        let mut w = lc.write().unwrap();
        w.console_logon_token = h.token;
        w.console_logon_url = h.url;
    }
    if h.password.is_empty() {
        return Vec::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(h.password);
    hasher.update(&hash.salt);
    hasher.finalize()[..].into()
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
