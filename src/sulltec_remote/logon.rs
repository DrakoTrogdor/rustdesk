//! The console launch hand-off.
//!
//! When the console launches a client to connect somewhere, it passes an operator token and a
//! backend URL so the client can ask the console to sign the target's challenge — the console's
//! private key never leaves it.
//!
//! This module resolves where those two values came from. `client.rs` keeps only the few lines that
//! read and write them on `LoginConfigHandler`, because `id` and `hash` on that struct are
//! upstream's and private to that module — passing values out is cheaper than opening them up.

use hbb_common::log;
use std::path::PathBuf;

/// The operator token and backend URL from the launch hand-off. Either may be empty, in which case
/// the caller falls back to the normal password flow.
pub(crate) struct HandOff {
    pub token: String,
    pub url: String,
}

/// Resolve the hand-off on a first connect.
///
/// The console passes these by env (`ST_LOGON_TOKEN` / `ST_LOGON_URL`), but RustDesk's
/// single-instance model forwards a `--connect` to an ALREADY-RUNNING client, where env vars never
/// reach — so fall back to the runtime files the console also writes. Every candidate is **deleted
/// after reading**, parsed or not, to keep the token's on-disk lifetime as short as possible.
///
/// A reconnect does not come through here: the caller retains the token and URL in memory precisely
/// because by then these files are gone, and re-grants against the fresh challenge instead of
/// dropping to a password prompt.
///
/// `id` and `challenge` are used only for the diagnostic line — a hand-off that arrives without
/// them still resolves, and the caller decides what to do about it.
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

/// Hand-off file locations the console may have written, in read priority. MUST mirror the console
/// writer's `logon_handoff_targets`.
///
/// The machine-wide ProgramData path comes FIRST because a SERVICE install runs the connecting
/// client as SYSTEM, which cannot see the console operator's per-user temp dir. The temp path
/// remains for portable and user-context installs, and for consoles predating the ProgramData path.
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

/// Sign a logon challenge locally with `ST_LOGON_KEY`, for admin disaster-recovery and manual use.
///
/// This is the fallback when no console-signed grant is available. The normal path is a grant the
/// console signed for us, which keeps the console's private key on the console; this path needs the
/// key present in the environment, so it exists for the cases where reaching the console is the
/// thing that has failed.
///
/// The signature binds BOTH the target id and the challenge, so a grant captured for one device and
/// connection cannot be replayed against another. Returns `None` when the variable is unset or does
/// not hold a usable key, which leaves the caller on the normal password flow.
///
/// Produces an ATTACHED signature (`sig‖msg`) because that is what the fork's `decode_id_pk`
/// verifies against.
pub(crate) fn sign_locally(id: &str, challenge: &str) -> Option<Vec<u8>> {
    use hbb_common::sodiumoxide::{base64, crypto::sign};

    let key_b64 = std::env::var("ST_LOGON_KEY").ok()?;
    let sk_bytes = base64::decode(key_b64.trim(), base64::Variant::Original).ok()?;
    let sk = sign::SecretKey::from_slice(&sk_bytes)?;
    let msg = format!("CONSOLE-LOGON\n{id}\n{challenge}");
    Some(sign::sign(msg.as_bytes(), &sk))
}

/// A console-signed logon grant for one connection, plus the hand-off values worth retaining.
pub(crate) struct Grant {
    /// The signature over this connection's challenge. Empty when no grant could be obtained, which
    /// leaves the caller on the normal password flow.
    pub sig: Vec<u8>,
    /// The operator token and backend URL to keep in memory. Empty when there is nothing new to
    /// retain — either none was found, or the caller already had them.
    pub token: String,
    pub url: String,
}

/// Obtain a console-signed grant for this connection, resolving the launch hand-off first if the
/// caller does not already hold one.
///
/// Idempotent by the caller's check: it skips entirely when a grant is already held. Any failure
/// leaves `sig` empty rather than erroring, because the fallback — an ordinary password prompt — is a
/// perfectly good outcome and not worth propagating an error for.
///
/// The token and URL come back so the caller can retain them for the session. A RECONNECT gets a fresh
/// challenge and so needs a fresh grant, but by then the hand-off files have been deleted and a
/// forwarded `--connect` never saw the env vars — so without that in-memory copy a reconnect would
/// drop to a password prompt for no reason.
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
