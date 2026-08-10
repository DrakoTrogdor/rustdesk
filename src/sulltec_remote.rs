//! SullTec Remote — everything this fork adds to the client, in one tree.
//!
//! Upstream owns `src/`; this module owns `src/sulltec_remote/`. Keeping the fork's code here
//! rather than scattered beside upstream's means a file either belongs to them or to us, decided
//! by path alone, and `git` can never conflict on a file upstream does not have.
//!
//! What cannot live here is the handful of call sites that reach *into* upstream's own functions —
//! a heartbeat that must fire from their loop, a settings page that must grey out a locked control.
//! Those stay where they are by necessity; see `docs/FORK-EXPOSURE.md` in the parent repo for the
//! per-file split of what moved and what could not.

/// The SullTec product/build version, deliberately decoupled from the RustDesk protocol `VERSION`.
///
/// `VERSION` (e.g. "1.4.7") is load-bearing for the rendezvous handshake, PeerInfo and the
/// version-gated feature negotiation, so it has to stay in upstream's lineage. This instead tracks
/// the CONSOLE's version: it is what the console-driven update check compares against and what the
/// client reports for display, so a device's shown version lines up with the console's own.
///
/// `Build-Release.ps1` bakes the console's workspace version in via `SULLTEC_CLIENT_VERSION`;
/// an ad-hoc dev build without that env falls back to the protocol version.
pub const SULLTEC_VERSION: &str = match option_env!("SULLTEC_CLIENT_VERSION") {
    Some(v) => v,
    None => crate::VERSION,
};

/// Active Directory domain/OU discovery, folded into the sysinfo the client reports.
pub mod ad;

/// Hardware and software inventory, pulled by the server on a staleness TTL via the heartbeat.
pub mod inventory;


/// Connection-path logic: console key-pair logon verification and force-disconnect.
pub mod connection;

/// The console launch hand-off: where the operator token and backend URL come from.
pub mod logon;

/// The console's own keys in the heartbeat reply, dispatched from upstream's sync loop.
pub mod heartbeat;

/// HTTP transport policy the fork sets on upstream's shared clients.
pub mod http;

/// The client-native job channel: signed dispatch, collectors, and Ed25519-signed results.
pub mod jobs;
/// Compatibility with installs made before APP_NAME lost its space. Delete once every
/// device reports a version >= the rename release; see the module docs.

/// The console-driven update mechanism: forced check, resumable download, package verification.
pub mod update;

/// Windows-only fork code: the portable in-place update offer.
#[cfg(windows)]
pub mod windows;
