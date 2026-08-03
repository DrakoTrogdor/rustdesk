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

/// Active Directory domain/OU discovery, folded into the sysinfo the client reports.
pub mod ad;

/// Hardware and software inventory, pulled by the server on a staleness TTL via the heartbeat.
pub mod inventory;

/// The app-naming policy: identifier, folder, file-base and exe-name forms.
pub mod naming;

/// Connection-path logic: console key-pair logon verification and force-disconnect.
pub mod connection;

/// The console launch hand-off: where the operator token and backend URL come from.
pub mod logon;

/// The client-native job channel: signed dispatch, collectors, and Ed25519-signed results.
pub mod jobs;

/// Live process/service/Defender/Windows-Update snapshots, requested over the heartbeat.
pub mod snapshot;

/// The console-driven update mechanism: forced check, resumable download, package verification.
pub mod update;

/// Windows-only fork code: the portable in-place update offer.
#[cfg(windows)]
pub mod windows;
