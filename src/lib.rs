mod keyboard;
/// cbindgen:ignore
pub mod platform;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use platform::{
    clip_cursor, get_cursor, get_cursor_data, get_cursor_pos, get_focused_display,
    set_cursor_pos, start_os_service,
};
#[cfg(not(any(target_os = "ios")))]
/// cbindgen:ignore
mod server;
#[cfg(not(any(target_os = "ios")))]
pub use self::server::*;
mod client;
mod lan;
#[cfg(not(any(target_os = "ios")))]
mod rendezvous_mediator;
#[cfg(not(any(target_os = "ios")))]
pub use self::rendezvous_mediator::*;
/// cbindgen:ignore
pub mod common;
pub mod console_ad; // SullTec console: AD domain/OU in sysinfo
pub mod console_inventory; // SullTec console: hw/sw inventory, server-pulled via heartbeat
pub mod console_snapshot; // SullTec console: live process/service snapshots, operator-pulled
pub mod console_jobs; // SullTec console: client-native job channel (Ed25519-signed results)
#[cfg(not(any(target_os = "ios")))]
pub mod ipc;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
pub mod ui;
mod version;
pub use version::*;

/// SullTec product/build version, decoupled from the RustDesk protocol `VERSION` (above).
/// `VERSION` (e.g. "1.4.7") is load-bearing for the rendezvous handshake, PeerInfo, and the
/// version-gated feature negotiation in `common.rs` (file copy-paste, relative mouse, etc.) —
/// it must stay in the upstream lineage. `SULLTEC_VERSION` instead tracks the **console's**
/// version and is what the console-driven update check compares against and what the client
/// reports to the console for display, so a device's shown version lines up with the console.
/// Build-Release.ps1 bakes the console's workspace version in via `SULLTEC_CLIENT_VERSION`;
/// ad-hoc dev builds without that env fall back to the protocol `VERSION`.
pub const SULLTEC_VERSION: &str = match option_env!("SULLTEC_CLIENT_VERSION") {
    Some(v) => v,
    None => VERSION,
};
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
mod bridge_generated;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter_ffi;
use common::*;
mod auth_2fa;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(not(target_os = "ios"))]
mod clipboard;
#[cfg(not(any(target_os = "android", target_os = "ios", feature = "cli")))]
pub mod core_main;
mod custom_server;
mod lang;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod port_forward;

#[cfg(all(feature = "flutter", feature = "plugin_framework"))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod plugin;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tray;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod whiteboard;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod updater;

mod ui_cm_interface;
mod ui_interface;
mod ui_session_interface;

mod hbbs_http;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod clipboard_file;

pub mod privacy_mode;

#[cfg(windows)]
pub mod virtual_display_manager;

mod kcp_stream;
