//! SullTec Remote — everything this fork adds to the client, in one tree.

pub const SULLTEC_VERSION: &str = match option_env!("SULLTEC_CLIENT_VERSION") {
    Some(v) => v,
    None => crate::VERSION,
};

pub mod ad;



pub mod connection;

pub mod logon;

pub mod heartbeat;

pub mod http;

pub mod jobs;
pub mod update;

#[cfg(windows)]
pub mod windows;
