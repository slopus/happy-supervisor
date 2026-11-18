//! happy-supervisor: lets one trusted control plane run commands, read and write files, and
//! watch for changes on this machine. The contract is in `docs/`.

pub mod client;
pub mod dispatch;
pub mod enroll;
pub mod error;
pub mod exec;
pub mod fs;
pub mod helper;
pub mod link;
pub mod node_info;
pub mod policy;
mod process;
pub mod protocol;
pub mod sandbox;
pub mod state;
#[cfg(feature = "testing")]
pub mod testing;
pub mod watch;
pub mod wire;

#[cfg(test)]
mod testkit;

pub use error::{Error, ErrorKind, Result};

/// The crate version, reported as `supervisorVersion` and in `hello`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
