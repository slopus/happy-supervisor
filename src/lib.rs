//! happy-supervisor: lets one trusted control plane run commands, read and write files, and
//! watch for changes on this machine. The contract is in `docs/`.

pub mod error;
pub mod policy;
pub mod protocol;

pub use error::{Error, ErrorKind, Result};

/// The crate version, reported as `supervisorVersion` and in `node.hello`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
