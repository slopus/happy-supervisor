//! happy-supervisor: lets one trusted control plane run commands, read and write files, and
//! watch for changes on this machine. The contract is in `docs/`.
//!
//! The `node` feature (default) is the supervisor. `control-plane` alone is the control plane's
//! side of the link: `protocol`, `wire`, `link`, `ws::upgrade` and `server`.

#[cfg(feature = "node")]
pub mod client;
#[cfg(feature = "node")]
pub mod connect;
#[cfg(feature = "node")]
pub mod controller;
#[cfg(feature = "node")]
pub mod dispatch;
#[cfg(feature = "node")]
pub mod enroll;
pub mod error;
#[cfg(feature = "node")]
pub mod exec;
#[cfg(feature = "node")]
pub mod fs;
#[cfg(feature = "node")]
pub mod helper;
#[cfg(feature = "node")]
pub mod identity;
pub mod link;
#[cfg(feature = "node")]
pub mod node_info;
pub mod policy;
#[cfg(feature = "node")]
mod process;
pub mod protocol;
#[cfg(feature = "node")]
pub mod proxy;
#[cfg(feature = "node")]
pub mod sandbox;
#[cfg(feature = "node")]
pub mod serve;
pub mod server;
#[cfg(feature = "node")]
pub mod state;
#[cfg(feature = "node")]
pub mod streams;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "node")]
pub mod tunnel;
#[cfg(feature = "node")]
pub mod watch;
pub mod wire;
pub mod ws;

/// JSON literals for CBOR values, for this crate's tests and for tests of a control plane.
#[cfg(any(test, feature = "testing"))]
pub mod testkit;

#[cfg(feature = "node")]
pub use controller::Controller;
pub use error::{Error, ErrorKind, Result};
#[cfg(feature = "node")]
pub use process::init_limits;

/// The version reported as `supervisorVersion` and in `hello`: the release version a release
/// build sets in `HAPPY_SUPERVISOR_VERSION` (deploy/README.md), else the crate version.
pub const VERSION: &str = match option_env!("HAPPY_SUPERVISOR_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
