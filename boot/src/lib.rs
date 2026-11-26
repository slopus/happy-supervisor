//! happy-supervisor-boot (docs/boot.md): the service's entry point. It runs one verified
//! supervisor build, restarts it when it fails, and on the supervisor's request downloads,
//! verifies and starts another, going back to the one before when the new one does not connect.

/// This boot's version, as status reports it: the release version a release build sets in
/// `HAPPY_SUPERVISOR_VERSION` (deploy/README.md), else the crate version.
pub const VERSION: &str = match option_env!("HAPPY_SUPERVISOR_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

pub mod channel;
pub mod fetch;
pub mod minisign;
pub mod release;
pub mod store;
pub mod supervise;
#[cfg(test)]
mod testkit;
