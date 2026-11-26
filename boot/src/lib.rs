//! happy-supervisor-boot (docs/boot.md): the service's entry point. It runs one verified
//! supervisor build, restarts it when it fails, and on the supervisor's request downloads,
//! verifies and starts another, going back to the one before when the new one does not connect.

pub mod channel;
pub mod fetch;
pub mod minisign;
pub mod release;
pub mod store;
pub mod supervise;
#[cfg(test)]
mod testkit;
