//! Process trees for spawned commands: a Unix process group or a Windows Job Object, so a kill
//! or timeout reaches everything the command started. Owned by the exec track.

#[cfg(target_os = "linux")]
pub(crate) mod cgroups;
#[cfg(unix)]
pub(crate) mod pty;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use cgroups::Cgroup;
#[cfg(unix)]
pub(crate) use unix::{
    Tree, default_interrupt, exit_status, isolate, limit, limit_support, wait_exit,
};
#[cfg(windows)]
pub(crate) use windows::{
    Tree, exit_status, isolate, job_limits, limit_support, status_preamble, wait_exit,
};

/// Takes over the cgroup delegated to the supervisor, for `memoryBytes` and `processes` on
/// Linux (`cgroups::init`). Call it at startup, before the supervisor starts any process.
/// Elsewhere it does nothing.
pub fn init_limits() {
    #[cfg(target_os = "linux")]
    cgroups::init();
}

/// Only Linux puts a command in a cgroup of its own.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) enum Cgroup {}

#[cfg(not(target_os = "linux"))]
impl Cgroup {
    pub(crate) fn create(_: &crate::protocol::Limits) -> std::io::Result<Option<Cgroup>> {
        Ok(None)
    }

    pub(crate) fn join(&self, _: &mut std::process::Command) {
        match *self {}
    }

    pub(crate) fn out_of_memory(&self) -> bool {
        match *self {}
    }
}
