//! Process trees for spawned commands: a Unix process group or a Windows Job Object, so a kill
//! or timeout reaches everything the command started. Owned by the exec track.

#[cfg(unix)]
pub(crate) mod pty;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::{
    Tree, default_interrupt, exit_status, isolate, limit, limit_support, wait_exit,
};
#[cfg(windows)]
pub(crate) use windows::{
    Tree, exit_status, isolate, job_limits, limit_support, status_preamble, wait_exit,
};
