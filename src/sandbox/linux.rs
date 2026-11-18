//! Landlock + seccomp backend. Owned by the Linux track.

use std::process::Command;

use crate::error::{Error, Result};
use crate::helper::Job;
use crate::policy::ResolvedPolicy;
use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};

pub fn probe() -> SandboxInfo {
    SandboxInfo {
        mechanism: Mechanism::Landlock { abi: None },
        status: SandboxStatus::Unavailable {
            reason: "the Linux sandbox is not implemented yet".to_string(),
        },
        baseline_read: super::baseline_read(),
    }
}

pub fn prepare(job: &Job) -> Result<Command> {
    let _ = job;
    Err(Error::not_implemented("the Linux sandbox"))
}

pub fn enter(policy: &ResolvedPolicy) -> Result<()> {
    let _ = policy;
    Err(Error::not_implemented("the Linux sandbox"))
}
