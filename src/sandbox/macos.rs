//! Seatbelt (`sandbox-exec`) backend. Owned by the macOS track.

use std::process::Command;

use crate::error::{Error, Result};
use crate::helper::Job;
use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};

pub fn probe() -> SandboxInfo {
    SandboxInfo {
        mechanism: Mechanism::Seatbelt,
        status: SandboxStatus::Unavailable {
            reason: "the macOS sandbox is not implemented yet".to_string(),
        },
        baseline_read: super::baseline_read(),
    }
}

pub fn prepare(job: &Job) -> Result<Command> {
    let _ = job;
    Err(Error::not_implemented("the macOS sandbox"))
}
