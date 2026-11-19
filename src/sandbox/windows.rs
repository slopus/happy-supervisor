//! Windows has no sandbox backend (policy.md, Windows): sandboxed requests are refused.

use crate::error::{Error, Result};
use crate::helper::Job;
use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};

const REASON: &str = "Windows has no sandbox backend";

pub fn probe() -> SandboxInfo {
    SandboxInfo {
        mechanism: Mechanism::None,
        status: SandboxStatus::Unavailable {
            reason: REASON.to_string(),
        },
        baseline_read: super::baseline_read(),
        gaps: Vec::new(),
    }
}

pub fn prepare(plan: &super::Plan, job: &Job) -> Result<super::Prepared> {
    let _ = (plan, job);
    Err(Error::sandbox_unavailable(REASON))
}
