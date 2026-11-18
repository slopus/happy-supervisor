//! Running commands (`exec.*`). Owned by the exec track; the scaffold froze the signatures.

use crate::error::{Error, Result};
use crate::link::Outbox;
use crate::policy::Confinement;
use crate::protocol::{
    ExecId, ExecLogParams, ExecLogResult, ExecStartParams, ExecStartResult, ExecSummary,
    ExecWriteParams, KillSignal,
};

/// Every command of this node, running or recently exited. Commands outlive connections.
pub struct ExecManager {
    #[expect(dead_code, reason = "the exec track sends output and exits through it")]
    outbox: Outbox,
}

impl ExecManager {
    pub fn new(outbox: Outbox) -> ExecManager {
        ExecManager { outbox }
    }

    /// Starts a command. Sandboxed ones go through `sandbox::prepare` and the helper.
    pub async fn start(
        &self,
        params: ExecStartParams,
        confinement: Confinement,
    ) -> Result<ExecStartResult> {
        let _ = (params, confinement);
        Err(Error::not_implemented("exec.start"))
    }

    pub async fn write(&self, params: ExecWriteParams) -> Result<()> {
        let _ = params;
        Err(Error::not_implemented("exec.write"))
    }

    /// Signals the command's process group or Job Object and returns at once.
    pub fn kill(&self, exec_id: &ExecId, signal: KillSignal) -> Result<()> {
        let _ = (exec_id, signal);
        Err(Error::not_implemented("exec.kill"))
    }

    /// Reads a process's output log (api.md, `exec.log` and Output logs).
    pub async fn log(&self, params: ExecLogParams) -> Result<ExecLogResult> {
        let _ = params;
        Err(Error::not_implemented("exec.log"))
    }

    /// Running commands and the most recent exited ones, for `exec.list` and `node.ready`.
    pub fn list(&self) -> Vec<ExecSummary> {
        Vec::new()
    }

    /// Kills every running command. Called when the supervisor exits normally.
    pub async fn shutdown(&self) {}
}
