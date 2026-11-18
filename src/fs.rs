//! File operations (`fs.*`). Owned by the files track; the scaffold froze the types and
//! signatures.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::policy::Confinement;
use crate::protocol::{
    Empty, FsListResult, FsMkdirParams, FsPathParams, FsReadParams, FsReadResult, FsRemoveParams,
    FsStat, FsWriteParams, Value,
};

/// One file operation without its `access`. Travels to the sandbox helper inside a
/// [`Job`](crate::helper::Job).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FsRequest {
    Stat(FsPathParams),
    List(FsPathParams),
    Read(FsReadParams),
    Write(FsWriteParams),
    Mkdir(FsMkdirParams),
    Remove(FsRemoveParams),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FsResponse {
    Stat(FsStat),
    List(FsListResult),
    Read(FsReadResult),
    /// `{}`, the result of `fs.write`, `fs.mkdir` and `fs.remove`.
    Done,
}

impl FsResponse {
    /// The reply body of the request this answers.
    pub fn into_value(self) -> Value {
        match self {
            FsResponse::Stat(stat) => crate::wire::to_value(&stat),
            FsResponse::List(list) => crate::wire::to_value(&list),
            FsResponse::Read(read) => crate::wire::to_value(&read),
            FsResponse::Done => crate::wire::to_value(&Empty {}),
        }
    }
}

/// Runs a file request with this process's rights. Called in-process for raw access (on a
/// blocking thread) and inside the sandbox helper for sandboxed access.
pub fn perform(request: &FsRequest) -> Result<FsResponse> {
    let _ = request;
    Err(Error::not_implemented("fs::perform"))
}

/// Runs a file request under its confinement: raw in-process, sandboxed through the helper.
pub async fn handle(request: FsRequest, confinement: Confinement) -> Result<FsResponse> {
    let _ = (request, confinement);
    Err(Error::not_implemented("fs::handle"))
}
