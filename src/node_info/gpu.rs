//! GPU discovery per platform (node-info.md, `gpus`).

use crate::protocol::GpuInfo;

pub(super) fn probe() -> Vec<GpuInfo> {
    Vec::new()
}
