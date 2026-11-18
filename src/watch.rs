//! Watching for changes (`watch.*`). Owned by the files track; the scaffold froze the
//! signatures.

use crate::error::{Error, Result};
use crate::link::Outbox;
use crate::policy::Confinement;
use crate::protocol::{WatchId, WatchStartParams};

/// Every watch of this node. Watches outlive connections. A sandboxed watch reports only
/// changes its [`ResolvedPolicy::can_read`](crate::policy::ResolvedPolicy::can_read) allows.
pub struct WatchManager {
    #[expect(dead_code, reason = "the files track sends watch events through it")]
    outbox: Outbox,
}

impl WatchManager {
    pub fn new(outbox: Outbox) -> WatchManager {
        WatchManager { outbox }
    }

    pub async fn start(&self, params: WatchStartParams, confinement: Confinement) -> Result<()> {
        let _ = (params, confinement);
        Err(Error::not_implemented("watch.start"))
    }

    pub fn stop(&self, watch_id: &WatchId) -> Result<()> {
        let _ = watch_id;
        Err(Error::not_implemented("watch.stop"))
    }

    /// The active watches, for `node.ready`.
    pub fn ids(&self) -> Vec<WatchId> {
        Vec::new()
    }
}
