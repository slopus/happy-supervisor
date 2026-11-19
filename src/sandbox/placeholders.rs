//! Placeholders for deny paths that do not exist (policy.md, Paths that do not exist). Owned by
//! the Linux track; Windows uses it too.

use std::io;
use std::path::{Path, PathBuf};

/// The placeholders one operation created, removed on drop while still empty and still ours.
#[derive(Debug, Default)]
pub struct Placeholders {
    created: Vec<PathBuf>,
}

impl Placeholders {
    /// Creates a placeholder at the first missing component of each path in `missing_deny`
    /// whose parent `writable` allows, recording each under `records`.
    pub fn create(
        records: &Path,
        missing_deny: &[PathBuf],
        writable: impl Fn(&Path) -> bool,
    ) -> io::Result<Placeholders> {
        let _ = (records, &writable);
        if missing_deny.is_empty() {
            return Ok(Placeholders::default());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "placeholders are not implemented yet",
        ))
    }

    /// Removes the placeholders a previous run recorded under `records` and left behind.
    pub fn sweep(records: &Path) -> io::Result<()> {
        let _ = records;
        Ok(())
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.created
    }
}
