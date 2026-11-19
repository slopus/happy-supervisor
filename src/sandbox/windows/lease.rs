//! Exclusive use of one sandbox account. The lease file doubles as the journal of the paths
//! whose ACL names the slot's group: it is held open without sharing for the lease's lifetime,
//! and the next holder of a slot whose last holder died (a killed exec) revokes what it lists.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead as _, Seek as _, Write as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::acl;
use super::install::{Install, NetProfile, Slot};
use super::win::Sid;

const ERROR_SHARING_VIOLATION: i32 = 32;
/// How long an operation waits for a free account before it fails.
const WAIT: Duration = Duration::from_secs(60);

pub(super) struct Lease {
    pub slot: Slot,
    pub group: Sid,
    journal: File,
    paths: Vec<PathBuf>,
}

impl Lease {
    /// Takes the first free slot, waiting up to a minute for one.
    pub(super) fn acquire(install: &Install, dir: &Path, net: NetProfile) -> io::Result<Lease> {
        let deadline = Instant::now() + WAIT;
        let slots: Vec<&Slot> = install
            .slots
            .iter()
            .filter(|slot| slot.net == net)
            .collect();
        loop {
            for slot in &slots {
                let opened = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .share_mode(0)
                    .open(dir.join(format!("lease-{}", slot.account)));
                match opened {
                    Ok(journal) => return Lease::take((*slot).clone(), journal),
                    Err(err) if err.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {}
                    Err(err) => return Err(err),
                }
            }
            if Instant::now() > deadline {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "all {} sandbox accounts for {net:?} networking stayed busy for {}s",
                        slots.len(),
                        WAIT.as_secs()
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn take(slot: Slot, journal: File) -> io::Result<Lease> {
        let group = Sid::parse(&slot.group_sid)?;
        let mut lease = Lease {
            slot,
            group,
            journal,
            paths: Vec::new(),
        };
        let stale: Vec<PathBuf> = io::BufReader::new(&lease.journal)
            .lines()
            .map(|line| line.map(PathBuf::from))
            .collect::<io::Result<_>>()?;
        lease.paths = stale;
        lease.revoke_all()?;
        Ok(lease)
    }

    /// Notes `path` before its ACL changes, so a holder that dies mid-change is cleaned up too.
    pub(super) fn record(&mut self, path: &Path) -> io::Result<()> {
        let line = path
            .to_str()
            .ok_or_else(|| io::Error::other(format!("{} is not UTF-8", path.display())))?;
        writeln!(self.journal, "{line}")?;
        self.journal.sync_data()?;
        self.paths.push(path.to_path_buf());
        Ok(())
    }

    /// Revokes every ACE this lease added, deepest first, and empties the journal.
    pub(super) fn revoke_all(&mut self) -> io::Result<()> {
        let mut paths = std::mem::take(&mut self.paths);
        paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        paths.dedup();
        for path in &paths {
            match acl::revoke(path, &self.group) {
                Err(err) if path.exists() => return Err(err),
                _ => {}
            }
        }
        self.journal.set_len(0)?;
        self.journal.rewind()?;
        self.journal.sync_data()
    }
}
