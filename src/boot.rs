//! The channel to happy-supervisor-boot (boot.md, The channel), when boot started this
//! supervisor: boot's status arrives on stdin, one JSON line at a time, and requests leave on
//! stdout. `run` opens it once ([`attach`]); the rest of the node reads it through the functions
//! here. The end of stdin is boot asking the supervisor to stop.

use std::io::{BufRead as _, Write as _};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::error::{Error, Result};
use crate::protocol::BootStatus;

/// Set by boot to its own process ID.
pub const BOOT_ENV: &str = "HAPPY_SUPERVISOR_BOOT";

struct Channel {
    /// The last status boot sent.
    status: watch::Sender<Option<BootStatus>>,
    /// Becomes true when stdin ends.
    closed: watch::Sender<bool>,
    connected: AtomicBool,
    out: std::sync::Mutex<std::io::Stdout>,
}

static CHANNEL: OnceLock<Channel> = OnceLock::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum FromBoot {
    Status(BootStatus),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum ToBoot<'a> {
    Upgrade { version: &'a str },
    Connected {},
}

/// Opens the channel when boot started this process ([`BOOT_ENV`]): a thread reads boot's
/// lines from stdin until it ends. Does nothing otherwise, or when called again.
pub fn attach() {
    if std::env::var_os(BOOT_ENV).is_none() || CHANNEL.get().is_some() {
        return;
    }
    let channel = CHANNEL.get_or_init(|| Channel {
        status: watch::Sender::new(None),
        closed: watch::Sender::new(false),
        connected: AtomicBool::new(false),
        out: std::sync::Mutex::new(std::io::stdout()),
    });
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<FromBoot>(&line) {
                Ok(FromBoot::Status(status)) => {
                    channel.status.send_replace(Some(status));
                }
                Err(err) => tracing::debug!("ignored a line from boot: {err}"),
            }
        }
        channel.closed.send_replace(true);
    });
}

/// Whether boot started this supervisor.
pub fn attached() -> bool {
    CHANNEL.get().is_some()
}

/// The process ID boot gave, when it is this process's parent: the process the cgroup handoff
/// moves (process/cgroups.rs).
#[cfg(target_os = "linux")]
pub fn pid() -> Option<u32> {
    let pid: u32 = std::env::var(BOOT_ENV).ok()?.parse().ok()?;
    (pid == std::os::unix::process::parent_id()).then_some(pid)
}

/// What boot last reported, for NodeInfo `boot`.
pub fn status() -> Option<BootStatus> {
    CHANNEL
        .get()
        .and_then(|channel| channel.status.borrow().clone())
}

/// Every status boot reports from now on, for the event `node.boot`. `None` without boot.
pub fn statuses() -> Option<watch::Receiver<Option<BootStatus>>> {
    CHANNEL.get().map(|channel| channel.status.subscribe())
}

fn send(line: &ToBoot) -> Result<()> {
    let channel = CHANNEL.get().ok_or_else(not_attached)?;
    let mut line = serde_json::to_string(line).expect("the line serializes");
    line.push('\n');
    let mut out = channel.out.lock().unwrap_or_else(|e| e.into_inner());
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|err| Error::new(crate::ErrorKind::Io, format!("cannot reach boot: {err}")))
}

fn not_attached() -> Error {
    Error::new(
        crate::ErrorKind::PermissionDenied,
        "this node was not started by happy-supervisor-boot, so it cannot change its version; \
         install it again with the installer",
    )
}

/// Asks boot to run `version` (`node.upgrade`).
pub fn upgrade(version: &str) -> Result<()> {
    send(&ToBoot::Upgrade { version })
}

/// Tells boot, once, that a session opened: a new version is healthy.
pub fn connected() {
    if let Some(channel) = CHANNEL.get()
        && !channel.connected.swap(true, Ordering::SeqCst)
        && let Err(err) = send(&ToBoot::Connected {})
    {
        tracing::warn!("{err}");
    }
}

/// Resolves when boot closed stdin, asking the supervisor to stop. Never without boot.
pub async fn closed() {
    match CHANNEL.get() {
        Some(channel) => {
            let mut closed = channel.closed.subscribe();
            let _ = closed.wait_for(|closed| *closed).await;
        }
        None => std::future::pending().await,
    }
}
