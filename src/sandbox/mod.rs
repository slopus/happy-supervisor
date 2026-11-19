//! OS sandbox backends (docs/policy.md). `linux.rs` is owned by the Linux track, `macos.rs` by
//! the macOS track, `windows.rs` by the Windows track; this file holds the seam they implement.
//!
//! Each backend exports:
//!
//! * `probe() -> SandboxInfo`: what this node can enforce, decided by running a sandboxed
//!   `true` (node-info.md). Called once at startup.
//! * `prepare(&Plan, &Job) -> Result<Prepared>`: the command whose stdin receives
//!   [`encode_job`](crate::helper::encode_job), with what must live until the operation ends.
//!   The caller adds stdio, the process group, and for exec jobs the status pipe.
//! * Linux only, `enter(&ResolvedPolicy) -> Result<()>`: confines the calling helper process.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::policy::ResolvedPolicy;

mod placeholders;
pub use placeholders::Placeholders;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{enter, prepare, probe};

#[cfg(any(target_os = "macos", all(unix, test)))]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{prepare, probe};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{prepare, probe};

/// Where the placeholders of operations whose policy has `state_dir` are recorded, so a node
/// that crashed removes them at its next start.
pub fn placeholder_records(state_dir: &Path) -> PathBuf {
    state_dir.join("placeholders")
}

/// Where a command proxy listens, as the node sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

/// The command proxy of an exec with isolated networking (proxy.md, Egress proxy): the only
/// network its sandbox may reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPlan {
    pub http: Endpoint,
    pub socks: Endpoint,
}

/// What [`prepare`] confines one operation to.
#[derive(Clone, Debug)]
pub struct Plan<'a> {
    pub policy: &'a ResolvedPolicy,
    /// Present exactly when the policy's network is isolated and the operation is an exec.
    pub net: Option<NetPlan>,
    /// The supervisor binary that runs as the helper (`<exe> __sandbox`).
    pub exe: &'a Path,
}

/// A prepared operation. Keep it until the operation has ended: dropping it removes the
/// placeholders and closes the control socket.
#[derive(Debug)]
pub struct Prepared {
    /// Its stdin gets [`encode_job`](crate::helper::encode_job).
    pub command: std::process::Command,
    pub placeholders: Placeholders,
    /// Linux, isolated with `localBind`: how `tcp.open` with this exec's `execId` reaches its
    /// network namespace (tunnels.md).
    pub netns: Option<NetnsControl>,
}

impl Prepared {
    pub fn command(command: std::process::Command) -> Prepared {
        Prepared {
            command,
            placeholders: Placeholders::default(),
            netns: None,
        }
    }
}

/// The node's side of the control socket to a sandbox helper that owns a network namespace.
#[derive(Debug)]
pub struct NetnsControl {
    _private: (),
}

impl NetnsControl {
    /// Connects to `127.0.0.1:port` inside the namespace. Blocking: call it from
    /// `spawn_blocking`.
    pub fn connect(&self, port: u16) -> std::io::Result<std::net::TcpStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("no network namespace to reach port {port} in"),
        ))
    }
}

/// The existing system paths ordinary programs need to read here (node-info.md,
/// `baselineRead`). Reported to the control plane; never added to a policy.
pub fn baseline_read() -> Vec<String> {
    let candidates: &[&str] = if cfg!(target_os = "linux") {
        &[
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib32",
            "/lib64",
            "/etc",
            "/proc",
            "/sys/devices/system/cpu",
            "/opt",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/usr",
            "/bin",
            "/sbin",
            "/System",
            "/Library",
            "/private/etc",
            "/private/var/db/timezone",
            "/private/var/select",
            "/dev/fd",
            "/dev/tty",
            "/opt/homebrew",
        ]
    } else {
        &[]
    };
    let mut baseline: Vec<String> = candidates
        .iter()
        .filter(|path| Path::new(path).exists())
        .map(|path| path.to_string())
        .collect();
    if cfg!(target_os = "macos") {
        baseline.extend(developer_bundle());
    }
    baseline
}

/// The app bundle holding the active developer directory (`xcode-select -p`), such as
/// `/Applications/Xcode.app`. `/usr/bin/git`, `python3` and other shims run their tool from it,
/// and the tools load frameworks from all over the bundle. Command Line Tools live under
/// `/Library`, which the list already has.
fn developer_bundle() -> Option<String> {
    let selected = [
        "/private/var/db/xcode_select_link",
        "/private/var/select/developer_dir",
    ]
    .iter()
    .find_map(|link| std::fs::read_link(link).ok());
    let bundle = match &selected {
        Some(dir) => dir
            .ancestors()
            .find(|path| path.extension() == Some("app".as_ref()))?,
        // With nothing selected, the shims use Xcode at its default location.
        None => Path::new("/Applications/Xcode.app"),
    };
    if !bundle.exists() {
        return None;
    }
    bundle.to_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn baseline_keeps_existing_paths_only() {
        let baseline = super::baseline_read();
        assert!(baseline.contains(&"/usr".to_string()));
        assert!(baseline.contains(&"/proc".to_string()));
        for path in &baseline {
            assert!(std::path::Path::new(path).exists(), "{path}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn baseline_keeps_existing_paths_only() {
        let baseline = super::baseline_read();
        assert!(baseline.contains(&"/System".to_string()));
        assert!(baseline.contains(&"/private/var/select".to_string()));
        assert!(!baseline.contains(&"/dev".to_string()));
        assert!(!baseline.contains(&"/proc".to_string()));
    }
}
