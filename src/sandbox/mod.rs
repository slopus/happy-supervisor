//! OS sandbox backends (docs/policy.md, Enforcement by platform). `linux.rs` is owned by the
//! Linux track, `macos.rs` by the macOS track. Windows has no sandbox.
//!
//! Each backend exports:
//!
//! * `probe() -> SandboxInfo`: what this node can enforce, decided by running a sandboxed
//!   `true` (node-info.md). Called once at startup.
//! * `prepare(&Job) -> Result<std::process::Command>`: the command whose stdin receives
//!   [`encode_job`](crate::helper::encode_job). Linux: `<exe> __sandbox`. macOS:
//!   `/usr/bin/sandbox-exec -p <profile> <exe> __sandbox`. Windows: `sandbox_unavailable`.
//!   The caller adds stdio, the process group, and for exec jobs the status pipe.
//! * Linux only, `enter(&ResolvedPolicy) -> Result<()>`: confines the calling helper process.

use std::path::Path;

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
