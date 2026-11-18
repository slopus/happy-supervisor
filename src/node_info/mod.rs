//! NodeInfo collection (docs/node-info.md). Owned by the node-info track; the scaffold froze
//! the signature.

mod gpu;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::collections::BTreeMap;

use crate::protocol::{Arch, CpuInfo, MemoryInfo, NodeInfo, OsFamily, OsInfo, SandboxInfo};

/// Collects NodeInfo. Blocking, at most 5 s; call it from `spawn_blocking`. `name` defaults to
/// the hostname. Probes that fail leave their field null or empty.
pub fn collect(installation_id: &str, name: Option<&str>, sandbox: &SandboxInfo) -> NodeInfo {
    let family = if cfg!(target_os = "macos") {
        OsFamily::Macos
    } else if cfg!(windows) {
        OsFamily::Windows
    } else {
        OsFamily::Linux
    };
    let arch = if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    };
    NodeInfo {
        installation_id: installation_id.to_string(),
        name: name.unwrap_or_default().to_string(),
        hostname: String::new(),
        supervisor_version: crate::VERSION.to_string(),
        os: OsInfo {
            family,
            name: None,
            version: None,
            kernel_version: None,
            arch,
        },
        cpu: CpuInfo {
            model: None,
            physical_cores: None,
            logical_cores: 0,
        },
        memory: MemoryInfo {
            total_bytes: 0,
            swap_total_bytes: 0,
        },
        disks: Vec::new(),
        gpus: Vec::new(),
        sandbox: sandbox.clone(),
        default_env: BTreeMap::new(),
        collected_at_ms: 0,
    }
}
