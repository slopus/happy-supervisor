//! NodeInfo collection (docs/node-info.md). Each platform module reads how its OS describes
//! itself (os, arch, disks), `gpu` finds display adapters, and sysinfo supplies the CPU, memory
//! and hostname. Parsers are pure functions over captured text, compiled on every platform under
//! `cfg(test)` so their fixtures run everywhere.

mod gpu;
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(any(windows, test))]
mod windows;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(windows)]
use windows as platform;

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

use crate::protocol::{Arch, CpuInfo, MemoryInfo, NodeInfo, SandboxInfo};

/// Collects NodeInfo. Blocking, at most 5 s; call it from `spawn_blocking`. `name` defaults to
/// the hostname. Probes that fail leave their field null or empty.
pub fn collect(installation_id: &str, name: Option<&str>, sandbox: &SandboxInfo) -> NodeInfo {
    let gpus = std::thread::spawn(gpu::probe);
    let os = platform::os();
    let disks = platform::disks();
    let system = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing())
            .with_memory(MemoryRefreshKind::nothing().with_ram().with_swap()),
    );
    let logical_cores = match system.cpus().len() {
        0 => std::thread::available_parallelism().map_or(1, |n| n.get()),
        n => n,
    };
    let hostname = System::host_name().unwrap_or_default();
    NodeInfo {
        installation_id: installation_id.to_string(),
        name: name.unwrap_or(&hostname).to_string(),
        hostname,
        supervisor_version: crate::VERSION.to_string(),
        os,
        cpu: CpuInfo {
            model: system
                .cpus()
                .first()
                .map(|cpu| cpu.brand().trim().to_string())
                .filter(|brand| !brand.is_empty()),
            physical_cores: System::physical_core_count().map(|n| n as u32),
            logical_cores: logical_cores as u32,
        },
        memory: MemoryInfo {
            total_bytes: system.total_memory(),
            swap_total_bytes: system.total_swap(),
        },
        disks,
        gpus: gpus.join().unwrap_or_default(),
        sandbox: sandbox.clone(),
        default_env: default_env(),
        collected_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64),
    }
}

fn default_env() -> BTreeMap<String, String> {
    let keys: &[&str] = if cfg!(windows) {
        &[
            "PATH",
            "USERPROFILE",
            "USERNAME",
            "LANG",
            "TEMP",
            "TMP",
            "SystemRoot",
        ]
    } else {
        &["PATH", "HOME", "USER", "LANG", "TMPDIR"]
    };
    keys.iter()
        .filter_map(|key| Some((key.to_string(), std::env::var(key).ok()?)))
        .collect()
}

/// The architecture the binary was built for: the machine's, unless it runs translated.
fn binary_arch() -> Arch {
    if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    }
}
