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
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

use crate::identity::Identity;
use crate::protocol::{Arch, CpuInfo, MemoryInfo, NodeInfo, SandboxInfo};

/// The cutoff for every external probe (`nvidia-smi`, `system_profiler`, PowerShell).
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Collects NodeInfo. Blocking, at most 5 s; call it from `spawn_blocking`. `name` defaults to
/// the hostname. Probes that fail leave their field null or empty.
pub fn collect(
    installation_id: &str,
    name: Option<&str>,
    sandbox: &SandboxInfo,
    identity: &Identity,
) -> NodeInfo {
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
        boot: crate::boot::status(),
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
        identity: identity.info(),
        limits: crate::process::limit_support(),
        default_env: default_env(identity),
        collected_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64),
    }
}

/// With a workload user, `HOME` and `USER` are that user's.
fn default_env(identity: &Identity) -> BTreeMap<String, String> {
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
        .chain(identity.workload_env())
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

/// Runs `program` and returns its stdout when it exits successfully within [`PROBE_TIMEOUT`].
/// A program missing from `PATH`, failing, printing non-UTF-8 or running too long yields `None`.
fn probe_output(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    // A reader thread, because a pipe that fills up would stall the child until the cutoff.
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let read = stdout.read_to_end(&mut out);
        let _ = sender.send(read.map(|_| out));
    });
    let out = receiver.recv_timeout(PROBE_TIMEOUT);
    if out.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().ok()?;
    let out = out.ok()?.ok()?;
    if !status.success() {
        return None;
    }
    String::from_utf8(out).ok()
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Instant;

    use super::probe_output;

    #[test]
    fn probe_output_returns_stdout_of_a_successful_program() {
        assert_eq!(
            probe_output("sh", &["-c", "echo hello"]).as_deref(),
            Some("hello\n")
        );
    }

    #[test]
    fn probe_output_is_none_for_a_failing_or_missing_program() {
        assert_eq!(probe_output("sh", &["-c", "echo partial; exit 3"]), None);
        assert_eq!(probe_output("happy-supervisor-no-such-program", &[]), None);
    }

    #[test]
    fn probe_output_cuts_off_a_slow_program_at_three_seconds() {
        let started = Instant::now();
        assert_eq!(probe_output("sleep", &["10"]), None);
        let elapsed = started.elapsed().as_secs_f64();
        assert!((2.9..4.0).contains(&elapsed), "took {elapsed} s");
    }
}
