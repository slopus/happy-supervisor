use happy_supervisor::node_info::collect;
use happy_supervisor::protocol::{Mechanism, SandboxInfo, SandboxStatus};

fn unavailable_sandbox() -> SandboxInfo {
    SandboxInfo {
        mechanism: Mechanism::None,
        status: SandboxStatus::Unavailable {
            reason: "no sandbox in this test".to_string(),
        },
        baseline_read: vec!["/usr".to_string()],
    }
}

#[test]
fn identity_and_sandbox_pass_through_unchanged() {
    let sandbox = unavailable_sandbox();
    let info = collect("tz4a98xxat96iws9zmbrgj3a", Some("build-box-3"), &sandbox);
    assert_eq!(info.installation_id, "tz4a98xxat96iws9zmbrgj3a");
    assert_eq!(info.name, "build-box-3");
    assert_eq!(info.sandbox, sandbox);
    assert_eq!(info.supervisor_version, env!("CARGO_PKG_VERSION"));
}

#[cfg(unix)]
mod on_this_machine {
    use std::process::Command;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use happy_supervisor::protocol::{Arch, GpuVendor, NodeInfo, OsFamily};

    use super::*;

    fn shell(script: &str) -> String {
        let output = Command::new("sh").args(["-c", script]).output().unwrap();
        assert!(output.status.success(), "{script}");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn collect_timed() -> NodeInfo {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let started = Instant::now();
        let info = collect("tz4a98xxat96iws9zmbrgj3a", None, &unavailable_sandbox());
        let elapsed = started.elapsed();
        assert!(elapsed.as_secs_f64() < 5.0, "collection took {elapsed:?}");
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!((before..=after).contains(&info.collected_at_ms));
        eprintln!(
            "collected in {elapsed:?}:\n{}",
            serde_json::to_string_pretty(&info).unwrap()
        );
        info
    }

    #[test]
    fn collect_describes_this_machine() {
        let info = collect_timed();

        assert_eq!(info.hostname, shell("hostname"));
        assert_eq!(info.name, info.hostname);
        let expected_arch = match shell("uname -m").as_str() {
            "x86_64" => Arch::X86_64,
            "arm64" | "aarch64" => Arch::Aarch64,
            other => panic!("unexpected machine {other}"),
        };
        assert_eq!(info.os.arch, expected_arch);
        assert_eq!(
            info.os.kernel_version.as_deref(),
            Some(shell("uname -r").as_str())
        );

        assert!(
            info.cpu
                .model
                .as_deref()
                .is_some_and(|model| !model.is_empty())
        );
        assert_eq!(
            info.cpu.logical_cores.to_string(),
            shell("getconf _NPROCESSORS_ONLN")
        );
        assert!(
            info.cpu
                .physical_cores
                .is_some_and(|n| n > 0 && n <= info.cpu.logical_cores)
        );
        assert!(info.memory.total_bytes > 0);

        assert!(!info.disks.is_empty());
        for disk in &info.disks {
            assert!(disk.total_bytes > 0, "{disk:?}");
            assert!(disk.available_bytes <= disk.total_bytes, "{disk:?}");
        }
        let mut mount_points: Vec<&str> = info
            .disks
            .iter()
            .map(|disk| disk.mount_point.as_str())
            .collect();
        mount_points.sort();
        mount_points.dedup();
        assert_eq!(mount_points.len(), info.disks.len(), "{mount_points:?}");

        assert_eq!(
            info.default_env.get("PATH"),
            std::env::var("PATH").ok().as_ref()
        );
        assert!(
            info.default_env
                .keys()
                .all(|key| ["PATH", "HOME", "USER", "LANG", "TMPDIR"].contains(&key.as_str()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_distribution_memory_root_disk_and_nvidia_gpus() {
        let info = collect_timed();
        assert_eq!(info.os.family, OsFamily::Linux);
        let os_release = |key: &str| {
            shell(&format!(
                "if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; echo \"${key}\""
            ))
        };
        assert_eq!(info.os.name, Some(os_release("NAME")));
        assert_eq!(info.os.version, Some(os_release("VERSION_ID")));
        let mem_total_kib = shell("awk '/^MemTotal:/ { print $2 }' /proc/meminfo");
        assert_eq!(
            info.memory.total_bytes,
            mem_total_kib.parse::<u64>().unwrap() * 1024
        );

        let root = info.disks.iter().find(|disk| disk.mount_point == "/");
        let root_type = shell("awk '$2 == \"/\" { fs = $3 } END { print fs }' /proc/self/mounts");
        match root_type.as_str() {
            "overlay" | "tmpfs" | "rootfs" => assert_eq!(root, None),
            _ => assert_eq!(
                root.map(|disk| disk.file_system.as_str()),
                Some(root_type.as_str())
            ),
        }

        let smi = Command::new("nvidia-smi")
            .args(["--query-gpu=name", "--format=csv,noheader"])
            .output();
        if let Some(output) = smi.ok().filter(|output| output.status.success()) {
            for name in String::from_utf8(output.stdout).unwrap().lines() {
                assert!(
                    info.gpus.iter().any(|gpu| gpu.name == name.trim()
                        && gpu.vendor == GpuVendor::Nvidia
                        && gpu.memory_bytes.is_some_and(|bytes| bytes > 0)
                        && gpu.driver_version.is_some()),
                    "{name} missing from {:?}",
                    info.gpus
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reports_product_version_data_volume_and_apple_gpu() {
        let info = collect_timed();
        assert_eq!(info.os.family, OsFamily::Macos);
        assert_eq!(info.os.name.as_deref(), Some("macOS"));
        assert_eq!(info.os.version, Some(shell("sw_vers -productVersion")));
        assert_eq!(
            info.memory.total_bytes,
            shell("sysctl -n hw.memsize").parse::<u64>().unwrap()
        );
        assert_eq!(
            info.cpu.model,
            Some(shell("sysctl -n machdep.cpu.brand_string"))
        );

        let mount_points: Vec<&str> = info
            .disks
            .iter()
            .map(|disk| disk.mount_point.as_str())
            .collect();
        assert!(
            mount_points.contains(&"/System/Volumes/Data"),
            "{mount_points:?}"
        );
        assert!(!mount_points.contains(&"/"), "{mount_points:?}");
        assert!(
            !mount_points
                .iter()
                .any(|m| m.starts_with("/System/Volumes/") && *m != "/System/Volumes/Data"),
            "{mount_points:?}"
        );

        if is_physical_apple_silicon() {
            assert!(
                info.gpus.iter().any(|gpu| gpu.vendor == GpuVendor::Apple
                    && gpu.name.starts_with("Apple M")
                    && gpu.memory_bytes.is_none()),
                "{:?}",
                info.gpus
            );
        }
    }

    /// GitHub's macOS VMs report no GPU.
    #[cfg(target_os = "macos")]
    fn is_physical_apple_silicon() -> bool {
        shell("sysctl -n hw.optional.arm64 2>/dev/null || echo 0") == "1"
            && shell("sysctl -n kern.hv_vmm_present 2>/dev/null || echo 0") == "0"
    }
}
