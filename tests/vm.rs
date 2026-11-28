//! VM mode, phase 1 (docs/vm-mode.md): a real KVM guest booted from a static build of the
//! supervisor, its agent driven over the VMM's vsock.
//!
//! Needs `/dev/kvm` that the test's user can open, Cloud Hypervisor and Kata's guest kernel
//! (on `PATH` or at Kata's paths, vm/mod.rs), `mke2fs`, and a static build of the supervisor
//! for the guest: `HAPPY_SUPERVISOR_GUEST_EXE`, else
//! `target/x86_64-unknown-linux-musl/debug/happy-supervisor` (`cargo zigbuild --target
//! x86_64-unknown-linux-musl --bin happy-supervisor`). Without KVM, the VMM or the kernel the
//! test says why and passes. Once those exist, a missing guest build or `mke2fs` fails it.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use happy_supervisor::protocol::{
    Bytes, Event, ExecOutput, ExitStatus, FsReadResult, NodeInfo, VmInfo,
};
use happy_supervisor::vm::{Boot, Host, Vm};
use serde_json::json;

const WAIT: Duration = Duration::from_secs(30);

/// The VMM and kernel, or `None` after saying why this machine cannot run the test.
fn host() -> Option<Host> {
    let found = happy_supervisor::vm::kvm().and_then(|()| Host::find());
    match found {
        Ok(host) => Some(host),
        Err(reason) => {
            eprintln!("skipping: this machine cannot boot VMs: {reason}");
            None
        }
    }
}

fn guest_exe() -> PathBuf {
    let exe = std::env::var_os("HAPPY_SUPERVISOR_GUEST_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/x86_64-unknown-linux-musl/debug/happy-supervisor")
        });
    if let Err(why) = happy_supervisor::vm::require_static(&exe) {
        panic!(
            "this machine boots VMs, but there is no static guest build ({why}): run `cargo \
             zigbuild --target x86_64-unknown-linux-musl --bin happy-supervisor`, or set \
             HAPPY_SUPERVISOR_GUEST_EXE"
        );
    }
    exe
}

/// A 64 MiB ext4 root with `/etc/passwd` naming `happy` (uid 1000), and a marker file.
fn root_disk(dir: &Path) -> PathBuf {
    let tree = dir.join("tree");
    for sub in ["etc", "dev", "proc", "sys", "tmp", "run", "home/happy"] {
        std::fs::create_dir_all(tree.join(sub)).unwrap();
    }
    std::fs::write(
        tree.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/sh\nhappy:x:1000:1000::/home/happy:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(tree.join("etc/group"), "root:x:0:\nhappy:x:1000:\n").unwrap();
    std::fs::write(tree.join("etc/marker"), "hello from the root disk\n").unwrap();
    let disk = dir.join("root.ext4");
    let made = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-E", "root_owner=0:0", "-d"])
        .arg(&tree)
        .arg(&disk)
        .arg("64M")
        .status()
        .expect("mke2fs (e2fsprogs) is needed to make the guest's root");
    assert!(made.success(), "mke2fs failed");
    disk
}

#[tokio::test(flavor = "multi_thread")]
async fn a_guest_boots_and_its_agent_runs_work_as_its_user() {
    let Some(host) = host() else { return };
    let guest_exe = guest_exe();
    // Short, so the VMM's vsock socket paths fit in a socket address.
    let dir = tempfile::Builder::new()
        .prefix("hsvm")
        .tempdir_in("/tmp")
        .unwrap();
    let boot = Boot {
        vmm: host.vmm.clone(),
        kernel: host.kernel.clone(),
        guest_exe,
        run_dir: dir.path().join("run"),
        root_disk: root_disk(dir.path()),
        user: "happy".to_string(),
        vcpus: 1,
        memory_mib: 1024,
    };
    let started = std::time::Instant::now();
    let vm = match Vm::boot(&boot).await {
        Ok(vm) => vm,
        Err(err) => panic!("the VM did not boot: {err}"),
    };
    eprintln!("booted in {} ms", started.elapsed().as_millis());
    let ctl = vm.controller();

    // NodeInfo from inside: one vCPU, root running work as `happy`, and no KVM of its own.
    let info: NodeInfo = ctl.command("node.info", ()).await.unwrap();
    assert_eq!(info.cpu.logical_cores, 1);
    assert!(info.identity.root);
    assert_eq!(info.identity.workload_user.as_deref(), Some("happy"));
    assert_eq!(
        info.vm,
        Some(VmInfo::Unavailable {
            reason: "/dev/kvm does not exist".to_string()
        })
    );

    // The root is the disk, not the host.
    let read: FsReadResult = ctl
        .command(
            "fs.read",
            json!({ "path": "/etc/marker", "access": { "mode": "raw" } }),
        )
        .await
        .unwrap();
    assert_eq!(read.data, Bytes(b"hello from the root disk\n".to_vec()));

    // A command, as `happy`: the supervisor's own `info`, which names the user it runs as.
    let mut events = ctl.events();
    let _: serde_json::Value = ctl
        .command(
            "exec.start",
            json!({
                "execId": "info",
                "argv": ["/.happy-supervisor/happy-supervisor", "info", "--state-dir", "/tmp/info"],
                "cwd": "/",
                "env": { "PATH": "/usr/bin:/bin", "HOME": "/tmp" },
                "access": { "mode": "raw" }
            }),
        )
        .await
        .unwrap();
    let mut stdout = Vec::new();
    let exit = loop {
        match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
            Some(Event::ExecOutput(ExecOutput { data, .. })) => stdout.extend(data.0),
            Some(Event::ExecExit(exit)) => break exit,
            Some(_) => {}
            None => panic!("the events ended"),
        }
    };
    assert_eq!(
        exit.exit,
        ExitStatus::Exited { code: 0 },
        "{}\n--- console ---\n{}",
        String::from_utf8_lossy(&stdout),
        vm.console()
    );
    let printed: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(printed["identity"]["supervisorUser"], "happy");
    assert_eq!(printed["identity"]["root"], false);

    vm.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_guest_without_its_user_powers_off_and_the_boot_says_why() {
    let Some(host) = host() else { return };
    let guest_exe = guest_exe();
    let dir = tempfile::Builder::new()
        .prefix("hsvm")
        .tempdir_in("/tmp")
        .unwrap();
    let boot = Boot {
        vmm: host.vmm.clone(),
        kernel: host.kernel.clone(),
        guest_exe,
        run_dir: dir.path().join("run"),
        root_disk: root_disk(dir.path()),
        user: "nobody-here".to_string(),
        vcpus: 1,
        memory_mib: 1024,
    };
    let err = match Vm::boot(&boot).await {
        Ok(_) => panic!("a guest whose user is missing booted"),
        Err(err) => err,
    };
    assert!(
        err.message
            .starts_with("the VMM exited (exit status: 0) before the guest answered"),
        "{err}"
    );
    assert!(err.message.contains("nobody-here"), "{err}");
}
