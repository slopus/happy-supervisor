//! Cloud Hypervisor, the VMM (docs/vm-mode.md, Boot): the argv for one VM from a pure
//! function, and the process that runs it.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

/// One VM as the VMM runs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub cmdline: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disks: Vec<Disk>,
    /// The hybrid vsock's Unix socket (vm/hvsock.rs).
    pub vsock: PathBuf,
    /// Where the guest's serial console goes.
    pub console: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disk {
    pub path: PathBuf,
    pub readonly: bool,
}

/// The guest's CID. Hybrid vsock puts each VM behind its own socket, so it is the same for all.
pub const GUEST_CID: u32 = 3;

/// The arguments after the program. Each value is one argument, so no path is split. A disk is
/// always `image_type=raw`: a guessed qcow2 could name a backing file on the host.
pub fn argv(plan: &Plan) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "--kernel".into(),
        plan.kernel.clone().into(),
        "--initramfs".into(),
        plan.initramfs.clone().into(),
        "--cmdline".into(),
        plan.cmdline.clone().into(),
        "--cpus".into(),
        format!("boot={}", plan.vcpus).into(),
        "--memory".into(),
        format!("size={}M", plan.memory_mib).into(),
    ];
    for disk in &plan.disks {
        args.push("--disk".into());
        args.push(option_list(
            "path=",
            &disk.path,
            &format!(
                ",readonly={},image_type=raw",
                if disk.readonly { "on" } else { "off" }
            ),
        ));
    }
    args.push("--vsock".into());
    args.push(option_list(
        &format!("cid={GUEST_CID},socket="),
        &plan.vsock,
        "",
    ));
    args.push("--serial".into());
    args.push(option_list("file=", &plan.console, ""));
    args.push("--console".into());
    args.push("off".into());
    args
}

/// `<before><path><after>` as one argument, keeping a path that is not UTF-8.
fn option_list(before: &str, path: &Path, after: &str) -> OsString {
    let mut arg = OsString::from(before);
    arg.push(path.as_os_str());
    arg.push(after);
    arg
}

/// A running VMM. Dropping it kills the VMM.
#[derive(Debug)]
pub struct Process {
    child: Child,
}

impl Process {
    /// Starts `vmm` with `plan`, writing its own output to `log`, in a process group of its own.
    /// No parent-death signal: Linux sends it when the *thread* that forked exits, and tokio's
    /// blocking threads come and go. A supervisor that dies without dropping this leaves the
    /// VMM running, for the next start to sweep (docs/vm-mode.md, Failure modes).
    pub fn spawn(vmm: &Path, plan: &Plan, log: &Path) -> io::Result<Process> {
        let log = File::create(log)?;
        let mut command = Command::new(vmm);
        command
            .args(argv(plan))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(Process {
            child: command.spawn()?,
        })
    }

    /// The exit status, if it has exited.
    pub fn exited(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Kills the VMM and waits for it.
    pub fn kill(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.child.try_wait()? {
            return Ok(status);
        }
        self.child.kill()?;
        self.child.wait()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// What `<vmm> --version` printed, as `55.0` for `cloud-hypervisor v55.0`.
pub fn version(vmm: &Path) -> Result<String, String> {
    let output = Command::new(vmm)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("{} cannot run: {err}", vmm.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    parse_version(&printed).ok_or_else(|| {
        format!(
            "{} --version printed {:?}, not cloud-hypervisor's version",
            vmm.display(),
            printed.trim()
        )
    })
}

fn parse_version(printed: &str) -> Option<String> {
    let version = printed
        .trim()
        .strip_prefix("cloud-hypervisor v")?
        .split_whitespace()
        .next()?;
    Some(version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_vm_is_one_argv() {
        let plan = Plan {
            kernel: "/opt/kata/share/kata-containers/vmlinux.container".into(),
            initramfs: "/state/private/vm/run/0/initrd".into(),
            cmdline: "console=ttyS0 quiet -- __vm init".into(),
            vcpus: 2,
            memory_mib: 512,
            disks: vec![
                Disk {
                    path: "/state/private/vm/layers/a b.ext4".into(),
                    readonly: true,
                },
                Disk {
                    path: "/state/private/vm/vms/agent-7/state.ext4".into(),
                    readonly: false,
                },
            ],
            vsock: "/state/private/vm/run/0/v.sock".into(),
            console: "/state/private/vm/run/0/console.log".into(),
        };
        assert_eq!(
            argv(&plan),
            [
                "--kernel",
                "/opt/kata/share/kata-containers/vmlinux.container",
                "--initramfs",
                "/state/private/vm/run/0/initrd",
                "--cmdline",
                "console=ttyS0 quiet -- __vm init",
                "--cpus",
                "boot=2",
                "--memory",
                "size=512M",
                "--disk",
                "path=/state/private/vm/layers/a b.ext4,readonly=on,image_type=raw",
                "--disk",
                "path=/state/private/vm/vms/agent-7/state.ext4,readonly=off,image_type=raw",
                "--vsock",
                "cid=3,socket=/state/private/vm/run/0/v.sock",
                "--serial",
                "file=/state/private/vm/run/0/console.log",
                "--console",
                "off",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn versions() {
        assert_eq!(
            parse_version("cloud-hypervisor v55.0\n"),
            Some("55.0".to_string())
        );
        assert_eq!(
            parse_version("cloud-hypervisor v48.0-12-gabc dirty"),
            Some("48.0-12-gabc".to_string())
        );
        assert_eq!(parse_version("firecracker v1.9.0"), None);
        assert_eq!(parse_version(""), None);
    }
}
