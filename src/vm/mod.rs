//! VM mode (docs/vm-mode.md): KVM virtual machines whose guest runs this binary as its init and
//! agent. Phase 1 is booting one: the guest's initramfs (`cpio`), the VMM (`vmm`), the host's
//! side of its vsock (`hvsock`), the guest's side (`vsock`, `guest`), `boot`, which ties them
//! to a [`Controller`](crate::Controller) driving the guest, and NodeInfo `vm` ([`probe`]).

pub mod cpio;

#[cfg(target_os = "linux")]
mod boot;
#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
pub mod hvsock;
#[cfg(target_os = "linux")]
pub mod vmm;
#[cfg(target_os = "linux")]
pub mod vsock;

#[cfg(target_os = "linux")]
pub use boot::{Boot, Vm};

use std::path::{Path, PathBuf};

use crate::protocol::VmInfo;

/// Where Kata Containers installs Cloud Hypervisor and its guest kernel (kata-static,
/// kata-deploy), which the node uses when `cloud-hypervisor` is not on `PATH`.
pub const KATA_VMM: &str = "/opt/kata/bin/cloud-hypervisor";
pub const KATA_KERNEL: &str = "/opt/kata/share/kata-containers/vmlinux.container";

/// The VMM and guest kernel this node would boot VMs with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub vmm: PathBuf,
    pub vmm_version: String,
    /// Canonical, so NodeInfo names the kernel that boots, not Kata's symlink to it.
    pub kernel: PathBuf,
}

/// NodeInfo `vm` (node-info.md): whether this node can boot VMs, checked at every collection.
/// Cheap: it opens `/dev/kvm` and runs `cloud-hypervisor --version`, and boots nothing.
pub fn probe() -> VmInfo {
    match host() {
        Ok(host) => VmInfo::Available {
            vmm: crate::protocol::VmmInfo {
                kind: crate::protocol::VmmKind::CloudHypervisor,
                path: host.vmm.display().to_string(),
                version: host.vmm_version,
            },
            kernel: host.kernel.display().to_string(),
        },
        Err(reason) => VmInfo::Unavailable { reason },
    }
}

/// The node's VMM and kernel, or the first reason it cannot boot a VM: KVM, then the running
/// binary (a guest runs it, so it must be static), then the VMM and the kernel.
pub fn host() -> Result<Host, String> {
    if !cfg!(target_os = "linux") {
        return Err("VM mode needs Linux with KVM".to_string());
    }
    kvm()?;
    let exe = std::env::current_exe()
        .map_err(|err| format!("the supervisor's own binary cannot be found: {err}"))?;
    require_static(&exe)?;
    Host::find()
}

impl Host {
    /// The VMM, `cloud-hypervisor` on `PATH` or else Kata's, and Kata's guest kernel. Checks
    /// neither KVM nor the guest binary.
    pub fn find() -> Result<Host, String> {
        let vmm = find_vmm()?;
        let vmm_version = vmm_version(&vmm)?;
        let kernel = std::fs::canonicalize(KATA_KERNEL)
            .map_err(|err| format!("the guest kernel {KATA_KERNEL} is missing: {err}"))?;
        if !is_elf(&kernel) {
            return Err(format!(
                "the guest kernel {} is not an uncompressed vmlinux",
                kernel.display()
            ));
        }
        Ok(Host {
            vmm,
            vmm_version,
            kernel,
        })
    }
}

#[cfg(target_os = "linux")]
fn vmm_version(vmm: &Path) -> Result<String, String> {
    vmm::version(vmm)
}

#[cfg(not(target_os = "linux"))]
fn vmm_version(_: &Path) -> Result<String, String> {
    Err("VM mode needs Linux with KVM".to_string())
}

/// `/dev/kvm` opens read-write and speaks KVM API 12, the only version Linux has had.
#[cfg(target_os = "linux")]
pub fn kvm() -> Result<(), String> {
    use std::os::fd::AsRawFd as _;

    const KVM_GET_API_VERSION: libc::Ioctl = 0xAE00;
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => "/dev/kvm does not exist".to_string(),
            std::io::ErrorKind::PermissionDenied => {
                "/dev/kvm cannot be opened: the supervisor's user needs to be in group kvm"
                    .to_string()
            }
            _ => format!("/dev/kvm cannot be opened: {err}"),
        })?;
    // SAFETY: KVM_GET_API_VERSION takes no argument and only returns a number.
    let version = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if version != 12 {
        return Err(format!("/dev/kvm reports KVM API {version}, not 12"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn kvm() -> Result<(), String> {
    Err("VM mode needs Linux with KVM".to_string())
}

/// `cloud-hypervisor` on `PATH`, else Kata's.
fn find_vmm() -> Result<PathBuf, String> {
    let on_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join("cloud-hypervisor"))
            .find(|candidate| candidate.is_file())
    });
    on_path
        .or_else(|| {
            Path::new(KATA_VMM)
                .is_file()
                .then(|| PathBuf::from(KATA_VMM))
        })
        .ok_or_else(|| format!("cloud-hypervisor is neither on PATH nor at {KATA_VMM}"))
}

/// A guest runs the host's own binary on a kernel with no libraries, so it must be static, as
/// the Linux releases are.
pub fn require_static(exe: &Path) -> Result<(), String> {
    match interpreter(exe) {
        Ok(false) => Ok(()),
        Ok(true) => Err(format!(
            "{} is dynamically linked, and a VM's guest needs a static build",
            exe.display()
        )),
        Err(err) => Err(format!("{} cannot be read: {err}", exe.display())),
    }
}

fn is_elf(path: &Path) -> bool {
    use std::io::Read as _;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && magic == *b"\x7fELF"
}

/// Whether a 64-bit little-endian ELF file asks for a dynamic loader (a `PT_INTERP` program
/// header). Anything else is `InvalidData`.
fn interpreter(path: &Path) -> std::io::Result<bool> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    const PT_INTERP: u32 = 3;
    let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string());
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    if header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err(invalid("not a 64-bit little-endian ELF file"));
    }
    let phoff = u64::from_le_bytes(header[32..40].try_into().expect("8 bytes"));
    let phentsize = u16::from_le_bytes(header[54..56].try_into().expect("2 bytes"));
    let phnum = u16::from_le_bytes(header[56..58].try_into().expect("2 bytes"));
    if phentsize < 4 {
        return Err(invalid("its program headers are too small"));
    }
    let mut headers = vec![0u8; usize::from(phentsize) * usize::from(phnum)];
    file.seek(SeekFrom::Start(phoff))?;
    file.read_exact(&mut headers)?;
    Ok(headers
        .chunks(usize::from(phentsize))
        .any(|entry| u32::from_le_bytes(entry[..4].try_into().expect("4 bytes")) == PT_INTERP))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF header with two program headers, the second of type `second`.
    fn elf(second: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 64 + 2 * 56];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&6u32.to_le_bytes());
        bytes[120..124].copy_from_slice(&second.to_le_bytes());
        bytes
    }

    #[test]
    fn a_program_interpreter_means_dynamic() {
        let dir = tempfile::tempdir().unwrap();
        let dynamic = dir.path().join("dynamic");
        std::fs::write(&dynamic, elf(3)).unwrap();
        let fixed = dir.path().join("static");
        std::fs::write(&fixed, elf(1)).unwrap();
        let script = dir.path().join("script");
        std::fs::write(&script, "#!/bin/sh\necho hi\n".repeat(10)).unwrap();
        assert!(interpreter(&dynamic).unwrap());
        assert!(!interpreter(&fixed).unwrap());
        assert_eq!(
            require_static(&dynamic),
            Err(format!(
                "{} is dynamically linked, and a VM's guest needs a static build",
                dynamic.display()
            ))
        );
        assert_eq!(require_static(&fixed), Ok(()));
        assert_eq!(
            require_static(&script),
            Err(format!(
                "{} cannot be read: not a 64-bit little-endian ELF file",
                script.display()
            ))
        );
    }

    /// The test harness is a dynamic glibc build on Linux, unless built for musl.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn this_test_binary_is_dynamic() {
        assert!(interpreter(&std::env::current_exe().unwrap()).unwrap());
    }
}
