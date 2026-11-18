//! macOS: the product version and Darwin release from sysctl, the machine through Rosetta, and
//! disks from getfsstat.

use crate::protocol::Arch;
#[cfg(target_os = "macos")]
use crate::protocol::{DiskInfo, OsFamily, OsInfo};

// sys/mount.h. Spelled out so the filter and its fixture compile on every platform.
const MNT_RDONLY: u32 = 0x0000_0001;
#[cfg(target_os = "macos")]
const MNT_REMOVABLE: u32 = 0x0000_0200;
const MNT_LOCAL: u32 = 0x0000_1000;
const MNT_DONTBROWSE: u32 = 0x0010_0000;

/// Since Catalina the system lives on a read-only volume (a sealed snapshot since Big Sur)
/// mounted at `/`, and everything writable on this volume, firmlinked into `/`. The volume is
/// hidden from browsing like the other system volumes, but it is where the data is.
const DATA_VOLUME: &str = "/System/Volumes/Data";

#[cfg(target_os = "macos")]
pub(super) fn os() -> OsInfo {
    OsInfo {
        family: OsFamily::Macos,
        name: Some("macOS".to_string()),
        version: sysinfo::System::os_version(),
        kernel_version: sysinfo::System::kernel_version(),
        arch: machine_arch(super::binary_arch(), is_translated()),
    }
}

/// Whether this process is an x86_64 binary running under Rosetta.
#[cfg(target_os = "macos")]
fn is_translated() -> bool {
    let mut translated: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated and `size` is the size of the buffer `translated`.
    let status = unsafe {
        libc::sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&raw mut translated).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    status == 0 && translated == 1
}

#[cfg(target_os = "macos")]
pub(super) fn disks() -> Vec<DiskInfo> {
    data_volumes(mounted_filesystems())
        .into_iter()
        .map(|fs| DiskInfo {
            removable: fs.flags & MNT_REMOVABLE != 0,
            mount_point: fs.mount_point,
            file_system: fs.file_system,
            total_bytes: fs.total_bytes,
            available_bytes: fs.available_bytes,
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn mounted_filesystems() -> Vec<FsStat> {
    // SAFETY: a null buffer asks only for the count.
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count <= 0 {
        return Vec::new();
    }
    let mut buffer: Vec<libc::statfs> = Vec::with_capacity(count as usize);
    let bytes = (buffer.capacity() * std::mem::size_of::<libc::statfs>()) as libc::c_int;
    // SAFETY: `buffer` has room for `bytes` bytes, and getfsstat returns how many entries it
    // wrote, never more than fit.
    let written = unsafe { libc::getfsstat(buffer.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    if written <= 0 {
        return Vec::new();
    }
    // SAFETY: getfsstat initialized the first `written` entries.
    unsafe { buffer.set_len(written as usize) };
    let text = |chars: &[libc::c_char]| {
        let bytes: Vec<u8> = chars
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    buffer
        .iter()
        .map(|fs| FsStat {
            mount_point: text(&fs.f_mntonname),
            device: text(&fs.f_mntfromname),
            file_system: text(&fs.f_fstypename),
            flags: fs.f_flags,
            total_bytes: fs.f_blocks * u64::from(fs.f_bsize),
            available_bytes: fs.f_bavail * u64::from(fs.f_bsize),
        })
        .collect()
}

/// An x86_64 binary under Rosetta runs on an arm64 machine.
fn machine_arch(binary: Arch, translated: bool) -> Arch {
    if translated { Arch::Aarch64 } else { binary }
}

/// One getfsstat entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FsStat {
    mount_point: String,
    device: String,
    file_system: String,
    flags: u32,
    total_bytes: u64,
    available_bytes: u64,
}

/// The volumes that hold data: local, browsable (Finder shows them) or the data volume, with
/// some size, one per device. A read-only `/` is the system volume and duplicates the data
/// volume's container, so it is left out.
fn data_volumes(mounted: Vec<FsStat>) -> Vec<FsStat> {
    let mut volumes: Vec<FsStat> = Vec::new();
    for fs in mounted {
        let browsable = fs.flags & MNT_DONTBROWSE == 0 || fs.mount_point == DATA_VOLUME;
        let system_volume = fs.mount_point == "/" && fs.flags & MNT_RDONLY != 0;
        let keep = fs.flags & MNT_LOCAL != 0
            && browsable
            && !system_volume
            && fs.total_bytes > 0
            && !volumes.iter().any(|seen| seen.device == fs.device);
        if keep {
            volumes.push(fs);
        }
    }
    volumes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lines of `mount point, device, type, flags, blocks, available blocks, block size` as
    /// a small C program printed them from getfsstat on the Mac mini.
    fn captured(tsv: &str) -> Vec<FsStat> {
        tsv.lines()
            .map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                let number = |i: usize| fields[i].parse::<u64>().unwrap();
                FsStat {
                    mount_point: fields[0].to_string(),
                    device: fields[1].to_string(),
                    file_system: fields[2].to_string(),
                    flags: u32::from_str_radix(fields[3].trim_start_matches("0x"), 16).unwrap(),
                    total_bytes: number(4) * number(6),
                    available_bytes: number(5) * number(6),
                }
            })
            .collect()
    }

    #[test]
    fn a_mac_mini_reports_its_data_volume_and_scratch_volumes() {
        let mounted = captured(include_str!("fixtures/macos-getfsstat.tsv"));
        assert_eq!(mounted.len(), 16);
        let kept: Vec<(String, String, u64, u64)> = data_volumes(mounted)
            .into_iter()
            .map(|fs| {
                (
                    fs.mount_point,
                    fs.file_system,
                    fs.total_bytes,
                    fs.available_bytes,
                )
            })
            .collect();
        assert_eq!(
            kept,
            vec![
                (
                    "/System/Volumes/Data".to_string(),
                    "apfs".to_string(),
                    994662584320,
                    248356749312
                ),
                (
                    "/Volumes/HappyScratch".to_string(),
                    "apfs".to_string(),
                    150000001024,
                    23407599616
                ),
                (
                    "/Volumes/HappyScratch400".to_string(),
                    "apfs".to_string(),
                    400000000000,
                    223629262848
                ),
            ]
        );
    }

    #[test]
    fn a_writable_root_before_catalina_is_kept() {
        let mojave = FsStat {
            mount_point: "/".to_string(),
            device: "/dev/disk1s1".to_string(),
            file_system: "apfs".to_string(),
            flags: MNT_LOCAL | 0x4000,
            total_bytes: 500_000_000_000,
            available_bytes: 100_000_000_000,
        };
        assert_eq!(data_volumes(vec![mojave.clone()]), vec![mojave]);
    }

    #[test]
    fn rosetta_reports_the_arm64_machine() {
        assert_eq!(machine_arch(Arch::X86_64, true), Arch::Aarch64);
        assert_eq!(machine_arch(Arch::X86_64, false), Arch::X86_64);
        assert_eq!(machine_arch(Arch::Aarch64, false), Arch::Aarch64);
    }
}
