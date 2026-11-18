//! Linux: the distribution from os-release, kernel and machine from uname, and disks from
//! `/proc/self/mountinfo` with sizes from statvfs.

use crate::protocol::Arch;
#[cfg(target_os = "linux")]
use crate::protocol::{DiskInfo, OsFamily, OsInfo};

/// Filesystems that live on a block device but hold read-only images rather than data: snaps,
/// composefs and optical media.
const IMAGE_FILESYSTEMS: &[&str] = &["squashfs", "erofs", "iso9660"];

#[cfg(target_os = "linux")]
pub(super) fn os() -> OsInfo {
    let release = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    let (name, version) = parse_os_release(&release);
    OsInfo {
        family: OsFamily::Linux,
        name,
        version,
        kernel_version: sysinfo::System::kernel_version(),
        arch: parse_machine(&sysinfo::System::cpu_arch()).unwrap_or_else(super::binary_arch),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn disks() -> Vec<DiskInfo> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    local_mounts(&mountinfo)
        .into_iter()
        .filter_map(|mount| {
            let stat = nix::sys::statvfs::statvfs(mount.mount_point.as_str()).ok()?;
            let block = stat.fragment_size() as u64;
            let total_bytes = stat.blocks() as u64 * block;
            (total_bytes > 0).then(|| DiskInfo {
                removable: is_removable(mount.device),
                mount_point: mount.mount_point,
                file_system: mount.file_system,
                total_bytes,
                available_bytes: stat.blocks_available() as u64 * block,
            })
        })
        .collect()
}

/// A USB disk or one the kernel flags removable. The flag is on the whole disk, so a partition
/// asks its parent.
#[cfg(target_os = "linux")]
fn is_removable((major, minor): (u32, u32)) -> bool {
    let Ok(device) = std::fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")) else {
        return false;
    };
    let disk = if device.join("partition").exists() {
        device.parent().unwrap_or(&device)
    } else {
        &device
    };
    let flagged =
        std::fs::read_to_string(disk.join("removable")).is_ok_and(|flag| flag.trim() == "1");
    flagged || device.to_string_lossy().contains("/usb")
}

/// `NAME` and `VERSION_ID` from an os-release file.
fn parse_os_release(text: &str) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        let slot = match key.trim() {
            "NAME" => &mut name,
            "VERSION_ID" => &mut version,
            _ => continue,
        };
        if !value.is_empty() {
            *slot = Some(value.replace("\\\"", "\"").replace("\\\\", "\\"));
        }
    }
    (name, version)
}

/// `uname -m` as an [`Arch`]. `None` for machines NodeInfo cannot name.
fn parse_machine(machine: &str) -> Option<Arch> {
    match machine {
        "x86_64" | "amd64" => Some(Arch::X86_64),
        "aarch64" | "arm64" => Some(Arch::Aarch64),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Mount {
    device: (u32, u32),
    mount_point: String,
    file_system: String,
}

/// The data filesystems of a mountinfo listing, one per device. A data filesystem is backed by
/// a block device (its source is under `/dev/`) or is a ZFS dataset; pseudo, overlay, network
/// and FUSE filesystems have other sources. A device mounted several times (bind mounts) keeps
/// the mount of its own root, else its shortest mount point.
fn local_mounts(mountinfo: &str) -> Vec<Mount> {
    let mut mounts: Vec<(Mount, bool)> = Vec::new();
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let before: Vec<&str> = before.split(' ').collect();
        let after: Vec<&str> = after.split(' ').collect();
        let (Some(device), Some(root), Some(mount_point), Some(file_system), Some(source)) = (
            before.get(2).and_then(|d| parse_device(d)),
            before.get(3),
            before.get(4),
            after.first(),
            after.get(1),
        ) else {
            continue;
        };
        let data = (source.starts_with("/dev/") && !IMAGE_FILESYSTEMS.contains(file_system))
            || *file_system == "zfs";
        if !data {
            continue;
        }
        let mount = Mount {
            device,
            mount_point: unescape(mount_point),
            file_system: file_system.to_string(),
        };
        let own_root = *root == "/";
        match mounts.iter_mut().find(|(seen, _)| seen.device == device) {
            Some(seen) => {
                let better = (own_root, std::cmp::Reverse(mount.mount_point.len()))
                    > (seen.1, std::cmp::Reverse(seen.0.mount_point.len()));
                if better {
                    *seen = (mount, own_root);
                }
            }
            None => mounts.push((mount, own_root)),
        }
    }
    mounts.into_iter().map(|(mount, _)| mount).collect()
}

fn parse_device(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Undoes mountinfo's octal escapes (`\040` for a space).
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).and_then(|digits| {
            let digits = std::str::from_utf8(digits).ok()?;
            u8::from_str_radix(digits, 8).ok()
        });
        match (bytes[i], octal) {
            (b'\\', Some(byte)) => {
                out.push(byte);
                i += 4;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_gives_name_and_version_id() {
        let debian = include_str!("fixtures/debian-os-release.txt");
        assert_eq!(
            parse_os_release(debian),
            (Some("Debian GNU/Linux".to_string()), Some("13".to_string()))
        );
        let unquoted = "NAME=Fedora Linux\nVERSION_ID=41\n# comment\n";
        assert_eq!(
            parse_os_release(unquoted),
            (Some("Fedora Linux".to_string()), Some("41".to_string()))
        );
        let rolling = "NAME='Arch Linux'\nID=arch\nBUILD_ID=rolling\n";
        assert_eq!(
            parse_os_release(rolling),
            (Some("Arch Linux".to_string()), None)
        );
        assert_eq!(parse_os_release(""), (None, None));
    }

    #[test]
    fn machine_names_map_to_arch() {
        assert_eq!(parse_machine("x86_64"), Some(Arch::X86_64));
        assert_eq!(parse_machine("aarch64"), Some(Arch::Aarch64));
        assert_eq!(parse_machine("arm64"), Some(Arch::Aarch64));
        assert_eq!(parse_machine("riscv64"), None);
    }

    fn mount(device: (u32, u32), mount_point: &str, file_system: &str) -> Mount {
        Mount {
            device,
            mount_point: mount_point.to_string(),
            file_system: file_system.to_string(),
        }
    }

    /// Captured on a Debian 13 workstation inside an agent sandbox: the host's mounts appear
    /// twice, and the sandbox bind-mounts subdirectories and single files of the same disks.
    #[test]
    fn mountinfo_from_a_sandboxed_workstation_keeps_one_mount_per_disk() {
        let mountinfo = include_str!("fixtures/linux-mountinfo.txt");
        assert_eq!(
            local_mounts(mountinfo),
            vec![
                mount((259, 3), "/", "ext4"),
                mount((259, 2), "/boot/efi", "vfat"),
                mount((259, 9), "/var/lib/happy-agent/happy", "ext4"),
            ]
        );
    }

    #[test]
    fn mountinfo_drops_network_overlay_and_image_filesystems() {
        let mountinfo = "\
22 1 0:21 / / rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
23 1 8:2 / /home rw,relatime - btrfs /dev/sda2 rw,subvol=/@home
24 1 8:2 /@data /srv/my\\040data rw,relatime - btrfs /dev/sda2 rw,subvol=/@data
25 1 0:50 / /mnt/nas rw,relatime - nfs4 nas.lan:/export rw,vers=4.2
26 1 0:51 / /mnt/ssh rw,relatime - fuse.sshfs me@host:/ rw,user_id=0
27 1 7:3 / /snap/core22/1380 ro,relatime - squashfs /dev/loop3 ro
28 1 0:60 / /tank/vms rw,relatime - zfs tank/vms rw,xattr
29 1 8:17 / /media/usb rw,relatime - fuseblk /dev/sdb1 rw,user_id=0
30 1 0:61 / /mnt/smb rw,relatime - cifs //server/share rw,vers=3.1.1
";
        assert_eq!(
            local_mounts(mountinfo),
            vec![
                mount((8, 2), "/home", "btrfs"),
                mount((0, 60), "/tank/vms", "zfs"),
                mount((8, 17), "/media/usb", "fuseblk"),
            ]
        );
    }

    #[test]
    fn a_device_seen_only_through_bind_mounts_keeps_the_shortest() {
        let mountinfo = "\
40 1 8:1 /var/lib/docker/containers/abc/hostname /etc/hostname rw - ext4 /dev/sda1 rw
41 1 8:1 /var/lib/docker/containers/abc/hosts /etc/hosts rw - ext4 /dev/sda1 rw
42 1 8:1 /home/me/project /work rw - ext4 /dev/sda1 rw
";
        assert_eq!(
            local_mounts(mountinfo),
            vec![mount((8, 1), "/work", "ext4")]
        );
    }

    #[test]
    fn mount_points_are_unescaped() {
        assert_eq!(unescape("/srv/my\\040data\\011x"), "/srv/my data\tx");
        assert_eq!(unescape("/plain\\"), "/plain\\");
    }
}
