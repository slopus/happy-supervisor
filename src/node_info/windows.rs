//! Windows: product name and version from the registry, the machine from IsWow64Process2, and
//! disks from sysinfo (fixed and removable volumes).

#[cfg(windows)]
use crate::protocol::{DiskInfo, OsFamily, OsInfo};

/// The first Windows 11 build. Windows 11 still writes "Windows 10" into `ProductName`.
const WINDOWS_11_BUILD: u32 = 22000;

#[cfg(windows)]
pub(super) fn os() -> OsInfo {
    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let build = registry::string(CURRENT_VERSION, "CurrentBuildNumber");
    let major = registry::dword(CURRENT_VERSION, "CurrentMajorVersionNumber");
    let minor = registry::dword(CURRENT_VERSION, "CurrentMinorVersionNumber");
    let product = registry::string(CURRENT_VERSION, "ProductName");
    OsInfo {
        family: OsFamily::Windows,
        name: product.map(|product| product_name(&product, build.as_deref())),
        version: match (major, minor, &build) {
            (Some(major), Some(minor), Some(build)) => Some(format!("{major}.{minor}.{build}")),
            _ => None,
        },
        kernel_version: build,
        arch: native_arch().unwrap_or_else(super::binary_arch),
    }
}

/// The machine's architecture, which differs from the binary's under WOW64 or x64 emulation
/// on ARM64.
#[cfg(windows)]
fn native_arch() -> Option<crate::protocol::Arch> {
    use windows_sys::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};

    let mut process = 0;
    let mut native = 0;
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing, and both out
    // pointers are valid u16s.
    let ok = unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) };
    match (ok != 0, native) {
        (true, IMAGE_FILE_MACHINE_AMD64) => Some(crate::protocol::Arch::X86_64),
        (true, IMAGE_FILE_MACHINE_ARM64) => Some(crate::protocol::Arch::Aarch64),
        _ => None,
    }
}

#[cfg(windows)]
pub(super) fn disks() -> Vec<DiskInfo> {
    sysinfo::Disks::new_with_refreshed_list()
        .iter()
        .filter(|disk| disk.total_space() > 0)
        .map(|disk| DiskInfo {
            mount_point: disk.mount_point().to_string_lossy().into_owned(),
            file_system: disk.file_system().to_string_lossy().into_owned(),
            total_bytes: disk.total_space(),
            available_bytes: disk.available_space(),
            removable: disk.is_removable(),
        })
        .collect()
}

#[cfg(windows)]
mod registry {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    pub(super) fn string(key: &str, value: &str) -> Option<String> {
        let (key, value) = (wide(key), wide(value));
        let mut size = 0u32;
        // SAFETY: both names are NUL-terminated; a null buffer asks only for the size in bytes.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status != 0 || size == 0 {
            return None;
        }
        let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
        // SAFETY: `buffer` holds `size` bytes, and RegGetValueW writes at most that many.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != 0 {
            return None;
        }
        let text = String::from_utf16_lossy(&buffer);
        Some(text.trim_end_matches('\0').to_string())
    }

    pub(super) fn dword(key: &str, value: &str) -> Option<u32> {
        let (key, value) = (wide(key), wide(value));
        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        // SAFETY: both names are NUL-terminated and `data` is a 4-byte buffer of `size` bytes.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&raw mut data).cast(),
                &mut size,
            )
        };
        (status == 0).then_some(data)
    }
}

/// `ProductName` corrected for Windows 11, which kept "Windows 10" there.
fn product_name(product: &str, build: Option<&str>) -> String {
    let eleven = build
        .and_then(|build| build.parse::<u32>().ok())
        .is_some_and(|build| build >= WINDOWS_11_BUILD);
    match product.strip_prefix("Windows 10") {
        Some(edition) if eleven => format!("Windows 11{edition}"),
        _ => product.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::product_name;

    #[test]
    fn windows_11_is_named_from_its_build() {
        assert_eq!(
            product_name("Windows 10 Pro", Some("26100")),
            "Windows 11 Pro"
        );
        assert_eq!(
            product_name("Windows 10 Pro", Some("19045")),
            "Windows 10 Pro"
        );
        assert_eq!(
            product_name("Windows Server 2022 Datacenter", Some("20348")),
            "Windows Server 2022 Datacenter"
        );
        assert_eq!(product_name("Windows 10 Home", None), "Windows 10 Home");
    }
}
