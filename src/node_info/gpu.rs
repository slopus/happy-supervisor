//! GPU discovery per platform (node-info.md, `gpus`). Linux walks PCI display devices and
//! enriches NVIDIA ones from `nvidia-smi`; macOS reads `system_profiler`; Windows reads
//! `Win32_VideoController` through PowerShell. The parsers take captured output.

use crate::protocol::{GpuInfo, GpuVendor};

#[cfg(target_os = "linux")]
pub(super) fn probe() -> Vec<GpuInfo> {
    let smi = std::thread::spawn(|| {
        super::probe_output(
            "nvidia-smi",
            &[
                "--query-gpu=pci.bus_id,memory.total,driver_version,name",
                "--format=csv,noheader,nounits",
            ],
        )
    });
    let displays = pci_displays();
    let pci_ids = [
        "/usr/share/hwdata/pci.ids",
        "/usr/share/misc/pci.ids",
        "/usr/share/pci.ids",
    ]
    .iter()
    .find_map(|path| std::fs::read_to_string(path).ok())
    .unwrap_or_default();
    let smi = smi.join().ok().flatten().unwrap_or_default();
    linux_gpus(displays, &parse_nvidia_smi(&smi), &pci_ids)
}

#[cfg(target_os = "macos")]
pub(super) fn probe() -> Vec<GpuInfo> {
    super::probe_output("system_profiler", &["SPDisplaysDataType", "-json"])
        .map(|json| parse_system_profiler(&json))
        .unwrap_or_default()
}

#[cfg(windows)]
pub(super) fn probe() -> Vec<GpuInfo> {
    const QUERY: &str = "ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,AdapterRAM,DriverVersion,PNPDeviceID)";
    super::probe_output(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", QUERY],
    )
    .map(|json| parse_video_controllers(&json))
    .unwrap_or_default()
}

#[cfg(any(target_os = "linux", windows, test))]
fn vendor_from_pci_id(id: u16) -> GpuVendor {
    match id {
        0x10de => GpuVendor::Nvidia,
        0x1002 | 0x1022 => GpuVendor::Amd,
        0x8086 => GpuVendor::Intel,
        0x106b => GpuVendor::Apple,
        _ => GpuVendor::Other,
    }
}

#[cfg(any(target_os = "macos", windows, test))]
/// The vendor named in free text such as "NVIDIA", "Advanced Micro Devices, Inc.",
/// "ATI Technologies Inc." or "sppci_vendor_Apple". Matches whole words, so "Corporation"
/// is not ATI.
fn vendor_from_text(text: &str) -> GpuVendor {
    let text = text.to_ascii_lowercase();
    let words: Vec<&str> = text.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    let has = |word: &str| words.contains(&word);
    if has("nvidia") {
        GpuVendor::Nvidia
    } else if has("amd") || has("ati") || (has("advanced") && has("micro")) {
        GpuVendor::Amd
    } else if has("intel") {
        GpuVendor::Intel
    } else if has("apple") {
        GpuVendor::Apple
    } else {
        GpuVendor::Other
    }
}

#[cfg(any(target_os = "linux", test))]
/// A PCI device of class 0x03 under `/sys/bus/pci/devices`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PciDisplay {
    /// `0000:01:00.0`.
    address: String,
    vendor: u16,
    device: u16,
    /// The firmware's name for an onboard device (`label`).
    label: Option<String>,
    /// amdgpu's `mem_info_vram_total`.
    vram_bytes: Option<u64>,
    /// The version of the bound driver's module.
    driver_version: Option<String>,
}

#[cfg(target_os = "linux")]
fn pci_displays() -> Vec<PciDisplay> {
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return Vec::new();
    };
    let read = |dir: &std::path::Path, file: &str| {
        std::fs::read_to_string(dir.join(file))
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
    };
    let hex = |text: Option<String>| u16::from_str_radix(text?.trim_start_matches("0x"), 16).ok();
    let mut displays: Vec<PciDisplay> = entries
        .filter_map(|entry| {
            let dir = entry.ok()?.path();
            if !read(&dir, "class")?.starts_with("0x03") {
                return None;
            }
            Some(PciDisplay {
                address: dir.file_name()?.to_string_lossy().into_owned(),
                vendor: hex(read(&dir, "vendor"))?,
                device: hex(read(&dir, "device"))?,
                label: read(&dir, "label"),
                vram_bytes: read(&dir, "mem_info_vram_total").and_then(|v| v.parse().ok()),
                driver_version: read(&dir, "driver/module/version"),
            })
        })
        .collect();
    displays.sort_by(|a, b| a.address.cmp(&b.address));
    displays
}

#[cfg(any(target_os = "linux", test))]
/// One line of `nvidia-smi --query-gpu=pci.bus_id,memory.total,driver_version,name
/// --format=csv,noheader,nounits`. The name is last because it is the one field that could
/// hold a comma.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NvidiaSmiGpu {
    /// The bus ID in sysfs form, `0000:01:00.0`.
    address: String,
    memory_bytes: Option<u64>,
    driver_version: Option<String>,
    name: String,
}

#[cfg(any(target_os = "linux", test))]
fn parse_nvidia_smi(csv: &str) -> Vec<NvidiaSmiGpu> {
    csv.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, ',').map(str::trim);
            let (bus_id, memory, driver, name) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            let known = |field: &str| !field.is_empty() && !field.starts_with('[');
            Some(NvidiaSmiGpu {
                address: sysfs_pci_address(bus_id)?,
                memory_bytes: memory.parse::<u64>().ok().map(|mib| mib * 1024 * 1024),
                driver_version: known(driver).then(|| driver.to_string()),
                name: name.to_string(),
            })
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
/// `00000000:01:00.0` (nvidia-smi, 32-bit domain, upper case) as sysfs writes it.
fn sysfs_pci_address(bus_id: &str) -> Option<String> {
    let (domain, rest) = bus_id.split_once(':')?;
    let domain = u32::from_str_radix(domain, 16).ok()?;
    Some(format!("{domain:04x}:{}", rest.to_ascii_lowercase()))
}

#[cfg(any(target_os = "linux", test))]
/// The device's name in a pci.ids database: device lines are tab-indented under their vendor.
fn pci_device_name(pci_ids: &str, vendor: u16, device: u16) -> Option<String> {
    let vendor = format!("{vendor:04x}  ");
    let device = format!("\t{device:04x}  ");
    let mut lines = pci_ids
        .lines()
        .skip_while(|line| !line.starts_with(&vendor));
    lines.next()?;
    lines
        .take_while(|line| line.starts_with('\t') || line.starts_with('#') || line.is_empty())
        .find_map(|line| line.strip_prefix(&device))
        .map(str::to_string)
}

#[cfg(any(target_os = "linux", test))]
/// PCI displays named by nvidia-smi, the firmware label, pci.ids or their IDs, in that order,
/// followed by any GPU nvidia-smi sees that is not on the PCI bus.
fn linux_gpus(displays: Vec<PciDisplay>, smi: &[NvidiaSmiGpu], pci_ids: &str) -> Vec<GpuInfo> {
    let mut gpus: Vec<GpuInfo> = displays
        .iter()
        .map(|display| {
            let vendor = vendor_from_pci_id(display.vendor);
            match smi.iter().find(|gpu| gpu.address == display.address) {
                Some(gpu) => GpuInfo {
                    name: gpu.name.clone(),
                    vendor,
                    memory_bytes: gpu.memory_bytes,
                    driver_version: gpu.driver_version.clone(),
                },
                None => GpuInfo {
                    name: display
                        .label
                        .clone()
                        .or_else(|| pci_device_name(pci_ids, display.vendor, display.device))
                        .unwrap_or_else(|| {
                            format!("{:04x}:{:04x}", display.vendor, display.device)
                        }),
                    vendor,
                    memory_bytes: display.vram_bytes,
                    driver_version: display.driver_version.clone(),
                },
            }
        })
        .collect();
    gpus.extend(
        smi.iter()
            .filter(|gpu| {
                !displays
                    .iter()
                    .any(|display| display.address == gpu.address)
            })
            .map(|gpu| GpuInfo {
                name: gpu.name.clone(),
                vendor: GpuVendor::Nvidia,
                memory_bytes: gpu.memory_bytes,
                driver_version: gpu.driver_version.clone(),
            }),
    );
    gpus
}

#[cfg(any(target_os = "macos", test))]
/// `system_profiler SPDisplaysDataType -json`. Apple Silicon GPUs share system memory and
/// carry no `spdisplays_vram`, so their memory is null.
fn parse_system_profiler(json: &str) -> Vec<GpuInfo> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(adapters) = root["SPDisplaysDataType"].as_array() else {
        return Vec::new();
    };
    adapters
        .iter()
        .filter_map(|adapter| {
            let field = |key: &str| adapter[key].as_str();
            let name = field("sppci_model").or(field("_name"))?;
            Some(GpuInfo {
                name: name.to_string(),
                vendor: vendor_from_text(field("spdisplays_vendor").unwrap_or(name)),
                memory_bytes: field("spdisplays_vram").and_then(parse_vram),
                driver_version: None,
            })
        })
        .collect()
}

#[cfg(any(target_os = "macos", test))]
/// `"8 GB"` or `"1536 MB"`, as system_profiler writes video memory.
fn parse_vram(text: &str) -> Option<u64> {
    let (amount, unit) = text.trim().split_once(' ')?;
    let amount: u64 = amount.parse().ok()?;
    let scale = match unit {
        "MB" => 1 << 20,
        "GB" => 1 << 30,
        _ => return None,
    };
    Some(amount * scale)
}

#[cfg(any(windows, test))]
/// `Win32_VideoController` rows as `ConvertTo-Json` prints them: an array, or a bare object
/// when PowerShell unwraps a single row. Basic and remote display adapters are left out.
fn parse_video_controllers(json: &str) -> Vec<GpuInfo> {
    /// `AdapterRAM` is a uint32, so a card with 4 GiB or more reports this or close to it.
    const SATURATED_RAM: u64 = 0xFFF0_0000;
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let rows = match root {
        serde_json::Value::Array(rows) => rows,
        row => vec![row],
    };
    rows.iter()
        .filter_map(|row| {
            let field = |key: &str| row[key].as_str().map(str::trim).filter(|v| !v.is_empty());
            let name = field("Name")?;
            if name.contains("Basic Display") || name.contains("Remote Display") {
                return None;
            }
            let pci_vendor = field("PNPDeviceID")
                .and_then(|id| {
                    id.to_ascii_uppercase()
                        .split_once("VEN_")
                        .map(|(_, rest)| rest.to_string())
                })
                .and_then(|rest| u16::from_str_radix(rest.get(..4)?, 16).ok());
            let vendor = match pci_vendor.map(vendor_from_pci_id) {
                Some(vendor) if vendor != GpuVendor::Other => vendor,
                _ => vendor_from_text(field("AdapterCompatibility").unwrap_or(name)),
            };
            Some(GpuInfo {
                name: name.to_string(),
                vendor,
                memory_bytes: row["AdapterRAM"]
                    .as_u64()
                    .filter(|&bytes| bytes > 0 && bytes < SATURATED_RAM),
                driver_version: field("DriverVersion").map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu(name: &str, vendor: GpuVendor, memory: Option<u64>, driver: Option<&str>) -> GpuInfo {
        GpuInfo {
            name: name.to_string(),
            vendor,
            memory_bytes: memory,
            driver_version: driver.map(str::to_string),
        }
    }

    #[test]
    fn vendor_text_matches_whole_words() {
        assert_eq!(vendor_from_text("NVIDIA Corporation"), GpuVendor::Nvidia);
        assert_eq!(
            vendor_from_text("Advanced Micro Devices, Inc."),
            GpuVendor::Amd
        );
        assert_eq!(vendor_from_text("ATI Technologies Inc."), GpuVendor::Amd);
        assert_eq!(vendor_from_text("sppci_vendor_amd"), GpuVendor::Amd);
        assert_eq!(vendor_from_text("Intel Corporation"), GpuVendor::Intel);
        assert_eq!(vendor_from_text("sppci_vendor_Apple"), GpuVendor::Apple);
        assert_eq!(
            vendor_from_text("Matrox Electronics Systems Ltd."),
            GpuVendor::Other
        );
    }

    /// Captured on a workstation with two RTX 4090s on driver 620.70.06.
    #[test]
    fn nvidia_smi_rows_carry_bus_memory_driver_and_name() {
        let rows = parse_nvidia_smi(include_str!("fixtures/nvidia-smi.csv"));
        let rtx = |address: &str| NvidiaSmiGpu {
            address: address.to_string(),
            memory_bytes: Some(25_757_220_864),
            driver_version: Some("620.70.06".to_string()),
            name: "NVIDIA GeForce RTX 4090".to_string(),
        };
        assert_eq!(rows, vec![rtx("0000:01:00.0"), rtx("0000:41:00.0")]);
        let odd =
            parse_nvidia_smi("00000000:C1:00.0, [N/A], [N/A], NVIDIA A100-SXM4-80GB, rev B\n");
        assert_eq!(
            odd,
            vec![NvidiaSmiGpu {
                address: "0000:c1:00.0".to_string(),
                memory_bytes: None,
                driver_version: None,
                name: "NVIDIA A100-SXM4-80GB, rev B".to_string(),
            }]
        );
    }

    #[test]
    fn pci_ids_names_devices_within_their_vendor_only() {
        let pci_ids = include_str!("fixtures/pci.ids.txt");
        assert_eq!(
            pci_device_name(pci_ids, 0x10de, 0x1287).as_deref(),
            Some("GK208B [GeForce GT 730]")
        );
        assert_eq!(
            pci_device_name(pci_ids, 0x1002, 0x744c).as_deref(),
            Some("Navi 31 [Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M]")
        );
        assert_eq!(pci_device_name(pci_ids, 0x1003, 0x744c), None);
        assert_eq!(pci_device_name(pci_ids, 0x1002, 0x0e3b), None);
        assert_eq!(pci_device_name("", 0x10de, 0x1287), None);
    }

    fn display(address: &str, vendor: u16, device: u16) -> PciDisplay {
        PciDisplay {
            address: address.to_string(),
            vendor,
            device,
            label: None,
            vram_bytes: None,
            driver_version: None,
        }
    }

    /// The workstation's three NVIDIA cards: two the driver supports, and a GT 730 it does not,
    /// which nvidia-smi leaves out.
    #[test]
    fn linux_gpus_merge_nvidia_smi_into_the_pci_listing() {
        let displays = vec![
            PciDisplay {
                driver_version: Some("620.70.06".to_string()),
                ..display("0000:01:00.0", 0x10de, 0x2684)
            },
            PciDisplay {
                driver_version: Some("620.70.06".to_string()),
                ..display("0000:41:00.0", 0x10de, 0x2684)
            },
            display("0000:42:00.0", 0x10de, 0x1287),
        ];
        let smi = parse_nvidia_smi(include_str!("fixtures/nvidia-smi.csv"));
        let rtx = gpu(
            "NVIDIA GeForce RTX 4090",
            GpuVendor::Nvidia,
            Some(25_757_220_864),
            Some("620.70.06"),
        );
        assert_eq!(
            linux_gpus(displays, &smi, include_str!("fixtures/pci.ids.txt")),
            vec![
                rtx.clone(),
                rtx,
                gpu("GK208B [GeForce GT 730]", GpuVendor::Nvidia, None, None),
            ]
        );
    }

    #[test]
    fn linux_gpus_without_nvidia_smi_use_label_pci_ids_or_ids() {
        let displays = vec![
            PciDisplay {
                vram_bytes: Some(25_753_026_560),
                ..display("0000:03:00.0", 0x1002, 0x744c)
            },
            PciDisplay {
                label: Some("Onboard IGD".to_string()),
                ..display("0000:00:02.0", 0x8086, 0xa780)
            },
            display("0000:05:00.0", 0x1a03, 0x2000),
        ];
        let tegra = NvidiaSmiGpu {
            address: "0000:00:00.0".to_string(),
            memory_bytes: None,
            driver_version: Some("540.4.0".to_string()),
            name: "Orin (nvgpu)".to_string(),
        };
        assert_eq!(
            linux_gpus(displays, &[tegra], include_str!("fixtures/pci.ids.txt")),
            vec![
                gpu(
                    "Navi 31 [Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M]",
                    GpuVendor::Amd,
                    Some(25_753_026_560),
                    None
                ),
                gpu("Onboard IGD", GpuVendor::Intel, None, None),
                gpu("1a03:2000", GpuVendor::Other, None, None),
                gpu("Orin (nvgpu)", GpuVendor::Nvidia, None, Some("540.4.0")),
            ]
        );
    }

    /// Captured on a Mac mini (M4 Pro, macOS 27) with one HDMI display.
    #[test]
    fn system_profiler_on_apple_silicon_reports_unified_memory_as_null() {
        assert_eq!(
            parse_system_profiler(include_str!("fixtures/macos-displays-m4pro.json")),
            vec![gpu("Apple M4 Pro", GpuVendor::Apple, None, None)]
        );
    }

    /// Hand-written after the keys system_profiler uses on Intel Macs with a discrete GPU.
    #[test]
    fn system_profiler_on_an_intel_mac_reports_discrete_vram() {
        let json = r#"{"SPDisplaysDataType":[
            {"_name":"kHW_IntelUHDGraphics630Item","sppci_model":"Intel UHD Graphics 630","spdisplays_vendor":"Intel","spdisplays_vram_shared":"1536 MB","sppci_bus":"spdisplays_builtin"},
            {"_name":"AMD Radeon Pro 5500M","sppci_model":"AMD Radeon Pro 5500M","spdisplays_vendor":"sppci_vendor_amd","spdisplays_vram":"8 GB","sppci_bus":"spdisplays_pcie_device"}
        ]}"#;
        assert_eq!(
            parse_system_profiler(json),
            vec![
                gpu("Intel UHD Graphics 630", GpuVendor::Intel, None, None),
                gpu("AMD Radeon Pro 5500M", GpuVendor::Amd, Some(8 << 30), None),
            ]
        );
        assert_eq!(parse_system_profiler("not json"), vec![]);
    }

    /// Hand-written after Microsoft's Win32_VideoController field names, with the uint32
    /// AdapterRAM saturating on a 24 GiB card.
    #[test]
    fn video_controllers_skip_basic_and_remote_adapters() {
        let json = r#"[
            {"Name":"NVIDIA GeForce RTX 4090","AdapterCompatibility":"NVIDIA","AdapterRAM":4293918720,"DriverVersion":"32.0.15.6094","PNPDeviceID":"PCI\\VEN_10DE&DEV_2684&SUBSYS_88E21043&REV_A1\\4&2283F625&0&0019"},
            {"Name":"Intel(R) UHD Graphics 770","AdapterCompatibility":"Intel Corporation","AdapterRAM":1073741824,"DriverVersion":"31.0.101.4502","PNPDeviceID":"PCI\\VEN_8086&DEV_4680&SUBSYS_86941043&REV_0C\\3&11583659&0&10"},
            {"Name":"Microsoft Basic Display Adapter","AdapterCompatibility":"(Standard display types)","AdapterRAM":null,"DriverVersion":"10.0.26100.1","PNPDeviceID":"PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02\\3&267A616A&0&10"},
            {"Name":"Microsoft Remote Display Adapter","AdapterCompatibility":"Microsoft","AdapterRAM":null,"DriverVersion":"10.0.26100.1882","PNPDeviceID":"SWD\\REMOTEDISPLAYENUM\\RDPIDD_INDIRECTDISPLAY&SESSIONID_0002"},
            {"Name":"Parsec Virtual Display Adapter","AdapterCompatibility":"Parsec Cloud, Inc.","AdapterRAM":0,"DriverVersion":"0.45.0.0","PNPDeviceID":"ROOT\\DISPLAY\\0000"}
        ]"#;
        assert_eq!(
            parse_video_controllers(json),
            vec![
                gpu(
                    "NVIDIA GeForce RTX 4090",
                    GpuVendor::Nvidia,
                    None,
                    Some("32.0.15.6094")
                ),
                gpu(
                    "Intel(R) UHD Graphics 770",
                    GpuVendor::Intel,
                    Some(1 << 30),
                    Some("31.0.101.4502")
                ),
                gpu(
                    "Parsec Virtual Display Adapter",
                    GpuVendor::Other,
                    None,
                    Some("0.45.0.0")
                ),
            ]
        );
        let single = r#"{"Name":"AMD Radeon RX 7900 XTX","AdapterCompatibility":"Advanced Micro Devices, Inc.","AdapterRAM":4293918720,"DriverVersion":"32.0.12011.1036","PNPDeviceID":"PCI\\VEN_1002&DEV_744C"}"#;
        assert_eq!(
            parse_video_controllers(single),
            vec![gpu(
                "AMD Radeon RX 7900 XTX",
                GpuVendor::Amd,
                None,
                Some("32.0.12011.1036")
            )]
        );
    }
}
