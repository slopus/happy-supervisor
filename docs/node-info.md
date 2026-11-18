# happy-supervisor node info

NodeInfo is the supervisor's description of its machine: what it is, what it has, and what it
can enforce. It is basic inventory, not monitoring. It is collected when the node joins, sent in
every `node.ready` event, and collected again on each `node.info` command (api.md). Nothing is
sampled over time. Free disk space is the one value that changes between collections.

A probe that fails leaves its field `null` (or a list empty) rather than failing the whole
collection. On the wire a `null` field is omitted (api.md, Encoding). Collection must finish in under 5 seconds. A slow external probe (for example
`nvidia-smi`) is cut off at 3 seconds.

## Example

```json
{
  "installationId": "tz4a98xxat96iws9zmbrgj3a",
  "name": "build-box-3",
  "hostname": "build-box-3.lan",
  "supervisorVersion": "0.1.0",
  "os": {
    "family": "linux",
    "name": "Debian GNU/Linux",
    "version": "13",
    "kernelVersion": "6.12.115+deb13.1-amd64",
    "arch": "x86_64"
  },
  "cpu": { "model": "AMD EPYC 9654 96-Core Processor", "physicalCores": 24, "logicalCores": 48 },
  "memory": { "totalBytes": 134217728000, "swapTotalBytes": 0 },
  "disks": [
    { "mountPoint": "/", "fileSystem": "ext4", "totalBytes": 1000000000000, "availableBytes": 400000000000, "removable": false }
  ],
  "gpus": [
    { "name": "NVIDIA L4", "vendor": "nvidia", "memoryBytes": 24152899584, "driverVersion": "580.82.07" }
  ],
  "sandbox": {
    "mechanism": "landlock",
    "available": true,
    "reason": null,
    "landlockAbi": 6,
    "baselineRead": ["/usr", "/bin", "/lib", "/lib64", "/etc"]
  },
  "defaultEnv": { "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/me", "USER": "me", "LANG": "C.UTF-8" },
  "collectedAtMs": 1763496000000
}
```

## Fields

### Identity

| Field | Type | Meaning |
|---|---|---|
| `installationId` | string | A [cuid2](https://github.com/paralleldrive/cuid2), 24 lowercase characters, generated the first time the supervisor runs with a given state directory and stored there in `private/installation-id`. It never changes after that, across restarts, re-joins and upgrades. Deleting the state directory makes a new installation. |
| `name` | string | The name given with `join --name`, stored with the credentials. Defaults to the hostname. |
| `hostname` | string | The OS hostname at collection time. |
| `supervisorVersion` | string | The crate version of the running binary. |

### `os`

| Field | Type | Meaning |
|---|---|---|
| `family` | `"linux"` \| `"macos"` \| `"windows"` | The OS family. |
| `name` | string \| null | Distribution or product name. Linux: `NAME` from `/etc/os-release`. macOS: `"macOS"`. Windows: the product name, such as `"Windows 11 Pro"`. |
| `version` | string \| null | Linux: `VERSION_ID`. macOS: the product version (`"15.1"`). Windows: `major.minor.build` (`"10.0.26100"`). |
| `kernelVersion` | string \| null | Linux: `uname -r`. macOS: the Darwin release (`"24.1.0"`). Windows: the build number. |
| `arch` | `"x86_64"` \| `"aarch64"` | The CPU architecture of the **machine**, not the binary. An x86_64 binary under Rosetta reports `aarch64`. |

### `cpu`

| Field | Type | Meaning |
|---|---|---|
| `model` | string \| null | The brand string of the first CPU. |
| `physicalCores` | integer \| null | Physical cores. |
| `logicalCores` | integer | Logical processors available to the OS. |

### `memory`

| Field | Type | Meaning |
|---|---|---|
| `totalBytes` | integer | Installed physical memory as the OS reports it. |
| `swapTotalBytes` | integer | Configured swap or page file. |

### `disks`

One entry per mounted local filesystem that holds data: physical disks, partitions and volumes.
Pseudo-filesystems (`proc`, `sysfs`, `tmpfs`, `devtmpfs`, `overlay`, `squashfs`, `autofs`, and
the like) and macOS system snapshots that duplicate the data volume are left out. Network
filesystems are left out.

| Field | Type | Meaning |
|---|---|---|
| `mountPoint` | string | Where it is mounted (`/`, `/System/Volumes/Data`, `C:\`). |
| `fileSystem` | string | `ext4`, `apfs`, `NTFS` and so on. |
| `totalBytes` | integer | Size. |
| `availableBytes` | integer | Space available to the supervisor's user. |
| `removable` | bool | Removable media. |

### `gpus`

One entry per display or compute adapter. Empty when there are none or detection fails.

| Field | Type | Meaning |
|---|---|---|
| `name` | string | The adapter name (`"NVIDIA L4"`, `"Apple M2 Pro"`). |
| `vendor` | `"nvidia"` \| `"amd"` \| `"intel"` \| `"apple"` \| `"other"` | The vendor. |
| `memoryBytes` | integer \| null | Dedicated memory. `null` for unified memory or when unknown. |
| `driverVersion` | string \| null | The driver version when the OS reports it. |

How each platform finds them:

* **Linux.** PCI devices of class `0x03` (display) under `/sys/bus/pci/devices`, with vendor
  from the PCI vendor ID. NVIDIA names, memory and driver come from `nvidia-smi
  --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits` when it is on
  `PATH`. Otherwise the name is `/sys/.../label` or the vendor and device IDs (`"10de:27b8"`).
  AMD dedicated memory is `mem_info_vram_total` under the device's `drm` directory.
* **macOS.** `system_profiler SPDisplaysDataType -json`: `sppci_model` for the name, vendor from
  `spdisplays_vendor`, and `spdisplays_vram` for discrete memory. Apple Silicon reports
  unified memory as `null`.
* **Windows.** `Win32_VideoController` through PowerShell `Get-CimInstance` (`Name`,
  `AdapterCompatibility`, `AdapterRAM`, `DriverVersion`). Basic display and remote display
  adapters are left out.

### `sandbox`

What this node can enforce for `{ "mode": "sandboxed" }` commands (policy.md).

| Field | Type | Meaning |
|---|---|---|
| `mechanism` | `"landlock"` \| `"seatbelt"` \| `"none"` | The backend. |
| `available` | bool | Whether sandboxed commands can run. Decided by actually running a sandboxed `true` at startup, not by checking for features. |
| `reason` | string \| null | Why it is unavailable, in one sentence (for example "Landlock is not in the kernel's active LSM list"). |
| `landlockAbi` | integer \| null | Linux only. The Landlock ABI version the kernel supports. It determines the gaps listed in policy.md. |
| `baselineRead` | array of paths | Existing system paths that ordinary programs need to read on this machine. The supervisor never adds these to a policy itself. |

`baselineRead` by platform, keeping only paths that exist:

* Linux: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/etc`, `/proc`, `/sys/devices/system/cpu`, `/opt`. (`/proc` because `/proc/self` resolves to one process and its children would lose it.)
* macOS: `/usr`, `/bin`, `/sbin`, `/System`, `/Library`, `/private/etc`, `/private/var/db/timezone`, `/dev`, `/opt/homebrew`.
* Windows: empty.

### `defaultEnv`

The environment a command would usually get on this machine, for the control plane to copy into
`exec.start`. It holds `PATH`, `HOME` (`USERPROFILE` on Windows), `USER` (`USERNAME` on
Windows), `LANG` and `TMPDIR` (`TEMP` and `TMP` on Windows) when set in the supervisor's
environment, and also `SystemRoot` on Windows. Nothing else of the supervisor's environment is
reported.

### `collectedAtMs`

Unix epoch milliseconds when the collection finished.
