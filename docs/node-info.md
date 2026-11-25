# happy-supervisor node info

NodeInfo is the supervisor's description of its machine: what it is, what it has, and what it
can enforce. It is basic inventory, not monitoring. It is collected when the node joins, sent in
every `node.ready` event, and collected again on each `node.info` command (api.md). Nothing is
sampled over time. Free disk space is the one value that changes between collections.

A probe that fails leaves its field `null` (or a list empty) rather than failing the whole
collection. On the wire a `null` field is omitted (api.md, Encoding). Collection must finish in
under 5 seconds. The external probes (`nvidia-smi`, `system_profiler`, PowerShell) run alongside
the rest of the collection, and each is cut off at 3 seconds.

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
    "mechanism": "bubblewrap",
    "version": "0.11.0",
    "available": true,
    "reason": null,
    "baselineRead": ["/usr", "/bin", "/lib", "/lib64", "/etc"],
    "gaps": [
      "a command killed by a signal is reported as exiting with 128 plus the signal number",
      "32-bit x86 and x32 programs cannot run in the sandbox"
    ]
  },
  "identity": { "supervisorUser": "root", "workloadUser": "happy-workload", "root": true },
  "limits": { "memoryBytes": false, "processes": false, "cpuSeconds": true },
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
| `supervisorVersion` | string | The running binary's release version (`0.2.0-linux.1`), or its crate version when it was not built as a release. |

### `os`

| Field | Type | Meaning |
|---|---|---|
| `family` | `"linux"` \| `"macos"` \| `"windows"` | The OS family. |
| `name` | string \| null | Distribution or product name. Linux: `NAME` from `/etc/os-release`. macOS: `"macOS"`. Windows: the product name, such as `"Windows 11 Pro"`. |
| `version` | string \| null | Linux: `VERSION_ID`. macOS: the product version (`"15.1"`). Windows: `major.minor.build` (`"10.0.26100"`). |
| `kernelVersion` | string \| null | Linux: `uname -r`. macOS: the Darwin release (`"24.1.0"`). Windows: the build number. |
| `arch` | `"x86_64"` \| `"aarch64"` | The CPU architecture of the **machine**, not the binary. An x86_64 binary under Rosetta reports `aarch64` (`sysctl.proc_translated`), and one under emulation on Windows on ARM reports `aarch64` (`IsWow64Process2`). Linux reports `uname -m`. |

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

* **Linux.** From `/proc/self/mountinfo`: filesystems whose source is a block device under
  `/dev/`, and ZFS datasets. That leaves out pseudo, overlay, network and FUSE filesystems
  (`fuseblk`, which sits on a block device, stays). Read-only images (`squashfs`, `erofs`,
  `iso9660`) are left out. A device mounted several times, as bind mounts do, is listed once,
  at the mount of its own root, else at its shortest mount point. Sizes come from `statvfs`.
  `removable` is the disk's `removable` flag in sysfs, or a disk on USB.
* **macOS.** From `getfsstat`: local volumes that Finder shows, plus the data volume
  `/System/Volumes/Data`, which is hidden like the other system volumes but holds the data.
  Since Catalina `/` is the read-only system volume in the same APFS container, so `/` is left
  out and the data volume stands for it. `removable` is `MNT_REMOVABLE`.
* **Windows.** Fixed and removable volumes; `removable` is `DRIVE_REMOVABLE`.

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
  --query-gpu=pci.bus_id,memory.total,driver_version,name --format=csv,noheader,nounits` when
  it is on `PATH`, matched to the PCI device by bus ID. A card the driver does not support is
  absent from `nvidia-smi` and is listed from PCI alone. Otherwise the name is the device's
  `label`, its name in `pci.ids` (`"AD102 [GeForce RTX 4090]"`), or the vendor and device IDs
  (`"10de:2684"`), and the driver version is the bound driver module's `version`. AMD dedicated
  memory is `mem_info_vram_total` in the PCI device directory. GPUs `nvidia-smi` lists that are
  not on the PCI bus are appended.
* **macOS.** `system_profiler SPDisplaysDataType -json`: `sppci_model` for the name, vendor from
  `spdisplays_vendor`, and `spdisplays_vram` for discrete memory. Apple Silicon reports
  unified memory as `null`.
* **Windows.** `Win32_VideoController` through PowerShell `Get-CimInstance` (`Name`,
  `AdapterCompatibility`, `AdapterRAM`, `DriverVersion`, `PNPDeviceID`). The vendor is the PCI
  vendor in `PNPDeviceID`, else `AdapterCompatibility`. `AdapterRAM` is a 32-bit field that
  saturates near 4 GiB, so a saturated value reports `null`. Basic display and remote display
  adapters are left out.

### `sandbox`

What this node can enforce for `{ "mode": "sandboxed" }` commands (policy.md).

| Field | Type | Meaning |
|---|---|---|
| `mechanism` | `"bubblewrap"` \| `"seatbelt"` \| `"windows"` \| `"none"` | The backend: bubblewrap and seccomp on Linux, Seatbelt on macOS, a restricted token with ACLs and a firewall on Windows (policy.md). |
| `version` | string \| null | Bubblewrap only: what `bwrap --version` printed. |
| `available` | bool | Whether sandboxed commands can run. Decided by actually running a sandboxed `true` at startup, not by checking for features. |
| `reason` | string \| null | Why it is unavailable, in one sentence (for example "bwrap is not on PATH", or "unprivileged user namespaces are disabled"). |
| `baselineRead` | array of paths | Existing system paths that ordinary programs need to read on this machine. The supervisor never adds these to a policy itself. |
| `gaps` | array of strings | What this node's sandbox does not enforce, one sentence each, so the control plane can see it without knowing kernels. The Linux list depends on the kernel. Empty when `available` is false. |

`baselineRead` by platform, keeping only paths that exist:

* Linux: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/etc`, `/proc`, `/sys/devices/system/cpu`, `/opt`. (`/proc` because `/proc/self` resolves to one process and its children would lose it.)
* macOS: `/usr`, `/bin`, `/sbin`, `/System`, `/Library`, `/private/etc`, `/private/var/db/timezone`, `/private/var/select`, `/dev/fd`, `/dev/tty`, `/opt/homebrew`, and the app bundle of the selected developer directory (`/Applications/Xcode.app` by default). `/bin/sh` reads `/private/var/select/sh`. `/usr/bin/git`, `/usr/bin/python3` and the other developer shims run their tool from the Xcode bundle (Command Line Tools live under `/Library`). The shims cache their lookups in the user's `DARWIN_USER_TEMP_DIR` whatever `TMPDIR` says, and a policy cannot redirect it. They work without writing it, but each call then prints two errors and takes seconds longer; `filesystem.writeTemp` (policy.md) and `identity.tempDir` exist for this.
* Windows: empty.

### `identity`

Who the supervisor runs as, and who its work runs as (policy.md, Workload user).

| Field | Type | Meaning |
|---|---|---|
| `supervisorUser` | string | The supervisor process's user name (its uid on Unix if it has none). |
| `workloadUser` | string \| null | With `--workload-user`, the user every command, file operation and watch runs as. Never root: the node does not start with a root workload user. `null` when work runs as `supervisorUser`. |
| `root` | bool | The supervisor runs as root (Unix) or with an elevated administrator token (Windows). With `workloadUser` null, its work does too. On Linux `root` with `workloadUser` null never happens: the supervisor refuses to start that way. |
| `system` | `{ "user": string }` \| null | The account `{ "mode": "system" }` work runs as (policy.md, System access), such as `{ "user": "happy-system" }`. `null` when the node refuses system access: it was not enabled, the supervisor is not root, or the account no longer exists. Read again at every collection, but `node.ready` is sent only when a session starts, not when one resumes (api.md, Sessions), so a control plane that shows it calls `node.info` after a resume. The node checks `private/system` on every request whatever it last reported. Newer than the key registry, so its keys travel as text. |
| `tempDir` | string \| null | The work user's own temp directory, without a trailing separator. macOS: its `DARWIN_USER_TEMP_DIR` (`/var/folders/6p/y937…/T`), which the OS derives from the uid, read at startup by running `/usr/bin/getconf DARWIN_USER_TEMP_DIR` as that user. `null` on Linux and Windows, or when it cannot be read. A policy's `filesystem.writeTemp` makes it writable (policy.md). It is newer than the key registry, so it travels as text (api.md). |

So raw and sandboxed work runs as root exactly when `workloadUser` is null and `root` is true,
which only macOS and Windows allow. System access runs as `system.user`, whatever the others
say.

### `limits`

Which `exec.start` `limits` (api.md) this node enforces. A limit marked `false` is refused with
`sandbox_unavailable`.

| Field | Type | Meaning |
|---|---|---|
| `memoryBytes` | bool | Windows: a Job Object memory limit. Linux: `memory.max` of a cgroup v2 per command, `true` when the supervisor's cgroup was delegated to it and has the `memory` controller (install.md, `Delegate=yes`). macOS: `false`, because no rlimit bounds a process tree's memory (`RLIMIT_AS` counts address space, not memory). |
| `processes` | bool | Windows: a Job Object active-process limit. Linux: `pids.max` of the same cgroup, `true` with a delegated cgroup that has the `pids` controller. macOS: `false`, because `RLIMIT_NPROC` counts every process of the user, not of the tree. |
| `cpuSeconds` | bool | `true` everywhere: `RLIMIT_CPU` on Unix, a Job Object per-process time limit on Windows. |

### `defaultEnv`

The environment a command would usually get on this machine, for the control plane to copy into
`exec.start`. It holds `PATH`, `HOME` (`USERPROFILE` on Windows), `USER` (`USERNAME` on
Windows), `LANG` and `TMPDIR` (`TEMP` and `TMP` on Windows) when set in the supervisor's
environment, and also `SystemRoot` on Windows. With a workload user, `HOME` and `USER` are that
user's home directory and name. On Linux with system access as `happy-system`, `PATH` ends with
`/opt/happy-system/npm/bin`, where its `npm install -g` puts programs (policy.md, System
access). Nothing else of the supervisor's environment is reported.

### `collectedAtMs`

Unix epoch milliseconds when the collection finished.
