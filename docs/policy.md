# happy-supervisor sandbox policy (v2)

A **policy** is the manifest a sandboxed command, file operation or watch carries. It says, explicitly,
what the operation may read, write and reach on the network. The supervisor adds no defaults of
its own: every policy states its own default for reads, for writes and for network egress, and
the exceptions to it. The operating system enforces it, through bubblewrap and seccomp on Linux,
Seatbelt on macOS, and a restricted token with ACLs and a firewall on Windows.

```json
{
  "filesystem": {
    "read":  { "default": "allow", "allow": [], "deny": ["/home/me/.ssh", "/home/me/.aws"] },
    "write": { "default": "deny",  "allow": ["/home/me/repo", "/tmp/job-17"], "deny": ["/home/me/repo/.git/hooks"] }
  },
  "network": {
    "mode": "isolated",
    "egress": { "default": "deny", "allow": ["github.com", "*.githubusercontent.com"], "deny": [] },
    "ports": [443, 22],
    "localBind": false,
    "unixSockets": false
  }
}
```

Every field shown is required except `filesystem.writeTemp` (below). There is no implicit grant
and no implicit denial except the two fixed rules in "Fixed rules".

## Filesystem

`filesystem.read` and `filesystem.write` are each a **rule set**:

| Field | Meaning |
|---|---|
| `default` | `"allow"` or `"deny"`: what applies to a path no entry matches. |
| `allow` | Absolute paths that are allowed, with everything below them. |
| `deny` | Absolute paths that are denied, with everything below them. |

**The most specific entry wins.** For a path P, the entry whose path is the longest prefix of P
(by whole components) decides. When `allow` and `deny` name the same path, deny wins. When no
entry matches, `default` decides. The rule is the same for reads and writes.

**Writing implies reading.** A path the write rules allow is also readable, whatever the read rules
say about it, including `read.default: "deny"`. A path that a `read.deny` entry decides (the most
specific read entry for it is a deny) but the write rules allow is a contradiction the policy must
not contain; it is `invalid_params`.

Examples, with `read.default: "deny"`, `read.allow: ["/home/me"]`, `read.deny: ["/home/me/.ssh"]`:
`/home/me/repo/a.rs` is readable, `/home/me/.ssh/id_ed25519` is not, `/etc/passwd` is not.

Paths are absolute and normalized (no `.` or `..` or empty components, no NUL); a trailing
separator is ignored. Each list holds at most 1024 paths. Paths are matched after resolving
symlinks in the policy's own entries when they exist; a path that does not exist is matched by
name.

### `writeTemp`

`filesystem.writeTemp` is optional and defaults to `false`. With `true`, the work user's own temp
directory, NodeInfo `identity.tempDir` (node-info.md), is writable as if it were in
`write.allow`: a `write.deny` entry at the same path still wins, deeper entries still apply, a
`read.deny` that decides it is the usual contradiction (`invalid_params`), and inside the state
directory it grants nothing. On a node whose `tempDir` is `null` it grants nothing. A node older
than this field refuses it as an unknown key (api.md, Encoding), so send it only to a node that
reports `tempDir`.

It exists for macOS, where the developer tools' shims (`/usr/bin/git`, `/usr/bin/python3`) and
other system code write to `DARWIN_USER_TEMP_DIR` whatever `TMPDIR` says, and the policy
author cannot know that path.

### Paths that do not exist

* An `allow` entry that does not exist grants its name: if the operation creates it (and its parent
  is writable), it is allowed.
* A `deny` entry that does not exist is still denied. Where the mechanism needs something to
  mount over (bubblewrap) or attach an ACL to (Windows), the supervisor creates a **placeholder**:
  an empty, read-only file or directory at the first missing component. It records every
  placeholder it creates and removes it after the operation ends if it is still empty and still
  the one it created. Placeholders appear only inside directories the policy makes writable,
  which is the only place the operation could otherwise create the denied path. Seatbelt matches
  paths rather than files, so macOS needs no placeholder: it denies writing the first missing
  component by name.

## Fixed rules

1. **The supervisor's private state directory** (its credentials and keys) is denied for read and
   write whatever the policy says.
2. **Devices and procfs** are the sandbox's own, not host paths: on Linux the sandbox gets a
   private `/dev` (null, zero, full, random, urandom, tty, ptmx, shm) and a private `/proc` for its
   own PID namespace; the policy does not govern them. On macOS, where there is no private `/dev`,
   exactly those device nodes are readable and writable. On Windows the equivalent named devices
   (`NUL`, console) are available.

## Network

`network` is one of two shapes.

**Host** networking: the sandbox shares the machine's network, unrestricted outbound.

```json
{ "mode": "host", "localBind": true, "unixSockets": true }
```

**Isolated** networking: the sandbox has no route out except the node's proxies, which apply the
egress rules.

```json
{
  "mode": "isolated",
  "egress": { "default": "deny", "allow": ["github.com", "*.npmjs.org"], "deny": [] },
  "ports": [443],
  "localBind": false,
  "unixSockets": false
}
```

| Field | Meaning |
|---|---|
| `egress.default` | `"allow"` or `"deny"`: hosts no entry matches. `{ "default": "deny", "allow": [], "deny": [] }` is no network at all. |
| `egress.allow`, `egress.deny` | Host entries: an exact DNS name, `*.` and a suffix (matches names under it, not the suffix itself), or an address prefix such as `10.0.0.0/8` or `2001:db8::/32` (no bits set below the length). An IP literal is the prefix of its full length. At most 1024 each. How they decide is below. |
| `ports` | The destination ports allowed, or `null` for any port. |
| `localBind` | May bind and listen on TCP and UDP ports. In isolated mode those listeners are in the sandbox's own network, reachable only from inside it and through `tcp.open` with the command's `execId` (tunnels.md). |
| `unixSockets` | May create Unix domain sockets (bind or connect). Filesystem sockets also need their directory writable. |

How `egress` decides, in two steps that never compare a name with a prefix:

1. **The host.** A DNS name is decided by the name entries alone: the most specific match wins (an
   exact name over any `*.` pattern, a longer suffix over a shorter one), deny on a tie, and
   `default` when none matches. An IP literal is decided the same way by the prefixes alone, the
   longest one winning. A prefix never admits a name, so a name no entry allows is refused under
   `default: "deny"` without being resolved.
2. **Its addresses.** Each address the host resolves to is decided by the longest prefix
   containing it, deny on a tie. A prefix that denies an address drops it even when a name entry
   allowed the host, and a prefix that denies the IPv4 address an IPv6 one carries (NAT64, 6to4)
   drops that too. A prefix that allows an address lets it through even if it is internal. An
   address no prefix contains is dropped if it is internal (below). The connection uses the
   addresses that are left.

So `allow: ["db.corp.example"]` with `deny: ["10.0.0.0/8"]` refuses `db.corp.example` if it
resolves only into `10.0.0.0/8`, and `allow: ["10.0.0.0/8"]` alone lets a command reach
`10.1.2.3` but not a name that resolves to it.

How isolated networking works (proxy.md, "Egress proxy"):

* The sandbox can reach exactly two endpoints: an HTTP proxy and a SOCKS5 proxy, both run by the
  node outside the sandbox. `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (and lowercase forms) point
  at them. Everything else is unreachable: on Linux the sandbox has its own network namespace with
  only loopback; on macOS Seatbelt allows outbound connections only to the two proxy ports; on
  Windows a firewall filter keyed on the sandbox's identity allows only those ports on loopback.
* The proxies resolve the name themselves, check the host against `egress` and the port against
  `ports`, and then refuse any resolved address that is loopback, private, link-local, CGNAT,
  multicast or the node's own, unless a prefix in `egress.allow` decides that address.
* Seatbelt cannot tell loopback from other local addresses, so on macOS an isolated command
  with `localBind` may listen on any local address and accept connections from other hosts, and
  it cannot connect to its own listeners. The macOS probe lists this in `gaps`.
* UDP (including direct DNS) and other protocols have no route in isolated mode. Name resolution
  happens in the proxy.
* A file operation or watch has no proxy: under an isolated policy it has no network at all, and
  still runs. Only an exec gets the two proxies.
* Hosts listed in the command's credential `proxy.hosts` (proxy.md) go to the control plane, which
  can inject credentials. They must also pass `egress` step 1; their addresses are the control
  plane's to resolve and check.

## What each platform requires

| Platform | Requirement | Reported in |
|---|---|---|
| Linux | `bwrap` 0.8+ on `PATH` (or at a configured path), unprivileged user namespaces (or a setuid `bwrap`), kernel seccomp. On Ubuntu 24.04+, an AppArmor profile that allows `bwrap` user namespaces (below). | NodeInfo `sandbox.available`, `sandbox.reason` |
| macOS | `/usr/bin/sandbox-exec`. | same |
| Windows | Windows 10 1809+ / Server 2019+, the supervisor installed once with administrator rights to create the sandbox accounts and firewall filters. | same |

A node that cannot enforce a policy replies `sandbox_unavailable` and never runs the operation
with less.

Ubuntu 24.04 and later restrict unprivileged user namespaces through AppArmor. Allow them for
`bwrap` with `/etc/apparmor.d/bwrap`, then `sudo apparmor_parser -r /etc/apparmor.d/bwrap`:

```
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
```

### Linux: gaps and errors

The Linux probe lists these in `gaps`:

* With `localBind: false`, TCP `bind` is refused (Landlock ABI 4, Linux 6.7), but a TCP socket
  can still listen on an ephemeral port without binding, and a UDP socket that sends first gets
  an ephemeral port and receives replies on it. On older kernels, `localBind: false` with
  `unixSockets: true` also refuses binding Unix sockets.
* Connecting to an existing Unix socket needs only that the socket be readable, not its
  directory writable.
* 32-bit x86 and x32 programs cannot run in the sandbox.
* A command killed by a signal is reported as exiting with 128 plus the signal number.

What a command sees on Linux:

* Reading a read-denied file fails with `EACCES`. The path is still there, as the host's
  `/dev/null` bound `nodev` in place of the file.
* Listing a read-denied directory succeeds and shows it empty: it is an empty read-only tmpfs.
  Opening anything below it fails with `ENOENT` unless a deeper allow entry mounts that path
  back.
* Writing a write-denied file under a readable directory fails with `EROFS`; reading it works.
* Creating, renaming or removing an entry in a write-denied directory fails with `EROFS`.
* A missing deny path behaves the same at its placeholder: a file placeholder as a read-denied
  file, a directory placeholder as a read- and write-denied directory.
* With `localBind: false`, `bind` fails with `EPERM` where seccomp refuses it (`unixSockets:
  false`, or a kernel before 6.7), and with `EACCES` where Landlock does. Where seccomp refuses it,
  the node also sends `net.bindDenied` with the TCP or UDP address and port (api.md), so the
  control plane can tell the command it needs `localBind`. To do that, `bind` goes to a seccomp
  user notification that the sandbox helper's parent half, outside the filter, answers with
  `EPERM`; if that listener is gone, `bind` fails with `ENOSYS` instead. A process whose seccomp
  filters already have a listener (Linux allows one), or a kernel before 5.0, gets the plain
  refusal and no event.
* In isolated mode, connecting to `127.0.0.1` or `::1` reaches the sandbox's own loopback, where
  nothing but the proxies listens unless the command does, so a client that bypasses the proxy
  for loopback (`NO_PROXY`) gets `ECONNREFUSED`. The node does not report it: that would put
  every `connect`, each one to the proxies included, through a seccomp notification.
* If bubblewrap itself fails to set up the sandbox, the command is reported as exiting with
  code 1.

Through `fs.*` all of these answer `permission_denied`, because the node checks the policy first
(api.md, `fs.stat`).

### Windows: escapes, gaps and errors

**Network rules on Windows follow the account, not the token's choices.** `install-sandbox`
creates a pool of accounts for each combination of network mode and `localBind`, and each
account belongs to the network groups its pool needs. A command runs as an account of its
policy's pool. The firewall's blocks match a token that holds such a group in any state: a
restricted token of the command's own can make the group deny-only, but cannot drop it, so the
command cannot step out of a block. Its permits (the proxy ports, loopback) match only an
enabled group, so a command can lose one but never gain one. A process elsewhere on the machine
whose restricted token restricts to none of Everyone, RESTRICTED and WRITE RESTRICTED also fails
the blocks' check and loses the network.

Why not an AppContainer: it was evaluated and does not fit. A container is denied `NUL`, which
many programs open; it has no DNS without granting network capabilities that also open the
network; reaching loopback needs an administrator's exemption per container; and it requires a
user profile for its account.

Reads use the separate-account model: the command runs as one of the sandbox's own unprivileged
accounts, and the policy adds and removes access with ACLs. So `read.default: "deny"` is not
exact on Windows: the command can still read what any local user can, such as the Windows and
Program Files directories and other world-readable data. Under `read.default: "allow"` it
cannot read the supervisor account's private files, such as its profile, unless `read.allow`
lists them.

Under `write.default: "deny"` the command's token is write-restricted, and Windows gives a
restricted token no Schannel credentials. TLS through Schannel (curl.exe, PowerShell, .NET) fails
with `SEC_E_NO_CREDENTIALS`; programs with their own TLS (OpenSSL, rustls, Go, Node, Python)
work.

The Windows probe lists these and its other gaps in `gaps`, among them: `unixSockets: false` is
not enforced; `localBind: false` blocks TCP listen but not UDP bind; in isolated mode the command
can reach every port in the proxy port range, and with `localBind` every loopback port; names
still resolve through the DNS Client service; processes started through system services (WMI,
Task Scheduler) leave the Job Object.

## Raw access

`{ "mode": "raw" }` access carries no policy and runs with the supervisor's rights, or with the
workload user's when the node has one (below). Raw processes are still killed as a tree.

## Workload user

A supervisor running as root can run all of its work as one unprivileged user: `run` or `serve`
with `--workload-user <name>`, or the name on the first line of `private/workload-user` in the
state directory, which an installer writes. Every command, raw or sandboxed, and every file
operation then runs with that user's uid, gid and supplementary groups, so the OS checks what
it may read, write and run as that user, beneath any policy. NodeInfo `identity` reports it
(node-info.md), so a control plane can refuse to share a node whose work would run as root.

* The node refuses to start if the user does not exist, is root (uid 0), or the supervisor is
  not root. On Linux it also refuses to start as root without a workload user, so raw and
  sandboxed work there never runs as root (install.md); only system access does (below). A Linux supervisor that is not root runs work as itself.
* A command enters its `cwd` as that user. A raw file operation runs in the sandbox helper, as
  that user and without a policy. A `tty` command's terminal belongs to that user.
* A watch's OS watch runs in a helper process as that user, so it can watch only what that user
  can read, and new directories are listed as that user. The supervisor applies a sandboxed
  watch's policy to what the helper reports, as without a workload user.
* The supervisor itself stays root. Its private state directory stays `0700`, and the state
  directory becomes `0711` so the user can reach `public/ca-bundle.pem`. On Linux, bubblewrap
  runs as the user, so unprivileged user namespaces must be allowed for it. An isolated
  command's sandbox reaches its proxy sockets through descriptors the node passes it, not by
  path, so no other process of the user can reach them.
* A `log.kind: "file"` log is created or truncated by a helper running as that user, which
  hands the supervisor the open log and its directory. The supervisor writes through those and
  makes its rewrites relative to that directory, never by path, and gives each rewritten file
  the owner and mode of the one it replaces.
* Not supported yet: a workload user on Windows, where the node does not start with one.

## System access

`{ "mode": "system" }` access carries no policy and runs as the account that installs
system-wide software on this machine, so `apt-get install`, `npm install -g` and `brew install`
work. It is off unless an administrator enables it, and the control plane asks for it per
command, file operation or watch.

* `sudo happy-supervisor system enable [--user <name>] [--path <dir>]... --state-dir <dir>`
  records the account, and the directories to put first in its commands' `PATH`, in
  `private/system`, which only root can read or write. `system disable` removes it, and `system
  status` prints it. Each takes the service's state directory (install.md) and refuses one that
  does not exist. `install.sh --system` runs `system enable` after joining.
* On Linux the account is `happy-system`, which `system enable` creates when it is missing: a
  system user with a home and no login shell, owning the npm prefix `/opt/happy-system/npm`,
  which its `~/.npmrc` names, so `npm install -g` works without root. `/etc/profile.d/happy-system.sh`
  appends `/opt/happy-system/npm/bin` to the `PATH` of every user but root, and NodeInfo
  `defaultEnv`, on a node with a workload user, appends it to `PATH` too, so every command finds
  what it installs; appended, so nothing it installs shadows a system program, though a user
  whose `PATH` has it runs what `happy-system` put there under a name nothing earlier has. Root's
  `PATH` never gets it, and neither does `defaultEnv` when raw commands run as root. The prefix
  is not under `/usr/local`, whose directories root searches first, and `/opt/happy-system` must
  be root's, under directories only root may write. `system enable` refuses an existing
  `happy-system` that is root, in root's group or in any group but its own. `/etc/cron.deny`
  and `/etc/at.deny` name the account, and `system disable` kills every process it has, so
  nothing it left behind keeps running. An administrator can give the account a package manager
  of its own, such as Homebrew on Linux under `/home/linuxbrew/.linuxbrew` owned by
  `happy-system`, with `--path` for its `bin`.
* `apt-get install` as `happy-system` goes through the supervisor, which runs it as root with
  package names only (Installing with apt, below).
* `--user root` runs system access as root on Linux, so every `apt-get` command works. It is
  root-equivalent: a system command can then read the node's credentials (below), and `system
  enable` and `system status` say so.
* On macOS the account is the owner of Homebrew (`/opt/homebrew`, else `/usr/local/Homebrew`),
  because `brew` refuses to run as root and Homebrew's `npm -g` installs into its prefix; without
  Homebrew it is root. `--user` names another account. Root on macOS with Homebrew (for
  `installer -pkg`) needs `--user root`, and then `brew` does not work.
* Only a supervisor running as root can run it, since only root can become another account
  without giving one to its workload user. A node installed without sudo refuses it. No sudoers
  entry and no setuid program is involved, so the workload user, which every raw command runs
  as, gains nothing.
* The node reads `private/system` on every system request, so `system disable` refuses the next
  one without a restart. Running commands keep running, except on Linux as `happy-system`,
  whose processes it kills. A refusal is `permission_denied` and
  says why: the supervisor is not root, system access is not enabled, or its account no longer
  exists. NodeInfo `identity.system` names the account, or is `null` when the node refuses it.
* A system command, file operation or watch is unconfined and runs as that account, like raw
  access as the workload user (above). A command's environment is `env` with the account's
  `HOME`, `USER` and `LOGNAME`, on macOS its `TMPDIR`, and Homebrew's `bin` and `sbin` at the
  front of `PATH`, ahead of any other copy (api.md, `exec.start`).
* The node trusts `private/system` only while the state directory, `private/` and the file are
  the supervisor's user's own and writable by no one else, its path is absolute and goes through
  no symlink, and every directory above it is root's or the supervisor's user's and writable by
  no one else unless it is sticky (`/tmp`), so no other user can replace any of it. `system
  enable` and `disable` check the same before they write. Otherwise it refuses, and `system enable`
  does not enable it. The check reads mode bits, which on Linux include a POSIX ACL's mask; a
  macOS ACL on a directory of a custom state path that lets another user write is not seen, so
  keep a custom state path out of such directories.
* The supervisor logs each system operation (its command and program, or its path) with the
  account it ran as.
* `happy-system`, and Homebrew's owner on macOS, cannot read `private/`, so the node token and
  the proxy CA key stay the supervisor's. As root (`--user root`), a system command can read
  them, rewrite `private/system` so a later `system disable` does not hold, and replace the
  supervisor: that hands the control plane the machine. Turn it off in the control plane as
  well, and after a node that ran root system commands has it disabled, rotate its token
  (`node.update`). On macOS, Homebrew's owner is usually the person who uses the Mac, whose own
  files system commands can then read.
* Not supported on Windows, where the node refuses it.

### Installing with apt

`apt-get` needs root, and an `apt-get` that runs as root with options the caller picks can run
anything as root (`-o APT::Update::Pre-Invoke::=…`, a local `.deb`, a `Dpkg::Pre-Invoke` in an
`APT_CONFIG`). So a Linux system command that runs as `happy-system` asks the supervisor instead,
which takes package names and nothing else:

* Each such command gets a socket, `/opt/happy-system/apt/<pid>-<n>.sock`, owned by
  `happy-system`, mode `0600`, in a directory only root may change. It exists from the spawn to
  the command's exit, when the supervisor closes and removes it. The command's environment names
  it in `HAPPY_APT_SOCKET`.
* `/opt/happy-system/bin`, root's, holds a copy of the supervisor binary and the links `apt` and
  `apt-get` to it, and comes first in the command's `PATH`. Run under those names, the binary
  forwards `install` and the package names, with its standard output and error, and exits as
  `apt-get` did. It takes `apt-get install` or `apt install`, `-y`, `-q`, `--yes`,
  `--assume-yes`, `--quiet` and `--no-install-recommends`, and refuses anything else (`update`,
  `remove`, other options) with exit code 100 and a message saying what is allowed.
* The supervisor answers only a process of the command's own session (the command leads it) whose
  user is `happy-system`, by the socket's peer credentials, so a process that called `setsid`, or
  that the command left running after its exit, cannot install. It checks each name itself
  (lowercase letters, digits, `+`, `.` and `-`; 2 to 128 characters; starting with a letter or
  digit; not ending in `-` or `.deb`), so `=version`, `/release`, `:arch`, a file and a removal
  are refused whatever reaches the socket, and runs
  `/usr/bin/apt-get install -y -q --no-remove [--no-install-recommends] <names>` with a fixed
  environment (`PATH`, `HOME=/root`, `LANG`, `DEBIAN_FRONTEND=noninteractive`), standard input
  closed and `/` as working directory, one at a time. It logs the names.
* So a system command can install, as root, any package of the repositories the administrator
  configured, whose maintainer scripts then run as root. It cannot add a repository, pick a
  version or remove a package, and `apt-get update` is the administrator's.
