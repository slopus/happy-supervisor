# happy-supervisor sandbox policy

A **policy** is the manifest a sandboxed command carries. It says which paths the operation may
read, which it may write, and whether it may bind local ports or Unix sockets. Everything not
granted is denied, and the operating system enforces it, not the supervisor's own checks. The
same policy means the same thing for a command (`exec.start`), a file command (`fs.*`) and a
watch (`watch.start`). The wire format of commands is in [api.md](api.md).

```json
{
  "read": ["/usr", "/lib", "/etc/ssl", "/home/me/repo"],
  "write": ["/home/me/repo/target", "/tmp/job-17"],
  "localBind": false,
  "unixSockets": false
}
```

## Fields

| Field | Type | Meaning |
|---|---|---|
| `read` | array of absolute paths | May be read, listed, and executed. |
| `write` | array of absolute paths | May also be created, modified, renamed and removed. Write implies read. |
| `localBind` | bool | May bind and listen on TCP and UDP ports, on any local address. |
| `unixSockets` | bool | May create (bind) Unix domain sockets. A filesystem socket also needs its directory in `write`. |

All four fields are required. Each list holds at most 256 paths.

## Paths

* A path must be absolute and normalized: no `.` or `..` components, no empty components, no NUL.
  A trailing separator is ignored. A path that breaks these rules makes the command
  `invalid_params`.
* A directory grant covers the directory and everything below it. A file grant covers that
  file only.
* Grants are resolved when the operation starts. Each path is canonicalized, so symlinks are
  followed and the grant applies to the real location. On macOS, `/tmp` grants `/private/tmp`.
  A symlink created later inside a granted directory does not extend the grant: the OS checks the
  real path of every access.
* **A path that does not exist grants nothing.** It is skipped and reported in `ignoredPaths`. A
  directory created later at that path stays inaccessible to the running operation. To let an
  operation create `out/`, grant its existing parent.
* There are no deny lists. The narrowest way to express "everything but X" is to grant X's
  siblings.

## The supervisor never creates anything to sandbox

The supervisor never creates a file, directory, mount point or placeholder in order to apply a
policy. It does not bind-mount, does not create empty files to mask paths, and does not
pre-create granted paths. A sandboxed operation leaves the filesystem exactly as a raw operation
with the same effects would. The only things that change are the ones the operation itself
writes. This is why missing paths are skipped rather than created, and why the Linux backend
uses Landlock, a path-access LSM, rather than mount namespaces.

## Always granted

So that ordinary programs run, every sandbox also gets:

* `/dev/null`: read and write.
* `/dev/zero`, `/dev/random`, `/dev/urandom`: read.

Nothing else is implicit. Executables, shared libraries, certificate stores and locale data
must be granted by the policy. NodeInfo's `sandbox.baselineRead` lists the system paths this
machine needs to run ordinary programs, for the control plane to copy into policies
(node-info.md). The supervisor reports that list as a fact. It never adds it on its own.

## Always denied

The private part of the supervisor's state directory (`private/`, which holds its credentials and
its proxy CA key) is neither readable nor writable by any sandboxed operation, even when a
granted path contains it. The one exception to "nothing implicit" is the node's CA bundle
(`public/ca-bundle.pem`), readable by sandboxed commands that use a proxy (proxy.md).

## Outbound network

Outbound connections are not restricted by this version of the policy. A sandboxed process may
connect to any address the machine can reach, including loopback services. `localBind` and
`unixSockets` govern only what the process may *listen on*.

## Processes

A sandboxed process, and every process it starts, stays in the sandbox. It cannot raise its
privileges (setuid and file capabilities are ignored). It cannot debug, or signal, processes
outside its own sandbox where the platform can prevent it (table below).

## Enforcement by platform

The node reports what it can enforce in NodeInfo's `sandbox` section. A command whose policy
needs a restriction the node cannot enforce replies `sandbox_unavailable` and does not run. The
supervisor never weakens a policy silently.

### Linux: Landlock and seccomp

Requires Landlock ABI 1 or newer (kernel 5.13+) enabled in the running LSM list. The sandboxed
operation runs in a fresh helper process that restricts itself and then execs the command or
performs the file operation.

| Policy | Mechanism |
|---|---|
| `read` | Landlock read-file, read-dir and execute on each granted path. |
| `write` | Landlock write, create (regular, directory, symlink, FIFO), remove, truncate (ABI 3+) and cross-directory rename and link (ABI 2+). Device-node creation is never granted. A file grant gets only the rights that apply to a file (read, execute, write, truncate). |
| state directory | Landlock is allow-only, so when a granted directory contains the state directory, that grant is replaced by grants on each existing entry beside the path to it. The directories on that path are not granted themselves: they cannot be listed, and entries created in them later are denied. Symlinks among those entries are skipped. |
| `localBind: false` | Landlock denies TCP bind (ABI 4+, kernel 6.7+). When `unixSockets` is also false, seccomp denies `bind` and `listen` outright with `EPERM`, which also covers UDP and every other socket family, netlink included. |
| `unixSockets: false` | Landlock withholds socket creation in every directory. When `localBind` is also false, seccomp's `bind` denial also covers abstract-namespace sockets. |
| processes | `no_new_privs`. Landlock confines ptrace to the sandbox. ABI 6+ also scopes signals and abstract Unix socket connections to the sandbox. |

Every requested restriction must be fully enforced. The helper asks Landlock for exactly the
rights its kernel's ABI supports and fails with `sandbox_unavailable` rather than run under a
weaker ruleset. Landlock's device ioctl (ABI 5) and Unix socket connect (ABI 9) rights are not
handled, so ioctl on an opened device and connecting to a socket work as without a sandbox.

The seccomp filter only allows system calls of the native architecture. A 32-bit (compat)
program is killed at its first system call when the filter applies, because its socket calls
cannot be filtered reliably.

Gaps the node reports:

* With `localBind: false, unixSockets: true`, UDP ports can still be bound, and a TCP socket can
  still listen on an ephemeral port by calling `listen` without `bind`. Landlock controls only
  explicit TCP `bind`, and seccomp cannot tell a TCP `listen` from a Unix socket one.
* With `localBind: true, unixSockets: false`, abstract-namespace Unix sockets can still be
  bound. Filesystem sockets are denied.
* On ABI 1 to 3 kernels, `localBind: false` is enforced only with `unixSockets: false` (the
  seccomp path). Other combinations reply `sandbox_unavailable`.
* On ABI 1 and 2, `truncate(2)` on a readable file is not restricted by Landlock. File
  permissions still apply.

### macOS: Seatbelt

The operation runs under `/usr/bin/sandbox-exec` with a profile generated from the policy:
`(deny default)`, `file-read*` for `read`, `file-read*` and `file-write*` for `write`
(`subpath` for directories, `literal` for files), `network-bind` and `network-inbound` for
loopback and local addresses only when `localBind`, and Unix socket binding only when
`unixSockets`. Outbound network, process fork and exec, and the Mach services the C library
needs (directory lookups, logging, notifications, DNS) are allowed. Seatbelt applies the last
matching rule, and the state directory's deny comes after every grant, so it overrides any
containing grant. Signals
and process inspection are limited to the same sandbox.

### Windows

No sandbox. Sandboxed commands reply `sandbox_unavailable`. Raw commands work.

## Raw access

`{ "mode": "raw" }` runs with the supervisor's own rights and no policy. It is for the control
plane's trusted maintenance. Raw processes still run in their own process group or Job Object
so they can be killed as a tree.
