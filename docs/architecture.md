# happy-supervisor architecture

One Rust crate, `happy-supervisor`, with a library (`src/lib.rs`) and a binary (`src/main.rs`).
The library is what the binary runs, and what a Rust control plane can depend on for the wire
types (`protocol`) and the in-process test control plane (`testing`, behind the `testing`
feature).

Targets: `x86_64`/`aarch64` × `linux` (gnu), `apple-darwin`, `pc-windows-msvc`.

## Data flow

```
control plane ──wss── client ──► dispatch ──► exec      ──► sandbox::prepare ─► helper (child)
                         ▲                 ├─► files     ──► raw: fs::perform in-process
                         │                 │               └► sandboxed: helper (child) runs fs::perform
                         │                 ├─► watch     ──► notify + ResolvedPolicy filter
                         │                 └─► node_info
                         └──── events (bounded outbound queue) ◄── exec / watch
```

## Core types and where they live

| Type | Module | Owner |
|---|---|---|
| JSON-RPC envelope, every request/response/notification param type, `Access`, `Policy` wire shape, `NodeInfo` | `protocol` | scaffold, frozen |
| `Error { kind: ErrorKind, message }`, `ErrorKind` ↔ code/kind table | `error` | scaffold |
| `Policy::validate` (path rules), `ResolvedPolicy` (canonical grants, `ignored`, hidden state dir), `ResolvedPolicy::can_read/can_write` | `policy` | scaffold |
| `Job { policy, hidden, op: JobOp }`, `JobOp::{Exec, Fs}`, the length-prefixed job framing on the helper's stdin, `helper::main` | `helper` | scaffold |
| `sandbox::prepare(&Job, &ResolvedPolicy) -> Result<std::process::Command>`, `sandbox::probe() -> SandboxInfo`, `sandbox::enter(&Job)` (Linux, inside helper) | `sandbox/{mod,linux,macos,windows}` | Linux / macOS tracks |
| `StateDir` (paths, installation ID, credentials load/store) | `state` | transport track |
| `Events` (bounded outbound queue with drop accounting) | `events` | transport track |
| `ExecManager` | `exec`, `process/{unix,windows}` | exec track |
| `fs::perform(&FsRequest) -> Result<FsResponse>` | `fs` | files track |
| `WatchManager` | `watch` | files track |
| `node_info::collect(&StateDir) -> NodeInfo` | `node_info/*` | node-info track |
| `dispatch(Request, &Node) -> Response` | `dispatch` | scaffold wires methods to the functions above |

## The sandbox helper

Every sandboxed operation, command or file, runs in a fresh child: the supervisor's own binary
invoked as `happy-supervisor __sandbox`. The child reads one job from stdin as a 4-byte
big-endian length followed by that many bytes of JSON. It reads the job with unbuffered reads, so
nothing past the job is consumed. Then:

* Linux: the helper calls `sandbox::enter(&job)` (Landlock + `no_new_privs` + seccomp) on itself.
  It is a fresh single-threaded process, so it may allocate freely. It never forks a
  multi-threaded server.
* macOS: the parent spawned it as `/usr/bin/sandbox-exec -p <profile> <exe> __sandbox`, so it is
  already confined.
* Then `JobOp::Exec` execs the command (`execve`, so the PID stays the same and the rest of stdin
  belongs to the command). `JobOp::Fs` runs `fs::perform` and writes one JSON line,
  `{"ok": FsResponse}` or `{"err": Error}`, to stdout, then exits 0.

Raw operations never use the helper. Raw file requests run `fs::perform` in-process on a
blocking thread. Raw commands are spawned directly.

The job travels on stdin, never in argv or the environment, so other users cannot see
the command's environment in `ps`.

## Process lifetime

Every command, raw or sandboxed, is its own process group (Unix, `setsid` in the outer
`Command`'s `pre_exec`, applied before the helper runs) or Job Object with
`KILL_ON_JOB_CLOSE` (Windows). Kill and timeout signal the whole group. When the supervisor exits
normally it kills every running group.

## State directory

Default: Linux `$XDG_STATE_HOME/happy-supervisor` (else `~/.local/state/happy-supervisor`;
`/var/lib/happy-supervisor` when running as root). macOS
`~/Library/Application Support/happy-supervisor`. Windows `%LOCALAPPDATA%\happy-supervisor`.
`--state-dir` overrides it. It contains `installation-id` and `credentials.json`, created
`0700` and `0600`. It is the `hidden` path of every job.

## Testing

`happy_supervisor::testing::ControlPlane` (feature `testing`) is an in-process axum server
implementing api.md's join and connect endpoints. It issues join tokens, records joins, and
exposes `request(method, params) -> Result<Value>` and a stream of notifications for one
connected node. Integration tests start it on `127.0.0.1:0`, run `join` and `run` against it
(in-process via the library, and as the real binary), and assert on the wire. They run on
Linux and macOS natively.
