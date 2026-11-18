# happy-supervisor architecture

One Rust crate, `happy-supervisor`, with a library (`src/lib.rs`) and a binary (`src/main.rs`).
The library is what the binary runs, and what a Rust control plane can depend on for the wire
types (`protocol`) and the in-process test control plane (`testing`, behind the `testing`
feature).

Targets: `x86_64`/`aarch64` × `linux` (gnu), `apple-darwin`, `pc-windows-msvc`.

## Data flow

```
control plane ──wss── client ── link::Session ──► dispatch ──► exec      ──► sandbox::prepare ─► helper (child)
                                   ▲  (queue, acks,        ├─► files     ──► raw: fs::perform in-process
                                   │   dedup, resume)      │               └► sandboxed: helper (child) runs fs::perform
                                   │                       ├─► watch     ──► notify + ResolvedPolicy filter
                                   │                       └─► node_info
                                   └──── Outbox (send handle) ◄── exec / watch / replies
```

## Core types and where they live

| Type | Module | Owner |
|---|---|---|
| Link frames (`hello`, `welcome`, `msg`, `ack`, `bye`), every message kind's body type (commands, replies, events), `Access`, `Policy` wire shape, `NodeInfo` | `protocol` | scaffold, frozen |
| `Error { kind: ErrorKind, message }`, `ErrorKind` ↔ `kind` string table | `error` | scaffold |
| `Policy` (validated when built or parsed: path rules, list sizes), `ResolvedPolicy` (canonical grants, `ignored`, hidden state dir, `can_read`/`can_write`), `Confinement::{Raw, Sandboxed(ResolvedPolicy)}` | `policy` | scaffold |
| `Job { policy: ResolvedPolicy, op: JobOp }`, `JobOp::{Exec, Fs}`, the length-prefixed job framing on the helper's stdin, the exec status pipe, `helper::main` | `helper` | scaffold |
| `sandbox::prepare(&Job) -> Result<std::process::Command>`, `sandbox::probe() -> SandboxInfo`, `sandbox::baseline_read()`, `sandbox::enter(&ResolvedPolicy)` (Linux, inside helper) | `sandbox/{mod,linux,macos,windows}` | Linux / macOS tracks |
| `StateDir` (paths, installation ID, credentials load/store) | `state` | transport track |
| `link::Session`: the sans-IO session state machine (outgoing queue with droppable/retained budgets and drop accounting, UUIDv7 IDs, cursor acks, dedup, resend on resume, lost-session detection). Used unchanged by the node and `testing::ControlPlane`; `Role` is the only difference | `link` | scaffold |
| `Outbox`: the cloneable handle exec, watch and the driver use to send events, commands and replies into the session | `link` | scaffold |
| `enroll::join`, `client::run` (WebSocket, reconnect loop, driving the `Session`), `testing::ControlPlane` | `enroll`, `client`, `testing` | transport track |
| `ExecManager` (processes, timeouts, output logs, `exec.log`) | `exec`, `process/{unix,windows}` | exec track |
| `fs::perform(&FsRequest) -> Result<FsResponse>`, `fs::handle(FsRequest, Confinement)` | `fs` | files track |
| `WatchManager` | `watch` | files track |
| `node_info::collect(installation_id, name, &SandboxInfo) -> NodeInfo` | `node_info/*` | node-info track |
| `Node`, `dispatch(&Node, kind, body) -> Result<Value>` for every command kind | `dispatch` | scaffold wires kinds to the functions above |

`dispatch` is the command boundary. It parses bodies into the `protocol` types, which validate
IDs, argv, absolute paths, policies and log limits as they parse. It turns `access` into a
`Confinement` once: `raw` stays raw, and `sandboxed` replies `sandbox_unavailable` unless the
probed `SandboxInfo` is available, then resolves the policy against the state directory. Code
behind it trusts those types and does not validate them again.

## The sandbox helper

Every sandboxed operation, command or file, runs in a fresh child: the supervisor's own binary
invoked as `happy-supervisor __sandbox`. The child reads one job from stdin as a 4-byte
big-endian length followed by that many bytes of JSON. It reads the job with unbuffered reads, so
nothing past the job is consumed. Then:

* Linux: the helper calls `sandbox::enter(&job.policy)` (Landlock + `no_new_privs` + seccomp) on itself.
  It is a fresh single-threaded process, so it may allocate freely. It never forks a
  multi-threaded server.
* macOS: the parent spawned it as `/usr/bin/sandbox-exec -p <profile> <exe> __sandbox`, so it is
  already confined.
* Then `JobOp::Exec` execs the command (`execve`, so the PID stays the same and the rest of stdin
  belongs to the command). The parent passes the write end of a pipe as the helper's fd 3. If
  confinement or the exec fails, the helper writes the `Error` as JSON there and exits 127. A
  successful exec closes it (close-on-exec) with nothing written, so the parent learns whether
  the command started before it replies to `exec.start`. `JobOp::Fs` runs `fs::perform` and
  writes one JSON line, `{"ok": FsResponse}` or `{"err": Error}`, to stdout, then exits 0.
* A job that cannot be read exits 125.

The parent resolves the policy and sends the `ResolvedPolicy` in the job, so the parent's view
(`ignoredPaths`, the macOS profile, watch filtering) and the helper's Landlock rules come from
the same canonical grants.

Raw operations never use the helper. Raw file commands run `fs::perform` in-process on a
blocking thread. Raw commands are spawned directly.

The job travels on stdin, never in argv or the environment, so other users cannot see
the command's environment in `ps`.

## The link

`link::Session` holds no sockets and no tasks. It is a state machine fed with events
(`connected`, `frame received`, `disconnected`, `tick(now)`) that returns frames to write and
messages to deliver. `client.rs` owns the WebSocket and the reconnect loop and drives it. This
keeps every protocol rule in one place, testable with literal frames and a fake clock, and lets
the test control plane reuse it rather than reimplementing the protocol.

The driver loop is: on connect call `connected`, write every `poll_transmit`; on each text frame
call `receive`; after any call drain `poll_transmit` to the socket and `poll_incoming` to the
handlers; sleep until `deadline` and call `tick`; wake on `changed` (an `Outbox` call) and
drain again; close the socket when `is_closing` and nothing is left to transmit; call
`disconnected` when the socket is gone. On the node, after `Incoming::Opened`, if
`needs_ready()` collect `Node::ready_state` and call `ready`. Every `Incoming::Message` goes to
`dispatch`, and its result to `Outbox::reply`. The clock is injected (`link::Clock`), so tests
use `link::ManualClock`.

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
implementing api.md's join endpoint and the connect endpoint, speaking the link protocol through
the same `link::Session` the node uses. It issues join tokens, records joins, and exposes
`command(kind, body) -> Result<Value>` and a stream of events for one connected node. For network
tests it can drop the connection, stall acks, forget a session (so the next `welcome` is
`resumed: false`), revoke the node, and change `resumeWindowMs`. Integration tests start it on `127.0.0.1:0`, run `join` and `run` against it
(in-process via the library, and as the real binary), and assert on the wire. They run on
Linux and macOS natively.

An in-process test runs as the test harness, not as `happy-supervisor`, so before any sandboxed
operation it calls `helper::set_exe(env!("CARGO_BIN_EXE_happy-supervisor").into())` to point the
helper at the real binary.
