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
| Link frames (`hello`, `welcome`, `msg`, `ack`, `bye`), every message kind's body type (commands, replies, events), `Access`, `Policy` wire shape, `NodeInfo`, the proxy types (`ProxySpec`, `ProxyToken`, `HostPattern`, `StreamId`, `ProxyMessage` and its bodies) | `protocol` | scaffold, frozen |
| `Wire::{Plain, Deflate}` (subprotocol ↔ frame codec: 1-byte prefix, raw deflate, 32 MiB inflate bound), `to_cbor`/`from_cbor`/`to_value`/`from_value`, the dynamic body `Value` | `wire` | scaffold |
| `Error { kind: ErrorKind, message }`, `ErrorKind` ↔ `kind` string table | `error` | scaffold |
| `Policy` (validated when built or parsed: path rules, list sizes), `ResolvedPolicy` (canonical grants, `ignored`, hidden state dir, `can_read`/`can_write`, `grant_read_file` for the CA bundle), `Confinement::{Raw, Sandboxed(ResolvedPolicy)}` | `policy` | scaffold |
| `Job { policy: ResolvedPolicy, op: JobOp }`, `JobOp::{Exec, Fs}`, the length-prefixed job framing on the helper's stdin, the exec status pipe, `helper::main` | `helper` | scaffold |
| `sandbox::prepare(&Job) -> Result<std::process::Command>`, `sandbox::probe() -> SandboxInfo`, `sandbox::baseline_read()`, `sandbox::enter(&ResolvedPolicy)` (Linux, inside helper) | `sandbox/{mod,linux,macos,windows}` | Linux / macOS tracks |
| `StateDir` (paths, `private_dir`/`public_dir`, installation ID, credentials load/store) | `state` | transport track |
| `link::Session`: the sans-IO session state machine (outgoing queue with droppable/retained budgets and drop accounting, UUIDv7 IDs, cursor acks, dedup, resend on resume, lost-session detection). Used unchanged by the node and `testing::ControlPlane`; `Role` is the only difference | `link` | scaffold |
| `Outbox`: the cloneable handle exec, watch and the driver use to send events, commands and replies into the session | `link` | scaffold |
| `enroll::join`, `client::run` (WebSocket, reconnect loop, driving the `Session`), `testing::ControlPlane` | `enroll`, `client`, `testing` | transport track |
| `ExecManager` (processes, timeouts, output logs, `exec.log`) | `exec`, `process/{unix,windows}` | exec track |
| `fs::perform(&FsRequest) -> Result<FsResponse>`, `fs::handle(FsRequest, Confinement)` | `fs` | files track |
| `WatchManager` | `watch` | files track |
| `NodeCa` (the CA and `public/ca-bundle.pem`), `ProxyManager` (`start_for_exec` → `ProxyLease`, `on_event`, `session_lost`), `Upstream` (implemented by `Outbox`) | `proxy/*` | proxy track |
| `node_info::collect(installation_id, name, &SandboxInfo) -> NodeInfo` | `node_info/*` | node-info track |
| `Node`, `dispatch(&Node, kind, body) -> Option<Result<Value>>`: a reply for every command kind, `None` for a `proxy.*` stream message | `dispatch` | scaffold wires kinds to the functions above |

`dispatch` is the command boundary. It parses bodies into the `protocol` types, which validate
IDs, argv, absolute paths, policies and log limits as they parse. It turns `access` into a
`Confinement` once: `raw` stays raw, and `sandboxed` replies `sandbox_unavailable` unless the
probed `SandboxInfo` is available, then resolves the policy with `private/` as the hidden path.
For an `exec.start` with `proxy` it starts the command's proxy, grants a sandboxed command read
access to the CA bundle, and hands the `ProxyLease` to `ExecManager::start`, which holds it until
the command exits. Code behind it trusts those types and does not validate them again.

## The sandbox helper

Every sandboxed operation, command or file, runs in a fresh child: the supervisor's own binary
invoked as `happy-supervisor __sandbox`. The child reads one job from stdin as a 4-byte
big-endian length followed by that many bytes of CBOR, the same encoding as the link. It reads the job with unbuffered reads, so
nothing past the job is consumed. Then:

* Linux: the helper calls `sandbox::enter(&job.policy)` (Landlock + `no_new_privs` + seccomp) on itself.
  It is a fresh single-threaded process, so it may allocate freely. It never forks a
  multi-threaded server.
* macOS: the parent spawned it as `/usr/bin/sandbox-exec -p <profile> <exe> __sandbox`, so it is
  already confined.
* Then `JobOp::Exec` execs the command (`execve`, so the PID stays the same and the rest of stdin
  belongs to the command). The parent passes the write end of a pipe as the helper's fd 3. If
  confinement or the exec fails, the helper writes the `Error` as CBOR there and exits 127. A
  successful exec closes it (close-on-exec) with nothing written, so the parent learns whether
  the command started before it replies to `exec.start`. `JobOp::Fs` runs `fs::perform` and
  writes one frame, `{"ok": FsResponse}` or `{"err": Error}` as length-prefixed CBOR, to stdout,
  then exits 0.
* A job that cannot be read exits 125.

The parent resolves the policy and sends the `ResolvedPolicy` in the job, so the parent's view
(`ignoredPaths`, the macOS profile, watch filtering) and the helper's Landlock rules come from
the same canonical grants.

Raw operations never use the helper. Raw file commands run `fs::perform` in-process on a
blocking thread. Raw commands are spawned directly.

The job travels on stdin, never in argv or the environment, so other users cannot see
the command's environment in `ps`.

## Watching

Watches run in the supervisor, not in the sandbox helper. A watch lives as long as the control
plane wants, and an OS sandbox would cost a long-lived helper process per watch. Watching shows
only names and kinds of changes, never contents, so filtering them is enough: a sandboxed watch
keeps the `ResolvedPolicy` its `access` resolved to, the same canonical grants a helper would
get, and reports a change only when `can_read` allows its path. notify watches the canonical
root and does not follow symlinks, so every path the OS reports is canonical and `can_read`
applies to it directly. The state directory is never readable, so it is never reported.

Each watch is a notify watcher feeding a bounded channel, and one task that owns its
`WatchState`: the scope (canonical root, the path as given, the filter) and the batch being
collected until its deadline. The task sends through `Outbox`, which turns a full droppable
queue into `overflow`. A full channel also becomes `overflow`.

## The link

`link::Session` holds no sockets and no tasks. It is a state machine fed with events
(`connected`, `frame received`, `disconnected`, `tick(now)`) that returns frames to write and
messages to deliver. `client.rs` owns the WebSocket and the reconnect loop and drives it. This
keeps every protocol rule in one place, testable with literal frames and a fake clock, and lets
the test control plane reuse it rather than reimplementing the protocol.

The driver loop is: on connect call `connected` with the negotiated `Wire`, write every
`poll_transmit` as a binary frame; on each binary frame call `receive` (a text frame is
`reject`); after any call drain `poll_transmit` to the socket and `poll_incoming` to the
handlers; sleep until `deadline` and call `tick`; wake on `changed` (an `Outbox` call) and drain
again; close the socket when `is_closing` and nothing is left to transmit; call `disconnected`
when the socket is gone. On the node, after `Incoming::Opened`, if `needs_ready()` collect
`Node::ready_state` and call `ready`. Every `Incoming::Message` goes to `dispatch`, and its
result, when there is one, to `Outbox::reply`. On `Incoming::Lost` call `Node::session_lost`. The
clock is injected (`link::Clock`), so tests use `link::ManualClock`.

In `client::run` the handlers are one task holding a `FuturesUnordered` of `dispatch` futures.
Messages are pushed in arrival order, which is ID order, so each command starts in order (its
synchronous prefix, such as an `exec.write` taking its process's stdin, runs in order) and then
runs concurrently with the others. Stream messages complete on their first poll, so a
stream's pieces reach the proxy in order. The session outlives connections; handlers and
running commands outlive both. `run_until(state, stop)` is `run` with a test-controlled stop.

## Process lifetime

Every command, raw or sandboxed, is its own process group (Unix, `setsid` in the outer
`Command`'s `pre_exec`, applied before the helper runs) or Job Object with
`KILL_ON_JOB_CLOSE` (Windows). Kill and timeout signal the whole group. When the supervisor exits
normally it kills every running group.

## State directory

Default: Linux `$XDG_STATE_HOME/happy-supervisor` (else `~/.local/state/happy-supervisor`;
`/var/lib/happy-supervisor` when running as root). macOS
`~/Library/Application Support/happy-supervisor`. Windows `%LOCALAPPDATA%\happy-supervisor`.
`--state-dir` overrides it. Created `0700`. Two parts:

* `private/` (`0700`): `installation-id`, `credentials.json` (`0600`), and the proxy CA's key
  `proxy-ca.key` (`0600`) and certificate `proxy-ca.crt`. It is the `hidden` path of every job: no sandboxed operation can read
  or write it, whatever its policy grants.
* `public/`: `ca-bundle.pem`, rewritten at each start (proxy.md). Sandboxed commands with a
  `proxy` get read access to that one file.

## Testing

`happy_supervisor::testing::ControlPlane` (feature `testing`) is an in-process axum server
implementing api.md's join endpoint and the connect endpoint, speaking the link protocol through
the same `link::Session` the node uses, for one node at a time. It issues single-use join tokens,
records joins, and exposes `command(kind, body) -> Result<Value>`, `send_proxy`, and a stream of
events (`proxy.*` included). `Options` chooses whether it selects the deflate subprotocol and its
`resumeWindowMs`. For network tests it can drop the connection, stall acks, forget a session (so
the next `welcome` is `resumed: false`), revoke the node (`bye` with `revoked`, then `401`), and
change `resumeWindowMs`. It counts the frames and bytes each way, on the wire and as CBOR, and the
replies that answered no waiting command, which would mean a command ran twice.
`happy_supervisor::testkit` (same feature) writes CBOR values as JSON literals, `h'…'` for bytes.

`tests/e2e.rs` runs the real binary: `happy-supervisor join` against the control plane, then
`happy-supervisor run` as a child process, and drives it over the link. Other integration tests
use the library in-process. They run on Linux and macOS natively.

An in-process test runs as the test harness, not as `happy-supervisor`, so before any sandboxed
operation it calls `helper::set_exe(env!("CARGO_BIN_EXE_happy-supervisor").into())` to point the
helper at the real binary.
