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
| Link frame bodies (`hello`, `welcome`, `msg`, `part`, `ack`, `bye`), every message kind's body type (commands, replies, events), `Access`, `Policy` wire shape, `NodeInfo`, the proxy types (`ProxySpec`, `ProxyToken`, `HostPattern`, `StreamId`, `ProxyMessage` and its bodies) | `protocol` | scaffold, frozen |
| Frame layout (`frame`/`split`: 16-byte ID prefix, then the body, 1 MiB bound), the key registry, `to_cbor`/`from_cbor` (compact) and `to_value`/`from_value`, the dynamic body `Value` | `wire` | scaffold |
| `ws::dial` (the node's upgrade: bearer token, subprotocol, permessage-deflate offer, platform roots), `ws::Socket` (one frame written at a time while reading, over yawc), `ws::options` | `ws` | scaffold |
| `Error { kind: ErrorKind, message }`, `ErrorKind` ↔ `kind` string table | `error` | scaffold |
| `Policy` (validated when built or parsed: path rules, list sizes), `ResolvedPolicy` (canonical grants, `ignored`, hidden state dir, `can_read`/`can_write`, `grant_read_file` for the CA bundle), `Confinement::{Raw, Sandboxed(ResolvedPolicy)}` | `policy` | scaffold |
| `Job { policy: ResolvedPolicy, op: JobOp }`, `JobOp::{Exec, Fs}`, the length-prefixed job framing on the helper's stdin, the exec status pipe, `helper::main` | `helper` | scaffold |
| `sandbox::prepare(&Job) -> Result<std::process::Command>`, `sandbox::probe() -> SandboxInfo`, `sandbox::baseline_read()`, `sandbox::enter(&ResolvedPolicy)` (Linux, inside helper) | `sandbox/{mod,linux,macos,windows}` | Linux / macOS tracks |
| `StateDir` (paths, `private_dir`/`public_dir`, installation ID, credentials load/store) | `state` | transport track |
| `link::Session`: the sans-IO session state machine (lanes with deficit round robin, parts and their reassembly, droppable/retained budgets and drop accounting, UUIDv7 frame IDs assigned as frames are written, kept frames and resend on resume, cursor acks, dedup by frame ID, lost-session detection). `link::lane_of` derives a message's lane. Used unchanged by the node and `testing::ControlPlane`; `Role` is the only difference | `link` | scaffold |
| `Outbox`: the cloneable handle exec, watch and the driver use to send events, commands and replies into the session | `link` | scaffold |
| `enroll::join`, `client::run` (WebSocket, reconnect loop, driving the `Session`), `testing::ControlPlane` | `enroll`, `client`, `testing` | transport track |
| `ExecManager` (processes, timeouts, output logs, `exec.log`) | `exec`, `process/{unix,windows}` | exec track |
| `fs::perform(&FsRequest) -> Result<FsResponse>`, `fs::handle(FsRequest, Confinement)` | `fs` | files track |
| `WatchManager` | `watch` | files track |
| `Streams`: the node's one stream table for proxy streams and tunnels. A stream is a `Kind` (`Http` with its command, or `Tcp`), an `Outbound` side (window, uncredited bytes, ended) and an `Inbound` side (awaiting a proxy response head, open, ended); one lock, one 1024-stream limit, one 32 MiB budget of uncredited bytes. `Upstream` (implemented by `Outbox`) is where its `proxy.*` and `tcp.*` messages go | `streams` | proxy track |
| `NodeCa` (the CA and `public/ca-bundle.pem`), `ProxyManager` (`start_for_exec` → `ProxyLease`, `on_event`, `session_lost`) | `proxy/*` | proxy track |
| `TunnelManager` (`open` for `tcp.open`, `on_event`, `session_lost`): one task per tunnel moving bytes between its loopback socket and its stream | `tunnel` | proxy track |
| `node_info::collect(installation_id, name, &SandboxInfo) -> NodeInfo` | `node_info/*` | node-info track |
| `Node`, `dispatch(&Node, kind, body) -> Option<Result<Value>>`: a reply for every command kind, `None` for a `proxy.*` or `tcp.*` stream message | `dispatch` | scaffold wires kinds to the functions above |

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

Each message waits in its lane (api.md, Lanes): one queue per process, watch or stream, one per
other command or reply, and the control lane. `poll_transmit` picks the next frame when it is
called: control frames (`hello`, `welcome`, `ack`, `bye`), then kept frames to resend after a
resume, then the control lane, then the other lanes in deficit round robin with a 64 KiB quantum.
The frame gets its ID then, and a message over 64 KiB goes as consecutive parts. Written data
frames are kept, byte for byte, until an `ack` covers them. Budgets are released part by part as
they are confirmed.

`ws` is the WebSocket, on yawc. Compression is yawc's permessage-deflate with context takeover
at DEFLATE level 2 (zlib-rs, pure Rust), below the link: a `Session` produces and consumes
uncompressed frames. `ws::Socket::next` polls reading and writing together, alternating which
goes first, and reports either a message or that the socket can take the next frame. A driver
writes one frame, then waits for that, and keeps reading meanwhile. A driver that stopped
reading while it wrote would deadlock against a peer doing the same once both socket buffers
fill.

The driver loop is: on connect call `connected`; on each binary message call `receive` (a text
message is `reject`); whenever the socket can take a frame and `poll_transmit` has one, write it;
drain `poll_incoming` to the handlers; sleep until `deadline` and call `tick`; wake on `changed`
(an `Outbox` call); close the socket when `is_closing` and nothing is left to transmit; call
`disconnected` when the socket is gone. On the node, after `Incoming::Opened`, if
`needs_ready()` collect `Node::ready_state` and call `ready`. Every `Incoming::Message` goes to
`dispatch`, and its result, when there is one, to `Outbox::reply`. On `Incoming::Lost` call
`Node::session_lost`. The clock is injected (`link::Clock`), so tests use `link::ManualClock`.

In `client::run` every handler is a task of its own, so a large reply's encoding never holds up
another. The messages of one process, watch or stream wait for the previous one's handler to
finish, so they are handled in delivery order (an `exec.write` reaches stdin in order, a stream's
pieces reach the proxy in order). Other messages start at once. The session outlives
connections; handlers and running commands outlive both. `run_until(state, stop)` is `run` with a
test-controlled stop. With the `testing` feature, `HAPPY_SUPERVISOR_SINGLE_LANE` puts every
message in one lane, to measure what lanes are worth.

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
implementing api.md's join endpoint and the connect endpoint (yawc's axum upgrade), speaking the
link protocol through
the same `link::Session` the node uses, for one node at a time. It issues single-use join tokens,
records joins, and exposes `command(kind, body) -> Result<Value>`, `send_proxy`, and a stream of
events (`proxy.*` included). `Options` sets its `resumeWindowMs`, and can make it decline compression, which the node
refuses. For network tests it can drop the connection, stall acks, forget a session (so
the next `welcome` is `resumed: false`), revoke the node (`bye` with `revoked`, then `401`), and
change `resumeWindowMs`. It counts the frames each way, their bytes as frames, and the bytes its
WebSocket connections carried over TCP, so tests can report compression against raw frame sizes.
It records the extensions offered and accepted, and the replies that answered no waiting command,
which would mean a command ran twice.
`happy_supervisor::testkit` (same feature) writes CBOR values as JSON literals, `h'…'` for bytes.

`tests/e2e.rs` runs the real binary: `happy-supervisor join` against the control plane, then
`happy-supervisor run` as a child process, and drives it over the link. Other integration tests
use the library in-process. They run on Linux and macOS natively.

An in-process test runs as the test harness, not as `happy-supervisor`, so before any sandboxed
operation it calls `helper::set_exe(env!("CARGO_BIN_EXE_happy-supervisor").into())` to point the
helper at the real binary.
