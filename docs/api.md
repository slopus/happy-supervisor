# happy-supervisor API

`happy-supervisor` runs on a machine and lets one trusted control plane run commands, read and
write files, and watch for changes there. The supervisor opens no inbound port. It dials out to
the control plane, proves who it is, and then serves requests over that one connection.

This document is the wire contract. The policy carried by sandboxed requests is in
[policy.md](policy.md). The node description is in [node-info.md](node-info.md).

## Joining and credentials

A machine joins once with a **join token**: short-lived, single-use, issued by the control plane
to whoever installs the supervisor. Joining exchanges it for a **node token**, a long-lived
credential only this machine holds. The join token is never stored.

```
happy-supervisor join --server https://control.example.com --token <join token> [--name <name>]
```

1. The supervisor loads or creates its installation ID (see node-info.md) and collects node info.
2. `POST {server}/v1/nodes/join`, JSON body:

   ```json
   { "joinToken": "jt_…", "installationId": "tz4a98xxat96iws9zmbrgj3a", "info": { …NodeInfo… } }
   ```

3. `200` answers:

   ```json
   { "nodeId": "n_…", "nodeToken": "nt_…" }
   ```

   Any other status is a failed join. `401`/`403` mean the token is invalid, expired or spent.
   The body may carry `{ "error": "…" }`, which the CLI prints.
4. The supervisor writes `credentials.json` atomically (write a temp file in the state directory,
   then rename), owner-only (`0600` on Unix). It holds `server`, `nodeId` and `nodeToken`.

Joining again replaces the stored credentials. The installation ID is kept.

`server` must be `https://host[:port]` with no path, query or credentials. Plain `http://` is
accepted only for a loopback host, for tests. TLS uses the platform's trust store.

### Rotation

The control plane can replace the node token at any time with `node.rotateCredential` (below).
The supervisor stores the new token durably before it answers, so an answered rotation is
never lost. If the answer is lost, the control plane should accept both tokens until the node
next connects with the new one.

## Connection

```
happy-supervisor run [--state-dir <dir>]
```

`run` opens a WebSocket to `{server}/v1/nodes/connect` (`wss://`, or `ws://` for a loopback
`http://` server) with `Authorization: Bearer <nodeToken>`.

* A `401` or `403` on the upgrade means the credential was revoked. `run` exits with code `3`
  and does not retry.
* Any other failure, or a dropped connection, is retried with exponential backoff from 1 s to
  60 s with ±20 % jitter. A connection that stays up for 60 s resets the backoff.
* WebSocket pings from the node every 20 s. A connection with no inbound frame for 60 s is
  closed and redialed.

Commands and watches **outlive the connection**. They keep running while the node redials.
Their events queue until the next connection (see Event delivery).

## Messages

Every frame is one UTF-8 JSON text message in [JSON-RPC 2.0](https://www.jsonrpc.org/specification)
form. The control plane sends **requests**. The node answers each with a **response** carrying
the same `id`. The node also sends **notifications**, which have no `id` and get no answer.
Requests are handled concurrently, and responses may arrive in any order.

```json
{ "jsonrpc": "2.0", "id": 7, "method": "fs.read", "params": { … } }
{ "jsonrpc": "2.0", "id": 7, "result": { … } }
{ "jsonrpc": "2.0", "id": 7, "error": { "code": -32001, "message": "…", "data": { "kind": "permission_denied" } } }
{ "jsonrpc": "2.0", "method": "exec.output", "params": { … } }
```

Binary payloads (file contents, process output, stdin) are standard base64 with padding, in
fields named `data`.

### Hello

The first frame on every connection is the node's `node.hello` notification:

```json
{
  "nodeId": "n_…",
  "installationId": "tz4a98xxat96iws9zmbrgj3a",
  "version": "0.1.0",
  "info": { …NodeInfo… },
  "execs": [ { "execId": "build-1", "state": "running" } ],
  "watches": [ "w-1" ]
}
```

`execs` and `watches` list what survived from earlier connections, so the control plane can
reconcile after a reconnect.

### Errors

| `data.kind` | `code` | Meaning |
|---|---|---|
| `invalid_params` | -32602 | Params do not parse, or violate a rule in this document or policy.md. |
| `method_not_found` | -32601 | Unknown method. |
| `not_found` | -32004 | The path, exec or watch does not exist. |
| `already_exists` | -32009 | An ID is in use, or `fs.write` with `create` found a file. |
| `permission_denied` | -32003 | The policy, or the OS, refused the operation. |
| `sandbox_unavailable` | -32010 | Sandboxed access was requested but this node cannot enforce it. `message` says why. |
| `too_large` | -32013 | A size limit in this document was exceeded. |
| `io` | -32000 | Any other OS error. `message` carries it. |

## Access

Every exec, file and watch request carries `access`. It is one of two shapes:

```json
{ "mode": "raw" }
{ "mode": "sandboxed", "policy": { "read": ["/usr", "/home/me/repo"], "write": ["/home/me/repo"], "localBind": false, "unixSockets": false } }
```

`raw` runs with the supervisor's full rights. `sandboxed` runs confined by the policy, enforced
by the operating system. The full policy rules are in policy.md. A node that cannot enforce
sandboxing answers sandboxed requests with `sandbox_unavailable`. It never falls back to raw.

## Node

### `node.info`

Params `{}`. Result: a freshly collected NodeInfo (node-info.md).

### `node.rotateCredential`

Params `{ "nodeToken": "nt_…" }`. The node stores the token durably, then answers `{}`. Later
connections use the new token. The current connection stays open.

## Processes

A process is identified by an `execId` the control plane chooses. That makes `exec.start` safe
to retry. A retried start with an ID already in use answers `already_exists` and starts nothing.
IDs are 1 to 64 characters of `[A-Za-z0-9_.-]`.

### `exec.start`

```json
{
  "execId": "build-1",
  "argv": ["/usr/bin/make", "-j8"],
  "cwd": "/home/me/repo",
  "env": { "PATH": "/usr/bin:/bin", "HOME": "/home/me" },
  "stdin": false,
  "timeout": { "ms": 600000, "action": { "kind": "background" } },
  "log": { "kind": "file", "path": "/home/me/repo/.logs/build-1.log", "limitBytes": 67108864 },
  "access": { "mode": "sandboxed", "policy": { … } }
}
```

* `argv[0]` is an absolute path, or a bare name looked up in `env.PATH`. `argv` is not
  interpreted by a shell. To run a shell line, send `["/bin/sh", "-c", "…"]`.
* `cwd` is absolute and must exist. Under a sandbox it must be readable by the policy.
* `env` is the **whole** environment. Nothing from the supervisor's own environment is passed.
  NodeInfo's `defaultEnv` holds the usual variables for this machine, for the control plane
  to copy.
* `stdin: true` keeps the process's stdin open for `exec.write`. `false` gives it an empty,
  closed stdin.
* `timeout` is optional. Without it the process runs until it exits or is killed. With it,
  after `ms` milliseconds the node applies `action`:
  * `{ "kind": "kill" }`. The process tree is killed and the exit is `timedOut`.
  * `{ "kind": "background" }`. The process keeps running. The node sends `exec.timedOut`, stops
    streaming `exec.output` for it, and from then on its output goes only to its log, which
    the control plane reads with `exec.log`. `exec.exit` still arrives when it ends.
* `log` is optional and defaults to `{ "kind": "memory" }`. Every process's combined output
  (stdout and stderr, in arrival order) is recorded in its log from the start, whether or not
  it ever times out, so `exec.log` works for every process. See Output logs.

Result:

```json
{ "execId": "build-1", "pid": 4242, "ignoredPaths": ["/home/me/.cache/nonexistent"] }
```

`ignoredPaths` lists the policy paths that did not exist and therefore grant nothing (policy.md).
It is empty for raw access.

A process that cannot start (binary missing, `cwd` refused) still gets its ID. The start
answers with the error, and no `exec.exit` follows.

Each command runs in its own process group (Unix) or Job Object (Windows). Killing it kills
the whole tree. A sandboxed process and everything it starts stay inside the sandbox.

### `exec.write`

Params `{ "execId": "…", "data": "<base64>", "eof": false }`. Writes to stdin. `eof: true`
closes stdin after the data. `data` may be empty. Writing to a process started with
`stdin: false`, or after `eof`, is `invalid_params`. At most 1 MiB of data per call.

### `exec.kill`

Params `{ "execId": "…", "signal": "terminate" }`, where `signal` is `terminate` (SIGTERM to the
process group, or `TerminateJobObject` on Windows) or `kill` (SIGKILL to the group, or
`TerminateJobObject`). Answers `{}` immediately. The exit arrives as `exec.exit`. Killing an
exited process answers `{}` and does nothing.

### `exec.list`

Params `{}`. Result `{ "execs": [ { "execId": "…", "state": "running" }, { "execId": "…", "state": "exited", "exit": { … } } ] }`.
The node keeps the 256 most recent exited processes. Older ones are forgotten, and their IDs
may be reused.

### `exec.output` (notification)

```json
{ "execId": "build-1", "stream": "stdout", "data": "<base64>", "droppedBytes": 0 }
```

Chunks are at most 64 KiB. Chunks of one stream arrive in order. `droppedBytes` counts output of
this stream that was dropped since the previous delivered chunk because the event queue was
full (see Event delivery).

### `exec.exit` (notification)

```json
{ "execId": "build-1", "exit": { "kind": "exited", "code": 0 } }
```

`exit` is one of:

* `{ "kind": "exited", "code": 0 }`. The process exited with that code.
* `{ "kind": "signaled", "signal": 9 }`. Unix only. A signal ended it.
* `{ "kind": "timedOut" }`. The timeout's `kill` action killed the tree.

A backgrounded process that later exits reports `exited` or `signaled` as usual.

`exec.exit` is sent after the last `exec.output` of the process, and is never dropped. Its
`logBytes` field is the total output the process produced (`{ "execId", "exit", "logBytes" }`).

### `exec.timedOut` (notification)

```json
{ "execId": "build-1", "action": "background", "logBytes": 183022 }
```

Sent once, when a `timeout` elapses, before anything else the action causes. For `kill`, the
`exec.exit` with `timedOut` follows. For `background`, no further `exec.output` is sent for this
process. `logBytes` is the output produced so far.

### `exec.log`

Params `{ "execId": "build-1", "offset": 0, "length": 65536 }`. Reads the process's log, running
or exited. `offset` defaults to 0, and `length` to 1 MiB, the most per call.

Result:

```json
{
  "data": "<base64>",
  "offset": 0,
  "totalBytes": 183022,
  "retained": [ { "start": 0, "end": 16384 }, { "start": 120000, "end": 183022 } ]
}
```

Offsets are positions in everything the process ever wrote, so they stay valid when the node
drops old output. `retained` lists the ranges the log still holds, at most two (see Output
logs). If `offset` falls in a dropped range, the read starts at the next retained byte, and the
answered `offset` says where. A read never crosses a dropped range: it stops at the range's end,
and the caller continues from the next `retained` start. To follow a running process, read from
the previous `offset` + data length until it reaches `totalBytes`.

A forgotten process (beyond the 256 retained) answers `not_found`. A file log's file remains on
disk after that.

## Output logs

Every process has one log of its combined output. Its size is limited, and when it fills, the
node keeps the **head** and the **most recent tail** and drops the middle. The beginning of a
run (what started, early errors) and its latest output are what readers need. Old middle
output is the least useful.

* The head is the first quarter of `limitBytes`. It is kept forever.
* The tail is the most recent output. Once the log is full, the oldest tail bytes are dropped,
  so the tail holds between half and three quarters of `limitBytes`. That gives at most two
  `retained` ranges, `[0, head)` and `[tailStart, totalBytes)`.

`log` is one of:

* `{ "kind": "memory", "limitBytes": 1048576 }`. Held in the supervisor's memory. `limitBytes`
  defaults to 1 MiB and may be at most 16 MiB. All memory logs on a node share a 256 MiB budget.
  When it is exceeded, the logs of the oldest exited processes are discarded first (their
  `exec.log` then answers with empty `retained`). An `exec.start` that would exceed the budget
  with running processes alone answers `too_large`.
* `{ "kind": "file", "path": "/abs/path.log", "limitBytes": 67108864 }`. Written to `path` as plain
  text, so it can also be read with `fs.read` or by people on the machine. `limitBytes` defaults
  to 64 MiB and may be at most 1 GiB. The parent directory must exist. The node never creates
  directories for a log. The file is created, or truncated if it exists. Under a sandbox, `path`
  must be writable by the policy, and the node checks that against the policy before starting.
  The node writes the log itself, not the sandboxed process. When the middle is dropped, the
  node rewrites the file as the head, one line `[happy-supervisor: N bytes omitted]`, then the
  tail, by writing a temp file beside it and renaming it over. `exec.log` offsets never count
  that line.

## Files

Every file request carries `path`, an absolute path, and `access`. Under a sandbox, reads need
the path in the policy's read set, and writes need it in the write set (policy.md). The
operation runs inside the same OS sandbox as a command with that policy. A sandboxed file
request therefore can do exactly what a sandboxed command could do.

Symlinks are followed, as `open` follows them. Under a sandbox, a symlink whose target lies
outside the policy is refused by the OS.

### `fs.stat`

Params `{ "path", "access" }`. Result:

```json
{ "kind": "file", "size": 1234, "modifiedMs": 1763496000000, "readonly": false }
```

`kind` is `file`, `directory`, `symlink` or `other`. `stat` follows symlinks. `symlink` appears
only from `fs.list`.

### `fs.list`

Params `{ "path", "access" }`. Result `{ "entries": [ { "name": "src", "kind": "directory", "size": 4096 } ] }`,
sorted by name. Entries are not followed, so a symlink lists as `symlink`. At most 10 000 entries.
A larger directory answers `too_large`.

### `fs.read`

Params `{ "path", "access", "offset": 0, "length": 1048576 }`. `offset` defaults to 0.
`length` defaults to the rest of the file, and at most 16 MiB is read per call (more is
`too_large`). Result `{ "data": "<base64>", "size": 1234 }`, where `size` is the whole file's
size.

### `fs.write`

Params `{ "path", "access", "data": "<base64>", "mode": "overwrite" }`. `mode` is:

* `create`. Fail with `already_exists` if the path exists.
* `overwrite`. Create or truncate, then write.
* `append`. Create or append.

The parent directory must exist. `fs.write` never creates directories. At most 16 MiB per call.
`overwrite` writes a temp file beside the target and renames it over, so readers never see a
half-written file. Result `{}`.

### `fs.mkdir`

Params `{ "path", "access", "recursive": false }`. `recursive` creates missing parents, like
`mkdir -p`, and succeeds if the directory exists. Result `{}`.

### `fs.remove`

Params `{ "path", "access", "recursive": false }`. Removes a file, a symlink (not its target)
or an empty directory. `recursive: true` removes a directory tree. Result `{}`.

## Watching

### `watch.start`

```json
{ "watchId": "w-1", "path": "/home/me/repo", "recursive": true, "access": { … } }
```

Starts reporting changes under `path`, which must exist. Under a sandbox, `path` must be
readable by the policy, and changes to paths the policy cannot read are never reported. The
control plane chooses `watchId`, with the same rules as `execId`. A node holds at most 64
watches. Result `{}`.

### `watch.stop`

Params `{ "watchId" }`. Result `{}`. Stopping an unknown watch is `not_found`.

### `watch.event` (notification)

```json
{ "watchId": "w-1", "changes": [ { "kind": "modified", "path": "/home/me/repo/src/main.rs" } ] }
```

`kind` is `created`, `modified`, `removed` or `renamed`. A rename reports `renamed` for the old
path and `created` for the new one when the OS gives both. Changes are batched for up to
100 ms. At most 256 changes go in one event.

```json
{ "watchId": "w-1", "overflow": true }
```

`overflow` means changes were lost (an OS queue overflowed, or the event queue was full). The
control plane should rescan what it cares about.

If the watched path itself is removed, the node sends a final event with that `removed` change,
then stops the watch.

## Event delivery

Notifications go through one outbound queue of at most 16 MiB. While the connection is down,
or the control plane reads slowly, the queue fills.

* When full, new `exec.output` chunks are dropped. The next delivered chunk of that stream
  carries the count in `droppedBytes`.
* When full, new `watch.event` changes are dropped, and the watch's next event is
  `overflow: true`.
* `exec.exit` is never dropped. There are at most as many as there are processes.

On reconnect, `node.hello` is sent first, then the queue drains in order.

## Limits

| What | Limit |
|---|---|
| Request frame | 32 MiB |
| `fs.read` / `fs.write` data | 16 MiB per call |
| `exec.write` data | 1 MiB per call |
| `exec.output` chunk | 64 KiB |
| Retained exited execs | 256 |
| `exec.log` read | 1 MiB per call |
| Memory log | 1 MiB default, 16 MiB max per process, 256 MiB per node |
| File log | 64 MiB default, 1 GiB max per process |
| Watches | 64 |
| Outbound event queue | 16 MiB |
