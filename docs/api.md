# happy-supervisor API

`happy-supervisor` runs on a machine and lets one trusted control plane run commands, read and
write files, and watch for changes there. The supervisor opens no inbound port. It dials out to
the control plane, proves who it is, and then the two sides exchange messages over that one
connection.

The protocol is built to survive bad networks. Both sides are peers that send each other
messages, like actors. Every message has a UUIDv7 ID, waits in its sender's outgoing queue
until the receiver confirms it, and is resent after a reconnect. A dropped connection resumes
where it left off. When resuming is impossible, both sides find out, and they start over
knowingly rather than silently losing messages.

This document is the wire contract. The policy carried by sandboxed commands is in
[policy.md](policy.md). The node description is in [node-info.md](node-info.md). Proxying a command's HTTP traffic
through the control plane is in [proxy.md](proxy.md).

## Joining and credentials

A machine joins once with a **join token**: short-lived, single-use, issued by the control plane
to whoever installs the supervisor. Joining exchanges it for a **node token**, a long-lived
credential only this machine holds, and tells the node where to connect. The join token is
never stored.

```
happy-supervisor join --url https://control.example.com/api/nodes/join --token <join token> [--name <name>]
```

`--url` is the **join endpoint itself**, a full URL the control plane hands out with the token.
The supervisor does not derive any path from it.

1. The supervisor loads or creates its installation ID (node-info.md) and collects node info.
2. `POST <join url>`, JSON body:

   ```json
   { "joinToken": "jt_…", "installationId": "tz4a98xxat96iws9zmbrgj3a", "name": "build-box-3", "info": { …NodeInfo… } }
   ```

3. `200` answers:

   ```json
   { "nodeId": "n_…", "nodeToken": "nt_…", "endpoint": "wss://edge-2.control.example.com/nodes/connect" }
   ```

   `endpoint` is the full WebSocket URL the node connects to from now on. It may be on another
   host than the join URL. Any other status is a failed join. `401`/`403` mean the token is
   invalid, expired or spent. The body may carry `{ "error": "…" }`, which the CLI prints.
4. The supervisor writes `private/credentials.json` in its state directory atomically (a temp file beside it,
   then rename), owner-only (`0600` on Unix). It holds `endpoint`, `nodeId`, `nodeToken` and
   `name`.

Joining again replaces the stored credentials. The installation ID is kept.

The join URL must be `https://`, and `endpoint` must be `wss://`. Plain `http://` and `ws://`
are accepted only for a loopback host, for tests. Neither may carry user credentials. TLS uses
the platform's trust store.

The control plane can later change the token, the endpoint, or both, with `node.update` (below).

## Connection

```
happy-supervisor run [--state-dir <dir>]
```

`run` opens a WebSocket to the stored `endpoint` with `Authorization: Bearer <nodeToken>`.

* A `401` or `403` on the upgrade means the credential was revoked. `run` exits with code `3`
  and does not retry.
* Any other failure, or a dropped connection, is retried with exponential backoff from 1 s to
  30 s with ±20 % jitter. A connection that stays up for 60 s resets the backoff.
* Each side sends a WebSocket ping every 15 s. A side that receives no frame for 45 s considers
  the connection dead, closes it, and (the node) redials.

Processes and watches **outlive connections and sessions**. They keep running while the node
redials.

## Link protocol

### Encoding

Every WebSocket frame is a **binary** frame holding one [CBOR](https://www.rfc-editor.org/rfc/rfc8949)
map with a `t` field naming the frame type. Text frames are a protocol error. The shapes in this
document are written as JSON for readability. On the wire:

* maps have text keys, the field names shown here;
* `data` fields, and header values in proxy.md, are CBOR byte strings (major type 2), not base64
  (examples write them as `h'…'`, CBOR diagnostic notation for bytes);
* UUIDs (message IDs, session IDs, stream IDs) are 16-byte byte strings;
* integers are CBOR integers, and absent optional fields are omitted rather than `null`, except
  where a field is shown as `null` (`hello.session`, `hello.cursor`).

The receiver ignores map keys it does not know, so either side can add fields. The one
exception is `access` and its `policy`: an unknown key there is `invalid_params`, so a node never
runs a command while ignoring a restriction it does not understand.

### Compression

The node offers two WebSocket subprotocols on the upgrade, in this order:

```
Sec-WebSocket-Protocol: happy-supervisor.v1.deflate, happy-supervisor.v1
```

The control plane picks one in its response. With `happy-supervisor.v1`, each frame's payload is
the CBOR map itself. With `happy-supervisor.v1.deflate`, each frame's payload starts with one
byte:

* `0x00`: the rest is the CBOR map, uncompressed;
* `0x01`: the rest is the CBOR map compressed as raw DEFLATE ([RFC 1951](https://www.rfc-editor.org/rfc/rfc1951)),
  no zlib or gzip header.

Each frame is compressed on its own, with no dictionary shared between frames. A resent message
then decodes with no history, and one corrupt frame cannot spoil the ones after it. The sender
compresses frames of 256 bytes or more and sends smaller ones as `0x00`. It also sends a frame
as `0x00` when compression did not make it smaller. A decompressed frame larger than the frame
limit (Limits) is a protocol error. A control plane that selects neither subprotocol, or none,
gets the connection closed: the node requires one of the two.

The join request (`POST <join url>`) is a single HTTPS exchange and stays JSON, so it can be
issued and debugged with ordinary HTTP tools.

### Sessions

A **session** is the state the two sides share about one conversation: each side's outgoing
queue, and the last message each has received from the other. A session spans any number of
connections. A connection is one WebSocket.

Each connection opens with a handshake. The node sends `hello`, the control plane answers
`welcome`, and neither sends anything else first.

```json
{ "t": "hello", "session": "0193a3b4-…", "cursor": "0193a3b5-…", "nodeId": "n_…", "installationId": "tz4a98xxat96iws9zmbrgj3a", "version": "0.1.0" }
{ "t": "welcome", "session": "0193a3b4-…", "resumed": true, "cursor": "0193a3b6-…", "resumeWindowMs": 300000 }
```

* `hello.session` is the session the node wants to resume, or `null` for a new one.
  `hello.cursor` is the node's cursor in that session (the latest message it received), or `null`.
* `welcome.resumed: true` means the control plane still has that session. Its `cursor` is
  the latest message it received from the node. Each side then resends, in order, every queued
  message after the other's cursor, and carries on.
* `welcome.resumed: false` means a **new session** with the `session` ID the control plane chose
  (a UUIDv7). The old session is lost (see Lost sessions). Both sides empty their queues and
  start again from nothing. The node's first message in a new session is always `node.ready`.
* `resumeWindowMs` is how long the control plane keeps a session after its connection drops.
  The node uses the same window (below).

### Messages

```json
{ "t": "msg", "id": "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b", "kind": "exec.start", "body": { … } }
```

* `id` is a UUIDv7 the sender generates. Within a session, each sender's IDs strictly increase,
  in the order it sent them. A sender that generates several IDs in one millisecond uses the
  RFC 9562 monotonic counter, so the order still holds.
* `kind` names the message. The tables below list every kind and its `body`.
* Messages from one sender are delivered and processed in ID order.

The receiver keeps the highest ID it has processed in the session. A message with an ID at or
below it is a duplicate from a resend: it is not processed again, only confirmed again by the next cursor. So each
message takes effect exactly once per session, however often the link breaks.

### Confirmations are a cursor

Each side confirms what it has received with a **cursor**: the UUIDv7 of the latest message it
has received and accepted from the other side. It never lists individual IDs. Because each
sender's IDs strictly increase and messages are processed in order, one cursor confirms that
message and every message before it.

```json
{ "t": "ack", "cursor": "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b" }
```

When an `ack` arrives, its receiver drops every queued message with an ID at or below `cursor`.
Accepted means handed to the handler, not finished (that is what a `reply` says). A side sends
its cursor no later than 200 ms after receiving a message, or after 64 messages since its last
`ack`, whichever comes first. An `ack` whose cursor has not moved is not sent, except to answer
a duplicate (its sender evidently missed the last one). Acks are not
messages: they have no ID, are never queued and never confirmed. A lost ack costs nothing,
because the next one carries a later cursor, and the handshake carries the cursor too.

### Commands and replies

Both sides send messages. A **command** asks the other side to do something and gets exactly one
`reply`. An **event** reports something and gets no reply. Today the control plane sends the
commands (`exec.start`, `fs.read`, …) and the node sends the events (`exec.output`,
`watch.event`, …), but the link does not care who sends what.

```json
{ "t": "msg", "id": "0193…a7", "kind": "reply", "body": { "to": "0193…12", "ok": { … } } }
{ "t": "msg", "id": "0193…a8", "kind": "reply", "body": { "to": "0193…13", "error": { "kind": "permission_denied", "message": "…" } } }
```

`to` is the command's message ID. A reply is an ordinary message, queued, resent and
confirmed like any other, so a command sent before a disconnect still gets its reply after the
link resumes. The node handles commands concurrently, so replies can arrive in any order.

### Lost sessions

A session is **lost**, and cannot be recovered, when:

* the control plane answers a `hello` with `resumed: false` (it restarted, or the window passed);
* the node could not reconnect within `resumeWindowMs` of the connection dropping. It then sends
  `hello` with `session: null`;
* either side sends `bye` (below);
* a side's queue of messages it must not drop passes 64 MiB. It sends `bye` with
  `"reason": "queue_overflow"` if it can and treats the session as lost.

```json
{ "t": "bye", "reason": "revoked", "message": "node removed by admin" }
```

`bye` ends the session on purpose. `reason` is `shutdown` (the sender is stopping), `revoked`
(the control plane removed the node, and `run` exits with code `3`), `queue_overflow` or
`protocol_error` (the peer sent something invalid). After `bye` the sender closes the WebSocket.
A node that receives any `bye` other than `revoked` reconnects with `session: null`.

When a session is lost, commands that had not been confirmed were never processed, and their
replies will never come. Messages the node had queued but the control plane never confirmed are
discarded. Processes and watches keep running. The node's `node.ready`, first in the new
session, lists all of them with their current state, so the control plane reconciles from that
and from `exec.log`, never from memory of the old session.

### `node.ready` (event)

```json
{
  "info": { …NodeInfo… },
  "previousSession": "0193a3b4-…",
  "execs": [ { "execId": "build-1", "state": "running", "logBytes": 1200 } ],
  "watches": [ "w-1" ]
}
```

`previousSession` is the lost session, or `null` on a node's first session since it started.

## Errors

A reply's `error.kind` is one of:

| `kind` | Meaning |
|---|---|
| `invalid_params` | The body does not parse, or violates a rule in this document or policy.md. |
| `unknown_kind` | The receiver does not know this message kind. |
| `not_found` | The path, process or watch does not exist. |
| `already_exists` | An ID is in use, or `fs.write` with `create` found a file. |
| `permission_denied` | The policy, or the OS, refused the operation. |
| `sandbox_unavailable` | Sandboxed access was requested but this node cannot enforce it. `message` says why. |
| `too_large` | A size limit in this document was exceeded. |
| `io` | Any other OS error. `message` carries it. |

A message of unknown kind is confirmed like any other and replied to with `unknown_kind`. The
receiver cannot tell an unknown command from an unknown event, so it replies to both, and a
side ignores a reply whose `to` is not a command it is waiting on. Either side can therefore add
events without breaking the other, at the cost of one small reply per unknown event.

In the sections below, a command's **params** are its message `body`, and its **result** is the
reply's `ok`. A `(event)` heading marks an event.

## Access

Every exec, file and watch command carries `access`. It is one of two shapes:

```json
{ "mode": "raw" }
{ "mode": "sandboxed", "policy": { "read": ["/usr", "/home/me/repo"], "write": ["/home/me/repo"], "localBind": false, "unixSockets": false } }
```

`raw` runs with the supervisor's full rights. `sandboxed` runs confined by the policy, enforced
by the operating system. The full policy rules are in policy.md. A node that cannot enforce
sandboxing replies to sandboxed commands with `sandbox_unavailable`. It never falls back to raw.

## Node

### `node.info`

Params `{}`. Result: a freshly collected NodeInfo (node-info.md).

### `node.update`

Params `{ "nodeToken": "nt_…", "endpoint": "wss://edge-5.control.example.com/nodes/connect" }`.
Both fields are optional, and at least one is required. The node stores them durably in
`credentials.json`, then replies `{}`. Later connections use them, and the current connection
stays open. A stored update is never lost. If the reply is lost, the session's resend delivers
it, or the control plane should accept both the old and new token until the node next
connects with the new one.

## Processes

A process is identified by an `execId` the control plane chooses. That makes `exec.start` safe
to retry. A retried start with an ID already in use replies `already_exists` and starts nothing.
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
  "proxy": { "token": "pt_8f1c…", "hosts": ["api.github.com"] },
  "access": { "mode": "sandboxed", "policy": { … } }
}
```

* `argv[0]` is an absolute path, or a bare name looked up in `env.PATH` (absolute entries only,
  in order; on Windows also with each `env.PATHEXT` extension). Without `PATH` a bare name is
  `not_found`. A relative path with a separator is `invalid_params`. `argv` is not interpreted
  by a shell. To run a shell line, send `["/bin/sh", "-c", "…"]`.
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
* `proxy` is optional: `{ "token", "hosts" }`. HTTP(S) requests the process makes to those hosts
  go through the control plane, which can add credentials. See [proxy.md](proxy.md).
* `log` is optional and defaults to `{ "kind": "memory" }`. Every process's combined output
  (stdout and stderr, in arrival order) is recorded in its log from the start, whether or not
  it ever times out, so `exec.log` works for every process. See Output logs.

Result:

```json
{ "execId": "build-1", "pid": 4242, "ignoredPaths": ["/home/me/.cache/nonexistent"] }
```

`ignoredPaths` lists the policy paths that did not exist and therefore grant nothing (policy.md).
It is empty for raw access.

A process that cannot start (binary missing, `cwd` refused, log file refused, memory budget
full) still gets its ID. The start replies with the error, and no `exec.exit` follows. It is
not listed by `exec.list` or `node.ready`, its `exec.log` is empty, and it counts as an exited
process for retention, so its ID frees up once 256 later processes have ended.

Each command runs in its own session and process group (Unix, `setsid`) or Job Object
(Windows). Killing it kills the whole tree. A sandboxed process and everything it starts stay
inside the sandbox. On Windows the process joins its Job Object right after it is created, so a
child it starts in that first instant can escape the tree.

### `exec.write`

Params `{ "execId": "…", "data": h'…', "eof": false }`. Writes to stdin. `eof: true`
closes stdin after the data. `data` may be empty. Writing to a process started with
`stdin: false`, after `eof`, or that is not running, is `invalid_params`. At most 1 MiB of data
per call (more is `too_large`). The reply comes once the process has taken the data into its
stdin pipe.

### `exec.kill`

Params `{ "execId": "…", "signal": "terminate" }`, where `signal` is `terminate` (SIGTERM to the
process group, or `TerminateJobObject` on Windows) or `kill` (SIGKILL to the group, or
`TerminateJobObject`). Replies `{}` immediately. The exit arrives as `exec.exit`. Killing an
exited process replies `{}` and does nothing. On Windows both end the tree with exit code 1.

### `exec.list`

Params `{}`. Result `{ "execs": [ { "execId": "…", "state": "running", "logBytes": 1200 }, { "execId": "…", "state": "exited", "exit": { … }, "logBytes": 0 } ] }`,
the same entries as `node.ready`'s `execs`.
The node keeps the 256 most recent exited processes. Older ones are forgotten, and their IDs
may be reused.

### `exec.output` (event)

```json
{ "execId": "build-1", "stream": "stdout", "data": h'…', "droppedBytes": 0 }
```

Chunks are at most 64 KiB. Chunks of one stream arrive in order. `droppedBytes` counts output of
this stream that was dropped since the previous delivered chunk because the event queue was
full (see Event delivery).

### `exec.exit` (event)

```json
{ "execId": "build-1", "exit": { "kind": "exited", "code": 0 }, "logBytes": 183022 }
```

`exit` is one of:

* `{ "kind": "exited", "code": 0 }`. The process exited with that code.
* `{ "kind": "signaled", "signal": 9 }`. Unix only. A signal ended it.
* `{ "kind": "timedOut" }`. The timeout's `kill` action killed the tree.

A backgrounded process that later exits reports `exited` or `signaled` as usual.

`exec.exit` is sent after the last `exec.output` of the process, and is never dropped.
`logBytes` is the total output the process produced. After the process exits, the node waits
for its stdout and stderr to close, or for them to stay silent for 100 ms, since processes it
left behind may hold them open. Output those leftovers write later is neither sent nor logged.

### `exec.timedOut` (event)

```json
{ "execId": "build-1", "action": "background", "logBytes": 183022 }
```

Sent once, when a `timeout` elapses, before anything else the action causes. For `kill`, the
`exec.exit` with `timedOut` follows. For `background`, no further `exec.output` is sent for this
process. `logBytes` is the output produced so far.

### `exec.log`

Params `{ "execId": "build-1", "offset": 0, "length": 65536 }`. Reads the process's log, running
or exited. `offset` defaults to 0, and `length` to 1 MiB, the most per call (more is
`too_large`).

Result:

```json
{
  "data": h'…',
  "offset": 0,
  "totalBytes": 183022,
  "retained": [ { "start": 0, "end": 16384 }, { "start": 120000, "end": 183022 } ]
}
```

Offsets are positions in everything the process ever wrote, so they stay valid when the node
drops old output. `retained` lists the non-empty ranges the log still holds, at most two (see
Output logs), so an empty log has none. If `offset` falls in a dropped range, the read starts at the next retained byte, and the
answered `offset` says where. A read never crosses a dropped range: it stops at the range's end,
and the caller continues from the next `retained` start. To follow a running process, read from
the previous `offset` + data length until it reaches `totalBytes`.

A forgotten process (beyond the 256 retained) replies `not_found`. A file log's file remains on
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
  A running process counts at its `limitBytes`, an exited one at the bytes its log still holds.
  When a start would exceed the budget, the logs of the oldest exited processes are discarded
  first (their `exec.log` then replies with empty `retained`, and `totalBytes` keeps counting).
  An `exec.start` that would exceed the budget with running processes alone replies
  `too_large`.
* `{ "kind": "file", "path": "/abs/path.log", "limitBytes": 67108864 }`. Written to `path` as plain
  text, so it can also be read with `fs.read` or by people on the machine. `limitBytes` defaults
  to 64 MiB and may be at most 1 GiB. The parent directory must exist. The node never creates
  directories for a log. The file is created, or truncated if it exists. Under a sandbox, `path`
  must be writable by the policy, and the node checks that against the policy before starting.
  The node writes the log itself, not the sandboxed process. When the middle is dropped, the
  node rewrites the file as the head, one line `[happy-supervisor: N bytes omitted]` (`N` is
  every byte dropped so far), then the tail, by writing `<name>.happy-supervisor-tmp` beside it
  and renaming it over. The line follows the head's last byte directly, even mid-line.
  `exec.log` offsets never count that line.

## Files

Every file command carries `path`, an absolute path, and `access`. Under a sandbox, reads need
the path in the policy's read set, and writes need it in the write set (policy.md). The
operation runs inside the same OS sandbox as a command with that policy. A sandboxed file
command therefore can do exactly what a sandboxed command could do.

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
A larger directory replies `too_large`.

### `fs.read`

Params `{ "path", "access", "offset": 0, "length": 1048576 }`. `offset` defaults to 0.
`length` defaults to the rest of the file, and at most 16 MiB is read per call (more is
`too_large`). Result `{ "data": h'…', "size": 1234 }`, where `size` is the whole file's
size.

### `fs.write`

Params `{ "path", "access", "data": h'…', "mode": "overwrite" }`. `mode` is:

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

### `watch.event` (event)

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

Each side has one outgoing queue per session. A message stays in it from the moment it is sent
until an `ack` covers it. While the connection is down, or the peer reads slowly, the queue
grows. The node bounds it in two parts:

* **Droppable** messages, `exec.output` and `watch.event`, may use 16 MiB of the queue. When that
  is full, a new one is not queued at all, so it never gets an ID. Output and changes are
  never lost for good this way, because the process log keeps output (`exec.log`), and
  `overflow` tells the control plane to rescan.
  * A dropped `exec.output` chunk is counted. The next queued chunk of that stream carries the
    count in `droppedBytes`.
  * Dropped `watch.event` changes make the watch's next queued event `overflow: true`.
* **Everything else** (replies, `exec.exit`, `exec.timedOut`, `node.ready`) is never dropped. If
  these alone pass 64 MiB, the session is lost (`queue_overflow`). Replies are bounded by the
  commands in flight and exits by the processes, so this means the peer stopped confirming.

On resume, each side resends its queue after the peer's cursor, then carries on. In a new
session, `node.ready` goes first.

## Limits

| What | Limit |
|---|---|
| WebSocket frame | 32 MiB, after decompression |
| Ack delay | 200 ms or 64 messages |
| Session resume window | set by `welcome.resumeWindowMs` |
| `fs.read` / `fs.write` data | 16 MiB per call |
| `exec.write` data | 1 MiB per call |
| `exec.output` chunk | 64 KiB |
| Retained exited execs | 256 |
| `exec.log` read | 1 MiB per call |
| Memory log | 1 MiB default, 16 MiB max per process, 256 MiB per node |
| File log | 64 MiB default, 1 GiB max per process |
| Watches | 64 |
| Outgoing queue, droppable messages | 16 MiB |
| Outgoing queue, everything else | 64 MiB, then the session is lost |
