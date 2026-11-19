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
through the control plane is in [proxy.md](proxy.md). TCP tunnels to the node's loopback ports are in
[tunnels.md](tunnels.md).

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

### Frame layout

Every WebSocket frame is a **binary** frame. Text frames are a protocol error. A frame is a fixed
16-byte prefix followed by the body:

```
+------------------------------+------------------------------+
| frame ID                     | body                         |
| 16 bytes, UUIDv7, big-endian | CBOR map                     |
+------------------------------+------------------------------+
```

Each frame is one WebSocket binary message. Compression, when negotiated, is applied by the
WebSocket layer to the whole message (Compression), so the prefix compresses with the rest.

* **frame ID.** A UUIDv7 the sender assigns when it writes the frame. Within a session, each
  sender's frame IDs strictly increase in the order it writes them, across connections. A sender
  that generates several in one millisecond uses the RFC 9562 monotonic counter.
* **body.** A CBOR ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) map with a `t` field naming
  the frame type.

The shapes in this document are written as JSON for readability, with the frame ID shown as
`"id"`, although on the wire it is the prefix and not a map key. In the body:

* map keys are the integers of the key registry (Key registry, below);
* `data` fields, and header values in proxy.md, are CBOR byte strings, not base64 (examples write
  them as `h'…'`, CBOR diagnostic notation for bytes);
* UUIDs inside bodies (session IDs, cursors, stream IDs, `to`, `of`) are 16-byte byte strings;
* integers are CBOR integers, and absent optional fields are omitted rather than `null`, except
  where a field is shown as `null` (`hello.session`, `hello.cursor`).

### Key registry

Every field name in this document, every frame type (`t`) and every message `kind` has a number
in the registry. In a body, a map key that is in the registry is that CBOR unsigned integer, not
the text. A frame's `t` value, and a `msg` frame's `kind` value, are their numbers too. Other
values stay as they are, so `"stream": "stdout"` is `0x0d 0x66 "stdout"`, and the `kind` inside a
body (an exit, a change, an error) stays text.

* The registry is **append-only**. A number is never changed and never reused. A new name gets
  the next number.
* A text key, `t` or `kind` that is not in the registry passes through as text. A sender may add
  a field, or a message kind, before it has a number, and an older receiver still reads it.
* A number the receiver's registry does not have, or a number used in the wrong place (a frame
  type as a key), is a protocol error. Numbers 0 to 23 encode in one byte. They go to the most
  frequent names.
* Keys of free-form maps (`env`, `defaultEnv`) are data, but the same rule applies to them, so
  an environment variable named `path` travels as `28` and arrives as `path`.

An `ack` is its 16-byte frame ID, then `a2 00 05 03 50 <16-byte cursor>`: 37 bytes. A 16-byte
`exec.output` chunk of `build-1` is 60 bytes:

```
<16-byte frame ID>
a3 00 04 01 0a 02                             t: msg, kind: exec.output, body:
a4 0c 67 "build-1" 0d 66 "stdout" 09 50 <16 bytes> 0e 00
                                              execId, stream, data, droppedBytes: 0
```

| Number | Name | Role |
|---|---|---|
| 0 | `t` | key |
| 1 | `kind` | key |
| 2 | `body` | key |
| 3 | `cursor` | key |
| 4 | `msg` | frame |
| 5 | `ack` | frame |
| 6 | `part` | frame |
| 7 | `of` | key |
| 8 | `last` | key |
| 9 | `data` | key |
| 10 | `exec.output` | kind |
| 11 | `reply` | kind |
| 12 | `execId` | key |
| 13 | `stream` | key |
| 14 | `droppedBytes` | key |
| 15 | `to` | key |
| 16 | `ok` | key |
| 17 | `error` | key |
| 18 | `streamId` | key |
| 19 | `tcp.data` | kind |
| 20 | `proxy.body` | kind |
| 21 | `watch.event` | kind |
| 22 | `watchId` | key |
| 23 | `changes` | key |
| 24 | `exec.exit` | kind |
| 25 | `exit` | key |
| 26 | `logBytes` | key |
| 27 | `code` | key |
| 28 | `path` | key |
| 29 | `hello` | frame |
| 30 | `welcome` | frame |
| 31 | `bye` | frame |
| 32 | `proxy.credit` | kind |
| 33 | `proxy.request` | kind |
| 34 | `proxy.response` | kind |
| 35 | `proxy.end` | kind |
| 36 | `proxy.reset` | kind |
| 37 | `node.ready` | kind |
| 38 | `exec.timedOut` | kind |
| 39 | `node.info` | kind |
| 40 | `node.update` | kind |
| 41 | `exec.start` | kind |
| 42 | `exec.write` | kind |
| 43 | `exec.kill` | kind |
| 44 | `exec.list` | kind |
| 45 | `exec.log` | kind |
| 46 | `fs.stat` | kind |
| 47 | `fs.list` | kind |
| 48 | `fs.read` | kind |
| 49 | `fs.write` | kind |
| 50 | `fs.mkdir` | kind |
| 51 | `fs.remove` | kind |
| 52 | `watch.start` | kind |
| 53 | `watch.stop` | kind |
| 54 | `bytes` | key |
| 55 | `message` | key |
| 56 | `session` | key |
| 57 | `resumed` | key |
| 58 | `resumeWindowMs` | key |
| 59 | `nodeId` | key |
| 60 | `installationId` | key |
| 61 | `version` | key |
| 62 | `reason` | key |
| 63 | `previousSession` | key |
| 64 | `signal` | key |
| 65 | `overflow` | key |
| 66 | `headers` | key |
| 67 | `status` | key |
| 68 | `method` | key |
| 69 | `scheme` | key |
| 70 | `host` | key |
| 71 | `port` | key |
| 72 | `token` | key |
| 73 | `hosts` | key |
| 74 | `proxy` | key |
| 75 | `argv` | key |
| 76 | `cwd` | key |
| 77 | `env` | key |
| 78 | `stdin` | key |
| 79 | `timeout` | key |
| 80 | `ms` | key |
| 81 | `action` | key |
| 82 | `log` | key |
| 83 | `limitBytes` | key |
| 84 | `access` | key |
| 85 | `mode` | key |
| 86 | `policy` | key |
| 87 | `read` | key |
| 88 | `write` | key |
| 89 | `localBind` | key |
| 90 | `unixSockets` | key |
| 91 | `eof` | key |
| 92 | `pid` | key |
| 93 | `ignoredPaths` | key |
| 94 | `execs` | key |
| 95 | `state` | key |
| 96 | `offset` | key |
| 97 | `length` | key |
| 98 | `totalBytes` | key |
| 99 | `retained` | key |
| 100 | `start` | key |
| 101 | `end` | key |
| 102 | `entries` | key |
| 103 | `name` | key |
| 104 | `size` | key |
| 105 | `modifiedMs` | key |
| 106 | `readonly` | key |
| 107 | `recursive` | key |
| 108 | `nodeToken` | key |
| 109 | `endpoint` | key |
| 110 | `info` | key |
| 111 | `watches` | key |
| 112 | `hostname` | key |
| 113 | `supervisorVersion` | key |
| 114 | `os` | key |
| 115 | `family` | key |
| 116 | `kernelVersion` | key |
| 117 | `arch` | key |
| 118 | `cpu` | key |
| 119 | `model` | key |
| 120 | `logicalCores` | key |
| 121 | `physicalCores` | key |
| 122 | `memory` | key |
| 123 | `swapTotalBytes` | key |
| 124 | `disks` | key |
| 125 | `mountPoint` | key |
| 126 | `fileSystem` | key |
| 127 | `availableBytes` | key |
| 128 | `removable` | key |
| 129 | `gpus` | key |
| 130 | `vendor` | key |
| 131 | `memoryBytes` | key |
| 132 | `driverVersion` | key |
| 133 | `sandbox` | key |
| 134 | `mechanism` | key |
| 135 | `available` | key |
| 136 | `landlockAbi` | key |
| 137 | `baselineRead` | key |
| 138 | `gaps` | key |
| 139 | `defaultEnv` | key |
| 140 | `collectedAtMs` | key |
| 141 | `joinToken` | key |
| 142 | `tcp.credit` | kind |
| 143 | `tcp.open` | kind |
| 144 | `tcp.end` | kind |
| 145 | `tcp.reset` | kind |
| 146 | `filesystem` | key |
| 147 | `allow` | key |
| 148 | `deny` | key |
| 149 | `default` | key |
| 150 | `network` | key |
| 151 | `egress` | key |
| 152 | `ports` | key |
| 153 | `net.denied` | kind |
| 154 | `via` | key |
| 155 | `dropped` | key |
| 156 | `fs.rename` | kind |
| 157 | `from` | key |

The receiver ignores map keys it does not know, so either side can add fields. The one
exception is `access` and its `policy`: an unknown key there is `invalid_params`, so a node never
runs a command while ignoring a restriction it does not understand.

### Compression

Compression is the WebSocket standard's own, **permessage-deflate** ([RFC 7692](https://www.rfc-editor.org/rfc/rfc7692)),
negotiated on the upgrade. The node offers:

```
Sec-WebSocket-Protocol: happy-supervisor.v1
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
```

Compression is **always on**. The control plane must select the subprotocol `happy-supervisor.v1`
**and** accept the permessage-deflate extension. If its response lacks either, the node closes the
connection and retries with backoff, logging which one was missing. Every message is compressed,
with context takeover in both directions (the default), so each direction of the connection is one
DEFLATE stream. Every frame compresses against what was sent before it: repeated keys, IDs, the
same process's previous output. Small frames shrink as much as large ones. On a measured sequence
of build-output frames and acks, frames averaged 80.5 bytes uncompressed and 26.7 bytes with a
shared stream.

A bare `client_max_window_bits` lets the control plane choose the window the node compresses
with. Answering `client_max_window_bits=15` keeps the full 32 KiB window, so a frame can
compress against the last few frames. A small window gives most of that up.

The protocol above the WebSocket never sees compression. A frame is the same bytes either way.
Compression state belongs to the WebSocket connection, so a new connection starts fresh, and
frames resent after a resume are simply compressed again. A message that inflates past the frame
limit (Limits) closes the connection.

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
{ "id": "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b", "t": "msg", "kind": "exec.start", "body": { … } }
```

* `id` is the frame ID from the prefix (Frame layout). It is the message's ID: replies name it in
  `to`.
* `kind` names the message. The tables below list every kind and its `body`.

Only `msg` and `part` frames are **data frames**. They are kept by the sender until confirmed,
resent after a resume, and counted by the cursor. `hello`, `welcome`, `ack` and `bye` carry a frame
ID like every frame, but are never kept, resent or counted.

The receiver reads the prefix of every frame and drops a data frame whose ID is at or below its cursor without decoding the body.

The receiver keeps the highest data-frame ID it has accepted in the session, its cursor. A data
frame with an ID at or below it is a duplicate from a resend. It is not processed again, only
confirmed again. So each message takes effect exactly once per session, however often the link
breaks.

### Lanes: no message blocks the others

One connection carries everything: process output, file transfers, proxy and tunnel streams,
commands and replies. To keep a large transfer or a busy stream from delaying everything behind
it, each side sends through **lanes** and splits large messages into **parts**.

**Lanes.** Every message belongs to exactly one lane, derived from what it is about:

| Lane | Messages |
|---|---|
| `exec:<execId>` | `exec.start`, `exec.write`, `exec.kill`, `exec.output`, `exec.timedOut`, `exec.exit`, and `exec.log` for that process |
| `watch:<watchId>` | `watch.start`, `watch.stop`, `watch.event` for that watch |
| `stream:<streamId>` | every `proxy.*` and `tcp.*` message of that stream |
| `msg:<id>` | a command not covered above, alone (for example `fs.write` with 16 MiB) |
| `reply:<commandId>` | the reply to such a command (for example a large `fs.read` result) |
| `control` | `node.*` commands, their replies, and `node.ready`. Always small. |

A reply goes in the lane of its command when the command has an entity lane (an `exec.write`
reply travels in `exec:<execId>`, a `tcp.open` reply in `stream:<streamId>`). Otherwise it gets its
own `reply:<commandId>` lane, so a large reply never delays another. Commands without an entity
lane (`fs.*`) are independent of each other, so each travels alone.

**Order is per lane.** Messages of one lane arrive and are processed in the order they were sent.
Messages of different lanes may arrive in any order relative to each other. Everything that has to
stay ordered (a process's output before its exit, stdin writes, a stream's bytes) shares a lane.

**Parts.** A message whose CBOR body would exceed 64 KiB is sent as a run of `part` frames,
each carrying at most 64 KiB of the `msg` frame's CBOR body:

```json
{ "t": "part", "id": "0193…f1", "of": "0193…e0", "last": false, "data": h'…' }
```

* `id` is the part's own frame ID from the prefix, so the cursor confirms parts like any data frame.
* `of` is the ID of the message's first part, which is also the message's ID (the `to` of its
  reply). Every part of the message carries it.
* `last: true` marks the final part. The receiver concatenates the `data` of the parts of one `of`
  in order. The result is the CBOR body of a `msg` frame (uncompressed). The receiver decodes it and
  processes it then, as the message with ID `of`.
* Parts of one message are sent consecutively within its lane. Parts of different lanes
  interleave.
* A reassembled message may be up to 32 MiB. More is a protocol error. A receiver holds at most
  64 MiB of incomplete messages per session. More is `queue_overflow`.
* Incomplete messages survive a resumed session (their parts were confirmed or are resent). A lost
  session discards them.

**Scheduling.** The sender keeps one queue per lane. Whenever the WebSocket can take another frame
(the sender writes one frame at a time and waits for the socket, rather than buffering ahead), it
picks the next frame:

1. An `ack`, if one is due. Acks never wait behind data.
2. The `control` lane, if it has a frame. Control traffic is small and latency-sensitive.
3. Otherwise, the next lane in **deficit round robin** with a quantum of 64 KiB. Each lane with
   queued frames gets up to 64 KiB per round, so a lane with a 16 MiB transfer and a lane with a
   200-byte message each get a turn. The small one waits at most one part of every other busy lane.

The frame gets its ID as it is written. Quanta and the scheduling policy are the sender's own
choice, and a sender may use another fair policy. The wire rules are per-lane order and the 64 KiB
part limit. The receiver delivers each message once it is complete, in the order messages
complete. A receiver that runs handlers concurrently (the node does) keeps the handlers of one
entity, meaning one process, watch or stream, in delivery order, so `exec.write`s reach stdin in
order. Handlers of different entities run in parallel.

**Resume.** On resume, frames already written (with IDs) after the peer's cursor are resent first,
in ID order. Then scheduling continues from the lane queues. Messages that never reached the wire
have no ID yet, and simply go out later.

### Confirmations are a cursor

Each side confirms what it has received with a **cursor**: the frame ID of the latest data frame it
has received and accepted from the other side. It never lists individual IDs. Because each
sender's frame IDs strictly increase in wire order, one cursor confirms that data frame and every
data frame before it.

```json
{ "t": "ack", "cursor": "0193a3b4-7c2e-7aa1-9f00-3c1d2e4f5a6b" }
```

When an `ack` arrives, its receiver drops every kept data frame with an ID at or below `cursor`.
Accepted means handed to the handler, not finished (that is what a `reply` says). A side sends
its cursor no later than 200 ms after receiving a data frame, or after 64 data frames since its
last `ack`, whichever comes first. An `ack` whose cursor has not moved is not sent, except that a
duplicate is acked again. Acks are not data frames: they are never kept, resent or confirmed. A lost ack costs nothing,
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
| `connection_refused` | `tcp.open` found nothing listening (tunnels.md). |
| `timed_out` | `tcp.open` did not connect within 10 s (tunnels.md). |

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
{ "mode": "sandboxed", "policy": {
    "filesystem": {
      "read":  { "default": "deny", "allow": ["/usr", "/home/me/repo"], "deny": [] },
      "write": { "default": "deny", "allow": ["/home/me/repo"], "deny": ["/home/me/repo/.git/hooks"] }
    },
    "network": { "mode": "host", "localBind": false, "unixSockets": false } } }
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
{ "execId": "build-1", "pid": 4242 }
```

A process that cannot start (binary missing, `cwd` refused, log file refused, memory budget
full) still gets its ID. The start replies with the error, and no `exec.exit` follows. It is
not listed by `exec.list` or `node.ready`, its `exec.log` is empty, and it counts as an exited
process for retention, so its ID frees up once 256 later processes have ended.

Each command runs in its own session and process group (Unix, `setsid`) or Job Object
(Windows). Killing it kills the whole tree. A sandboxed process and everything it starts stay
inside the sandbox. On Windows the process is created suspended and runs only once it is in its
Job Object, so nothing it starts escapes the tree.

### `exec.write`

Params `{ "execId": "…", "data": h'…', "eof": false }`. Writes to stdin. `eof: true`
closes stdin after the data. `data` may be empty. Writing to a process started with
`stdin: false`, after `eof`, or that is not running, is `invalid_params`. At most 1 MiB of data
per call (more is `too_large`). The reply comes once the process has taken the data into its
stdin pipe.

### `exec.kill`

Params `{ "execId": "…", "signal": "terminate" }`, where `signal` is `interrupt` (SIGINT to the
process group, as Ctrl-C at a terminal), `terminate` (SIGTERM to the group, or
`TerminateJobObject` on Windows) or `kill` (SIGKILL to the group, or `TerminateJobObject`).
Replies `{}` immediately. The exit arrives as `exec.exit`; a command may handle `interrupt` and
keep running. Killing an exited process replies `{}` and does nothing. On Windows `terminate`
and `kill` end the tree with exit code 1, and `interrupt` replies `io` (not supported yet).

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

### `net.denied` (event)

```json
{ "execId": "e_1", "host": "evil.example", "port": 443, "via": "http", "reason": "egress" }
```

The process's command proxy refused a connection (proxy.md, Egress proxy). `via` is `http` or
`socks5`. `reason` is `egress` (the host failed `network.egress`), `port` (not in
`network.ports`), `address` (every resolved address was filtered), `resolve` (no address), or
`credential` (a credential host asked through SOCKS5, which cannot carry the credential route).
At most 20 a second per process. `dropped` (int) is present on the next event after some were
rate-limited, and counts them. Sent in the process's lane, `exec:<execId>`.

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

Under a sandbox the supervisor also checks the path, with symlinks resolved, against the
policy before the helper runs. A sandbox shows a hidden path as missing (bubblewrap) or lets its
metadata through (Seatbelt), so the policy decides first and every platform answers
`permission_denied`.

### `fs.list`

Params `{ "path", "access" }`. Result `{ "entries": [ { "name": "src", "kind": "directory", "size": 4096 } ] }`,
sorted by name. Entries are not followed, so a symlink lists as `symlink`, and its `size` is the
length of its target path. A name that is not valid UTF-8 is reported with U+FFFD in place of
the invalid bytes. At most 10 000 entries. A larger directory replies `too_large`.

### `fs.read`

Params `{ "path", "access", "offset": 0, "length": 1048576 }`. `offset` defaults to 0.
`length` defaults to the rest of the file, and at most 16 MiB is read per call (more is
`too_large`). Without `length`, a rest longer than 16 MiB is `too_large` too. The rest is found by
reading, not from the size, so files that report size 0 (such as Linux's `/proc`) read fully.
Result `{ "data": h'…', "size": 1234 }`, where `size` is the whole file's size. An
`offset` at or past the end reads no data.

### `fs.write`

Params `{ "path", "access", "data": h'…', "mode": "overwrite" }`. `mode` is:

* `create`. Fail with `already_exists` if the path exists.
* `overwrite`. Create or truncate, then write.
* `append`. Create or append.

The parent directory must exist. `fs.write` never creates directories. At most 16 MiB per call.
`overwrite` writes a temp file beside the target and renames it over, so readers never see a
half-written file. The replacement keeps the target's permissions. Through a symlink, the file
it points to is replaced and the link stays. `overwrite` refuses what writing the file in place
would refuse, such as a read-only file. When the directory does not allow the temp file but the
file itself is writable (a sandbox policy that grants only the file), the file is truncated and
written in place instead, and readers can then see it half-written. Result `{}`.

### `fs.mkdir`

Params `{ "path", "access", "recursive": false }`. `recursive` creates missing parents, like
`mkdir -p`, and succeeds if the directory exists. Result `{}`.

### `fs.remove`

Params `{ "path", "access", "recursive": false }`. Removes a file, a symlink (not its target)
or an empty directory. `recursive: true` removes a directory tree. Symlinks inside the tree are
removed, never followed. Result `{}`.

### `fs.rename`

Params `{ "from", "to", "access" }`. Moves `from` to `to` in one step, like `rename(2)`: a file,
a symlink (not its target) or a directory. An existing `to` is replaced when it is a file and
`from` is not a directory; a directory may replace only an empty directory (not on Windows).
`to`'s parent must exist. Under a sandbox both paths need the policy's write set, checked on
their parents with symlinks resolved and the last component as given. A move across
filesystems fails with `io`, and so does one between two of a Linux sandbox's mounts, such as
two separate write `allow` entries; copy and remove instead. Result `{}`.

## Watching

### `watch.start`

```json
{ "watchId": "w-1", "path": "/home/me/repo", "recursive": true, "access": { … } }
```

Starts reporting changes under `path`, which must exist (else `not_found`). `path` may be a
directory or a file. `recursive: false` reports only `path` and its direct children. Under a
sandbox, `path` must be readable by the policy (else `permission_denied`), and changes to paths
the policy cannot read, such as the supervisor's state directory, are never reported. The
control plane chooses `watchId`, with the same rules as `execId`. An ID in use is
`already_exists`. A node holds at most 64 watches, and a 65th is `too_large`. Result `{}`.

Symlinks inside the watched tree are reported as themselves and never followed, so changes
behind them are not reported. Changed paths are reported under `path` as written, even when it
runs through a symlink (on macOS, `/tmp/x` is reported as `/tmp/x/…`, not `/private/tmp/x/…`).

On Linux each watch holds one inotify instance and, when recursive, one inotify watch per
directory. The OS caps both per user (`fs.inotify.max_user_instances`, by default 128, and
`fs.inotify.max_user_watches`). A start that hits a cap replies `io`.

### `watch.stop`

Params `{ "watchId" }`. Result `{}`. Stopping an unknown watch is `not_found`.

### `watch.event` (event)

```json
{ "watchId": "w-1", "changes": [ { "kind": "modified", "path": "/home/me/repo/src/main.rs" } ] }
```

`kind` is `created`, `modified`, `removed` or `renamed`. A rename reports `renamed` for the old
path and `created` for the new one when the OS gives both. macOS does not say which side of a
rename a path was on, so the node reports `created` if the path exists afterwards and `renamed`
if it does not. Changes are batched for up to 100 ms. At most 256 changes go in one event.
Within a batch, a change identical to the previous change of the same path is left out, so a
file written in many pieces reports `modified` once.

When a directory appears under a recursive watch, by creation or by moving in, each entry
already in it is reported `created` too, since the OS reports nothing for entries made before
it watched the directory. A path can therefore be reported `created` twice. A directory with
more than 10 000 entries is reported as `overflow` instead.

```json
{ "watchId": "w-1", "overflow": true }
```

`overflow` means changes were lost (an OS queue overflowed, or the event queue was full). The
control plane should rescan what it cares about.

If the watched path itself is removed, the node sends a final event with that `removed` change,
then stops the watch. Moving it away, or replacing it with a new file or directory, counts as
removing it. The watch's ID is free again after that.

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
| WebSocket frame | 64 KiB of message per frame (`part`), 1 MiB after decompression |
| Reassembled message | 32 MiB |
| Incomplete messages held by a receiver | 64 MiB per session |
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

## Control-plane library

A control plane written in Rust uses this crate's side of the link instead of reimplementing it:

```toml
happy-supervisor = { git = "https://github.com/slopus/happy-supervisor", default-features = false, features = ["control-plane"] }
```

The `control-plane` feature builds only `protocol` (the types), `wire` (the codec), `link`
(`Session`, every link rule), `ws` (the socket and `upgrade`), `server` and `error`, with none of
the node: no processes, sandbox, files, watches, proxies or state directory. The default `node`
feature is the supervisor. Two pieces connect the link to a server:

* `ws::upgrade(&mut request, level)` accepts a node's WebSocket after the control plane has
  checked its `Authorization`. It works with any `http::Request` that hyper upgrades, including
  axum's `Request`. It answers `400` (`ws::Refused`) when the request does not offer
  `happy-supervisor.v1` and `permessage-deflate`, and otherwise returns the `101` response to
  send and an `Upgrading` whose `socket()` resolves once the node has switched protocols.
* `server::ControlPlaneLink::new(resume_window_ms)` is one node's link, as the control plane. Give
  it each socket the node connects with (`attach`, which drops the previous one). It pings, drops
  silent connections, acknowledges, resends and resumes. Use it with:
  * `command(kind, params)` / `call(kind, body)`: a command and its reply. `CallError` tells
    the node's error reply (`Node`) from the link's: `NoSession` (not sent), `Lost` (the session
    was lost before the reply, so it may or may not have run), `Closed`, and `BadReply`.
  * `events()`: `Opened { session, resumed, hello }`, every node event as `Event`, `Lost`, and
    `Disconnected { replaced }`, in order.
  * `send_proxy`, `send_tcp`: the control plane's side of proxy streams and tunnels.
  * `bye(reason, message)`: ends the session; `revoked` makes the node exit.
  * `session()`, `opened(timeout)`, `close()`.

One `ControlPlaneLink` serves one node for as long as the control plane wants it, across
connections and sessions. `Controller` (serve.md) is the same link over a WebSocket it dials.
