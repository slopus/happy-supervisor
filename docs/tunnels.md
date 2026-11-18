# happy-supervisor TCP tunnels

The control plane can open raw TCP connections to ports listening on the node's **loopback
interface** and carry them over the link. A command can start a dev server on
`127.0.0.1:3000`, and the control plane can reach it with no inbound port, firewall rule or
SSH. Many connections share the one WebSocket. Each is a **stream** with its own flow control, so
one slow connection never stalls the others or the rest of the protocol.

Tunnels use the same stream rules as the credential proxy (proxy.md): UUIDv7 stream IDs, 1 MiB
windows per direction, `credit`, `reset`, and ordered, confirmed, never-dropped messages
(api.md, Link protocol). One stream table in the node holds both kinds, and the per-node stream
limit counts both.

## Opening

`tcp.open` is a **command** from the control plane:

```json
{ "streamId": "0193…", "host": "127.0.0.1", "port": 3000 }
```

* `streamId` is a UUIDv7 the control plane chooses. It names the stream from then on. An ID in use
  replies `already_exists`.
* `host` is `127.0.0.1`, `::1` or `localhost`. Anything else is `invalid_params`. Only loopback is
  reachable. A tunnel is not a general network exit from the node. `localhost` tries `::1`,
  then `127.0.0.1`.
* `port` is 1 to 65535.

The node connects, and replies `{}` once the TCP connection is established, with a 10 s connect
timeout. A refused connection replies `connection_refused`, and a timeout replies `timed_out`.
These are two new error kinds (api.md, Errors). Either way, no stream exists afterwards.

Data may follow only after the reply `{}`. The control plane can also send `tcp.data` immediately
after `tcp.open`, without waiting. The node buffers it within the stream's window, and discards it
if the connect fails.

## Bytes

Both directions, all events (no reply):

* `tcp.data { streamId, data }`. Up to 64 KiB of bytes, in order.
* `tcp.end { streamId }`. The sender has nothing more to send, a TCP half-close (`FIN`). The node
  shuts down the write side of the local socket when it receives one, and sends one when the
  local socket reads EOF. A stream closes when both sides have ended and all data is delivered.
* `tcp.reset { streamId, reason }`. Abandon the stream in both directions. The node closes the
  local socket with an RST (linger 0) when it receives one, and sends one when the local socket
  fails.
* `tcp.credit { streamId, bytes }`. The receiver has written `bytes` more to its side (the local
  socket, or the control plane's client), so the sender's window grows by that much.

A sender may have at most 1 MiB of uncredited `tcp.data` per direction. The node stops reading
the local socket when its window is empty, so TCP backpressure reaches the local server.

## Limits and failure

* At most 1024 open streams per node, proxy streams included. Past that `tcp.open` replies
  `too_large`.
* When the session is lost (api.md, Lost sessions), every tunnel is reset and its local socket
  closed. Unlike processes, connections do not survive a lost session. A **resumed** session
  keeps them, since no message was lost.
* A tunnel lives independently of processes. When the process that owns the listening port
  exits, the local server closes the connection, and the node sends `tcp.end` or `tcp.reset` as
  the socket reports.
* Raw access only. Tunnels are part of the control plane's trusted surface, like raw commands,
  and carry no policy.

## What this is not

* Not reverse forwarding. The node does not listen for local clients to reach the control plane.
  The credential proxy covers HTTP in that direction.
* Not UDP.
