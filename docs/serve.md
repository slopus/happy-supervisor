# happy-supervisor local listener (`serve`)

Besides dialing out to a control plane (`run`), the supervisor can **listen** for one directly:

```
happy-supervisor serve --listen 127.0.0.1:7777 --token-file /path/token [--state-dir DIR]
happy-supervisor serve --listen unix:/run/happy/supervisor.sock --token-file /path/token
```

This exists for integration tests and for local embedding: a test, or a program on the same machine,
connects and drives the node with the full protocol without any server.

* The node accepts WebSocket upgrades on `GET /` at the given address. The protocol on the connection
  is exactly api.md's link protocol (subprotocol `happy-supervisor.v1`, permessage-deflate required,
  `hello` from the node first, sessions, cursors, resume, lanes), with the connecting client in the
  control plane's role.
* Authentication: `Authorization: Bearer <token>`, compared in constant time with the contents of
  `--token-file` (trailing newline trimmed). A missing or wrong token gets `401` before the upgrade.
  `--token-file -` reads the token from stdin once.
* `--listen` accepts `IP:PORT` (port `0` picks one; the chosen address is printed on stdout as one
  line `listening <addr>`) or `unix:PATH` (the socket file is created `0600`). A non-loopback IP is
  allowed but the node logs a warning: the listener speaks plain `ws://`, so put TLS in front.
* One client session at a time. A second connection that presents a session ID resumes it (taking
  over from the first, which is closed); one that presents `session: null` starts a new session and
  the old one is lost, exactly as when a control plane forgets a session.
  The replaced connection is closed with WebSocket close code `4001` ("replaced by a newer
  connection"). A client that gets it must not redial, or the two would take the node from each
  other; `Controller` stops, and its calls fail.
* A request for anything but `GET /` is `404`. A request that does not offer the subprotocol or
  permessage-deflate is `400`.
* No join is needed and no credentials file is read. The installation ID still comes from the state
  directory. `serve` and `run` cannot share a state directory at the same time (it is locked).

## The Rust client

The library exports `happy_supervisor::Controller`, the control-plane side of the protocol, usable by
tests and Rust programs against either a `serve` node or (in tests) an in-process one:

```rust
let ctl = Controller::connect("ws://127.0.0.1:7777", token).await?;
let info: NodeInfo = ctl.command("node.info", ()).await?;
let mut events = ctl.events();          // exec.output, exec.exit, watch.event, ...
```

It is the same `link::Session` the node and `testing::ControlPlane` use, in the control-plane role,
over a real WebSocket, with reconnect and resume.
