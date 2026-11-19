# happy-supervisor

`happy-supervisor` runs on a machine and lets one trusted control plane run commands, read and
write files, and watch for changes there. It dials out to the control plane over a WebSocket, so
the machine opens no inbound port. Both sides queue their messages until the other confirms
them, so a dropped connection resumes without losing or repeating anything, and a session that
cannot resume is detected rather than silently lost. Commands and file operations run either raw, with the
supervisor's rights, or sandboxed by a policy the operating system enforces (bubblewrap and
seccomp on Linux, Seatbelt on macOS, a restricted token on Windows). It runs on Linux, macOS and
Windows, on x86_64 and aarch64.

```
happy-supervisor join --url https://control.example.com/api/nodes/join --token <join token> [--name <name>] [--state-dir <dir>]
happy-supervisor run [--state-dir <dir>]
happy-supervisor serve --listen 127.0.0.1:7777 --token-file <file> [--state-dir <dir>]
happy-supervisor info [--state-dir <dir>]
```

`join` exchanges a single-use join token at the join endpoint for a long-lived node credential
and the endpoint to connect to. `run` connects and serves the control plane until the
credential is revoked (exit code 3). `serve` listens instead of dialing, for tests and local
programs that drive the node with `happy_supervisor::Controller`. `info` prints this
machine's NodeInfo as JSON.

The contract:

* [docs/api.md](docs/api.md) covers joining, the link protocol, and every command and event.
* [docs/policy.md](docs/policy.md) covers what a sandbox policy grants, and how each platform enforces it.
* [docs/node-info.md](docs/node-info.md) covers the machine description the node reports.
* [docs/serve.md](docs/serve.md) covers the local listener and the Rust `Controller`.
* [docs/architecture.md](docs/architecture.md) covers the modules, the sandbox helper and the link session.

The library exports the wire types (`happy_supervisor::protocol`), the sans-IO link session
both sides can drive (`happy_supervisor::link`), the control-plane client for a `serve` node
(`happy_supervisor::Controller`), and, with the `testing` feature, an in-process
control plane for tests (`happy_supervisor::testing`).
