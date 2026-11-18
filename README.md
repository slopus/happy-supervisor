# happy-supervisor

`happy-supervisor` runs on a machine and lets one trusted control plane run commands, read and
write files, and watch for changes there. It dials out to the control plane over a WebSocket, so
the machine opens no inbound port. Commands and file operations run either raw, with the
supervisor's rights, or sandboxed by a policy the operating system enforces (Landlock on Linux,
Seatbelt on macOS). It runs on Linux, macOS and Windows, on x86_64 and aarch64.

```
happy-supervisor join --server https://control.example.com --token <join token> [--name <name>] [--state-dir <dir>]
happy-supervisor run [--state-dir <dir>]
happy-supervisor info [--state-dir <dir>]
```

`join` exchanges a single-use join token for a long-lived node credential. `run` connects and
serves the control plane until the credential is revoked (exit code 3). `info` prints this
machine's NodeInfo as JSON.

The contract:

* [docs/api.md](docs/api.md) covers joining, the connection, and every method and notification.
* [docs/policy.md](docs/policy.md) covers what a sandbox policy grants, and how each platform enforces it.
* [docs/node-info.md](docs/node-info.md) covers the machine description the node reports.
* [docs/architecture.md](docs/architecture.md) covers the modules and the sandbox helper.

The library exports the wire types (`happy_supervisor::protocol`) and, with the `testing`
feature, an in-process control plane for tests (`happy_supervisor::testing`).
