# happy-supervisor-boot

`happy-supervisor-boot` is the service's entry point on an installed node. It starts the
supervisor, restarts it when it fails, and changes its version when the control plane asks.
Boot is installed once and never updates itself: only an installer replaces it. Everything that
may need fixing later lives in the supervisor, which boot replaces.

Boot does five things:

* it downloads a supervisor build from where releases are served (deploy/README.md, Hosting);
* it checks that build against the release key compiled into it, before storing it;
* it checks the build again before every start, so a changed file on disk never runs;
* it starts the build and restarts it when it exits;
* it reports what it is doing to the supervisor, which reports it to the control plane.

It is its own package, `boot/`, with no part of the supervisor in it and few dependencies: ring
(Ed25519, SHA-256), blake2 (minisign's prehash), ureq over rustls with the platform's verifier
(HTTPS), and serde_json.

## What boot runs

A build may run only when all of these hold:

* the release's `SHA256SUMS` is signed by one of the release keys compiled into boot
  (`release::RELEASE_KEYS`; minisign, Ed25519);
* the signature's trusted comment is exactly `happy-supervisor <version>`, for the version asked
  for. The comment is signed too, so one release's list cannot be served as another's;
* the binary's SHA-256 is the one that list gives for this platform's file,
  `happy-supervisor-<os>-<arch>` (`.exe` on Windows).

These are the same checks the installers make (deploy/README.md, Releasing). Boot makes them
on the downloaded files before anything reaches `versions/`. It makes them again, from the stored
list, signature and binary, right before each start, crash restarts included. A stored copy
that fails is downloaded again. If the download fails too, that version is not started.

A version is a release version as the pipeline accepts it: `[0-9A-Za-z.+-]`, at most 64 bytes,
starting with a letter or digit.

## Files

```
<dir>/state.json                     {"current":"0.2.9","previous":"0.2.8"}
<dir>/versions/<version>/happy-supervisor        (happy-supervisor.exe on Windows)
<dir>/versions/<version>/SHA256SUMS
<dir>/versions/<version>/SHA256SUMS.minisig
```

`<dir>` is the boot directory the installer passes as `--dir`. A build is downloaded into
`versions/.<version>.<pid>/` and verified there. Only then is that directory renamed to
`versions/<version>/`. `state.json` is replaced the same way, through a file beside it and a
rename. Boot keeps the current and previous versions and removes the others once a new version
connects. On Unix the directories and binaries are `0755` and the lists `0644`, whatever the
umask, because a workload user runs the supervisor's binary as itself (policy.md, Workload user).

## Commands

```
happy-supervisor-boot install --dir <dir> [--base <url>] [--version <version>]
happy-supervisor-boot run --dir <dir> [--base <url>] -- <supervisor arguments>...
happy-supervisor-boot exec --dir <dir> -- <supervisor arguments>...
```

* `install` downloads and verifies a version, by default the one `releases/latest` names. It
  makes that version current, keeps the one before it as previous, and prints the binary's path.
  The installers use it, then run that binary's `join`.
* `run` starts the current version with the arguments after `--`, such as `run --state-dir <dir>
  --workload-user happy-workload`. It runs until the supervisor exits with code `3`, which means
  the control plane revoked the node (api.md, Connection), and then exits `3` too. If there is
  no current version, it installs the latest first.

* `exec` verifies the current version, as before a start, and runs it with the arguments after
  `--`, in place of boot on Unix. The installers make `happy-supervisor` a script that runs it,
  so `sudo happy-supervisor system enable …` runs the version boot runs.

`--base` defaults to `https://get.happy.engineering`. It must be `https://`. Plain `http://` is
allowed only on a loopback host, for tests. Releases are fetched from `<base>/releases/<version>/`.

## Running

Boot runs one supervisor at a time, with `HAPPY_SUPERVISOR_BOOT` set to boot's own process ID
and stdin and stdout piped to boot. Its stderr is boot's.

* **The supervisor exits on its own.** Boot verifies the build again and restarts it, after 1 s
  at first and doubling to 30 s. A run of 60 s, or a connection, resets the wait. `restarts`
  counts these restarts, and `lastExit` says how the last one ended. Exit code `3` is passed on
  instead.
* **A new version is asked for** (`upgrade`). Boot downloads and verifies it while the running
  supervisor keeps working. A download or verification that fails changes nothing: the state
  becomes `failed` with the reason. If the build verifies, boot stops the running supervisor and
  starts the new version.
* **The new version connects** (`connected`) within 120 s. It becomes current, the one before
  becomes previous, and older builds are removed.
* **The new version exits first, or does not connect in time.** Boot stops it and starts the
  version before it. The state becomes `failed`, with a reason such as
  `0.3.0 exited with code 1 before it connected` or `0.3.0 did not connect within 120 s`.
  `state.json` never named the new version, so a restart of boot also runs the old one.

Asking for the running version clears a failure. Asking for the previous version is how to go
back: it is kept, so it is not downloaded again. A request made while a download is running
waits for that download to finish, then runs. A version asked for while another is starting
replaces it, and the version to go back to stays the one that last connected.

Stopping a supervisor closes its stdin after every status line already sent. A supervisor that
speaks the channel takes the end of stdin as its signal to stop (`bye` with `shutdown`), on
every platform. After 5 s, boot sends `SIGTERM` on Unix, for a supervisor that does not read the
channel. After 5 s more, boot kills it.

An upgrade restarts the supervisor. The supervisor kills its commands when it exits (architecture.md,
Process lifetime), so the control plane should ask for an upgrade only when the node is idle. The
new supervisor starts a new session (api.md, Lost sessions).

## The channel

One JSON object per line in each direction. The supervisor ignores lines it does not
understand, and boot passes any other line from the supervisor's stdout on to its own stdout.

Boot to the supervisor, on its stdin: the status, once when the supervisor starts and again on
every change.

```json
{"status":{"bootVersion":"0.1.0","running":"0.2.9","previous":"0.2.8","target":"0.3.0","state":"failed","error":"0.3.0 did not connect within 120 s","restarts":1,"lastExit":"exited with code 1"}}
```

| Field | |
|---|---|
| `bootVersion` | This boot's version. It never changes on a node. |
| `running` | The version running, or starting when `state` is `starting`. |
| `previous` | The version kept to go back to, or `null`. |
| `target` | The version last asked for, until it runs. `null` when nothing was asked for. |
| `state` | `idle`, `downloading`, `verifying`, `starting` or `failed`. |
| `error` | With `failed`, why the last change failed. |
| `restarts` | How many times `running` was restarted after exiting on its own. |
| `lastExit` | How it last exited: `exited with code 1`, or `killed by signal 9`. Omitted before the first restart. |

`downloading`, `verifying` and the first `starting` reach the supervisor that is being
replaced. The new one gets `starting` at its start, then `idle` once it has connected. A version
that failed and was replaced gets `failed` at its start.

The supervisor to boot, on its stdout:

```json
{"upgrade":{"version":"0.3.0"}}
{"connected":{}}
```

`upgrade` asks for a version. `connected` says that the supervisor's first session has opened,
which is what makes a new version healthy.

## The supervisor's side

The supervisor speaks the channel only in `run` with `HAPPY_SUPERVISOR_BOOT` set (`src/boot.rs`):

* It sends `connected` once, when its first session opens.
* It sends `upgrade` for `node.upgrade` (api.md).
* It reports each status after the first as the event `node.boot`, and the latest one as
  NodeInfo `boot`.
* When stdin ends, it stops as it does on `SIGTERM`.

Without the variable, it reads nothing from stdin and replies `permission_denied` to
`node.upgrade`.

On Linux, boot and the supervisor share the service's delegated cgroup (install.md,
`Delegate=yes`). If boot's process ID is the supervisor's parent, the supervisor moves boot into
a `boot` leaf and itself into the `supervisor` leaf (process/cgroups.rs). A supervisor that boot
starts later begins in `boot`, so it takes the cgroup above that leaf as the delegated one. That
leaf holds only boot and the supervisor. So `limits` work under boot as they do without it. All
of this is in the supervisor, so it can still change.

Supervisor versions before the channel never send `connected`. Boot can run one that is already
installed, but an upgrade to one rolls back after 120 s.

## Release keys

`release::RELEASE_KEYS` (`boot/src/release.rs`) is a fixed list of minisign public keys. A build
verifies when any one of them signed its `SHA256SUMS`. The first is the release key that the
publish trigger signs with (minisign key ID `349DDAD36F92423A`; deploy/README.md, Google Cloud).

Boot never updates itself, so the list it was built with is the list a node trusts until an
installer replaces boot. A second, backup key lets the release key be replaced (lost, leaked,
rotated) without that: sign releases with the backup key instead, and every boot already trusts
them.

The backup key is made offline, by the key's owner, on a machine that never holds the release
key, and its secret key never goes online:

```
minisign -G -p happy-supervisor-backup.pub -s happy-supervisor-backup.key
```

minisign asks for a password for the secret key. Keep `happy-supervisor-backup.key` and its
password offline. The public key is the second line of `happy-supervisor-backup.pub` (it starts
with `RW`). Add it as the second entry of `RELEASE_KEYS`, and it takes effect for every boot
built from then on:

```rust
pub const RELEASE_KEYS: &[&str] = &[
    "RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr",
    "RW…the backup public key…",
];
```

Boots built before that trust the release key alone.
