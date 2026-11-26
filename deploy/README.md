# Releases

A release is five supervisor binaries and five happy-supervisor-boot binaries (docs/boot.md),
`SHA256SUMS` over exactly the binaries it has, its minisign signature, and the installers,
served at `https://get.happy.engineering`:

```
https://get.happy.engineering/install.sh             the installer for Linux and macOS
https://get.happy.engineering/install.ps1            the installer for Windows
https://get.happy.engineering/releases/latest        the latest version, one line
https://get.happy.engineering/releases/<version>/    happy-supervisor-{linux-x86_64,linux-aarch64,
                                                     macos-aarch64,macos-x86_64,windows-x86_64.exe},
                                                     happy-supervisor-boot-{the same five},
                                                     SHA256SUMS, SHA256SUMS.minisig
```

Versions are immutable: `publish.sh` never writes over an existing `releases/<version>/`, so every
release needs a new version. The installers check `SHA256SUMS` against the release key (minisign
key ID `349DDAD36F92423A`, public `RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr`,
embedded in both) and the binary against `SHA256SUMS` before they write anything. The secret
half lives only in Secret Manager secret `happy-supervisor-signing-key`.

| File | What it is |
|---|---|
| `VERSION` | The next release's version, one line. A change to it on `main` starts a release. |
| `install.sh`, `install.ps1` | The installers (below). |
| `test_install.py` | `install.sh` in a scratch filesystem: `python3 -m unittest discover -s deploy -p 'test_*.py'`. CI runs it with shellcheck. |
| `publish.sh` | Signs a staged release and publishes it (the publish trigger runs a byte copy). |
| `../.github/workflows/release.yml` | Tests, builds and stages a release, then makes it a GitHub Release. |

## The installers

The control plane hands out the install command with three variables:

| Variable | |
|---|---|
| `HAPPY_JOIN_URL` | The full join endpoint, as `join --url` takes it. |
| `HAPPY_JOIN_TOKEN` | The single-use join token. |
| `HAPPY_NODE_NAME` | Optional: the node's name (`join --name`). Defaults to the hostname. |

```
curl -fsSL https://get.happy.engineering/install.sh | sudo HAPPY_JOIN_URL=… HAPPY_JOIN_TOKEN=… sh
$env:HAPPY_JOIN_URL='…'; $env:HAPPY_JOIN_TOKEN='…'; irm https://get.happy.engineering/install.ps1 | iex
```

* **Linux and macOS with sudo** (a system install): the service runs as root with
  `--workload-user happy-workload`, and the installer creates that user. On Linux it installs
  bubblewrap when it is missing, and the AppArmor profile where AppArmor restricts user
  namespaces (Ubuntu 23.10 and later), or refuses and says why. The service is a systemd unit or
  a LaunchDaemon. NodeInfo reports `root: true, workloadUser: "happy-workload"`.
* **Linux and macOS without sudo** (a user install): a systemd user unit (with lingering) or a
  LaunchAgent, running as the user who installed it, with no workload user. On Linux it refuses
  when bubblewrap is missing, which it cannot install. NodeInfo reports `root: false,
  workloadUser: null`.
* **Windows**, in an elevated PowerShell signed in as the user it runs as: `install-sandbox`, then
  a scheduled task that runs the supervisor as that user at logon, not elevated.

On Linux and macOS the service is happy-supervisor-boot (docs/boot.md). It runs the supervisor
and changes its version when the control plane asks (api.md, `node.upgrade`). `install.sh` checks
boot's binary against the signed `SHA256SUMS`. It installs boot as `happy-supervisor-boot` and runs
`happy-supervisor-boot install` with the version. Boot downloads and verifies the supervisor into
its boot directory:

| | Boot | Boot directory | `happy-supervisor` |
|---|---|---|---|
| System install | `/usr/local/bin/happy-supervisor-boot` | `/usr/local/lib/happy-supervisor` | `/usr/local/bin/happy-supervisor` |
| User install | `~/.local/bin/happy-supervisor-boot` | `~/.local/lib/happy-supervisor` | `~/.local/bin/happy-supervisor` |

`happy-supervisor` is a script that runs `happy-supervisor-boot exec`, so the commands below run
the version the service runs, and boot verifies it first. A release without boot cannot be
installed this way. Windows does not run boot yet.

`install.sh --system` (`sh -s -- --system`, with sudo only) also enables system access
(docs/policy.md, System access): the control plane may run chosen commands as `happy-system` on
Linux, which it creates with an npm prefix it owns, for `npm install -g`, and as Homebrew's owner
on macOS, for `brew install` and `npm install -g`. `apt-get install` needs root on Linux: `sudo
happy-supervisor system enable --user root --state-dir <dir>`, which is root-equivalent. NodeInfo
then reports `identity.system`. `sudo happy-supervisor system enable|disable --state-dir <dir>`
changes it later, with the service's state directory: `/var/lib/happy-supervisor` on Linux,
`"/Library/Application Support/happy-supervisor"` on macOS.

Run again without `HAPPY_JOIN_TOKEN` to upgrade a joined computer in place. That also moves a
computer installed before boot onto it: the service is rewritten to run boot. `install.sh
--uninstall` (or `$env:HAPPY_UNINSTALL='1'`) removes it, with boot and its directory. `HAPPY_SUPERVISOR_VERSION` pins a
release and `HAPPY_INSTALL_BASE` serves releases from elsewhere.

## Releasing

Push a change to `VERSION` to `main`. `.github/workflows/release.yml` then:

1. refuses a version that is already served or released (versions are immutable);
2. runs the whole suite, `ci.yml`, on Linux x86_64 and aarch64, macOS aarch64 and x86_64, and
   Windows;
3. builds each platform's supervisor and boot on its own OS and architecture, with
   `HAPPY_SUPERVISOR_VERSION` set so nodes report it (Linux: static musl through
   `cargo-zigbuild`), and starts them there (`info`, `--version`);
4. writes `SHA256SUMS` over exactly the ten and a build provenance attestation for them;
5. stages the release, the installers, `VERSION` and the attestation (`attestation.sigstore.json`)
   at `gs://happy-supervisor-staging-<project number>/<commit>/<run id>-<attempt>/`,
   `SHA256SUMS` last;
6. once the publish trigger serves the signed `SHA256SUMS`, checks it is this run's list under the
   release key and creates GitHub Release `v<version>` with the same files.

The publish trigger signs and publishes it with no approval. A project owner later moves `latest`
with the promote trigger: publishing a version never changes what a new install gets.

### Google Cloud

Held in happy-terraform:

* Workload Identity pool `github`, provider `happy-supervisor`: GitHub's OIDC tokens for this
  repository (`repository_id` and `repository_owner_id`), push events to `refs/heads/main`, from
  `.github/workflows/release.yml` on `main` only.
* Service account `happy-supervisor-github`, impersonable only through that provider, allowed to
  create objects in the staging bucket and nothing else (no read, no replace).
* Trigger `happy-supervisor-publish`, no approval, run by `happy-supervisor-publish`, the
  only identity that may read secret `happy-supervisor-signing-key`. A Pub/Sub notification of the
  staging bucket starts it when a `<commit>/<run id>-<attempt>/SHA256SUMS` arrives. Its steps are
  inline and run none of the repository's code: copy that prefix; check that the ten binaries
  (five supervisors, five boots) match `SHA256SUMS` and that the attestation names each of
  them, this repository's `release.yml` on `refs/heads/main` and that commit; then run the byte copy of `publish.sh`
  without `--latest`, with `RELEASE_BUCKET=<the bucket behind get.happy.engineering>`,
  `MINISIGN_PUBLIC_KEY=RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr` and
  `MINISIGN_SECRET_KEY_B64` from the secret.
* Trigger `happy-supervisor-promote`, started by publishing the version to its topic (project
  owners only), no approval: checks the served release against the release key, then copies its
  installers from `releases/<version>/` to the root and points `releases/latest` at it.

## Hosting

* The releases bucket, publicly readable, served at `https://get.happy.engineering` (and
  `https://get.happy-clusters.com`); only `happy-supervisor-publish` writes it.
* The staging bucket `happy-supervisor-staging-<project number>`, private, objects deleted after
  30 days.
* The signing key in Secret Manager as `happy-supervisor-signing-key`.

## Release notes

One version names one build. Bump `VERSION` in the commit that releases, and give it a bullet
here in that commit; `test_install.py` fails without one. Changes after a release go under an
**Unreleased** bullet until the next bump. Never reuse a version: `publish.sh` refuses one that
exists. Commits between releases do not bump `VERSION`, since a bump on `main` is what starts a
release; a binary built from them reports `VERSION` only if built as a release, which only the
triggers and `release.yml` do.

* **0.2.0-linux.1.** The first release from this repository. On Windows the sandbox's install
  record is now version 2 (accounts pooled per network profile): run `install.ps1` again, or
  `happy-supervisor install-sandbox` as an administrator, on every Windows node; it deletes the
  version 1 accounts first. A Linux supervisor running as root refuses to start without
  `--workload-user`.
* **0.2.0-linux.2.** Linux enforces `limits.memoryBytes` and `limits.processes` when the
  service's cgroup is delegated to the supervisor, and the installer's unit now says
  `Delegate=yes`. On an existing Linux node, run `install.sh` again, or add `Delegate=yes` to the
  unit's `[Service]` and restart it. A command killed for `memoryBytes` exits with
  `{ "kind": "memoryLimit" }`. `join` no longer takes `--token`: it reads `HAPPY_JOIN_TOKEN` or
  `--token-file` (`-` for stdin), so the token never shows in `ps`.
* **0.2.0-linux.3.** The first published release: the code of 0.2.0-linux.2 (never published),
  now built, tested and released by `release.yml` for all five platforms, so it is the first
  with macOS and Windows binaries and `install.ps1`. It is also a GitHub Release.
* **0.2.0-linux.4.** The first published release, the code of 0.2.0-linux.2 for all five
  platforms (0.2.0-linux.3 never built: release.yml checked the version by grepping the binary).
* **0.2.0-linux.5.** The same code; 0.2.0-linux.4 never built either (its commit lacked the
  check fix it described).
* **0.2.1.** The code of 0.2.0-linux.5, for all five platforms (Linux x86_64 and aarch64, macOS
  aarch64 and x86_64, Windows x86_64), under a version without a platform suffix. Versions from
  here on name one build for every platform.
* **0.2.2.** On the Linux release builds (static musl), isolated commands work again: the proxy
  sockets are opened with `O_PATH`, which musl dropped, so every isolated exec failed with
  "cannot open …/http.sock: No such device or address".
* **0.2.3.** The code of 0.2.2; the release pipeline now publishes without an approval.
* **0.2.4.** A refused bind in a sandboxed command is reported as the event `net.bindDenied`
  (a control plane that does not know it replies `unknown_kind`, which the node ignores). As
  PID 1 (in a container), `run` and `serve` keep an init in front of them that reaps orphans. The
  proxy's 403 says the sandbox blocked the host and that the command needs more access.
* **0.2.6.** A policy may set `filesystem.writeTemp` to let a command write the work user's own
  temp directory, which NodeInfo reports as `identity.tempDir` (macOS: `DARWIN_USER_TEMP_DIR`).
  On macOS, file operations run under isolated policies.
* **0.2.7.** System access: `{ "mode": "system" }` runs a command, file operation or watch
  as the account that installs software (root on Linux, Homebrew's owner on macOS), once an
  administrator runs `sudo happy-supervisor system enable` or installs with `install.sh
  --system`. NodeInfo reports it as `identity.system`.
  On Linux, system access runs as `happy-system`, which `system enable` creates with the npm
  prefix `/opt/happy-system/npm` and which cannot read the node's credentials; root only with
  `--user root`. `system disable` kills its processes, and `install.sh --uninstall` removes it.
  Its `apt-get install <names>` and bare `apt-get update` ask the supervisor, which runs them as
  root, with package names only, for that command's processes while it runs.
* **0.2.8.** `fs.read` takes `beneath`, a directory the path must resolve under through no
  symlink, reading only a regular file, and reports `file`, which a later range passes back to
  fail if the path now opens another or a changed file. Both travel as text, so older control
  planes and nodes ignore them.
