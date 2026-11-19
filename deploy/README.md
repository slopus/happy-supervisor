# Releases

A release is five binaries, `SHA256SUMS` over exactly the binaries it has, its minisign
signature, and the installers, served at `https://get.happy.engineering`:

```
https://get.happy.engineering/install.sh             the installer for Linux and macOS
https://get.happy.engineering/install.ps1            the installer for Windows
https://get.happy.engineering/releases/latest        the latest version, one line
https://get.happy.engineering/releases/<version>/    happy-supervisor-{linux-x86_64,linux-aarch64,
                                                     macos-aarch64,macos-x86_64,windows-x86_64.exe},
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

Run again without `HAPPY_JOIN_TOKEN` to upgrade a joined computer in place; `install.sh
--uninstall` (or `$env:HAPPY_UNINSTALL='1'`) removes it. `HAPPY_SUPERVISOR_VERSION` pins a
release and `HAPPY_INSTALL_BASE` serves releases from elsewhere.

## Releasing

Push a change to `VERSION` to `main`. `.github/workflows/release.yml` then:

1. refuses a version that is already served or released (versions are immutable);
2. runs the whole suite, `ci.yml`, on Linux x86_64 and aarch64, macOS aarch64 and x86_64, and
   Windows;
3. builds each binary on its own OS and architecture, with `HAPPY_SUPERVISOR_VERSION` set so
   nodes report it (Linux: static musl through `cargo-zigbuild`), and starts it there (`info`);
4. writes `SHA256SUMS` over exactly the five and a build provenance attestation for them;
5. stages the release, the installers, `VERSION` and the attestation (`attestation.sigstore.json`)
   at `gs://happy-supervisor-staging-<project number>/<commit>/<run id>-<attempt>/`,
   `SHA256SUMS` last;
6. once the publish trigger serves the signed `SHA256SUMS`, checks it is this run's list under the
   release key and creates GitHub Release `v<version>` with the same files.

A person approves the publish in Cloud Build, and later moves `latest` with the promote trigger:
publishing a version never changes what a new install gets.

### Google Cloud

Held in happy-terraform:

* Workload Identity pool `github`, provider `happy-supervisor`: GitHub's OIDC tokens for this
  repository (`repository_id` and `repository_owner_id`), push events to `refs/heads/main`, from
  `.github/workflows/release.yml` on `main` only.
* Service account `happy-supervisor-github`, impersonable only through that provider, allowed to
  create objects in the staging bucket and nothing else (no read, no replace).
* Trigger `happy-supervisor-publish`, approval required, run by `happy-supervisor-publish`, the
  only identity that may read secret `happy-supervisor-signing-key`. A Pub/Sub notification of the
  staging bucket starts it when a `<commit>/<run id>-<attempt>/SHA256SUMS` arrives. Its steps are
  inline and run none of the repository's code: copy that prefix; check that the five binaries
  match `SHA256SUMS` and that the attestation names each of them, this repository's
  `release.yml` on `refs/heads/main` and that commit; then run the byte copy of `publish.sh`
  without `--latest`, with `RELEASE_BUCKET=<the bucket behind get.happy.engineering>`,
  `MINISIGN_PUBLIC_KEY=RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr` and
  `MINISIGN_SECRET_KEY_B64` from the secret.
* Trigger `happy-supervisor-promote`, run by hand with the version, approval required: checks the
  served release against the release key, then copies its installers from
  `releases/<version>/` to the root and points `releases/latest` at it.

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
