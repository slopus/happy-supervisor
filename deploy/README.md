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
| `Dockerfile`, `cloudbuild.yaml` | The Linux release as Cloud Build builds it. |
| `publish.sh` | Signs a built release and publishes it. |
| `../.github/workflows/release.yml` | All five binaries on GitHub's hosted runners, by hand. |

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

Push a change to `VERSION` to `main` and approve the two Cloud Build triggers:

1. `happy-supervisor-release` builds `Dockerfile` with that version (Linux x86_64 and aarch64,
   musl, `HAPPY_SUPERVISOR_VERSION` set so nodes report it) and stages the release in the
   staging bucket under the commit: `gs://<staging>/<commit>/`.
2. `happy-supervisor-publish` waits for that commit's staged `SHA256SUMS`, signs it and publishes
   it with `publish.sh --latest`. It runs none of the repository's code at build time: its steps,
   with a byte copy of `publish.sh`, are held in happy-terraform.

macOS and Windows cannot be built on a Linux builder (their SDKs cannot be fetched there under
their licences), so a Cloud Build release is Linux only, and its `install.ps1` is not published.
For all five, run `gh workflow run release.yml -f version=<version>` and publish its artifact
with `deploy/publish.sh <dir> --latest`, with the environment below.

### The triggers

`happy-supervisor-release`:

* Event: push to branch `^main$` of GitHub repository `slopus/happy-supervisor`, included files
  `deploy/VERSION`. Requires approval.
* Configuration: `deploy/cloudbuild.yaml` from the repository, substitution
  `_STAGING_BUCKET=happy-supervisor-staging-<project number>`.
* Service account: one that may write the staging bucket and nothing else (today
  `happy-cluster-build`).

`happy-supervisor-publish`:

* Event: the same push (`^main$` of `slopus/happy-supervisor`, included files `deploy/VERSION`).
  Requires approval.
* Configuration: inline, in happy-terraform. Service account `happy-supervisor-publish`, the only
  identity that may read secret `happy-supervisor-signing-key`; it reads the staging bucket and
  writes the releases bucket.
* Steps, in an image with `gcloud`, `curl`, `minisign` and `sha256sum`:
  1. Poll for `gs://happy-supervisor-staging-<project number>/$COMMIT_SHA/SHA256SUMS` for up to
     an hour, then copy that prefix to `/workspace/release`.
  2. Run the byte copy of `deploy/publish.sh` as the script, with `PUBLISH_DIR=/workspace/release`,
     `LATEST=1`, `RELEASE_BUCKET=<the bucket behind get.happy.engineering>`,
     `MINISIGN_PUBLIC_KEY=RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr`, and
     `MINISIGN_SECRET_KEY_B64` from `happy-supervisor-signing-key` (`secretEnv`).

Against today's triggers (on `slopus/happy-cluster`) that is a new repository, `deploy/VERSION`
instead of `deploy/supervisor/VERSION`, `deploy/cloudbuild.yaml` instead of the inline build, the
staged files directly under the commit, `deploy/publish.sh` instead of
`deploy/gke/publish-supervisor.sh`, and the new bucket.

## Hosting

Infra sets up, once:

* A Cloud Storage bucket for releases, publicly readable (`allUsers: roles/storage.objectViewer`),
  and the `happy-supervisor-publish` service account allowed to create objects in it.
* The DNS name `get.happy.engineering` and TLS for it, serving that bucket at the root (a load
  balancer with a backend bucket and a managed certificate).
* The staging bucket `happy-supervisor-staging-<project number>`, private.
* The signing key in Secret Manager as `happy-supervisor-signing-key` (the existing key).
* The two Cloud Build triggers above, connected to this repository.

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
