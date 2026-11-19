---
name: release
description: Release a new happy-supervisor version for all five platforms, from the VERSION bump through CI, the automatic publish, the promote, and verification. Use when asked to release, publish, deploy, ship or promote the supervisor, or to "build a new supervisor version".
---

# Releasing happy-supervisor

`deploy/README.md` (Releasing, Google Cloud, Hosting) is the reference. This is the checklist.

## This repository is public

Everything you commit, every issue, every release note and every workflow log is published.

- Never put a secret, token, key, password, join token, signed URL, or email address in a commit,
  a release note, a log line or a workflow. The signing key exists only in Secret Manager and
  only the publish trigger reads it. No job here may hold it, and no JSON service-account key may
  be added to Actions.
- Never paste command output from the operator's side (build logs, tokens)
  into the repository.
- Do not add workflows or automatic triggers, and do not loosen `release.yml`'s permissions or the
  identity it signs in with, without the owner's explicit instruction. Actions that run with a
  token stay pinned by commit.
- Push to `main` fast-forward only. Never force.

## Steps

1. **Pick the version.** Use a plain version that has never been used, such as `0.2.2`, with no
   platform suffix: every release has all five platforms. Versions are immutable. Check that it
   is free:

   ```
   curl -s -o /dev/null -w '%{http_code}\n' https://get.happy.engineering/releases/<v>/SHA256SUMS   # 404
   gh release view v<v> --repo slopus/happy-supervisor                                          # fails
   ```

2. **Make one commit** that changes `deploy/VERSION` and adds the release-notes bullet
   `* **<v>.** …` at the end of `deploy/README.md`. `test_install.py` fails without the bullet.
   Push it to `main`. A change to `deploy/VERSION` on `main` is the only thing that starts a
   release.

3. **Watch `release.yml`** (`gh run list --workflow release.yml`, then `gh run view <id>`). It
   refuses a used version, runs the whole suite (`ci.yml`) on Linux x86_64 and aarch64, macOS
   aarch64 and x86_64, and Windows, builds each binary on its own platform, checks that it
   reports the version and architecture (`info`), attests it, and stages the release. It takes
   about 15 minutes; macOS x86_64 is the slowest.
   - Two known flakes. Rerun only the failed jobs, once (`gh run rerun <id> --failed`):
     - Windows `install-sandbox`: "The password does not meet the password policy requirements".
     - `tests/workload.rs`: "Text file busy".
   - Any other failure is real. Stop and report it; do not rerun blindly. Nothing is published
     until the publish step below, so a failed version can be fixed and released again, or skipped
     with a new bump.

4. **Publish runs by itself.** When `SHA256SUMS` is staged, Cloud Build trigger
   `happy-supervisor-publish` starts with no approval. It runs none of this repository's code. It
   checks the five binaries against `SHA256SUMS` and their attestations (this repository's
   `release.yml` on `refs/heads/main`, at that commit), then signs and publishes `releases/<v>/`
   without moving `latest`. It takes a minute or two. The workflow's `github-release` job then sees
   the signed list served and creates GitHub Release `v<v>` with the same files. If publish fails,
   its Cloud Build log says why; nothing is published.

5. **Promote: an operator moves `latest`.** Publishing never changes what a new install gets.
   Someone allowed to publish to topic `happy-supervisor-promote` (the project's owners) runs
   `gcloud pubsub topics publish happy-supervisor-promote --attribute=version=<v> --project <project>`.
   The `happy-supervisor-promote` build starts with no approval, verifies the served release,
   copies that release's own `install.sh` and `install.ps1` to the root, and points
   `releases/latest` at it.

6. **Verify** on GitHub and every host that serves releases:
   - all five binaries, `SHA256SUMS`, `SHA256SUMS.minisig`, `install.sh` and `install.ps1` are
     byte-identical everywhere;
   - `minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr`
     passes, and `sha256sum -c SHA256SUMS` passes for all five;
   - `releases/latest` is `<v>`, and the root installers equal `releases/<v>/install.*`;
   - a binary for this machine runs: `happy-supervisor info --state-dir <scratch>` reports
     `supervisorVersion` `<v>`.

   Check `releases/latest` and the GitHub Release first; they answer in seconds. Downloading
   every binary from every host takes minutes, so say that you are doing it.

7. **Tell the control plane's maintainers.** The control plane pins this crate by commit, and its
   tests fetch the release of the pinned commit, so the pin moves to the released commit.

## Timing

The tests and builds take about 15 minutes; publish and promote take a minute or two each. Report
where the release stands while you wait instead of polling silently.
