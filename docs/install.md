# Installing the supervisor

The installers do all of this. With the join URL and token from the control plane:

```
curl -fsSL https://get.happy.engineering/install.sh | sudo HAPPY_JOIN_URL=<join url> HAPPY_JOIN_TOKEN=<token> sh
$env:HAPPY_JOIN_URL='<join url>'; $env:HAPPY_JOIN_TOKEN='<token>'; irm https://get.happy.engineering/install.ps1 | iex
```

[deploy/README.md](../deploy/README.md) says what they do, without sudo too. The rest of this
page is the same by hand.

## Linux

On Linux the supervisor's work never runs as root (SECURITY.md). The supervisor runs as root and
runs every command, file operation and watch as a separate, unprivileged workload user (policy.md,
Workload user). A supervisor running as root refuses to start without `--workload-user`. One
that is not root runs its work as itself, which is already a separate user.

1. Install the binary and bubblewrap 0.8 or later:

   ```
   sudo install -m 0755 happy-supervisor /usr/local/bin/happy-supervisor
   sudo apt-get install bubblewrap        # or your distribution's package
   ```

2. Create the workload user, with no login shell and a home of its own, which commands get as
   `HOME` (NodeInfo `defaultEnv`):

   ```
   sudo useradd --system --create-home --home-dir /home/happy-workload \
     --shell /usr/sbin/nologin happy-workload
   ```

   Its files, and whatever its groups grant, are what raw work can read and write. Do not add it
   to `sudo`, `docker` or other groups that amount to root.

3. Let the workload user's bubblewrap create user namespaces: bubblewrap runs as that user.
   Most distributions allow unprivileged user namespaces. Ubuntu 24.04 and later restrict them
   through AppArmor: write `/etc/apparmor.d/bwrap` and load it with
   `sudo apparmor_parser -r /etc/apparmor.d/bwrap`.

   ```
   abi <abi/4.0>,
   include <tunables/global>

   profile bwrap /usr/bin/bwrap flags=(unconfined) {
     userns,
   }
   ```

   Older Debian kernels need `sysctl kernel.unprivileged_userns_clone=1`. Check with
   `sudo -u happy-workload bwrap --ro-bind / / --unshare-all true`, and with
   `sudo happy-supervisor info --workload-user happy-workload`, whose `sandbox.available` must
   be `true` (node-info.md).

4. Join. The state directory defaults to `/var/lib/happy-supervisor` for root:

   ```
   sudo happy-supervisor join --url <join url> --token-file - --workload-user happy-workload
   ```

   and paste the join token on stdin. `HAPPY_JOIN_TOKEN` works too, where `sudo` passes it on.
   The token is never an argument, which every user's `ps` shows.

5. Run it as a service, `/etc/systemd/system/happy-supervisor.service`:

   ```
   [Unit]
   Description=happy-supervisor
   Wants=network-online.target
   After=network-online.target

   [Service]
   User=root
   ExecStart=/usr/local/bin/happy-supervisor run --state-dir /var/lib/happy-supervisor \
     --workload-user happy-workload
   Restart=on-failure
   # Exit code 3: the control plane revoked the credential. Join again instead.
   RestartPreventExitStatus=3
   # The service's cgroup is the supervisor's, for exec.start limits.memoryBytes and processes.
   Delegate=yes

   [Install]
   WantedBy=multi-user.target
   ```

   Then `sudo systemctl daemon-reload && sudo systemctl enable --now happy-supervisor`.

   `Delegate=yes` gives the supervisor the service's cgroup (cgroup v2). It moves itself into a
   `supervisor` child and runs each command with `memoryBytes` or `processes` in a child of its
   own, `exec-<pid>-<n>`, with `memory.max` and `pids.max`. Without delegation, or when another
   process shares its cgroup, NodeInfo `limits` reports both `false` and `exec.start` refuses
   them; the log says why at startup. A user service needs the user manager to delegate the
   `memory` and `pids` controllers, as systemd's `user@.service` does by default.

   Do not add `RestrictNamespaces=`, `PrivateUsers=` or `ProtectSystem=`/`ProtectHome=`: the
   sandbox needs user namespaces and mounts of its own, and the commands the control plane runs
   see the filesystem the service sees.

The state directory's private part, credentials included, stays `0700` root, so neither raw nor
sandboxed work can read it (policy.md, Fixed rules).

6. Optionally, let the control plane run chosen commands as root, for `apt-get install` and
   `npm install -g` (policy.md, System access):

   ```
   sudo happy-supervisor system enable --state-dir /var/lib/happy-supervisor
   ```

   It takes effect at once, without a restart, and `system disable` turns it off the same way.
   A system command is root, so it can read the credentials too.

## Containers

The supervisor may be a container's entry point, as `happy-supervisor run` or `serve`. bubblewrap
needs what it needs on a host: user namespaces, and a seccomp profile and AppArmor policy that let
it create them and mount (for example Docker's `--security-opt seccomp=unconfined
--security-opt apparmor=unconfined`).

A process whose parent exits is reparented to PID 1, which must reap it, and every sandboxed
command leaves one: bubblewrap's own init outlives the bubblewrap the supervisor waits for by a
moment. When the supervisor starts as PID 1, it forks and keeps a small init in front of itself
that reaps them, passes `SIGTERM`, `SIGINT`, `SIGHUP`, `SIGQUIT`, `SIGUSR1` and `SIGUSR2` on, and
exits with the supervisor's code (128 plus the signal when a signal ended it). So `docker run
--init` is not needed, and does no harm: the supervisor is then not PID 1 and leaves the reaping
to Docker's init.

When the control plane revokes the node, `run` exits with code 3 (api.md, Connection), and every
later start only gets a `401` and exits 3 again until the machine joins again. The systemd unit
above stops there (`RestartPreventExitStatus=3`), but a container restart policy cannot exempt an
exit code: Docker's `always`, `unless-stopped` and `on-failure`, and Kubernetes' `restartPolicy`,
start a revoked node forever, each start logging a `401`. Restart only failures, and make the
entry point exit 0 for code 3, for example with this script as `entrypoint.sh`:

```sh
#!/bin/sh
# Runs the supervisor. Exits 0 instead of 3 once the control plane revoked the node, so a restart
# policy that restarts only failures leaves it stopped.
happy-supervisor run "$@" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT
wait "$pid"
code=$?
# A trapped signal ends the wait early, with 128 plus the signal; wait again for the real code.
while kill -0 "$pid" 2>/dev/null; do
  wait "$pid"
  code=$?
done
[ "$code" -eq 3 ] && exit 0
exit "$code"
```

```
docker run --init --restart on-failure ... /entrypoint.sh --state-dir /state --workload-user happy-workload
```

The shell is not an init, so `--init` puts Docker's in front of it to reap orphans. A Kubernetes
Pod does the same with `restartPolicy: OnFailure`; a Deployment always restarts its containers,
so scale it to zero for a revoked node.

## macOS

Run the supervisor as the user whose files its commands should see, for example from a
LaunchAgent, or as root with `--workload-user`. Sandboxed commands need `/usr/bin/sandbox-exec`.

A root supervisor can also run system access (policy.md, System access): `sudo happy-supervisor
system enable --state-dir <dir>` makes it run as Homebrew's owner, so `brew install` and
Homebrew's `npm install -g` work, or as root without Homebrew. A LaunchAgent install already runs
raw commands as its user, who can run `brew` if they own Homebrew.

## Windows

Run `happy-supervisor install-sandbox` once, as an administrator, as the account that runs the
supervisor (policy.md, What each platform requires). A workload user is not supported on
Windows.
