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
   sudo happy-supervisor join --url <join url> --token <join token> \
     --workload-user happy-workload
   ```

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

   [Install]
   WantedBy=multi-user.target
   ```

   Then `sudo systemctl daemon-reload && sudo systemctl enable --now happy-supervisor`.

   Do not add `RestrictNamespaces=`, `PrivateUsers=` or `ProtectSystem=`/`ProtectHome=`: the
   sandbox needs user namespaces and mounts of its own, and the commands the control plane runs
   see the filesystem the service sees.

The state directory's private part, credentials included, stays `0700` root, so neither raw nor
sandboxed work can read it (policy.md, Fixed rules).

## macOS

Run the supervisor as the user whose files its commands should see, for example from a
LaunchAgent, or as root with `--workload-user`. Sandboxed commands need `/usr/bin/sandbox-exec`.

## Windows

Run `happy-supervisor install-sandbox` once, as an administrator, as the account that runs the
supervisor (policy.md, What each platform requires). A workload user is not supported on
Windows.
