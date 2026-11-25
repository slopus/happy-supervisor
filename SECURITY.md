# Security requirements

These are the project's security requirements. Every change must keep them. Where a platform
cannot meet one, the node says so (NodeInfo `sandbox`) and refuses the operation; it never runs
it with less. The details live in [docs/policy.md](docs/policy.md),
[docs/proxy.md](docs/proxy.md), [docs/tunnels.md](docs/tunnels.md) and [docs/api.md](docs/api.md),
and how to install the node is in [docs/install.md](docs/install.md).

## Trust model

1. The node trusts exactly one control plane. The control plane decides what runs on the
   machine; the node enforces what the control plane asks for and adds nothing of its own.
2. The node only dials out. It opens no inbound port, except `serve --listen`, which is for
   tests and local programs and requires a token.
3. Joining uses a temporary, single-use join token. The node posts it to the full join URL and
   gets back a permanent node credential and the endpoint to connect to. The join URL is
   `https://` and the endpoint is `wss://`; plain HTTP is accepted only for loopback, for tests.
4. The node credential and the node's private keys live in the private part of the state
   directory, readable only by the supervisor's user. They never appear in logs, events, command
   environments, or anything a sandboxed operation can read.
5. The control plane can rotate the credential or move the node to another endpoint. A revoked
   credential stops the node (exit code 3).

## Commands, files and watches

6. Every command, file operation and watch is either **raw**, running with the rights of the
   node's workload user (the supervisor's own when it has none), **sandboxed** by a policy
   that the operating system enforces, as that same user, or **system**, unconfined as the
   account that installs software (`happy-system` on Linux, which cannot read the node's private
   state and installs with apt through the supervisor, by package name only; root only if the
   administrator names it). System access is off until the machine's
   administrator enables it as root, needs a supervisor running as root, and gives the workload
   user no way to it (no sudoers entry, no setuid program).
7. A sandboxed command, `fs.*` call and watch are bound by the same policy. A watch reports only
   paths the policy lets it read.
8. Commands run as a process tree that the node can always kill completely: a process group on
   Unix, a Job Object on Windows. This applies to raw commands too.
9. A supervisor with a workload user never runs raw or sandboxed work as itself. It refuses to
   start if that user is missing or is root, and it refuses an operation it cannot yet run as
   that user. On Linux, a root supervisor requires a workload user, so only system access ever
   runs as root there.

## The policy

10. **Everything is explicit.** The control plane's policy states the default for reads, for
    writes and for network egress, and the exceptions to each. There is no built-in
    allow-by-default and no built-in deny-by-default.
11. The most specific entry wins; when `allow` and `deny` name the same path or host, deny wins.
    Addresses: a CIDR or IP deny entry refuses a resolved address even when an allow entry admits
    the name; names and prefixes are never compared for specificity.
12. Writing implies reading. A policy whose explicit `read.deny` entry decides a path that its
    write rules allow is rejected; a read default of deny is not a contradiction.
13. The only fixed rules are: the supervisor's private state directory is always denied, and the
    sandbox gets its own devices and `/proc`.
14. A deny entry that does not exist yet is still denied. The node may create an empty
    placeholder file or folder to enforce it, as Codex and Anthropic's sandbox-runtime do. It
    records every placeholder and removes it afterwards if it is still empty and still its own.

## Enforcement by platform

15. **Linux:** bubblewrap and seccomp, as in Codex and sandbox-runtime. seccomp blocks at least
    io_uring, ptrace, other processes' memory, bpf, perf events, userfaultfd, keyrings, mounts and
    new namespaces, and Unix sockets when the policy denies them.
16. **macOS:** Seatbelt (`sandbox-exec`) with a profile generated from the policy.
17. **Windows:** a real sandbox, as in Codex's `windows-sandbox-rs`: a dedicated identity, ACLs on
    the policy's paths, and firewall filters for the network.
18. Host requirements are acceptable: bubblewrap and unprivileged user namespaces on Linux, a
    one-time administrator install on Windows. A node without them reports the sandbox as
    unavailable. Isolated networking on Linux also needs the state directory's path short enough
    that its proxy sockets' paths fit in 107 bytes.

## Network

19. The policy chooses per command between **host** networking and **isolated** networking, and
    separately whether the command may bind local ports and whether it may use Unix sockets.
20. In isolated mode the command has no route out except the node's own HTTP and SOCKS5
    proxies, which run outside the sandbox and apply the policy's egress rules (hosts and ports).
    No network at all is an egress policy with `default: deny` and nothing allowed.
21. The proxies resolve names themselves, once, and refuse loopback, private, link-local, CGNAT,
    multicast and the node's own addresses unless an `egress.allow` IP or prefix contains it.
22. Every refusal by policy is reported to the control plane (`net.denied`). A name that does not
    resolve in host mode is a network error, not a refusal.

## Credential proxy

23. Credentials never reach the machine. HTTP requests to the hosts a command lists go through
    the control plane, which injects credentials there. The command carries only an opaque proxy
    token, which the node never logs and never puts in the command's environment.
24. A host that goes through the credential proxy must also be allowed by the command's egress
    rules.

## Link and tunnels

25. Everything between the node and the control plane goes over the one authenticated WebSocket.
    Every message is acknowledged; a session that cannot resume is detected and reported, never
    silently continued.
26. TCP tunnels connect only to the node's loopback, or to the loopback of a sandboxed command
    whose policy allows binding ports. The bytes are not encrypted inside the link, so the link
    itself must be TLS (`wss://`) outside of tests.
