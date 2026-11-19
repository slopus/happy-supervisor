//! The Seatbelt backend on a real Mac: the built binary as the helper, under `sandbox-exec`.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use happy_supervisor::ErrorKind;
use happy_supervisor::helper::{self, Job, JobOp};
use happy_supervisor::policy::{Default, HostRules, Network, Policy, ResolvedPolicy, RuleSet};
use happy_supervisor::protocol::{AbsPath, Argv, Mechanism, SandboxStatus};
use happy_supervisor::sandbox::{self, Endpoint, NetPlan, Plan};

const EXE: &str = env!("CARGO_BIN_EXE_happy-supervisor");

const TCP_LISTEN: &str = r#"use IO::Socket::IP; IO::Socket::IP->new(Listen => 1, LocalHost => $ARGV[0], LocalPort => 0, Proto => "tcp") or die "$!\n"; print "bound\n""#;
const UDP_BIND: &str = r#"use IO::Socket::IP; IO::Socket::IP->new(LocalHost => $ARGV[0], LocalPort => 0, Proto => "udp") or die "$!\n"; print "bound\n""#;
const UDP_SEND: &str = r#"use IO::Socket::IP; my $s = IO::Socket::IP->new(PeerHost => $ARGV[0], PeerPort => 53, Proto => "udp") or die "$!\n"; $s->send("x") or die "$!\n"; print "sent\n""#;
const UNIX_BIND: &str = r#"use IO::Socket::UNIX; IO::Socket::UNIX->new(Local => $ARGV[0], Listen => 1) or die "$!\n"; print "bound\n""#;
const TCP_CONNECT: &str = r#"use IO::Socket::IP; my $s = IO::Socket::IP->new(PeerHost => "127.0.0.1", PeerPort => $ARGV[0]) or die "$!\n"; print "connected\n""#;
const TCP_ACCEPT: &str = r#"use IO::Socket::IP; my $l = IO::Socket::IP->new(Listen => 1, LocalHost => "127.0.0.1", LocalPort => 0) or die "$!\n"; my $c = IO::Socket::IP->new(PeerHost => "127.0.0.1", PeerPort => $l->sockport) or die "$!\n"; $l->accept or die "$!\n"; print "accepted\n""#;
const UNIX_ACCEPT: &str = r#"use IO::Socket::UNIX; my $l = IO::Socket::UNIX->new(Local => $ARGV[0], Listen => 1) or die "$!\n"; my $c = IO::Socket::UNIX->new(Peer => $ARGV[0]) or die "$!\n"; $l->accept or die "$!\n"; print "accepted\n""#;
const UNIX_CONNECT: &str = r#"use IO::Socket::UNIX; IO::Socket::UNIX->new(Peer => $ARGV[0]) or die "$!\n"; print "connected\n""#;
const RESOLVE: &str = r#"use Socket; my ($err, @addrs) = Socket::getaddrinfo($ARGV[0], "443"); print $err ? "unresolved\n" : "resolved\n""#;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Exit 0, with this stdout.
    Ok(String),
    /// A non-zero exit that reported `Operation not permitted` (EPERM, Seatbelt's answer).
    Denied,
    Failed {
        code: Option<i32>,
        stderr: String,
    },
}

use Outcome::Denied;

fn ok(stdout: &str) -> Outcome {
    Outcome::Ok(stdout.to_string())
}

/// A policy row: deny-by-default reads with the machine's baseline allowed, deny-by-default
/// writes, host networking without binding or Unix sockets. Each row states what it changes.
#[derive(Clone)]
struct P(Policy);

fn paths(list: &[&Path]) -> Vec<PathBuf> {
    list.iter().map(|p| p.to_path_buf()).collect()
}

fn policy() -> P {
    P(Policy {
        read: RuleSet {
            default: Default::Deny,
            allow: sandbox::baseline_read()
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            deny: vec![],
        },
        write: RuleSet {
            default: Default::Deny,
            allow: vec![],
            deny: vec![],
        },
        network: Network::Host {
            local_bind: false,
            unix_sockets: false,
        },
    })
}

impl P {
    fn read_default_allow(mut self) -> P {
        self.0.read.default = Default::Allow;
        self
    }
    fn write_default_allow(mut self) -> P {
        self.0.write.default = Default::Allow;
        self
    }
    fn read_allow(mut self, list: &[&Path]) -> P {
        self.0.read.allow.extend(paths(list));
        self
    }
    fn read_deny(mut self, list: &[&Path]) -> P {
        self.0.read.deny.extend(paths(list));
        self
    }
    /// Also allows reading them: a path read rules deny, by default too, may not be writable.
    fn write_allow(mut self, list: &[&Path]) -> P {
        self.0.read.allow.extend(paths(list));
        self.0.write.allow.extend(paths(list));
        self
    }
    fn write_deny(mut self, list: &[&Path]) -> P {
        self.0.write.deny.extend(paths(list));
        self
    }
    fn net(mut self, local_bind: bool, unix_sockets: bool) -> P {
        self.0.network = match self.0.network {
            Network::Host { .. } => Network::Host {
                local_bind,
                unix_sockets,
            },
            Network::Isolated { egress, ports, .. } => Network::Isolated {
                egress,
                ports,
                local_bind,
                unix_sockets,
            },
        };
        self
    }
    fn isolated(mut self) -> P {
        self.0.network = Network::Isolated {
            egress: HostRules {
                default: Default::Deny,
                allow: vec![],
                deny: vec![],
            },
            ports: None,
            local_bind: false,
            unix_sockets: false,
        };
        self
    }
}

/// The command proxy of isolated rows: its two loopback ports.
#[derive(Clone, Copy)]
struct Proxies {
    http: SocketAddr,
    socks: SocketAddr,
}

/// Runs `argv` through `sandbox::prepare` and the helper, the way `exec.start` does.
fn run(policy: &P, state: &Path, proxies: Proxies, argv: &[&str]) -> Outcome {
    helper::set_exe(PathBuf::from(EXE));
    let net = match policy.0.network {
        Network::Host { .. } => None,
        Network::Isolated { .. } => Some(NetPlan {
            http: Endpoint::Tcp(proxies.http),
            socks: Endpoint::Tcp(proxies.socks),
        }),
    };
    let mut env = BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);
    if net.is_some() {
        env.insert("http_proxy".to_string(), format!("http://{}", proxies.http));
    }
    let job = Job {
        policy: ResolvedPolicy::resolve(&policy.0, state).unwrap(),
        op: JobOp::Exec {
            argv: Argv::try_from(argv.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap(),
            cwd: AbsPath::try_from("/").unwrap(),
            env,
        },
    };
    let exe = PathBuf::from(EXE);
    let plan = Plan {
        policy: &job.policy,
        net,
        exe: &exe,
    };
    let (mut status_reader, status_writer) = std::io::pipe().unwrap();
    let status_fd = status_writer.as_raw_fd();
    let mut command = sandbox::prepare(&plan, &job).unwrap().command;
    // SAFETY: install_status_fd is async-signal-safe and runs in the forked child.
    unsafe {
        command.pre_exec(move || helper::install_status_fd(status_fd));
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(status_writer);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&helper::encode_job(&job))
        .unwrap();
    let mut status = Vec::new();
    status_reader.read_to_end(&mut status).unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    match helper::parse_exec_status(&status) {
        Ok(()) if output.status.success() => Outcome::Ok(String::from_utf8(output.stdout).unwrap()),
        Ok(()) if stderr.contains("Operation not permitted") => Denied,
        Err(err) if err.kind == ErrorKind::PermissionDenied => Denied,
        Ok(()) => Outcome::Failed {
            code: output.status.code(),
            stderr,
        },
        Err(err) => Outcome::Failed {
            code: output.status.code(),
            stderr: err.to_string(),
        },
    }
}

fn sh(script: String) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-c".to_string(), script]
}

fn perl(script: &str, arg: impl ToString) -> Vec<String> {
    vec![
        "/usr/bin/perl".to_string(),
        "-e".to_string(),
        script.to_string(),
        arg.to_string(),
    ]
}

struct Tree {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        for sub in [
            "data/sub",
            "out",
            "outside/public",
            "state",
            "bin",
            "repo/.git/hooks",
        ] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        for (file, text) in [
            ("data/file.txt", "data\n"),
            ("data/other.txt", "other\n"),
            ("data/sub/deep.txt", "deep\n"),
            ("outside/secret.txt", "secret\n"),
            ("outside/public/note.txt", "note\n"),
            ("out/existing.txt", "existing\n"),
            ("state/credentials.json", "{}\n"),
            ("repo/.git/hooks/pre-commit", "original\n"),
        ] {
            std::fs::write(root.join(file), text).unwrap();
        }
        std::os::unix::fs::symlink(root.join("outside/secret.txt"), root.join("data/escape"))
            .unwrap();
        std::os::unix::fs::symlink(root.join("state/credentials.json"), root.join("data/key"))
            .unwrap();
        std::fs::write(root.join("bin/hello"), "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(
            root.join("bin/hello"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        Tree { _dir: dir, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn show(&self, rel: &str) -> String {
        self.path(rel).to_str().unwrap().to_string()
    }
}

/// Answers every HTTP request with `proxied`, standing in for the command proxy.
fn fake_proxy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                request.push(byte[0]);
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxied\n",
            );
        }
    });
    addr
}

fn idle_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

#[test]
fn policy_combinations_and_their_outcomes() {
    let tree = Tree::new();
    let t = |rel: &str| tree.path(rel);
    let p = |rel: &str| tree.show(rel);
    let state = t("state");

    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let short_tmp = Path::new("/tmp").join(tmp.path().file_name().unwrap());
    let private_tmp = Path::new("/private/tmp").join(tmp.path().file_name().unwrap());

    let socks = idle_listener();
    let proxies = Proxies {
        http: fake_proxy(),
        socks: socks.local_addr().unwrap(),
    };
    let other = idle_listener();
    let other_port = other.local_addr().unwrap().port();
    let unix_path = t("host.sock");
    let unix = std::os::unix::net::UnixListener::bind(&unix_path).unwrap();
    std::thread::spawn(move || for _ in unix.incoming() {});
    let mut outsider = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let curl = |args: String| {
        sh(format!(
            "/usr/bin/curl -sS --max-time 10 {args}; echo rc=$?"
        ))
    };

    let none = policy;
    let rows: Vec<(&str, P, Vec<String>, Outcome)> = vec![
        (
            "read: an allowed directory",
            policy().read_allow(&[&t("data")]),
            sh(format!("cat {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "read: default deny",
            none(),
            sh(format!("cat {}", p("data/file.txt"))),
            Denied,
        ),
        (
            "read: default deny, no listing",
            none(),
            sh(format!("ls {}", p("data"))),
            Denied,
        ),
        (
            "read: default allow",
            policy().read_default_allow(),
            sh(format!("cat {}", p("outside/secret.txt"))),
            ok("secret\n"),
        ),
        (
            "read: default allow, a deny hole",
            policy()
                .read_default_allow()
                .read_deny(&[&t("outside")]),
            sh(format!("cat {}", p("outside/secret.txt"))),
            Denied,
        ),
        (
            "read: default allow, an allow inside the deny hole",
            policy()
                .read_default_allow()
                .read_deny(&[&t("outside")])
                .read_allow(&[&t("outside/public")]),
            sh(format!("cat {}", p("outside/public/note.txt"))),
            ok("note\n"),
        ),
        (
            "read: default deny, a deny inside an allow",
            policy()
                .read_allow(&[&t("data")])
                .read_deny(&[&t("data/sub")]),
            sh(format!("cat {}", p("data/sub/deep.txt"))),
            Denied,
        ),
        (
            "read: an allow inside a deny inside an allow",
            policy()
                .read_allow(&[&tree.root, &t("outside/public")])
                .read_deny(&[&t("outside")]),
            sh(format!(
                "cat {} {}",
                p("data/file.txt"),
                p("outside/public/note.txt")
            )),
            ok("data\nnote\n"),
        ),
        (
            "read: the same path allowed and denied is denied",
            policy()
                .read_allow(&[&t("data")])
                .read_deny(&[&t("data")]),
            sh(format!("cat {}", p("data/file.txt"))),
            Denied,
        ),
        (
            "write: an allowed directory",
            policy().write_allow(&[&t("out")]),
            sh(format!("echo new > {0}/a && cat {0}/a", p("out"))),
            ok("new\n"),
        ),
        (
            "write: a write allow is readable",
            policy().write_allow(&[&t("out")]),
            sh(format!("cat {}", p("out/existing.txt"))),
            ok("existing\n"),
        ),
        (
            "write: a read allow does not write",
            policy().read_allow(&[&t("out")]),
            sh(format!("echo new > {}/b", p("out"))),
            Denied,
        ),
        (
            "write: default allow, a deny hole",
            policy()
                .read_default_allow()
                .write_default_allow()
                .write_deny(&[&t("data")]),
            sh(format!("echo x > {}/x", p("data"))),
            Denied,
        ),
        (
            "write: default allow writes elsewhere",
            policy()
                .read_default_allow()
                .write_default_allow()
                .write_deny(&[&t("data")]),
            sh(format!("echo x > {0}/c && cat {0}/c", p("out"))),
            ok("x\n"),
        ),
        (
            "write: an allow inside a deny inside an allow",
            policy()
                .write_allow(&[&tree.root, &t("data/sub")])
                .write_deny(&[&t("data")]),
            sh(format!("echo y > {0}/y && cat {0}/y", p("data/sub"))),
            ok("y\n"),
        ),
        (
            "write: no rename out of a read-only directory",
            policy()
                .read_allow(&[&t("data")])
                .write_allow(&[&t("out")]),
            sh(format!("mv {} {}/moved", p("data/other.txt"), p("out"))),
            Denied,
        ),
        (
            "write: a denied path inside an allowed one",
            policy()
                .write_allow(&[&t("repo")])
                .write_deny(&[&t("repo/.git/hooks")]),
            sh(format!("echo evil > {}", p("repo/.git/hooks/pre-commit"))),
            Denied,
        ),
        (
            "write: no rename of a directory above a denied path",
            policy()
                .write_allow(&[&t("repo")])
                .write_deny(&[&t("repo/.git/hooks")]),
            sh(format!("mv {} {}", p("repo/.git"), p("repo/moved"))),
            Denied,
        ),
        (
            "write: no hard link to a denied file",
            policy()
                .write_allow(&[&t("repo")])
                .write_deny(&[&t("repo/.git/hooks")]),
            sh(format!(
                "ln {} {}",
                p("repo/.git/hooks/pre-commit"),
                p("repo/link")
            )),
            Denied,
        ),
        (
            "missing: a denied path that does not exist cannot be created",
            policy()
                .write_allow(&[&t("out")])
                .write_deny(&[&t("out/missing")]),
            sh(format!("mkdir {}", p("out/missing"))),
            Denied,
        ),
        (
            "missing: nor planted by renaming its missing parent into place",
            policy()
                .write_allow(&[&t("out")])
                .write_deny(&[&t("out/new/hooks")]),
            sh(format!(
                "mkdir -p {0}/staged/hooks && mv {0}/staged {0}/new",
                p("out")
            )),
            Denied,
        ),
        (
            "missing: an allowed path that does not exist can be created",
            policy().write_allow(&[&t("out/fresh")]),
            sh(format!("mkdir {0} && echo z > {0}/z && cat {0}/z", p("out/fresh"))),
            ok("z\n"),
        ),
        (
            "symlink: inside an allow, pointing outside",
            policy().read_allow(&[&t("data")]),
            sh(format!("cat {}", p("data/escape"))),
            Denied,
        ),
        (
            "symlink: an allow on the link allows its target",
            policy().read_allow(&[&t("data/escape")]),
            sh(format!("cat {}", p("outside/secret.txt"))),
            ok("secret\n"),
        ),
        (
            "tmp: a /tmp entry covers /tmp and /private/tmp",
            policy().write_allow(&[&short_tmp]),
            sh(format!(
                "echo a > {0}/f && echo b > {1}/g && cat {1}/f {0}/g",
                short_tmp.display(),
                private_tmp.display()
            )),
            ok("a\nb\n"),
        ),
        (
            "state: denied inside a write allow",
            policy().write_allow(&[&tree.root]),
            sh(format!("cat {}", p("state/credentials.json"))),
            Denied,
        ),
        (
            "state: denied under default allow",
            policy().read_default_allow().write_default_allow(),
            sh(format!("cat {}", p("state/credentials.json"))),
            Denied,
        ),
        (
            "state: denied when the policy allows it by name",
            policy().read_allow(&[&state]).write_allow(&[&state]),
            sh(format!("cat {}", p("state/credentials.json"))),
            Denied,
        ),
        (
            "state: not listable",
            policy().write_allow(&[&tree.root]),
            sh(format!("ls {}", p("state"))),
            Denied,
        ),
        (
            "state: unwritable",
            policy().write_allow(&[&tree.root]),
            sh(format!("echo x > {}/new", p("state"))),
            Denied,
        ),
        (
            "state: cannot be renamed away",
            policy().write_allow(&[&tree.root]),
            sh(format!("mv {} {}", p("state"), p("stolen"))),
            Denied,
        ),
        (
            "state: not through a symlink",
            policy().write_allow(&[&tree.root]),
            sh(format!("cat {}", p("data/key"))),
            Denied,
        ),
        (
            "state: its siblings stay allowed",
            policy().write_allow(&[&tree.root]),
            sh(format!("cat {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "paths: realpath and pwd -P inside an allow",
            policy().read_allow(&[&t("data")]),
            sh(format!(
                "/bin/realpath {}; cd {} && pwd -P",
                p("data/file.txt"),
                p("data")
            )),
            ok(&format!("{}\n{}\n", p("data/file.txt"), p("data"))),
        ),
        (
            "exec: a binary outside the readable paths",
            none(),
            vec![p("bin/hello")],
            Denied,
        ),
        (
            "exec: a binary inside a read allow",
            policy().read_allow(&[&t("bin")]),
            vec![p("bin/hello")],
            ok("hi\n"),
        ),
        (
            "children: a grandchild is still confined",
            policy().read_allow(&[&t("data")]),
            sh(format!("sh -c 'sh -c \"cat {}\"'", p("outside/secret.txt"))),
            Denied,
        ),
        (
            "devices: usable whatever the policy denies",
            policy().read_default_allow().read_deny(&[Path::new("/dev")]),
            sh("echo x > /dev/null && head -c 3 /dev/urandom | wc -c | tr -d ' ' && echo out > /dev/stdout".to_string()),
            ok("3\nout\n"),
        ),
        (
            "tcp: listen without localBind",
            none(),
            perl(TCP_LISTEN, "127.0.0.1"),
            Denied,
        ),
        (
            "tcp: listen on loopback with localBind",
            none().net(true, false),
            perl(TCP_LISTEN, "127.0.0.1"),
            ok("bound\n"),
        ),
        (
            "tcp: listen on IPv6 loopback with localBind",
            none().net(true, false),
            perl(TCP_LISTEN, "::1"),
            ok("bound\n"),
        ),
        (
            "tcp: listen on every address with localBind",
            none().net(true, false),
            perl(TCP_LISTEN, "0.0.0.0"),
            ok("bound\n"),
        ),
        (
            "tcp: accept with localBind",
            none().net(true, false),
            perl(TCP_ACCEPT, ""),
            ok("accepted\n"),
        ),
        (
            "udp: bind without localBind",
            none(),
            perl(UDP_BIND, "127.0.0.1"),
            Denied,
        ),
        (
            "udp: bind with localBind",
            none().net(true, false),
            perl(UDP_BIND, "127.0.0.1"),
            ok("bound\n"),
        ),
        (
            "unix: bind without unixSockets",
            policy().write_allow(&[&t("out")]),
            perl(UNIX_BIND, p("out/a.sock")),
            Denied,
        ),
        (
            "unix: bind with unixSockets in a writable directory",
            policy().write_allow(&[&t("out")]).net(false, true),
            perl(UNIX_BIND, p("out/b.sock")),
            ok("bound\n"),
        ),
        (
            "unix: bind with unixSockets in a read-only directory",
            policy()
                .read_allow(&[&t("data")])
                .write_allow(&[&t("out")])
                .net(false, true),
            perl(UNIX_BIND, p("data/c.sock")),
            Denied,
        ),
        (
            "unix: accept with unixSockets",
            policy().write_allow(&[&t("out")]).net(false, true),
            perl(UNIX_ACCEPT, p("out/e.sock")),
            ok("accepted\n"),
        ),
        (
            "unix: localBind does not bind unix sockets",
            policy().write_allow(&[&t("out")]).net(true, false),
            perl(UNIX_BIND, p("out/d.sock")),
            Denied,
        ),
        (
            "unix: connect without unixSockets",
            none(),
            perl(UNIX_CONNECT, unix_path.display()),
            Denied,
        ),
        (
            "unix: connect with unixSockets",
            none().net(false, true),
            perl(UNIX_CONNECT, unix_path.display()),
            ok("connected\n"),
        ),
        (
            "host: tcp connect to any port",
            none(),
            perl(TCP_CONNECT, other_port),
            ok("connected\n"),
        ),
        (
            "host: dns without unixSockets",
            none(),
            perl(RESOLVE, "apple.com"),
            ok("resolved\n"),
        ),
        (
            "isolated: curl https direct",
            none().isolated(),
            curl("-o /dev/null https://example.com/".to_string()),
            ok("rc=6\n"),
        ),
        (
            "isolated: curl to an IP address direct",
            none().isolated(),
            curl("--noproxy '*' -o /dev/null http://1.1.1.1/".to_string()),
            ok("rc=7\n"),
        ),
        (
            "isolated: curl through http_proxy on the allowed port",
            none().isolated(),
            curl("http://example.com/".to_string()),
            ok("proxied\nrc=0\n"),
        ),
        (
            "isolated: tcp connect to the socks port",
            none().isolated(),
            perl(TCP_CONNECT, proxies.socks.port()),
            ok("connected\n"),
        ),
        (
            "isolated: tcp connect to another localhost port",
            none().isolated(),
            perl(TCP_CONNECT, other_port),
            Denied,
        ),
        (
            "isolated: dns",
            none().isolated(),
            perl(RESOLVE, "apple.com"),
            ok("unresolved\n"),
        ),
        (
            "isolated: dns with unixSockets",
            none().isolated().net(false, true),
            perl(RESOLVE, "apple.com"),
            ok("unresolved\n"),
        ),
        (
            "isolated: udp to a public resolver",
            none().isolated(),
            perl(UDP_SEND, "8.8.8.8"),
            Denied,
        ),
        (
            "isolated: listen without localBind",
            none().isolated(),
            perl(TCP_LISTEN, "127.0.0.1"),
            Denied,
        ),
        (
            "isolated: listen on loopback with localBind",
            none().isolated().net(true, false),
            perl(TCP_LISTEN, "127.0.0.1"),
            ok("bound\n"),
        ),
        (
            "isolated: localBind cannot be held to loopback (a gap)",
            none().isolated().net(true, false),
            perl(TCP_LISTEN, "0.0.0.0"),
            ok("bound\n"),
        ),
        (
            "isolated: unix connect without unixSockets",
            none().isolated(),
            perl(UNIX_CONNECT, unix_path.display()),
            Denied,
        ),
        (
            "isolated: unix connect with unixSockets",
            none().isolated().net(false, true),
            perl(UNIX_CONNECT, unix_path.display()),
            ok("connected\n"),
        ),
        (
            "lookups: the user's name",
            none(),
            sh("id -un".to_string()),
            ok(&user_name()),
        ),
        (
            "signal: a process outside the sandbox",
            none(),
            sh(format!("kill -0 {}", outsider.id())),
            Denied,
        ),
        (
            "signal: its own child",
            none(),
            sh("sleep 30 & kill $!; wait $!; echo $?".to_string()),
            ok("143\n"),
        ),
    ];

    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (name, policy, argv, outcome) in rows {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        actual.push((name, run(&policy, &state, proxies, &argv)));
        expected.push((name, outcome));
    }
    outsider.kill().unwrap();
    outsider.wait().unwrap();
    assert_eq!(actual, expected);

    assert!(!t("out/missing").exists());
    assert!(!t("out/new").exists());
    assert!(!t("out/a.sock").exists());
    assert!(t("out/b.sock").exists());
    assert!(!t("state/new").exists());
    assert!(t("state/credentials.json").exists());
    assert_eq!(
        std::fs::read_to_string(t("repo/.git/hooks/pre-commit")).unwrap(),
        "original\n"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("f")).unwrap(),
        "a\n"
    );
}

#[test]
fn programs_run_on_the_baseline() {
    let tree = Tree::new();
    let proxies = Proxies {
        http: "127.0.0.1:9".parse().unwrap(),
        socks: "127.0.0.1:9".parse().unwrap(),
    };
    let cases: Vec<(Vec<String>, Outcome)> = vec![
        (vec!["/bin/echo".to_string(), "hi".to_string()], ok("hi\n")),
        (
            sh("echo $0; /usr/bin/env true && echo env".to_string()),
            ok("/bin/sh\nenv\n"),
        ),
        (sh("echo fd | cat /dev/fd/0".to_string()), ok("fd\n")),
        (sh("echo stdin | cat /dev/stdin".to_string()), ok("stdin\n")),
        (
            vec!["/usr/bin/git".to_string(), "--version".to_string()],
            Outcome::Ok(git_version()),
        ),
        (
            vec![
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                "print(6 * 7)".to_string(),
            ],
            ok("42\n"),
        ),
    ];
    for (argv, expected) in cases {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        assert_eq!(
            run(&policy(), &tree.path("state"), proxies, &argv),
            expected,
            "{argv:?}"
        );
    }
}

fn user_name() -> String {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

fn git_version() -> String {
    let output = std::process::Command::new("/usr/bin/git")
        .arg("--version")
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn probe_runs_a_sandboxed_true() {
    helper::set_exe(PathBuf::from(EXE));
    let info = sandbox::probe();
    assert_eq!(info.mechanism, Mechanism::Seatbelt);
    assert_eq!(info.status, SandboxStatus::Available);
    assert_eq!(info.baseline_read, sandbox::baseline_read());
    assert_eq!(info.gaps.len(), 2);
}
