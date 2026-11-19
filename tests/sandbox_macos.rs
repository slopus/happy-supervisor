//! The Seatbelt backend on a real Mac: the built binary as the helper, under `sandbox-exec`.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use happy_supervisor::ErrorKind;
use happy_supervisor::helper::{self, Job, JobOp};
use happy_supervisor::policy::{ResolvedPolicy, allow_list};
use happy_supervisor::protocol::{AbsPath, Argv, Mechanism, SandboxStatus};
use happy_supervisor::sandbox;

const TCP_LISTEN: &str = r#"use IO::Socket::IP; IO::Socket::IP->new(Listen => 1, LocalHost => $ARGV[0], LocalPort => 0, Proto => "tcp") or die "$!\n"; print "bound\n""#;
const UDP_BIND: &str = r#"use IO::Socket::IP; IO::Socket::IP->new(LocalHost => $ARGV[0], LocalPort => 0, Proto => "udp") or die "$!\n"; print "bound\n""#;
const UNIX_BIND: &str = r#"use IO::Socket::UNIX; IO::Socket::UNIX->new(Local => $ARGV[0], Listen => 1) or die "$!\n"; print "bound\n""#;
const TCP_CONNECT: &str = r#"use IO::Socket::IP; my $s = IO::Socket::IP->new(PeerHost => "127.0.0.1", PeerPort => $ARGV[0]) or die "$!\n"; print $s "hello\n"; print "connected\n""#;
const TCP_ACCEPT: &str = r#"use IO::Socket::IP; my $l = IO::Socket::IP->new(Listen => 1, LocalHost => "127.0.0.1", LocalPort => 0) or die "$!\n"; my $c = IO::Socket::IP->new(PeerHost => "127.0.0.1", PeerPort => $l->sockport) or die "$!\n"; $l->accept or die "$!\n"; print "accepted\n""#;
const UNIX_ACCEPT: &str = r#"use IO::Socket::UNIX; my $l = IO::Socket::UNIX->new(Local => $ARGV[0], Listen => 1) or die "$!\n"; my $c = IO::Socket::UNIX->new(Peer => $ARGV[0]) or die "$!\n"; $l->accept or die "$!\n"; print "accepted\n""#;
const UNIX_CONNECT: &str = r#"use IO::Socket::UNIX; IO::Socket::UNIX->new(Peer => $ARGV[0]) or die "$!\n"; print "connected\n""#;
const RESOLVE: &str = r#"use Socket; my ($err, @addrs) = Socket::getaddrinfo($ARGV[0], "443"); die "$err\n" if $err; print "resolved\n""#;

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

/// What the test spawner needs from a policy row.
struct Grants {
    read: Vec<String>,
    write: Vec<String>,
    local_bind: bool,
    unix_sockets: bool,
}

fn grants(read: &[&Path], write: &[&Path]) -> Grants {
    let text = |paths: &[&Path]| -> Vec<String> {
        paths
            .iter()
            .map(|p| p.to_str().unwrap().to_string())
            .collect()
    };
    Grants {
        read: text(read),
        write: text(write),
        local_bind: false,
        unix_sockets: false,
    }
}

impl Grants {
    fn local_bind(mut self) -> Grants {
        self.local_bind = true;
        self
    }

    fn unix_sockets(mut self) -> Grants {
        self.unix_sockets = true;
        self
    }
}

/// Runs `argv` through `sandbox::prepare` and the helper, the way `exec.start` does, with the
/// machine's baseline added to the row's read grants.
fn run(grants: &Grants, state: &Path, argv: &[&str]) -> Outcome {
    helper::set_exe(PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor")));
    let read: Vec<String> = sandbox::baseline_read()
        .into_iter()
        .chain(grants.read.iter().cloned())
        .collect();
    let policy = allow_list(
        read,
        grants.write.clone(),
        grants.local_bind,
        grants.unix_sockets,
    );
    let job = Job {
        policy: ResolvedPolicy::resolve(&policy, state).unwrap(),
        op: JobOp::Exec {
            argv: Argv::try_from(argv.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap(),
            cwd: AbsPath::try_from("/").unwrap(),
            env: BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]),
        },
    };
    let (mut status_reader, status_writer) = std::io::pipe().unwrap();
    let status_fd = status_writer.as_raw_fd();
    let exe = helper::exe().unwrap();
    let plan = sandbox::Plan {
        policy: &job.policy,
        net: None,
        exe: &exe,
    };
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
        for sub in ["data", "out", "outside", "state", "bin"] {
            std::fs::create_dir(root.join(sub)).unwrap();
        }
        std::fs::write(root.join("data/file.txt"), "data\n").unwrap();
        std::fs::write(root.join("data/other.txt"), "other\n").unwrap();
        std::fs::write(root.join("outside/secret.txt"), "secret\n").unwrap();
        std::fs::write(root.join("state/credentials.json"), "{}\n").unwrap();
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

#[test]
fn policy_combinations_and_their_outcomes() {
    let tree = Tree::new();
    let t = |rel: &str| tree.path(rel);
    let p = |rel: &str| tree.show(rel);
    let state = t("state");

    let tmp = tempfile::tempdir_in("/tmp").unwrap();
    let short_tmp = Path::new("/tmp").join(tmp.path().file_name().unwrap());
    let private_tmp = Path::new("/private/tmp").join(tmp.path().file_name().unwrap());

    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let tcp_server = std::thread::spawn(move || {
        let (mut stream, _) = tcp.accept().unwrap();
        let mut line = String::new();
        stream.read_to_string(&mut line).unwrap();
        line
    });
    let unix_path = t("host.sock");
    let unix = std::os::unix::net::UnixListener::bind(&unix_path).unwrap();
    std::thread::spawn(move || {
        let _ = unix.accept();
    });
    let mut outsider = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();

    let none = || grants(&[], &[]);
    let rows: Vec<(&str, Grants, Vec<String>, Outcome)> = vec![
        (
            "read: a granted directory",
            grants(&[&t("data")], &[]),
            sh(format!("cat {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "read: nothing granted",
            none(),
            sh(format!("cat {}", p("data/file.txt"))),
            Denied,
        ),
        (
            "read: the directory is not listable without a grant",
            none(),
            sh(format!("ls {}", p("data"))),
            Denied,
        ),
        (
            "write: a granted directory",
            grants(&[], &[&t("out")]),
            sh(format!("echo new > {0}/a && cat {0}/a", p("out"))),
            ok("new\n"),
        ),
        (
            "write: a read grant does not write",
            grants(&[&t("out")], &[]),
            sh(format!("echo new > {}/b", p("out"))),
            Denied,
        ),
        (
            "write: no rename out of a read grant",
            grants(&[&t("data")], &[&t("out")]),
            sh(format!("mv {} {}/moved", p("data/other.txt"), p("out"))),
            Denied,
        ),
        (
            "file grant: the file",
            grants(&[&t("data/file.txt")], &[]),
            sh(format!("cat {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "file grant: append to a written file",
            grants(&[], &[&t("data/other.txt")]),
            sh(format!("echo more >> {0} && cat {0}", p("data/other.txt"))),
            ok("other\nmore\n"),
        ),
        (
            "file grant: not its sibling",
            grants(&[&t("data/file.txt")], &[]),
            sh(format!("cat {}", p("data/other.txt"))),
            Denied,
        ),
        (
            "symlink: inside a grant, pointing outside",
            grants(&[&t("data")], &[]),
            sh(format!("cat {}", p("data/escape"))),
            Denied,
        ),
        (
            "symlink: a grant on the link grants its target",
            grants(&[&t("data/escape")], &[]),
            sh(format!("cat {}", p("outside/secret.txt"))),
            ok("secret\n"),
        ),
        (
            "symlink: a grant on the link, read through the link",
            grants(&[&t("data/escape")], &[]),
            sh(format!("cat {}", p("data/escape"))),
            Denied,
        ),
        (
            "tmp: a /tmp grant covers /tmp and /private/tmp",
            grants(&[], &[&short_tmp]),
            sh(format!(
                "echo a > {0}/f && echo b > {1}/g && cat {1}/f {0}/g",
                short_tmp.display(),
                private_tmp.display()
            )),
            ok("a\nb\n"),
        ),
        (
            "missing: a missing write path grants nothing",
            grants(&[], &[&t("missing")]),
            sh(format!("mkdir {}", p("missing"))),
            Denied,
        ),
        (
            "state: unreadable inside a write grant",
            grants(&[], &[&tree.root]),
            sh(format!("cat {}", p("state/credentials.json"))),
            Denied,
        ),
        (
            "state: not listable",
            grants(&[], &[&tree.root]),
            sh(format!("ls {}", p("state"))),
            Denied,
        ),
        (
            "state: unwritable",
            grants(&[], &[&tree.root]),
            sh(format!("echo x > {}/new", p("state"))),
            Denied,
        ),
        (
            "state: cannot be renamed away",
            grants(&[], &[&tree.root]),
            sh(format!("mv {} {}", p("state"), p("stolen"))),
            Denied,
        ),
        (
            "state: not through a symlink in a grant",
            grants(&[], &[&tree.root]),
            sh(format!("cat {}", p("data/key"))),
            Denied,
        ),
        (
            "state: its siblings stay granted",
            grants(&[], &[&tree.root]),
            sh(format!("cat {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "paths: realpath and pwd -P inside a grant",
            grants(&[&t("data")], &[]),
            sh(format!(
                "/bin/realpath {}; cd {} && pwd -P",
                p("data/file.txt"),
                p("data")
            )),
            ok(&format!("{}\n{}\n", p("data/file.txt"), p("data"))),
        ),
        (
            "exec: a binary outside the grants",
            none(),
            vec![p("bin/hello")],
            Denied,
        ),
        (
            "exec: a binary inside a read grant",
            grants(&[&t("bin")], &[]),
            vec![p("bin/hello")],
            ok("hi\n"),
        ),
        (
            "children: a grandchild is still confined",
            grants(&[&t("data")], &[]),
            sh(format!("sh -c 'sh -c \"cat {}\"'", p("outside/secret.txt"))),
            Denied,
        ),
        (
            "children: a grandchild keeps the grants",
            grants(&[&t("data")], &[]),
            sh(format!("sh -c 'sh -c \"cat {}\"'", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "tcp: listen without localBind",
            none(),
            perl(TCP_LISTEN, "127.0.0.1"),
            Denied,
        ),
        (
            "tcp: listen on loopback with localBind",
            none().local_bind(),
            perl(TCP_LISTEN, "127.0.0.1"),
            ok("bound\n"),
        ),
        (
            "tcp: listen on IPv6 loopback with localBind",
            none().local_bind(),
            perl(TCP_LISTEN, "::1"),
            ok("bound\n"),
        ),
        (
            "tcp: listen on every address with localBind",
            none().local_bind(),
            perl(TCP_LISTEN, "0.0.0.0"),
            ok("bound\n"),
        ),
        (
            "tcp: accept with localBind",
            none().local_bind(),
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
            none().local_bind(),
            perl(UDP_BIND, "127.0.0.1"),
            ok("bound\n"),
        ),
        (
            "unix: bind without unixSockets",
            grants(&[], &[&t("out")]),
            perl(UNIX_BIND, p("out/a.sock")),
            Denied,
        ),
        (
            "unix: bind with unixSockets in a write grant",
            grants(&[], &[&t("out")]).unix_sockets(),
            perl(UNIX_BIND, p("out/b.sock")),
            ok("bound\n"),
        ),
        (
            "unix: accept with unixSockets",
            grants(&[], &[&t("out")]).unix_sockets(),
            perl(UNIX_ACCEPT, p("out/e.sock")),
            ok("accepted\n"),
        ),
        (
            "unix: bind with unixSockets in a read grant",
            grants(&[&t("data")], &[&t("out")]).unix_sockets(),
            perl(UNIX_BIND, p("data/c.sock")),
            Denied,
        ),
        (
            "unix: localBind does not bind unix sockets",
            grants(&[], &[&t("out")]).local_bind(),
            perl(UNIX_BIND, p("out/d.sock")),
            Denied,
        ),
        (
            "outbound: tcp connect to a listener outside the sandbox",
            none(),
            perl(TCP_CONNECT, tcp_port),
            ok("connected\n"),
        ),
        (
            "outbound: unix connect to a listener outside the sandbox",
            none(),
            perl(UNIX_CONNECT, unix_path.display()),
            ok("connected\n"),
        ),
        (
            "outbound: dns",
            none(),
            perl(RESOLVE, "apple.com"),
            ok("resolved\n"),
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
            "signal: itself",
            none(),
            sh("kill -0 $$ && echo alive".to_string()),
            ok("alive\n"),
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
    for (name, grants, argv, outcome) in rows {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        actual.push((name, run(&grants, &state, &argv)));
        expected.push((name, outcome));
    }
    outsider.kill().unwrap();
    outsider.wait().unwrap();
    assert_eq!(actual, expected);

    assert_eq!(tcp_server.join().unwrap(), "hello\n");
    assert!(!t("missing").exists());
    assert!(!t("out/a.sock").exists());
    assert!(t("out/b.sock").exists());
    assert!(!t("out/d.sock").exists());
    assert!(!t("state/new").exists());
    assert!(t("state/credentials.json").exists());
    assert_eq!(
        std::fs::read_to_string(t("data/other.txt")).unwrap(),
        "other\nmore\n"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("f")).unwrap(),
        "a\n"
    );
}

#[test]
fn programs_run_on_the_baseline() {
    let tree = Tree::new();
    let cases: Vec<(Vec<String>, Outcome)> = vec![
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
            run(&grants(&[], &[]), &tree.path("state"), &argv),
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
    helper::set_exe(PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor")));
    let info = sandbox::probe();
    assert_eq!(info.mechanism, Mechanism::Seatbelt);
    assert_eq!(info.status, SandboxStatus::Available);
    assert_eq!(info.baseline_read, sandbox::baseline_read());
}
