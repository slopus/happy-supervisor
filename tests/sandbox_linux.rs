//! The Linux sandbox through the real binary: `sandbox::prepare` builds the bubblewrap command,
//! and the job goes over stdin with the exec status pipe on fd 3, as the exec module does. Each
//! test is a policy, a command, and the outcome the policy promises.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

use happy_supervisor::helper::{self, Job, JobOp};
use happy_supervisor::policy::{Default, HostRules, Network, Policy, ResolvedPolicy, RuleSet};
use happy_supervisor::protocol::{AbsPath, Argv, Mechanism, SandboxStatus};
use happy_supervisor::sandbox::{self, Endpoint, NetPlan, Plan, Prepared};

const EXE: &str = env!("CARGO_BIN_EXE_happy-supervisor");

/// Set in the environment of this test binary when it runs inside a sandbox as a command; see
/// [`child_action`].
const ACTION_VAR: &str = "HAPPY_SANDBOX_TEST_ACTION";
const ARG_VAR: &str = "HAPPY_SANDBOX_TEST_ARG";

/// A tree of real paths to sandbox. `state` is the state directory every policy denies.
struct Tree {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        Tree::in_dir(&std::env::temp_dir())
    }

    fn in_dir(dir: &Path) -> Tree {
        let tmp = tempfile::tempdir_in(dir).unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("state")).unwrap();
        std::fs::write(root.join("state/credentials.json"), "{\"token\":1}").unwrap();
        Tree { _tmp: tmp, root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn file(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.path(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn dir(&self, relative: &str) -> PathBuf {
        let path = self.path(relative);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// `rules` with every `{}` replaced by the tree's root.
    fn rules(&self, default: Default, allow: &[&str], deny: &[&str]) -> RuleSet {
        let root = self.root.to_str().unwrap();
        let expand = |paths: &[&str]| -> Vec<PathBuf> {
            paths
                .iter()
                .map(|p| PathBuf::from(p.replace("{}", root)))
                .collect()
        };
        RuleSet {
            default,
            allow: expand(allow),
            deny: expand(deny),
        }
    }

    fn resolve(&self, read: RuleSet, write: RuleSet, network: Network) -> ResolvedPolicy {
        let policy = Policy {
            read,
            write,
            network,
        };
        ResolvedPolicy::resolve(&policy, &self.path("state")).unwrap()
    }
}

fn host(local_bind: bool, unix_sockets: bool) -> Network {
    Network::Host {
        local_bind,
        unix_sockets,
    }
}

fn isolated(local_bind: bool, unix_sockets: bool) -> Network {
    Network::Isolated {
        egress: HostRules {
            default: Default::Deny,
            allow: vec![],
            deny: vec![],
        },
        ports: None,
        local_bind,
        unix_sockets,
    }
}

/// Reads everything, writes nothing.
fn read_all(tree: &Tree) -> RuleSet {
    tree.rules(Default::Allow, &[], &[])
}

fn write_none(tree: &Tree) -> RuleSet {
    tree.rules(Default::Deny, &[], &[])
}

#[derive(Debug)]
struct Run {
    code: Option<i32>,
    stdout: String,
    #[allow(dead_code)] // Shown when an assertion prints the run.
    stderr: String,
}

/// A sandboxed command that is running, with what `prepare` returned beside the command.
struct Started {
    child: Child,
    netns: Option<sandbox::NetnsControl>,
    _placeholders: sandbox::Placeholders,
}

fn start(
    policy: &ResolvedPolicy,
    net: Option<NetPlan>,
    argv: &[&str],
    env: &[(&str, &str)],
) -> Started {
    helper::set_exe(EXE.into());
    let job = Job {
        policy: policy.clone(),
        op: JobOp::Exec {
            argv: Argv::try_from(argv.iter().map(|a| a.to_string()).collect::<Vec<_>>()).unwrap(),
            cwd: AbsPath::try_from("/").unwrap(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            limits: happy_supervisor::protocol::Limits::default(),
        },
    };
    let plan = Plan {
        policy,
        net,
        exe: Path::new(EXE),
    };
    let Prepared {
        mut command,
        placeholders,
        netns,
    } = sandbox::prepare(&plan, &job).unwrap();
    let (mut status_reader, status_writer) = std::io::pipe().unwrap();
    let status_fd = status_writer.as_raw_fd();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid and install_status_fd are async-signal-safe and run in the forked child.
    unsafe {
        command.pre_exec(move || {
            libc::setsid();
            helper::install_status_fd(status_fd)
        });
    }
    let mut child = command.spawn().unwrap();
    drop(command);
    drop(status_writer);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&helper::encode_job(&job))
        .unwrap();
    let mut status = Vec::new();
    status_reader.read_to_end(&mut status).unwrap();
    assert_eq!(helper::parse_exec_status(&status), Ok(()));
    Started {
        child,
        netns,
        _placeholders: placeholders,
    }
}

fn run(policy: &ResolvedPolicy, net: Option<NetPlan>, argv: &[&str], env: &[(&str, &str)]) -> Run {
    let started = start(policy, net, argv, env);
    let output = started.child.wait_with_output().unwrap();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn sh(policy: &ResolvedPolicy, script: &str) -> Run {
    run(
        policy,
        None,
        &["/bin/sh", "-c", script],
        &[("PATH", "/usr/bin:/bin")],
    )
}

/// What `script` prints, and its exit code.
fn out(policy: &ResolvedPolicy, script: &str) -> (String, i32) {
    let run = sh(policy, script);
    (run.stdout, run.code.unwrap())
}

/// Runs this test binary inside the sandbox to perform one system-level operation, and returns
/// `ok` or the errno name it failed with.
fn act(policy: &ResolvedPolicy, action: &str, arg: &str) -> String {
    act_with(policy, None, action, arg)
}

fn act_with(policy: &ResolvedPolicy, net: Option<NetPlan>, action: &str, arg: &str) -> String {
    let run = run(
        policy,
        net,
        &child_argv(),
        &[(ACTION_VAR, action), (ARG_VAR, arg)],
    );
    result_of(&run.stdout).unwrap_or_else(|| panic!("no result from {action}: {run:?}"))
}

fn child_argv() -> Vec<&'static str> {
    let me = Box::leak(std::env::current_exe().unwrap().into_boxed_path());
    vec![
        me.to_str().unwrap(),
        "--exact",
        "child_action",
        "--nocapture",
        "--test-threads=1",
    ]
}

fn result_of(stdout: &str) -> Option<String> {
    // libtest has already printed "test child_action ... " on the same line.
    stdout.lines().find_map(|line| {
        line.split_once("RESULT ")
            .map(|(_, result)| result.to_string())
    })
}

/// The sandboxed half of [`act`]. A no-op in a normal test run.
#[test]
fn child_action() {
    let Ok(action) = std::env::var(ACTION_VAR) else {
        return;
    };
    let arg = std::env::var(ARG_VAR).unwrap_or_default();
    let errno = |rc: libc::c_long| match rc {
        rc if rc >= 0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    };
    let result: std::io::Result<String> = match action.as_str() {
        "tcp" => TcpListener::bind("127.0.0.1:0").map(|_| "ok".into()),
        "udp" => std::net::UdpSocket::bind("127.0.0.1:0").map(|_| "ok".into()),
        "unix" => UnixListener::bind(&arg).map(|_| "ok".into()),
        "socketpair" => std::os::unix::net::UnixStream::pair().map(|_| "ok".into()),
        "connect" => {
            TcpStream::connect_timeout(&arg.parse().unwrap(), std::time::Duration::from_secs(3))
                .map(|_| "ok".into())
        }
        // SAFETY: the raw system calls below get valid (or null) pointers and no fd is leaked
        // past this process, which exits right after.
        "io_uring" => {
            let mut params = [0u8; 120];
            errno(unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, params.as_mut_ptr()) })
                .map(|()| "ok".into())
        }
        "unshare-user" => errno(unsafe { libc::unshare(libc::CLONE_NEWUSER) } as libc::c_long)
            .map(|()| "ok".into()),
        "ptrace" => {
            errno(unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) }).map(|()| "ok".into())
        }
        "vsock" => {
            errno(unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) } as libc::c_long)
                .map(|()| "ok".into())
        }
        "http-get" => {
            // An absolute-form request, as a client configured with HTTP_PROXY sends it.
            TcpStream::connect(&arg).and_then(|mut proxy| {
                proxy.write_all(b"GET http://test.invalid/ HTTP/1.0\r\n\r\n")?;
                let mut response = String::new();
                proxy.read_to_string(&mut response)?;
                Ok(response.lines().last().unwrap_or("").to_string())
            })
        }
        "serve" => {
            // Listens, says where, and answers one connection.
            TcpListener::bind("127.0.0.1:0").and_then(|listener| {
                println!("PORT {}", listener.local_addr()?.port());
                let (mut stream, _) = listener.accept()?;
                stream.write_all(b"hello from inside")?;
                Ok("served".into())
            })
        }
        other => panic!("unknown action {other}"),
    };
    let result = match result {
        Ok(text) => text,
        Err(err) => match err.raw_os_error() {
            Some(libc::EPERM) => "EPERM".to_string(),
            Some(libc::EACCES) => "EACCES".to_string(),
            Some(libc::ENOSYS) => "ENOSYS".to_string(),
            Some(libc::ENETUNREACH) => "ENETUNREACH".to_string(),
            _ => format!("{err}"),
        },
    };
    println!("RESULT {result}");
    std::process::exit(0);
}

#[test]
fn probe_runs_a_sandboxed_true() {
    helper::set_exe(EXE.into());
    let info = sandbox::probe();
    assert_eq!(info.status, SandboxStatus::Available);
    let Mechanism::Bubblewrap {
        version: Some(version),
    } = info.mechanism
    else {
        panic!("not bubblewrap: {:?}", info.mechanism);
    };
    assert!(version.starts_with("0."), "{version}");
    assert_eq!(info.baseline_read, sandbox::baseline_read());
    assert!(info.gaps.len() >= 4, "{:?}", info.gaps);
}

#[test]
fn read_default_allow_with_deny_holes_and_deeper_allows() {
    let tree = Tree::new();
    tree.file("pub/note", "hello");
    tree.file("secret/key", "hunter2");
    tree.file("secret/shared/ok", "visible");
    tree.file("file-secret", "s3cret");
    let p = tree.resolve(
        tree.rules(
            Default::Allow,
            &["{}/secret/shared"],
            &["{}/secret", "{}/file-secret"],
        ),
        write_none(&tree),
        host(false, false),
    );
    let r = tree.root.display();
    let table = [
        (format!("cat {r}/pub/note"), ("hello".into(), 0)),
        (format!("ls -A {r}/secret"), ("shared\n".into(), 0)),
        (format!("cat {r}/secret/key"), ("".into(), 1)),
        (format!("cat {r}/secret/shared/ok"), ("visible".into(), 0)),
        (format!("cat {r}/file-secret"), ("".into(), 1)),
        (format!("echo x > {r}/pub/note"), ("".into(), 2)),
        (format!("touch {r}/secret/new"), ("".into(), 1)),
    ];
    for (script, expected) in table {
        assert_eq!(out(&p, &script), expected, "{script}");
    }
    assert_eq!(
        std::fs::read_to_string(tree.path("pub/note")).unwrap(),
        "hello"
    );
}

#[test]
fn read_default_deny_with_allow_holes_and_deeper_denies() {
    let tree = Tree::new();
    tree.file("repo/src/main.rs", "fn main() {}");
    tree.file("repo/.env", "TOKEN=1");
    tree.file("other/file", "other");
    let mut allow: Vec<String> = sandbox::baseline_read();
    allow.push(tree.path("repo").to_str().unwrap().to_string());
    let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
    let p = tree.resolve(
        tree.rules(Default::Deny, &allow, &["{}/repo/.env"]),
        write_none(&tree),
        host(false, false),
    );
    let r = tree.root.display();
    let table = [
        (
            format!("cat {r}/repo/src/main.rs"),
            ("fn main() {}".into(), 0),
        ),
        (format!("cat {r}/repo/.env"), ("".into(), 1)),
        (format!("test -e {r}/other"), ("".into(), 1)),
        ("touch /new-at-root".into(), ("".into(), 1)),
        (
            "cat /etc/hostname > /dev/null && echo ok".into(),
            ("ok\n".into(), 0),
        ),
    ];
    for (script, expected) in table {
        assert_eq!(out(&p, &script), expected, "{script}");
    }
}

#[test]
fn write_implies_read_and_deeper_write_denies_hold() {
    let tree = Tree::new();
    tree.file("work/existing", "old");
    tree.file("work/locked/file", "keep");
    let allow: Vec<String> = sandbox::baseline_read();
    let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
    let p = tree.resolve(
        tree.rules(Default::Deny, &allow, &[]),
        tree.rules(Default::Deny, &["{}/work"], &["{}/work/locked"]),
        host(false, false),
    );
    let w = tree.path("work");
    let w = w.display();
    let table = [
        (
            format!(
                "cat {w}/existing && echo new > {w}/existing && mkdir {w}/d && mv {w}/existing {w}/d/moved && cat {w}/d/moved"
            ),
            ("oldnew\n".into(), 0),
        ),
        // Write-denied, and the read rules do not allow it either.
        (format!("cat {w}/locked/file"), ("".into(), 1)),
        (format!("echo x > {w}/locked/file"), ("".into(), 2)),
        (format!("touch {w}/locked/new"), ("".into(), 1)),
        (format!("rm {w}/locked/file"), ("".into(), 1)),
    ];
    for (script, expected) in table {
        assert_eq!(out(&p, &script), expected, "{script}");
    }
    assert_eq!(
        std::fs::read_to_string(tree.path("work/d/moved")).unwrap(),
        "new\n"
    );
    assert_eq!(
        std::fs::read_to_string(tree.path("work/locked/file")).unwrap(),
        "keep"
    );
}

#[test]
fn the_state_dir_is_denied_whatever_the_policy_says() {
    let tree = Tree::new();
    let state = tree.path("state");
    let p = tree.resolve(
        tree.rules(Default::Allow, &["{}/state"], &[]),
        tree.rules(Default::Deny, &["{}"], &[]),
        host(false, false),
    );
    let s = state.display();
    let table = [
        (format!("cat {s}/credentials.json"), ("".into(), 1)),
        (format!("ls -A {s}"), ("".into(), 0)),
        (format!("touch {s}/new"), ("".into(), 1)),
        (
            format!("touch {}/beside", tree.root.display()),
            ("".into(), 0),
        ),
    ];
    for (script, expected) in table {
        assert_eq!(out(&p, &script), expected, "{script}");
    }
    assert_eq!(
        std::fs::read_to_string(state.join("credentials.json")).unwrap(),
        "{\"token\":1}"
    );
    assert!(!state.join("new").exists());
}

#[test]
fn a_missing_deny_path_gets_a_placeholder_for_the_run_only() {
    let tree = Tree::new();
    let repo = tree.dir("repo");
    let p = tree.resolve(
        read_all(&tree),
        tree.rules(
            Default::Deny,
            &["{}/repo"],
            &["{}/repo/.git/hooks", "{}/repo/.env"],
        ),
        host(false, false),
    );
    let r = repo.display();
    let table = [
        (format!("mkdir -p {r}/.git/hooks"), ("".into(), 1)),
        (
            format!("ls -A {r}/.git; test -d {r}/.git && echo dir"),
            ("dir\n".into(), 0),
        ),
        (format!("echo TOKEN > {r}/.env"), ("".into(), 2)),
        (format!("rmdir {r}/.git"), ("".into(), 1)),
        (format!("touch {r}/allowed && echo ok"), ("ok\n".into(), 0)),
    ];
    for (script, expected) in table {
        assert_eq!(out(&p, &script), expected, "{script}");
    }
    let mut left: Vec<String> = std::fs::read_dir(&repo)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["allowed"]);
    let records = std::fs::read_dir(tree.path("state/placeholders"))
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(records, 0);
}

#[test]
fn the_placeholder_exists_on_the_host_while_the_command_runs() {
    let tree = Tree::new();
    tree.dir("repo");
    let p = tree.resolve(
        read_all(&tree),
        tree.rules(Default::Deny, &["{}/repo"], &["{}/repo/.git/hooks"]),
        host(false, false),
    );
    let mut started = start(&p, None, &["/bin/sh", "-c", "echo up; read line"], &[]);
    let mut stdout = BufReader::new(started.child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "up\n");
    let git = tree.path("repo/.git");
    assert!(git.is_dir());
    assert!(std::fs::metadata(&git).unwrap().permissions().readonly());
    drop(started.child.stdin.take());
    started.child.wait().unwrap();
    drop(started);
    assert!(!git.exists());
}

#[test]
fn syscalls_that_escape_the_sandbox_are_refused() {
    let tree = Tree::new();
    let p = tree.resolve(read_all(&tree), write_none(&tree), host(true, true));
    let table = [
        ("io_uring", "EPERM"),
        ("unshare-user", "EPERM"),
        ("ptrace", "EPERM"),
    ];
    for (action, expected) in table {
        assert_eq!(act(&p, action, ""), expected, "{action}");
    }
    let (no_new_privs, _) = out(&p, "grep NoNewPrivs /proc/self/status");
    assert_eq!(no_new_privs, "NoNewPrivs:\t1\n");
}

#[test]
fn unix_sockets_and_local_bind_follow_the_policy() {
    let tree = Tree::new();
    let sockets = tree.dir("sockets");
    let write = || tree.rules(Default::Deny, &["{}/sockets"], &[]);
    // (localBind, unixSockets) -> tcp bind, udp bind, unix bind, socketpair
    let table: [((bool, bool), [&str; 4]); 4] = [
        ((false, false), ["EPERM", "EPERM", "EPERM", "EPERM"]),
        ((false, true), ["EACCES", "ok", "ok", "ok"]),
        ((true, false), ["ok", "ok", "EPERM", "EPERM"]),
        ((true, true), ["ok", "ok", "ok", "ok"]),
    ];
    for (n, ((local_bind, unix_sockets), expected)) in table.into_iter().enumerate() {
        for network in [
            host(local_bind, unix_sockets),
            isolated(local_bind, unix_sockets),
        ] {
            let p = tree.resolve(read_all(&tree), write(), network.clone());
            let socket = sockets.join(format!("s{n}-{}", matches!(network, Network::Host { .. })));
            let got = [
                act(&p, "tcp", ""),
                act(&p, "udp", ""),
                act(&p, "unix", socket.to_str().unwrap()),
                act(&p, "socketpair", ""),
            ];
            assert_eq!(got, expected, "{network:?}");
        }
    }
}

#[test]
fn isolated_without_a_proxy_reaches_nothing() {
    let tree = Tree::new();
    let p = tree.resolve(read_all(&tree), write_none(&tree), isolated(false, false));
    assert_eq!(act(&p, "connect", "1.1.1.1:443"), "ENETUNREACH");
    assert_eq!(act(&p, "vsock", ""), "EPERM");
    let (routes, _) = out(&p, "cat /proc/net/route | wc -l");
    assert_eq!(routes, "1\n");
}

/// A stub proxy on a Unix socket that forwards every connection to `upstream`.
fn stub_proxy(path: &Path, upstream: std::net::SocketAddr) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let mut client = client.unwrap();
            let mut server = TcpStream::connect(upstream).unwrap();
            let mut client_in = client.try_clone().unwrap();
            let mut server_out = server.try_clone().unwrap();
            std::thread::spawn(move || std::io::copy(&mut client_in, &mut server_out));
            let _ = std::io::copy(&mut server, &mut client);
            let _ = client.shutdown(std::net::Shutdown::Write);
        }
    });
}

/// An HTTP server that answers every request with `body` and closes.
fn http_server(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = write!(stream, "HTTP/1.0 200 OK\r\n\r\n{body}");
        }
    });
    addr
}

#[test]
fn isolated_reaches_the_proxies_through_the_bridge() {
    // Unix socket paths are short (108 bytes), so this tree lives in /tmp.
    let tree = Tree::in_dir(Path::new("/tmp"));
    let net_dir = tree.dir("state/net/e_1");
    let server = http_server("through the bridge");
    let (http, socks) = (net_dir.join("http.sock"), net_dir.join("socks.sock"));
    stub_proxy(&http, server);
    stub_proxy(&socks, server);
    let p = tree.resolve(read_all(&tree), write_none(&tree), isolated(false, false));
    let net = || {
        Some(NetPlan {
            http: Endpoint::Unix(http.clone()),
            socks: Endpoint::Unix(socks.clone()),
        })
    };
    assert_eq!(
        act_with(&p, net(), "http-get", "127.0.0.1:3128"),
        "through the bridge"
    );
    assert_eq!(
        act_with(&p, net(), "http-get", "127.0.0.1:1080"),
        "through the bridge"
    );
    assert_eq!(
        act_with(&p, net(), "connect", &server.to_string()),
        "Connection refused (os error 111)"
    );
}

/// A SOCKS5 proxy on a Unix socket that accepts any CONNECT and answers with the target it got.
fn stub_socks(path: &Path) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let mut client = client.unwrap();
            let mut head = [0u8; 3];
            client.read_exact(&mut head).unwrap();
            client.write_all(&[5, 0]).unwrap();
            let mut request = [0u8; 5];
            client.read_exact(&mut request).unwrap();
            let mut name = vec![0u8; request[4] as usize + 2];
            client.read_exact(&mut name).unwrap();
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            let host = String::from_utf8_lossy(&name[..name.len() - 2]).into_owned();
            client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            let _ = write!(client, "connected to {host}:{port}");
        }
    });
}

#[test]
fn connect_runs_inside_an_isolated_sandbox_through_the_bridge() {
    // Unix socket paths are short (108 bytes), so this tree lives in /tmp.
    let tree = Tree::in_dir(Path::new("/tmp"));
    let net_dir = tree.dir("state/net/1");
    let (http, socks) = (net_dir.join("http.sock"), net_dir.join("socks.sock"));
    stub_socks(&socks);
    let _http = UnixListener::bind(&http).unwrap();
    let p = tree.resolve(read_all(&tree), write_none(&tree), isolated(false, false));
    let net = NetPlan {
        http: Endpoint::Unix(http),
        socks: Endpoint::Unix(socks),
    };
    let run = run(
        &p,
        Some(net),
        &[EXE, "__connect", "github.com", "22"],
        &[("ALL_PROXY", "socks5h://127.0.0.1:1080")],
    );
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (Some(0), "connected to github.com:22"),
        "{run:?}"
    );
}

#[test]
fn tcp_open_reaches_a_listener_inside_the_namespace() {
    let tree = Tree::new();
    let p = tree.resolve(read_all(&tree), write_none(&tree), isolated(true, false));
    let mut started = start(&p, None, &child_argv(), &[(ACTION_VAR, "serve")]);
    let mut stdout = BufReader::new(started.child.stdout.take().unwrap());
    let port: u16 = loop {
        let mut line = String::new();
        assert_ne!(
            stdout.read_line(&mut line).unwrap(),
            0,
            "the command exited"
        );
        if let Some((_, port)) = line.split_once("PORT ") {
            break port.trim().parse().unwrap();
        }
    };
    // The namespace's port is free on the host, unless another process there took the same
    // number; a host listener on it must not be the one tcp.open reaches.
    let _host_listener = TcpListener::bind(("127.0.0.1", port));
    let netns = started
        .netns
        .as_ref()
        .expect("isolated with localBind has a control");
    assert_eq!(
        netns
            .connect(port.wrapping_add(1))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ECONNREFUSED)
    );
    let mut stream = netns.connect(port).unwrap();
    let mut greeting = String::new();
    stream.read_to_string(&mut greeting).unwrap();
    assert_eq!(greeting, "hello from inside");
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert_eq!(result_of(&rest).as_deref(), Some("served"));
    started.child.wait().unwrap();
    assert!(netns.connect(port).is_err());
}

#[test]
fn sigterm_to_the_process_group_reaches_the_command() {
    let tree = Tree::new();
    for network in [host(false, false), isolated(true, false)] {
        let p = tree.resolve(read_all(&tree), write_none(&tree), network.clone());
        let script = "trap 'echo got TERM; exit 3' TERM; echo ready; while :; do sleep 0.1; done";
        let mut started = start(
            &p,
            None,
            &["/bin/sh", "-c", script],
            &[("PATH", "/usr/bin:/bin")],
        );
        let mut stdout = BufReader::new(started.child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        // SAFETY: killpg has no memory effects; the group is the child's own session.
        assert_eq!(
            unsafe { libc::killpg(started.child.id() as i32, libc::SIGTERM) },
            0
        );
        let mut rest = String::new();
        stdout.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "got TERM\n", "{network:?}");
        assert_eq!(started.child.wait().unwrap().code(), Some(3), "{network:?}");
    }
}

#[test]
fn a_command_killed_by_a_signal_exits_with_128_plus_it() {
    let tree = Tree::new();
    for network in [host(false, false), isolated(true, false)] {
        let p = tree.resolve(read_all(&tree), write_none(&tree), network.clone());
        assert_eq!(sh(&p, "kill -KILL $$").code, Some(137), "{network:?}");
    }
}
