//! The Windows backend on a machine where `happy-supervisor install-sandbox` has run: the built
//! binary as the broker and the runner.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::windows::io::{AsRawHandle as _, IntoRawHandle as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use happy_supervisor::ErrorKind;
use happy_supervisor::fs::{self, FsRequest, FsResponse};
use happy_supervisor::helper::{self, Job, JobOp};
use happy_supervisor::policy::{
    Confinement, Default, HostRules, Network, Policy, ResolvedPolicy, RuleSet,
};
use happy_supervisor::protocol::{
    AbsPath, Argv, Bytes, FsReadParams, FsReadResult, FsRenameParams, FsWriteParams, Mechanism,
    SandboxStatus, WriteMode,
};
use happy_supervisor::sandbox::{self, Endpoint, NetPlan};
use windows_sys::Win32::Foundation::{
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Exit 0, with this stdout (CRLF as LF).
    Ok(String),
    /// Refused: `Access is denied` (ERROR_ACCESS_DENIED), WSAEACCES, `dir` finding nothing in a
    /// directory it may not list (every one listed here has entries), or a permission-denied
    /// status from the helper. `move` exits 0 even when refused.
    Denied,
    /// Another non-zero exit.
    Exit(i32),
}

use Outcome::Denied;

fn ok(stdout: &str) -> Outcome {
    Outcome::Ok(stdout.to_string())
}

#[derive(Clone, Copy)]
enum Net {
    Host,
    Isolated,
}

/// One row's policy: read and write allow/deny lists under a deny default.
#[derive(Clone)]
struct Grants {
    read: Vec<PathBuf>,
    read_deny: Vec<PathBuf>,
    write: Vec<PathBuf>,
    write_deny: Vec<PathBuf>,
    write_default: Default,
    net: Net,
    local_bind: bool,
    /// Written, and named by TEMP and TMP.
    temp: Option<PathBuf>,
}

fn grants(read: &[&Path], write: &[&Path]) -> Grants {
    let owned = |paths: &[&Path]| paths.iter().map(|p| p.to_path_buf()).collect::<Vec<_>>();
    let mut readable = owned(read);
    readable.extend(owned(write));
    Grants {
        read: readable,
        read_deny: Vec::new(),
        write: owned(write),
        write_deny: Vec::new(),
        write_default: Default::Deny,
        net: Net::Host,
        local_bind: false,
        temp: None,
    }
}

impl Grants {
    fn read_deny(mut self, path: &Path) -> Grants {
        self.read_deny.push(path.to_path_buf());
        self
    }

    fn write_deny(mut self, path: &Path) -> Grants {
        self.write_deny.push(path.to_path_buf());
        self
    }

    fn write_anywhere(mut self) -> Grants {
        self.write_default = Default::Allow;
        self
    }

    fn isolated(mut self) -> Grants {
        self.net = Net::Isolated;
        self
    }

    fn local_bind(mut self) -> Grants {
        self.local_bind = true;
        self
    }

    /// PowerShell runs in ConstrainedLanguage mode when it cannot write its temp directory.
    fn temp(mut self, path: &Path) -> Grants {
        self.read.push(path.to_path_buf());
        self.write.push(path.to_path_buf());
        self.temp = Some(path.to_path_buf());
        self
    }

    fn policy(&self) -> Policy {
        let rules = |default, allow: &[PathBuf], deny: &[PathBuf]| RuleSet {
            default,
            allow: allow.to_vec(),
            deny: deny.to_vec(),
        };
        Policy {
            read: rules(Default::Deny, &self.read, &self.read_deny),
            write: rules(self.write_default, &self.write, &self.write_deny),
            network: match self.net {
                Net::Host => Network::Host {
                    local_bind: self.local_bind,
                    unix_sockets: false,
                },
                Net::Isolated => Network::Isolated {
                    egress: HostRules {
                        default: Default::Allow,
                        allow: Vec::new(),
                        deny: Vec::new(),
                    },
                    ports: None,
                    local_bind: self.local_bind,
                    unix_sockets: false,
                },
            },
        }
    }
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap()
}

fn cmd(script: String) -> Vec<String> {
    vec![
        format!(r"{}\System32\cmd.exe", system_root()),
        "/d".to_string(),
        "/c".to_string(),
        script,
    ]
}

fn curl(args: &[&str]) -> Vec<String> {
    let mut argv = vec![
        format!(r"{}\System32\curl.exe", system_root()),
        "-sS".to_string(),
        "--max-time".to_string(),
        "15".to_string(),
    ];
    argv.extend(args.iter().map(|arg| arg.to_string()));
    argv
}

/// Git for Windows, whose HTTPS is OpenSSL's when asked.
fn git_ls_remote(url: &str, reference: &str) -> Vec<String> {
    vec![
        r"C:\Program Files\Git\cmd\git.exe".to_string(),
        "-c".to_string(),
        "http.sslBackend=openssl".to_string(),
        "ls-remote".to_string(),
        url.to_string(),
        reference.to_string(),
    ]
}

fn powershell(script: &str) -> Vec<String> {
    vec![
        format!(
            r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
            system_root()
        ),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        script.to_string(),
    ]
}

const TCP_LISTEN: &str = "$ErrorActionPreference = 'Stop'; $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start(); 'bound'";

/// One test at a time, so each lease takes the first account and a test can tell which one
/// a killed broker held.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A broker started on a job, until it exits.
struct Started {
    child: std::process::Child,
    status: std::io::PipeReader,
    _placeholders: sandbox::Placeholders,
}

/// Starts `argv` through `sandbox::prepare` and the broker, the way `exec.start` does: the
/// status pipe's write end is duplicated into the broker and named in the stdin preamble.
fn start(grants: &Grants, state: &Path, net: Option<NetPlan>, argv: &[String]) -> Started {
    helper::set_exe(PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor")));
    let root = system_root();
    let mut env = BTreeMap::from([
        ("SystemRoot".to_string(), root.clone()),
        ("windir".to_string(), root.clone()),
        ("SystemDrive".to_string(), root[..2].to_string()),
        ("PATH".to_string(), format!(r"{root}\System32;{root}")),
    ]);
    if let Some(temp) = &grants.temp {
        for name in ["TEMP", "TMP"] {
            env.insert(name.to_string(), temp.to_str().unwrap().to_string());
        }
    }
    let job = Job {
        policy: ResolvedPolicy::resolve(&grants.policy(), state).unwrap(),
        op: JobOp::Exec {
            argv: Argv::try_from(argv.to_vec()).unwrap(),
            cwd: AbsPath::try_from(root.as_str()).unwrap(),
            env,
        },
    };
    let exe = helper::exe().unwrap();
    let plan = sandbox::Plan {
        policy: &job.policy,
        net,
        exe: &exe,
    };
    let sandbox::Prepared {
        mut command,
        placeholders,
        ..
    } = sandbox::prepare(&plan, &job).unwrap();
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (status_reader, status_writer) = std::io::pipe().unwrap();
    let mut theirs: HANDLE = std::ptr::null_mut();
    // SAFETY: both process handles are open; the call closes our pipe handle.
    let duplicated = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            status_writer.into_raw_handle() as HANDLE,
            child.as_raw_handle() as HANDLE,
            &mut theirs,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        )
    };
    assert_ne!(duplicated, 0, "{}", std::io::Error::last_os_error());
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(helper::STATUS_MAGIC).unwrap();
    stdin.write_all(&(theirs as u64).to_le_bytes()).unwrap();
    stdin.write_all(&helper::encode_job(&job)).unwrap();
    drop(stdin);
    Started {
        child,
        status: status_reader,
        _placeholders: placeholders,
    }
}

fn run(grants: &Grants, state: &Path, net: Option<NetPlan>, argv: &[String]) -> (Outcome, String) {
    let mut started = start(grants, state, net, argv);
    let mut status = Vec::new();
    started.status.read_to_end(&mut status).unwrap();
    let output = started.child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let denied = [
        "Access is denied",
        "in a way forbidden by its",
        "File Not Found",
    ]
    .iter()
    .any(|text| stderr.contains(text) || stdout.contains(text));
    let outcome = match helper::parse_exec_status(&status) {
        Err(err) if err.kind == ErrorKind::PermissionDenied => Denied,
        Err(err) => return (Outcome::Exit(-1), err.to_string()),
        Ok(()) if denied => Denied,
        Ok(()) if output.status.success() => Outcome::Ok(stdout.clone()),
        Ok(()) => Outcome::Exit(output.status.code().unwrap_or(-1)),
    };
    (outcome, format!("stdout: {stdout}\nstderr: {stderr}"))
}

struct Tree {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    /// Under the user's own temp directory, which other local accounts cannot read.
    fn new() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let root = happy_supervisor::policy::canonicalize(dir.path()).unwrap();
        for sub in [
            "data/private",
            "out/locked",
            "outside/inner",
            "state",
            "tmp",
        ] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(root.join("data/file.txt"), "data\n").unwrap();
        std::fs::write(root.join("data/private/key.txt"), "key\n").unwrap();
        std::fs::write(root.join("outside/secret.txt"), "secret\n").unwrap();
        std::fs::write(root.join("outside/inner/open.txt"), "open\n").unwrap();
        std::fs::write(root.join("out/locked/keep.txt"), "keep\n").unwrap();
        std::fs::write(root.join("state/credentials.json"), "{}\n").unwrap();
        Tree { _dir: dir, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        rel.split('/')
            .fold(self.root.clone(), |path, part| path.join(part))
    }

    fn show(&self, rel: &str) -> String {
        self.path(rel).to_str().unwrap().to_string()
    }
}

/// An HTTP server answering every request with `ok`.
fn serve(listener: TcpListener) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
            );
        }
    });
}

/// A loopback listener on the first free port in `ports`.
fn bind_in(ports: std::ops::RangeInclusive<u16>) -> TcpListener {
    ports
        .into_iter()
        .find_map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok())
        .expect("a free port in the proxy range")
}

#[test]
fn the_probe_reports_an_installed_sandbox() {
    let _serial = serial();
    helper::set_exe(PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor")));
    let info = sandbox::probe();
    assert_eq!(info.status, SandboxStatus::Available);
    assert_eq!(info.mechanism, Mechanism::Windows);
    assert_eq!(info.gaps.len(), 13);
    assert_eq!(sandbox::windows::proxy_ports(), Some(47800..=47999));
}

#[test]
fn policy_combinations_and_their_outcomes() {
    let _serial = serial();
    let tree = Tree::new();
    let t = |rel: &str| tree.path(rel);
    let p = |rel: &str| tree.show(rel);
    let state = t("state");

    let ports = sandbox::windows::proxy_ports().unwrap();
    let in_range = bind_in(ports.clone());
    let in_port = in_range.local_addr().unwrap().port();
    serve(in_range);
    let out_range = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let out_port = out_range.local_addr().unwrap().port();
    assert!(!ports.contains(&out_port));
    serve(out_range);
    let in_url = format!("http://127.0.0.1:{in_port}/");
    let out_url = format!("http://127.0.0.1:{out_port}/");
    let proxy = |port: u16| Endpoint::Tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let net_plan = NetPlan {
        http: proxy(in_port),
        socks: proxy(in_port),
    };

    let none = || grants(&[], &[]);
    let rows: Vec<(&str, Grants, Vec<String>, Outcome)> = vec![
        (
            "read: a granted directory",
            grants(&[&t("data")], &[]),
            cmd(format!("type {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "read: nothing granted",
            none(),
            cmd(format!("type {}", p("data/file.txt"))),
            Denied,
        ),
        (
            "read: the directory is not listable without a grant",
            none(),
            cmd(format!("dir /b {}", p("data"))),
            Denied,
        ),
        (
            "read: a deny inside a granted directory",
            grants(&[&t("data")], &[]).read_deny(&t("data/private")),
            cmd(format!("type {}", p("data/private/key.txt"))),
            Denied,
        ),
        (
            "read: a deeper allow inside a deny",
            grants(&[&t("outside/inner")], &[]).read_deny(&t("outside")),
            cmd(format!("type {}", p("outside/inner/open.txt"))),
            ok("open\n"),
        ),
        (
            "read: the deny around that deeper allow",
            grants(&[&t("outside/inner")], &[]).read_deny(&t("outside")),
            cmd(format!("type {}", p("outside/secret.txt"))),
            Denied,
        ),
        (
            "write: a granted directory",
            grants(&[], &[&t("out")]),
            cmd(format!("echo new>{0}\\a&& type {0}\\a", p("out"))),
            ok("new\n"),
        ),
        (
            "write: a read grant does not write",
            grants(&[&t("out")], &[]),
            cmd(format!("echo new>{}\\b", p("out"))),
            Denied,
        ),
        (
            "write: a deny inside a granted directory",
            grants(&[], &[&t("out")]).write_deny(&t("out/locked")),
            cmd(format!("echo new>{}\\c", p("out/locked"))),
            Denied,
        ),
        (
            "write: the denied directory stays readable",
            grants(&[], &[&t("out")]).write_deny(&t("out/locked")),
            cmd(format!("type {}", p("out/locked/keep.txt"))),
            ok("keep\n"),
        ),
        (
            "missing: a denied directory below a write grant cannot be made",
            grants(&[], &[&t("out")]).write_deny(&t("out/later/deep")),
            cmd(format!("mkdir {}", p("out/later/deep"))),
            Denied,
        ),
        (
            "missing: a denied file below a write grant cannot be written",
            grants(&[], &[&t("out")]).write_deny(&t("out/never.txt")),
            cmd(format!("echo x>{}", p("out/never.txt"))),
            Denied,
        ),
        (
            "write: no rename out of a read grant",
            grants(&[&t("data")], &[&t("out")]),
            cmd(format!("move {} {}", p("data/file.txt"), p("out"))),
            Denied,
        ),
        (
            "state: unreadable inside a write grant",
            grants(&[], &[&tree.root]),
            cmd(format!("type {}", p("state/credentials.json"))),
            Denied,
        ),
        (
            "state: not listable",
            grants(&[], &[&tree.root]),
            cmd(format!("dir /b {}", p("state"))),
            Denied,
        ),
        (
            "state: unwritable",
            grants(&[], &[&tree.root]),
            cmd(format!("echo x>{}\\new", p("state"))),
            Denied,
        ),
        (
            "state: cannot be renamed away",
            grants(&[], &[&tree.root]),
            cmd(format!("move {} {}", p("state"), p("stolen"))),
            Denied,
        ),
        (
            "state: its siblings stay granted",
            grants(&[], &[&tree.root]),
            cmd(format!("type {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "children: a grandchild is still confined",
            grants(&[&t("data")], &[]),
            cmd(format!("cmd /d /c type {}", p("outside/secret.txt"))),
            Denied,
        ),
        (
            "children: a grandchild keeps the grants",
            grants(&[&t("data")], &[]),
            cmd(format!("cmd /d /c type {}", p("data/file.txt"))),
            ok("data\n"),
        ),
        (
            "host: loopback outside the proxy range",
            none(),
            curl(&[&out_url]),
            ok("ok\n"),
        ),
        (
            "host: TLS through Schannel, write-restricted",
            none(),
            curl(&["-o", "NUL", "https://example.com"]),
            Outcome::Exit(35),
        ),
        (
            "host: TLS through Schannel under write.default allow",
            none().write_anywhere(),
            curl(&["-o", "NUL", "-w", "%{http_code}", "https://example.com"]),
            ok("200"),
        ),
        (
            "host: TLS through OpenSSL, write-restricted",
            none(),
            git_ls_remote(
                "https://github.com/octocat/Hello-World",
                "refs/heads/master",
            ),
            ok("7fd1a60b01f91b314f59955a4e4d4e80d8edf11d\trefs/heads/master\n"),
        ),
        (
            "isolated: the internet, directly",
            none().isolated(),
            curl(&["-o", "NUL", "https://example.com"]),
            Outcome::Exit(7),
        ),
        (
            "isolated: loopback inside the proxy range",
            none().isolated(),
            curl(&[&in_url]),
            ok("ok\n"),
        ),
        (
            "isolated: loopback outside the proxy range",
            none().isolated(),
            curl(&[&out_url]),
            Outcome::Exit(7),
        ),
        (
            "isolated with localBind: loopback outside the proxy range (a gap)",
            none().isolated().local_bind(),
            curl(&[&out_url]),
            ok("ok\n"),
        ),
        (
            "isolated: names still resolve (a gap)",
            none().isolated(),
            cmd(
                "ping -n 1 -w 500 example.com | findstr /b Pinging >NUL && echo resolved"
                    .to_string(),
            ),
            ok("resolved\n"),
        ),
        (
            "listen: without localBind",
            none().temp(&t("tmp")),
            powershell(TCP_LISTEN),
            Denied,
        ),
        (
            "listen: with localBind",
            none().local_bind().temp(&t("tmp")),
            powershell(TCP_LISTEN),
            ok("bound\n"),
        ),
        (
            "listen: isolated with localBind",
            none().isolated().local_bind().temp(&t("tmp")),
            powershell(TCP_LISTEN),
            ok("bound\n"),
        ),
    ];

    let mut failures = Vec::new();
    for (label, grants, argv, expected) in rows {
        let net = matches!(grants.net, Net::Isolated).then(|| net_plan.clone());
        let started = Instant::now();
        let (outcome, output) = run(&grants, &state, net, &argv);
        eprintln!("{label}: {outcome:?} in {:?}", started.elapsed());
        if outcome != expected {
            failures.push(format!(
                "{label}: expected {expected:?}, got {outcome:?}\n{output}"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    assert_eq!(
        std::fs::read_to_string(t("data/file.txt")).unwrap(),
        "data\n"
    );
    assert!(
        !t("out/later").exists(),
        "the placeholder directory is gone"
    );
    assert!(!t("out/never.txt").exists(), "the placeholder file is gone");
    assert_eq!(
        std::fs::read_to_string(t("state/credentials.json")).unwrap(),
        "{}\n"
    );
    assert_eq!(
        std::fs::read_dir(t("out/locked")).unwrap().count(),
        1,
        "only keep.txt"
    );
}

/// Every ACE is inherited by the whole tree below its path, which Windows writes file by file
/// when the ACE is added and again when it is revoked.
#[test]
fn a_grant_reaches_the_bottom_of_a_large_tree() {
    let _serial = serial();
    let tree = Tree::new();
    let big = tree.path("big");
    for dir in 0..20 {
        let dir = big.join(format!("d{dir}"));
        std::fs::create_dir_all(&dir).unwrap();
        for file in 0..100 {
            std::fs::write(dir.join(format!("f{file}")), "x").unwrap();
        }
    }
    let deep = big.join(r"d7\a\b\c");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("leaf.txt"), "leaf\n").unwrap();
    let started = Instant::now();
    let (outcome, output) = run(
        &grants(&[], &[&big]),
        &tree.path("state"),
        None,
        &cmd(format!(
            r"type {0}\leaf.txt&& echo more>{0}\new.txt",
            deep.display()
        )),
    );
    eprintln!("2001 files: {:?}", started.elapsed());
    assert_eq!(outcome, ok("leaf\n"), "{output}");
    assert_eq!(
        std::fs::read_to_string(deep.join("new.txt")).unwrap(),
        "more\r\n"
    );
}

#[test]
fn concurrent_execs_each_lease_an_account() {
    let _serial = serial();
    let tree = Tree::new();
    let state = tree.path("state");
    let started: Vec<Started> = (0..4)
        .map(|i| {
            let out = tree.path(&format!("out/c{i}"));
            std::fs::create_dir(&out).unwrap();
            start(
                &grants(&[], &[&out]),
                &state,
                None,
                &cmd(format!(
                    r"echo c{i}>{}\n&& ping -n 2 127.0.0.1 >NUL",
                    out.display()
                )),
            )
        })
        .collect();
    for (i, mut started) in started.into_iter().enumerate() {
        let mut status = Vec::new();
        started.status.read_to_end(&mut status).unwrap();
        let output = started.child.wait_with_output().unwrap();
        assert_eq!(
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
            (Some(0), "".into()),
            "exec {i}"
        );
        assert_eq!(
            std::fs::read_to_string(tree.path(&format!("out/c{i}/n"))).unwrap(),
            format!("c{i}\r\n")
        );
    }
}

fn icacls(path: &Path) -> String {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A broker killed while its command runs leaves its ACEs; the next lease of that account
/// revokes them from the journal before adding its own.
#[test]
fn the_next_lease_revokes_what_a_killed_broker_left() {
    let _serial = serial();
    let tree = Tree::new();
    let out = tree.path("out");
    let mut started = start(
        &grants(&[], &[&out]),
        &tree.path("state"),
        None,
        &cmd(r"echo started& ping -n 60 127.0.0.1 >NUL".to_string()),
    );
    let mut line = [0u8; 9];
    started
        .child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut line)
        .unwrap();
    assert_eq!(&line, b"started\r\n");
    assert!(icacls(&out).contains("happy-sbx-"), "{}", icacls(&out));
    started.child.kill().unwrap();
    started.child.wait().unwrap();
    assert!(
        icacls(&out).contains("happy-sbx-"),
        "the broker revoked nothing"
    );

    let data = tree.path("data");
    let (outcome, output) = run(
        &grants(&[&data], &[]),
        &tree.path("state"),
        None,
        &cmd(format!(r"echo x>{}\after", out.display())),
    );
    assert_eq!(outcome, Denied, "{output}");
    assert!(!icacls(&out).contains("happy-sbx-"), "{}", icacls(&out));
    assert!(!icacls(&data).contains("happy-sbx-"), "{}", icacls(&data));
}

fn confinement(tree: &Tree, read: &[&str], write: &[&str]) -> Confinement {
    let paths = |rels: &[&str]| rels.iter().map(|rel| tree.path(rel)).collect::<Vec<_>>();
    let mut grants = grants(&[], &[]);
    grants.read = paths(read);
    grants.read.extend(paths(write));
    grants.write = paths(write);
    Confinement::Sandboxed(ResolvedPolicy::resolve(&grants.policy(), &tree.path("state")).unwrap())
}

fn abs(path: &Path) -> AbsPath {
    AbsPath::try_from(path.to_str().unwrap()).unwrap()
}

#[test]
fn file_operations_run_as_the_sandbox() {
    let _serial = serial();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        helper::set_exe(PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor")));
        let tree = Tree::new();
        let read = |rel: &str| {
            FsRequest::Read(FsReadParams {
                path: abs(&tree.path(rel)),
                offset: 0,
                length: None,
            })
        };
        let write = |rel: &str| {
            FsRequest::Write(FsWriteParams {
                path: abs(&tree.path(rel)),
                data: Bytes::new(b"written".to_vec()),
                mode: WriteMode::Overwrite,
            })
        };

        match fs::handle(read("data/file.txt"), confinement(&tree, &["data"], &[])).await {
            Ok(FsResponse::Read(FsReadResult { data, .. })) => {
                assert_eq!(data.into_vec(), b"data\n")
            }
            other => panic!("read answered {other:?}"),
        }
        let denied = |result: Result<FsResponse, happy_supervisor::Error>| {
            result.map(|_| ()).map_err(|err| err.kind)
        };
        assert_eq!(
            denied(
                fs::handle(
                    read("outside/secret.txt"),
                    confinement(&tree, &["data"], &[])
                )
                .await
            ),
            Err(ErrorKind::PermissionDenied)
        );
        assert_eq!(
            denied(fs::handle(write("out/new.txt"), confinement(&tree, &["out"], &[])).await),
            Err(ErrorKind::PermissionDenied)
        );
        assert_eq!(
            denied(fs::handle(write("out/new.txt"), confinement(&tree, &[], &["out"])).await),
            Ok(())
        );
        let rename = |from: &str, to: &str| {
            FsRequest::Rename(FsRenameParams {
                from: abs(&tree.path(from)),
                to: abs(&tree.path(to)),
            })
        };
        assert_eq!(
            denied(
                fs::handle(
                    rename("out/new.txt", "out/locked/moved.txt"),
                    confinement(&tree, &[], &["out"])
                )
                .await
            ),
            Ok(())
        );
        assert_eq!(
            denied(
                fs::handle(
                    rename("out/locked", "out/renamed"),
                    confinement(&tree, &[], &["out"])
                )
                .await
            ),
            Ok(())
        );
        assert_eq!(
            denied(
                fs::handle(
                    rename("data/file.txt", "out/stolen.txt"),
                    confinement(&tree, &["data"], &["out"])
                )
                .await
            ),
            Err(ErrorKind::PermissionDenied)
        );
        assert_eq!(
            std::fs::read_to_string(tree.path("out/renamed/moved.txt")).unwrap(),
            "written"
        );
        assert!(tree.path("data/file.txt").exists());
    });
}

/// `exec.start` itself: the status pipe through the preamble, stdin pumped through the broker
/// and the runner, the exit code back.
#[test]
fn exec_start_runs_through_the_broker() {
    use happy_supervisor::exec::ExecManager;
    use happy_supervisor::link::{ManualClock, NodeIdentity, Role, Session};
    use happy_supervisor::protocol::{
        ExecId, ExecLogParams, ExecStartParams, ExecState, ExecWriteParams, ExitStatus,
    };

    let _serial = serial();
    helper::set_exe(PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor")));
    let tree = Tree::new();
    let identity = NodeIdentity {
        node_id: "n_1".to_string(),
        installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
    };
    let (_session, outbox) = Session::new(Role::Node(identity), ManualClock::new(0));
    let exec = ExecManager::new(outbox);
    let root = system_root();
    let params = |exec_id: &str, argv: Vec<String>| -> ExecStartParams {
        serde_json::from_value(serde_json::json!({
            "execId": exec_id,
            "argv": argv,
            "cwd": root,
            "env": { "SystemRoot": root, "PATH": format!(r"{root}\System32") },
            "stdin": true,
        }))
        .unwrap()
    };
    let confinement = || confinement(&tree, &[], &["out"]);
    let id = |text: &str| ExecId::try_from(text).unwrap();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let exited = |exec_id: &str| {
            let exec_id = id(exec_id);
            let exec = &exec;
            async move {
                for _ in 0..1000 {
                    let state = exec
                        .list()
                        .into_iter()
                        .find(|summary| summary.exec_id == exec_id)
                        .map(|summary| summary.state);
                    if let Some(ExecState::Exited { exit }) = state {
                        return exit;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                panic!("{exec_id:?} did not exit");
            }
        };

        let mut argv = cmd(format!(
            r"echo inside& set /p line=& echo got !line!>{}\line.txt",
            tree.show("out")
        ));
        argv.insert(2, "/v:on".to_string());
        exec.start(params("w1", argv), confinement(), None)
            .await
            .unwrap();
        exec.write(ExecWriteParams {
            exec_id: id("w1"),
            data: Bytes::new(b"from stdin\r\n".to_vec()),
            eof: true,
        })
        .await
        .unwrap();
        assert_eq!(exited("w1").await, ExitStatus::Exited { code: 0 });
        let log = exec
            .log(ExecLogParams {
                exec_id: id("w1"),
                offset: 0,
                length: None,
            })
            .await
            .unwrap();
        assert_eq!(log.data.into_vec(), b"inside\r\n");

        let argv = cmd(format!(r"echo x>{}", tree.show("data/new.txt")));
        exec.start(params("w2", argv), confinement(), None)
            .await
            .unwrap();
        assert_eq!(exited("w2").await, ExitStatus::Exited { code: 1 });
        assert!(!tree.path("data/new.txt").exists());

        let argv = vec![r"C:\nonexistent\prog.exe".to_string()];
        let err = exec
            .start(params("w3", argv), confinement(), None)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotFound, "{err}");
    });
    assert_eq!(
        std::fs::read_to_string(tree.path("out/line.txt")).unwrap(),
        "got from stdin\r\n"
    );
}
