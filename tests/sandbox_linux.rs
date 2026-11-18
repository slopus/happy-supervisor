//! The Linux sandbox through the real helper binary: `sandbox::prepare` builds the command, and
//! the job goes over stdin with the exec status pipe on fd 3, as the exec module does.
#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use happy_supervisor::helper::{self, Job, JobOp};
use happy_supervisor::policy::{Policy, ResolvedPolicy};
use happy_supervisor::protocol::{AbsPath, Argv, Mechanism, SandboxStatus};
use happy_supervisor::{Error, ErrorKind, sandbox};

const EXE: &str = env!("CARGO_BIN_EXE_happy-supervisor");

/// Set in the environment of this test binary when it runs inside a sandbox as a command; see
/// [`child_action`].
const ACTION_VAR: &str = "HAPPY_SANDBOX_TEST_ACTION";
const ARG_VAR: &str = "HAPPY_SANDBOX_TEST_ARG";

#[derive(Debug)]
struct Run {
    started: Result<(), Error>,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// A tree of real paths to sandbox, and the state directory every job hides.
struct Tree {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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

    /// Every path below the root, with file contents, to compare before and after a run.
    fn snapshot(&self) -> BTreeSet<(PathBuf, Option<Vec<u8>>)> {
        fn walk(dir: &Path, out: &mut BTreeSet<(PathBuf, Option<Vec<u8>>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    out.insert((path.clone(), None));
                    walk(&path, out);
                } else if meta.is_file() {
                    out.insert((path.clone(), Some(std::fs::read(&path).unwrap())));
                } else {
                    out.insert((path, None));
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(&self.root, &mut out);
        out
    }
}

fn strings(paths: &[&Path]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.to_str().unwrap().to_string())
        .collect()
}

/// A policy with the node's baseline reads plus `read`, hiding `hidden`.
fn policy(
    read: &[&Path],
    write: &[&Path],
    local_bind: bool,
    unix_sockets: bool,
    hidden: &Path,
) -> ResolvedPolicy {
    let mut reads = sandbox::baseline_read();
    reads.extend(strings(read));
    let policy = Policy::new(reads, strings(write), local_bind, unix_sockets).unwrap();
    ResolvedPolicy::resolve(&policy, hidden)
}

fn run(policy: &ResolvedPolicy, argv: &[&str], env: &[(&str, &str)]) -> Run {
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
        },
    };
    let mut command = sandbox::prepare(&job).unwrap();
    let (mut status_reader, status_writer) = std::io::pipe().unwrap();
    let status_fd = status_writer.as_raw_fd();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: install_status_fd is async-signal-safe and runs in the forked child only.
    unsafe {
        command.pre_exec(move || helper::install_status_fd(status_fd));
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
    let output = child.wait_with_output().unwrap();
    Run {
        started: helper::parse_exec_status(&status),
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn sh(policy: &ResolvedPolicy, script: &str) -> Run {
    let run = run(
        policy,
        &["/bin/sh", "-c", script],
        &[("PATH", "/usr/bin:/bin")],
    );
    assert_eq!(run.started, Ok(()), "{run:?}");
    run
}

/// Runs `script` and returns its exit code, so a table of expectations reads as one line each.
fn code(policy: &ResolvedPolicy, script: &str) -> i32 {
    sh(policy, script).code.unwrap()
}

/// Runs this test binary inside the sandbox to perform one socket or signal operation, and
/// returns `ok` or the errno name it failed with.
fn act(policy: &ResolvedPolicy, action: &str, arg: &str) -> String {
    let me = std::env::current_exe().unwrap();
    let me = me.to_str().unwrap();
    let run = run(
        policy,
        &[
            me,
            "--exact",
            "child_action",
            "--nocapture",
            "--test-threads=1",
        ],
        &[(ACTION_VAR, action), (ARG_VAR, arg)],
    );
    assert_eq!(run.started, Ok(()), "{run:?}");
    // libtest has already printed "test child_action ... " on the same line.
    run.stdout
        .lines()
        .find_map(|line| line.split_once("RESULT ").map(|(_, result)| result))
        .unwrap_or_else(|| panic!("no result from {action}: {run:?}"))
        .to_string()
}

/// The sandboxed half of [`act`]. A no-op in a normal test run.
#[test]
fn child_action() {
    let Ok(action) = std::env::var(ACTION_VAR) else {
        return;
    };
    let arg = std::env::var(ARG_VAR).unwrap_or_default();
    let result = match action.as_str() {
        "tcp" => std::net::TcpListener::bind("127.0.0.1:0").map(drop),
        "tcp-unbound" => listen_unbound_tcp(),
        "udp" => std::net::UdpSocket::bind("127.0.0.1:0").map(drop),
        "unix" => std::os::unix::net::UnixListener::bind(&arg).map(drop),
        "abstract" => {
            use std::os::linux::net::SocketAddrExt as _;
            std::os::unix::net::SocketAddr::from_abstract_name(&arg)
                .and_then(|addr| std::os::unix::net::UnixListener::bind_addr(&addr))
                .map(drop)
        }
        "signal" => {
            // SAFETY: signal 0 only checks whether the signal could be sent.
            match unsafe { libc::kill(arg.parse().unwrap(), 0) } {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
        other => panic!("unknown action {other}"),
    };
    let result = match result {
        Ok(()) => "ok".to_string(),
        Err(err) => match err.raw_os_error() {
            Some(libc::EPERM) => "EPERM".to_string(),
            Some(libc::EACCES) => "EACCES".to_string(),
            _ => format!("{err}"),
        },
    };
    println!("RESULT {result}");
    std::process::exit(0);
}

fn listen_unbound_tcp() -> std::io::Result<()> {
    // SAFETY: plain socket calls on a descriptor this function owns and closes.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let listened = libc::listen(fd, 1);
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if listened == 0 { Ok(()) } else { Err(err) }
    }
}

fn this_test_binary() -> PathBuf {
    std::env::current_exe().unwrap()
}

fn landlock_abi() -> u32 {
    match sandbox::probe().mechanism {
        Mechanism::Landlock { abi: Some(abi) } => abi,
        other => panic!("no Landlock ABI: {other:?}"),
    }
}

#[test]
fn probe_runs_a_sandboxed_true() {
    helper::set_exe(EXE.into());
    let info = sandbox::probe();
    assert_eq!(info.status, SandboxStatus::Available);
    assert!(matches!(info.mechanism, Mechanism::Landlock { abi: Some(abi) } if abi >= 1));
    assert_eq!(info.baseline_read, sandbox::baseline_read());
}

#[test]
fn prepare_runs_this_binary_as_the_helper() {
    helper::set_exe(EXE.into());
    let tree = Tree::new();
    let job = Job {
        policy: policy(&[], &[], false, false, &tree.path("state")),
        op: JobOp::Exec {
            argv: Argv::try_from(vec!["/bin/true".to_string()]).unwrap(),
            cwd: AbsPath::try_from("/").unwrap(),
            env: BTreeMap::new(),
        },
    };
    let command = sandbox::prepare(&job).unwrap();
    assert_eq!(command.get_program(), EXE);
    assert_eq!(command.get_args().collect::<Vec<_>>(), ["__sandbox"]);
}

#[test]
fn a_command_outside_every_grant_does_not_start() {
    helper::set_exe(EXE.into());
    let tree = Tree::new();
    let nothing = ResolvedPolicy::resolve(
        &Policy::new(vec![], vec![], true, true).unwrap(),
        &tree.path("state"),
    );
    let run = run(&nothing, &["/bin/true"], &[]);
    assert_eq!(
        run.started,
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "Permission denied (os error 13)"
        ))
    );
    assert_eq!(run.code, Some(127));
}

#[test]
fn read_grant_allows_reading_only_inside_it() {
    let tree = Tree::new();
    tree.file("granted/note", "hello");
    tree.file("other/secret", "s3cret");
    let p = policy(
        &[&tree.path("granted")],
        &[],
        false,
        false,
        &tree.path("state"),
    );
    let granted = tree.path("granted");
    let other = tree.path("other");

    let read = sh(&p, &format!("cat {}/note", granted.display()));
    assert_eq!((read.code, read.stdout.as_str()), (Some(0), "hello"));
    assert_eq!(
        sh(&p, &format!("ls {}", granted.display())).stdout,
        "note\n"
    );

    let denied = sh(&p, &format!("cat {}/secret", other.display()));
    assert_eq!(denied.code, Some(1));
    assert!(denied.stderr.contains("Permission denied"), "{denied:?}");
    assert_eq!(code(&p, &format!("ls {}", other.display())), 2);

    assert_ne!(code(&p, &format!("echo x > {}/note", granted.display())), 0);
    assert_ne!(code(&p, &format!("touch {}/new", granted.display())), 0);
    assert_ne!(code(&p, &format!("rm {}/note", granted.display())), 0);
    assert_eq!(
        std::fs::read_to_string(granted.join("note")).unwrap(),
        "hello"
    );
    assert!(!granted.join("new").exists());
}

#[test]
fn write_grant_allows_changes_and_implies_read() {
    let tree = Tree::new();
    tree.file("work/existing", "old");
    tree.file("readonly/file", "keep");
    let work = tree.path("work");
    let p = policy(
        &[&tree.path("readonly")],
        &[&work],
        false,
        false,
        &tree.path("state"),
    );

    let script = format!(
        "cd {w} && cat existing && echo new > existing && mkdir d && echo f > d/f && mv d/f moved \
         && ln -s moved link && mkfifo fifo && rm fifo && rmdir d && : > existing && cat moved",
        w = work.display()
    );
    let run = sh(&p, &script);
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (Some(0), "oldf\n"),
        "{run:?}"
    );
    assert_eq!(std::fs::read_to_string(work.join("existing")).unwrap(), "");
    assert_eq!(
        std::fs::read_link(work.join("link")).unwrap(),
        Path::new("moved")
    );

    let readonly = tree.path("readonly");
    assert_ne!(
        code(&p, &format!("echo x > {}/file", readonly.display())),
        0
    );
    assert_ne!(
        code(
            &p,
            &format!(
                "mv {w}/moved {r}/moved",
                w = work.display(),
                r = readonly.display()
            )
        ),
        0
    );
    assert_eq!(
        std::fs::read_to_string(readonly.join("file")).unwrap(),
        "keep"
    );
    assert!(work.join("moved").exists());
}

#[test]
fn file_grant_covers_that_file_only() {
    let tree = Tree::new();
    let one = tree.file("dir/one", "1");
    tree.file("dir/two", "2");
    let w = tree.file("wdir/w", "w");
    let p = policy(&[&one], &[&w], false, false, &tree.path("state"));
    let dir = tree.path("dir");
    let wdir = tree.path("wdir");

    assert_eq!(sh(&p, &format!("cat {}", one.display())).stdout, "1");
    assert_ne!(code(&p, &format!("cat {}/two", dir.display())), 0);
    assert_ne!(code(&p, &format!("ls {}", dir.display())), 0);
    assert_ne!(code(&p, &format!("echo x >> {}", one.display())), 0);

    assert_eq!(code(&p, &format!("echo more >> {}", w.display())), 0);
    assert_eq!(std::fs::read_to_string(&w).unwrap(), "wmore\n");
    assert_ne!(code(&p, &format!("touch {}/new", wdir.display())), 0);
    assert_ne!(code(&p, &format!("rm {}", w.display())), 0);
    assert!(w.exists());
}

#[test]
fn symlink_inside_a_grant_does_not_reach_outside() {
    let tree = Tree::new();
    let secret = tree.file("outside/secret", "s3cret");
    tree.file("inside/real", "real");
    let inside = tree.path("inside");
    std::os::unix::fs::symlink(&secret, inside.join("to-secret")).unwrap();
    std::os::unix::fs::symlink(inside.join("real"), inside.join("to-real")).unwrap();
    let p = policy(&[], &[&inside], false, false, &tree.path("state"));

    let denied = sh(&p, &format!("cat {}/to-secret", inside.display()));
    assert_eq!(denied.code, Some(1));
    assert!(denied.stderr.contains("Permission denied"), "{denied:?}");
    assert_ne!(
        code(&p, &format!("echo x > {}/to-secret", inside.display())),
        0
    );
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "s3cret");
    assert_eq!(
        sh(&p, &format!("cat {}/to-real", inside.display())).stdout,
        "real"
    );

    assert_eq!(
        code(
            &p,
            &format!("ln -s {} {}/later", secret.display(), inside.display())
        ),
        0
    );
    assert_ne!(code(&p, &format!("cat {}/later", inside.display())), 0);
}

#[test]
fn missing_paths_are_ignored_and_never_created() {
    let tree = Tree::new();
    let parent = tree.dir("parent");
    tree.file("parent/present", "here");
    let missing_write = parent.join("out");
    let missing_read = tree.path("nowhere/deeper");
    let p = policy(
        &[&missing_read, &parent.join("present")],
        &[&missing_write],
        false,
        false,
        &tree.path("state"),
    );
    assert_eq!(
        p.ignored(),
        [
            missing_read.to_str().unwrap().to_string(),
            missing_write.to_str().unwrap().to_string()
        ]
    );

    let before = tree.snapshot();
    assert_eq!(
        sh(&p, &format!("cat {}/present", parent.display())).stdout,
        "here"
    );
    assert_ne!(code(&p, &format!("mkdir {}", missing_write.display())), 0);
    assert_ne!(
        code(&p, &format!("echo x > {}", missing_write.display())),
        0
    );
    assert_eq!(tree.snapshot(), before);
    assert!(!missing_write.exists());
    assert!(!tree.path("nowhere").exists());
}

#[test]
fn state_dir_stays_hidden_inside_granted_directories() {
    let tree = Tree::new();
    let state = tree.dir("home/.local/state/happy-supervisor");
    tree.file(
        "home/.local/state/happy-supervisor/credentials.json",
        "{\"token\":1}",
    );
    tree.file("home/.local/state/other.log", "log");
    tree.file("home/notes", "notes");
    tree.file("home/repo/src/main.rs", "fn main() {}");
    tree.file("beside", "beside");
    let home = tree.path("home");
    let p = policy(&[Path::new("/")], &[&home], false, false, &state);

    let creds = state.join("credentials.json");
    let denied = sh(&p, &format!("cat {}", creds.display()));
    assert_eq!(denied.code, Some(1));
    assert!(denied.stderr.contains("Permission denied"), "{denied:?}");
    assert_ne!(code(&p, &format!("ls {}", state.display())), 0);
    assert_ne!(code(&p, &format!("echo x > {}", creds.display())), 0);
    assert_ne!(code(&p, &format!("rm {}", creds.display())), 0);
    assert_ne!(
        code(
            &p,
            &format!("mv {} {}/stolen", creds.display(), home.display())
        ),
        0
    );
    assert_eq!(std::fs::read_to_string(&creds).unwrap(), "{\"token\":1}");

    let siblings = sh(
        &p,
        &format!(
            "cat {r}/beside {h}/notes {h}/.local/state/other.log {h}/repo/src/main.rs",
            r = tree.root.display(),
            h = home.display()
        ),
    );
    assert_eq!(siblings.stdout, "besidenoteslogfn main() {}");
    assert_eq!(
        code(&p, &format!("echo more >> {}/notes", home.display())),
        0
    );
    assert_eq!(code(&p, &format!("touch {}/repo/new", home.display())), 0);
    assert_eq!(sh(&p, "cat /etc/hostname").code, Some(0));

    // The directories on the way to the state directory are not granted themselves, so they
    // cannot be listed and new entries in them are denied.
    assert_ne!(code(&p, &format!("ls {}", home.display())), 0);
    assert_ne!(code(&p, &format!("touch {}/new", home.display())), 0);
    assert!(!home.join("new").exists());
}

#[test]
fn processes_cannot_gain_privileges_and_children_stay_confined() {
    let tree = Tree::new();
    let secret = tree.file("secret", "s3cret");
    let p = policy(&[], &[], false, false, &tree.path("state"));

    let run = sh(
        &p,
        &format!(
            "grep NoNewPrivs /proc/self/status; sh -c 'cat {s}'; (cat {s}) ; echo end",
            s = secret.display()
        ),
    );
    assert_eq!(run.stdout, "NoNewPrivs:\t1\nend\n");
    assert_eq!(
        run.stderr.matches("Permission denied").count(),
        2,
        "{run:?}"
    );
}

#[test]
fn signals_to_processes_outside_the_sandbox_are_denied() {
    let tree = Tree::new();
    let p = policy(&[&this_test_binary()], &[], true, true, &tree.path("state"));
    let outside = std::process::id().to_string();
    let expected = if landlock_abi() >= 6 { "EPERM" } else { "ok" };
    assert_eq!(act(&p, "signal", &outside), expected);
}

/// policy.md's Linux table, combination by combination, for ABI 4 and newer kernels.
#[test]
fn network_matrix() {
    if std::net::TcpListener::bind("127.0.0.1:0").is_err() {
        eprintln!("skipped: this host denies bind to the test process itself, sandbox or not");
        return;
    }
    let abi = landlock_abi();
    let tree = Tree::new();
    let dir = tree.dir("sockets");
    let state = tree.path("state");
    let exe = this_test_binary();

    // (localBind, unixSockets) -> tcp, tcp listen without bind, udp, unix path, abstract unix
    let table: [((bool, bool), [&str; 5]); 4] = [
        (
            (false, false),
            ["EPERM", "EPERM", "EPERM", "EPERM", "EPERM"],
        ),
        ((false, true), ["EACCES", "ok", "ok", "ok", "ok"]),
        ((true, false), ["ok", "ok", "ok", "EACCES", "ok"]),
        ((true, true), ["ok", "ok", "ok", "ok", "ok"]),
    ];
    for (n, ((local_bind, unix_sockets), expected)) in table.into_iter().enumerate() {
        if abi < 4 && (local_bind, unix_sockets) == (false, true) {
            continue;
        }
        let p = policy(&[&exe], &[&dir], local_bind, unix_sockets, &state);
        let socket = dir.join(format!("s{n}"));
        let got = [
            act(&p, "tcp", ""),
            act(&p, "tcp-unbound", ""),
            act(&p, "udp", ""),
            act(&p, "unix", socket.to_str().unwrap()),
            act(
                &p,
                "abstract",
                &format!("happy-sandbox-test-{}-{n}", std::process::id()),
            ),
        ];
        assert_eq!(
            got, expected,
            "localBind {local_bind}, unixSockets {unix_sockets}"
        );
    }
}
