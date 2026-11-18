//! Landlock + seccomp backend (docs/policy.md, Linux: Landlock and seccomp).
//!
//! [`prepare`] checks that the kernel can enforce the policy and returns `<exe> __sandbox`. The
//! fresh helper calls [`enter`], which turns the [`ResolvedPolicy`] into one Landlock ruleset
//! (and, when nothing may bind, a seccomp filter) on itself before it execs the command or
//! performs the file operation. Nothing on disk is created or mounted.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use landlock::{
    AccessFs, AccessNet, BitFlags, CompatLevel, Compatible as _, PathBeneath, RestrictionStatus,
    Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetError, RulesetStatus, Scope,
    make_bitflags,
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

use crate::error::{Error, Result};
use crate::helper::{self, Job, JobOp};
use crate::policy::{Grant, GrantKind, Policy, ResolvedPolicy, Rights};
use crate::protocol::{AbsPath, Argv, Mechanism, SandboxInfo, SandboxStatus};

pub fn probe() -> SandboxInfo {
    let status = match run_true() {
        Ok(()) => SandboxStatus::Available,
        Err(err) => SandboxStatus::Unavailable {
            reason: err.message,
        },
    };
    let abi = kernel_abi().ok();
    let gaps = match (&status, abi) {
        (SandboxStatus::Available, Some(abi)) => gaps(abi),
        _ => Vec::new(),
    };
    SandboxInfo {
        mechanism: Mechanism::Landlock { abi },
        status,
        baseline_read: super::baseline_read(),
        gaps,
    }
}

/// What a kernel with Landlock ABI `abi` leaves unenforced (policy.md, Gaps the node reports).
pub fn gaps(abi: u32) -> Vec<String> {
    let mut gaps = vec![
        "with localBind false and unixSockets true, UDP ports can still be bound, and a TCP \
         socket can listen on an ephemeral port without bind",
        "with localBind true and unixSockets false, abstract-namespace Unix sockets can still be \
         bound",
    ];
    if abi < 4 {
        gaps.push(
            "localBind false is enforced only together with unixSockets false; other \
             combinations reply sandbox_unavailable",
        );
    }
    if abi < 3 {
        gaps.push("truncate on a readable file is not restricted");
    }
    gaps.push("ioctl on an opened device and connecting to a Unix socket are not restricted");
    gaps.into_iter().map(str::to_string).collect()
}

pub fn prepare(job: &Job) -> Result<Command> {
    // Refuse what this kernel cannot enforce before anything is spawned.
    Enforcement::plan(
        kernel_abi()?,
        job.policy.local_bind(),
        job.policy.unix_sockets(),
    )?;
    let mut command = Command::new(helper::exe()?);
    command.arg("__sandbox");
    Ok(command)
}

pub fn enter(policy: &ResolvedPolicy) -> Result<()> {
    let plan = Enforcement::plan(kernel_abi()?, policy.local_bind(), policy.unix_sockets())?;
    restrict(&plan, &landlock_grants(policy))?;
    if plan.seccomp_denies_bind {
        deny_bind_and_listen()?;
    }
    Ok(())
}

/// How one policy is enforced on a kernel with a given Landlock ABI.
#[derive(Debug, PartialEq, Eq)]
struct Enforcement {
    /// The filesystem rights the ruleset handles: everything not granted below is denied.
    handled: BitFlags<AccessFs>,
    /// Granted on `read` paths.
    read: BitFlags<AccessFs>,
    /// Granted on `write` paths.
    write: BitFlags<AccessFs>,
    /// Landlock handles TCP bind and grants no port.
    denies_tcp_bind: bool,
    /// Landlock scopes signals and abstract Unix socket connections to the sandbox.
    scoped: bool,
    /// seccomp makes `bind` and `listen` fail with `EPERM`.
    seccomp_denies_bind: bool,
}

/// The rights that still apply when a grant is a file rather than a directory.
const FILE_RIGHTS: BitFlags<AccessFs> =
    make_bitflags!(AccessFs::{Execute | ReadFile | WriteFile | Truncate});

impl Enforcement {
    fn plan(abi: u32, local_bind: bool, unix_sockets: bool) -> Result<Enforcement> {
        let read = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
        let mut write = read
            | make_bitflags!(AccessFs::{WriteFile | RemoveDir | RemoveFile | MakeDir | MakeReg | MakeFifo | MakeSym});
        if abi >= 2 {
            write |= AccessFs::Refer;
        }
        if abi >= 3 {
            write |= AccessFs::Truncate;
        }
        let handled = write | make_bitflags!(AccessFs::{MakeSock | MakeChar | MakeBlock});
        if unix_sockets {
            write |= AccessFs::MakeSock;
        }
        let denies_tcp_bind = !local_bind && abi >= 4;
        let seccomp_denies_bind = !local_bind && !unix_sockets;
        if !local_bind && !denies_tcp_bind && !seccomp_denies_bind {
            return Err(Error::sandbox_unavailable(format!(
                "Landlock ABI {abi} cannot deny TCP binding while allowing Unix sockets (ABI 4, Linux 6.7, is needed)"
            )));
        }
        Ok(Enforcement {
            handled,
            read,
            write,
            denies_tcp_bind,
            scoped: abi >= 6,
            seccomp_denies_bind,
        })
    }
}

/// The Landlock ABI version of the running kernel.
fn kernel_abi() -> Result<u32> {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: with a null attribute and size 0, this flag only asks for the ABI version.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi >= 1 {
        return Ok(abi as u32);
    }
    let err = std::io::Error::last_os_error();
    Err(Error::sandbox_unavailable(match err.raw_os_error() {
        Some(libc::ENOSYS) => "this kernel was built without Landlock".to_string(),
        Some(libc::EOPNOTSUPP) => "Landlock is not in the kernel's active LSM list".to_string(),
        _ => format!("the kernel did not report a Landlock ABI: {err}"),
    }))
}

/// The grants as Landlock rules. Landlock only adds rights, so a directory grant that contains the
/// hidden state directory becomes grants on every existing entry beside the path down to it.
/// Symlinks among those entries are skipped: a grant applies to real locations only.
fn landlock_grants(policy: &ResolvedPolicy) -> Vec<Grant> {
    let hidden = policy.hidden();
    let mut grants = Vec::new();
    for grant in policy.grants() {
        let Ok(below) = hidden.strip_prefix(&grant.path) else {
            grants.push(grant.clone());
            continue;
        };
        let mut dir = grant.path.clone();
        for component in below.components() {
            let toward_hidden = dir.join(component);
            // An unreadable directory's entries cannot be named, so they stay denied.
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if path == toward_hidden || file_type.is_symlink() {
                    continue;
                }
                let kind = if file_type.is_dir() {
                    GrantKind::Directory
                } else {
                    GrantKind::File
                };
                grants.push(Grant {
                    path,
                    kind,
                    rights: grant.rights,
                });
            }
            dir = toward_hidden;
        }
    }
    grants
}

fn restrict(plan: &Enforcement, grants: &[Grant]) -> Result<()> {
    let refused = |err: RulesetError| {
        Error::sandbox_unavailable(format!("Landlock refused the ruleset: {err}"))
    };
    let status = build_and_restrict(plan, grants).map_err(refused)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(Error::sandbox_unavailable(format!(
            "Landlock enforced the ruleset {:?} with no_new_privs {}",
            status.ruleset, status.no_new_privs
        )));
    }
    Ok(())
}

fn build_and_restrict(
    plan: &Enforcement,
    grants: &[Grant],
) -> std::result::Result<RestrictionStatus, RulesetError> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(plan.handled)?;
    if plan.denies_tcp_bind {
        ruleset = ruleset.handle_access(AccessNet::BindTcp)?;
    }
    if plan.scoped {
        ruleset = ruleset.scope(Scope::Signal | Scope::AbstractUnixSocket)?;
    }
    let mut ruleset = ruleset.create()?;
    for grant in grants {
        let Some((fd, is_dir)) = open_grant(&grant.path) else {
            continue;
        };
        let mut access = match grant.rights {
            Rights::Read => plan.read,
            Rights::ReadWrite => plan.write,
        };
        if !is_dir {
            access &= FILE_RIGHTS;
        }
        ruleset = ruleset.add_rule(PathBeneath::new(fd, access))?;
    }
    ruleset.restrict_self()
}

/// Opens a grant without following a final symlink. `None` when it vanished, became a symlink,
/// or this process cannot reach it either, so the grant gives nothing.
fn open_grant(path: &Path) -> Option<(OwnedFd, bool)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let file_type = file.metadata().ok()?.file_type();
    if file_type.is_symlink() {
        return None;
    }
    Some((file.into(), file_type.is_dir()))
}

/// Makes `bind` and `listen` fail with `EPERM` for every socket family. `listen` too, because
/// listening on an unbound TCP socket binds it to an ephemeral port.
fn deny_bind_and_listen() -> Result<()> {
    fn unavailable(err: impl std::fmt::Display) -> Error {
        Error::sandbox_unavailable(format!("seccomp refused the bind filter: {err}"))
    }
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(unavailable)?;
    let mut syscalls = vec![libc::SYS_bind, libc::SYS_listen];
    if cfg!(target_arch = "x86_64") {
        // x32 system calls share the x86_64 audit arch and differ only in this bit.
        syscalls.extend([libc::SYS_bind | 0x4000_0000, libc::SYS_listen | 0x4000_0000]);
    }
    let rules = syscalls.into_iter().map(|nr| (nr, vec![])).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(unavailable)?;
    let program = BpfProgram::try_from(filter).map_err(unavailable)?;
    seccompiler::apply_filter(&program).map_err(unavailable)
}

/// Runs `true` through the helper under the strictest network policy and the baseline reads,
/// so availability means a real command got through Landlock and seccomp.
fn run_true() -> Result<()> {
    let program = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .ok_or_else(|| {
            Error::sandbox_unavailable("there is no `true` program to test the sandbox with")
        })?;
    let policy = Policy::new(super::baseline_read(), vec![], false, false)?;
    let job = Job {
        policy: ResolvedPolicy::resolve(&policy, Path::new("/nonexistent/happy-supervisor-probe")),
        op: JobOp::Exec {
            argv: Argv::try_from(vec![program.to_string()])?,
            cwd: AbsPath::try_from("/")?,
            env: BTreeMap::new(),
        },
    };
    let mut command = prepare(&job)?;
    let (mut status_reader, status_writer) = std::io::pipe()?;
    let status_fd = status_writer.as_raw_fd();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: install_status_fd is async-signal-safe and runs in the forked child only.
    unsafe {
        command.pre_exec(move || helper::install_status_fd(status_fd));
    }
    let mut child = command.spawn()?;
    drop(command);
    drop(status_writer);
    let written = child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&helper::encode_job(&job));
    let mut status = Vec::new();
    status_reader.read_to_end(&mut status)?;
    let exit = child.wait()?;
    helper::parse_exec_status(&status)?;
    written?;
    if !exit.success() {
        return Err(Error::sandbox_unavailable(format!(
            "a sandboxed `true` failed with {exit}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_depend_on_the_abi() {
        let six = gaps(6);
        assert_eq!(six.len(), 3);
        assert!(six[0].contains("listen on an ephemeral port without bind"));
        assert_eq!(
            six[2],
            "ioctl on an opened device and connecting to a Unix socket are not restricted"
        );
        assert_eq!(gaps(3).len(), 4);
        assert_eq!(gaps(2)[3], "truncate on a readable file is not restricted");
    }
    use crate::error::ErrorKind;
    use std::path::PathBuf;

    #[test]
    fn plans_by_abi() {
        let read = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
        let v1_write = read
            | make_bitflags!(AccessFs::{WriteFile | RemoveDir | RemoveFile | MakeDir | MakeReg | MakeFifo | MakeSym});
        let v3_write = v1_write | AccessFs::Refer | AccessFs::Truncate;
        let devices_and_sockets = make_bitflags!(AccessFs::{MakeSock | MakeChar | MakeBlock});

        assert_eq!(
            Enforcement::plan(1, false, false).unwrap(),
            Enforcement {
                handled: v1_write | devices_and_sockets,
                read,
                write: v1_write,
                denies_tcp_bind: false,
                scoped: false,
                seccomp_denies_bind: true,
            }
        );
        assert_eq!(
            Enforcement::plan(2, true, true).unwrap(),
            Enforcement {
                handled: v1_write | AccessFs::Refer | devices_and_sockets,
                read,
                write: v1_write | AccessFs::Refer | AccessFs::MakeSock,
                denies_tcp_bind: false,
                scoped: false,
                seccomp_denies_bind: false,
            }
        );
        assert_eq!(
            Enforcement::plan(4, false, true).unwrap(),
            Enforcement {
                handled: v3_write | devices_and_sockets,
                read,
                write: v3_write | AccessFs::MakeSock,
                denies_tcp_bind: true,
                scoped: false,
                seccomp_denies_bind: false,
            }
        );
        assert_eq!(
            Enforcement::plan(6, false, false).unwrap(),
            Enforcement {
                handled: v3_write | devices_and_sockets,
                read,
                write: v3_write,
                denies_tcp_bind: true,
                scoped: true,
                seccomp_denies_bind: true,
            }
        );
        assert_eq!(
            Enforcement::plan(7, true, false).unwrap(),
            Enforcement {
                handled: v3_write | devices_and_sockets,
                read,
                write: v3_write,
                denies_tcp_bind: false,
                scoped: true,
                seccomp_denies_bind: false,
            }
        );
    }

    #[test]
    fn old_abis_cannot_deny_tcp_bind_alone() {
        for abi in 1..=3 {
            let err = Enforcement::plan(abi, false, true).unwrap_err();
            assert_eq!(err.kind, ErrorKind::SandboxUnavailable);
            assert_eq!(
                err.message,
                format!(
                    "Landlock ABI {abi} cannot deny TCP binding while allowing Unix sockets (ABI 4, Linux 6.7, is needed)"
                )
            );
        }
    }

    #[test]
    fn state_dir_is_carved_out_of_a_containing_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let state = root.join("home/.local/state/happy-supervisor");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir(root.join("home/repo")).unwrap();
        std::fs::create_dir(root.join("home/.local/share")).unwrap();
        std::fs::write(root.join("home/.bashrc"), b"").unwrap();
        std::fs::write(root.join("home/.local/state/other.log"), b"").unwrap();
        std::fs::write(root.join("top.txt"), b"").unwrap();
        std::fs::write(state.join("credentials.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&root, root.join("home/.local/up")).unwrap();
        std::fs::create_dir(root.join("elsewhere")).unwrap();

        let s = |p: &Path| p.to_str().unwrap().to_string();
        let policy = Policy::new(
            vec![s(&root)],
            vec![s(&root.join("home")), s(&root.join("elsewhere"))],
            false,
            false,
        )
        .unwrap();
        let resolved = ResolvedPolicy::resolve(&policy, &state);
        let mut grants = landlock_grants(&resolved);
        grants.sort_by(|a, b| (&a.path, a.rights).cmp(&(&b.path, b.rights)));

        let grant = |path: &str, kind, rights| Grant {
            path: if path.starts_with("/dev/") {
                PathBuf::from(path)
            } else {
                root.join(path)
            },
            kind,
            rights,
        };
        use GrantKind::{Directory, File};
        use Rights::{Read, ReadWrite};
        let mut expected = vec![
            grant("elsewhere", Directory, ReadWrite),
            grant("elsewhere", Directory, Read),
            grant("home/.bashrc", File, Read),
            grant("home/.bashrc", File, ReadWrite),
            grant("home/.local/share", Directory, Read),
            grant("home/.local/share", Directory, ReadWrite),
            grant("home/.local/state/other.log", File, Read),
            grant("home/.local/state/other.log", File, ReadWrite),
            grant("home/repo", Directory, Read),
            grant("home/repo", Directory, ReadWrite),
            grant("top.txt", File, Read),
            grant("/dev/null", File, ReadWrite),
            grant("/dev/random", File, Read),
            grant("/dev/urandom", File, Read),
            grant("/dev/zero", File, Read),
        ];
        expected.sort_by(|a, b| (&a.path, a.rights).cmp(&(&b.path, b.rights)));
        assert_eq!(grants, expected);
    }

    #[test]
    fn grants_without_the_state_dir_pass_through() {
        let policy = Policy::new(vec!["/usr".into()], vec![], true, true).unwrap();
        let resolved = ResolvedPolicy::resolve(&policy, Path::new("/nonexistent/state"));
        assert_eq!(landlock_grants(&resolved), resolved.grants());
    }
}
