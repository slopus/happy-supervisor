//! The system calls a sandboxed command may not make, applied by the helper right before it
//! execs the command (docs/policy.md, Linux).
//!
//! The rules are a table, [`denials`], compiled with `seccompiler` (already a dependency, and the
//! compiler Codex and Firecracker use) into one filter per errno. A third filter, hand-written
//! because `seccompiler` matches syscall numbers only exactly, refuses every x32 call on x86_64:
//! x32 shares the x86_64 audit arch, so without it each rule would need its x32 twin. The
//! architecture check `seccompiler` emits kills any other ABI, such as i386 through `int 0x80`.
//! A fourth, hand-written too, hands `bind` to a user-notification listener where the policy
//! refuses it, so the node can report the address ([`notify_bind`], binds.rs).
//!
//! Compared with Codex and srt: their namespace, mount, io_uring and ptrace rules are all here.
//! `ioctl(TIOCSTI)` is added because the sandbox shares the node's session (see `prepare`).
//! Codex's per-call socket denials for proxy-only networking are not needed: the network
//! namespace has nothing but loopback, so only families the namespace does not fence (vsock,
//! bluetooth, ...) are refused.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::error::{Error, Result};

/// The network rules a filter enforces, from the policy's `network`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetRules {
    pub isolated: bool,
    pub unix_sockets: bool,
    /// Refuse `bind` and `listen` for every socket family.
    pub deny_bind: bool,
    /// `bind` goes to the listener of [`notify_bind`], which refuses it, rather than failing in
    /// this filter: a call this filter refused would never reach the listener.
    pub bind_notified: bool,
}

/// When a call is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum When {
    Always,
    /// The first argument has this bit set.
    Arg0HasFlag(u64),
    /// The first argument (a 32-bit int) equals this.
    Arg0Is(u64),
    /// The first argument (a 32-bit int) is none of these.
    Arg0NotIn(Vec<u64>),
    /// The second argument (a 32-bit int) equals this.
    Arg1Is(u64),
}

/// One refused call: the syscall number, when, and the errno it fails with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    pub name: &'static str,
    pub nr: i64,
    pub when: When,
    pub errno: i32,
}

// Numbers newer than some libc targets name; the same on x86_64 and aarch64 since Linux 5.1.
const SYS_OPEN_TREE: i64 = 428;
// musl's libc does not name it.
#[cfg(target_arch = "x86_64")]
const SYS_KEXEC_FILE_LOAD: i64 = 320;
#[cfg(target_arch = "aarch64")]
const SYS_KEXEC_FILE_LOAD: i64 = 294;
const SYS_MOVE_MOUNT: i64 = 429;
const SYS_FSOPEN: i64 = 430;
const SYS_FSCONFIG: i64 = 431;
const SYS_FSMOUNT: i64 = 432;
const SYS_FSPICK: i64 = 433;
const SYS_CLONE3: i64 = 435;
const SYS_MOUNT_SETATTR: i64 = 442;
const SYS_OPEN_TREE_ATTR: i64 = 467;

const CLONE_NEWTIME: u64 = 0x80;
/// Every namespace a clone(2) flag word can ask for. `CLONE_NEWTIME` is left out: in clone(2)
/// that bit is part of the exit signal, and unshare(2) checks it separately.
const CLONE_NAMESPACES: [u64; 7] = [
    libc::CLONE_NEWNS as u64,
    libc::CLONE_NEWCGROUP as u64,
    libc::CLONE_NEWUTS as u64,
    libc::CLONE_NEWIPC as u64,
    libc::CLONE_NEWUSER as u64,
    libc::CLONE_NEWPID as u64,
    libc::CLONE_NEWNET as u64,
];

/// Every call the command may not make under `net`.
pub fn denials(net: NetRules) -> Vec<Denial> {
    let eperm = |name, nr, when| Denial {
        name,
        nr,
        when,
        errno: libc::EPERM,
    };
    let mut denials = vec![
        // io_uring performs socket, open and connect operations from a shared ring that no
        // filter can inspect.
        eperm("io_uring_setup", libc::SYS_io_uring_setup, When::Always),
        eperm("io_uring_enter", libc::SYS_io_uring_enter, When::Always),
        eperm(
            "io_uring_register",
            libc::SYS_io_uring_register,
            When::Always,
        ),
        eperm("ptrace", libc::SYS_ptrace, When::Always),
        eperm("process_vm_readv", libc::SYS_process_vm_readv, When::Always),
        eperm(
            "process_vm_writev",
            libc::SYS_process_vm_writev,
            When::Always,
        ),
        eperm("kexec_load", libc::SYS_kexec_load, When::Always),
        eperm("kexec_file_load", SYS_KEXEC_FILE_LOAD, When::Always),
        eperm("bpf", libc::SYS_bpf, When::Always),
        eperm("perf_event_open", libc::SYS_perf_event_open, When::Always),
        eperm("userfaultfd", libc::SYS_userfaultfd, When::Always),
        // Keyrings are shared with the node's session, and request_key can run host helpers.
        eperm("keyctl", libc::SYS_keyctl, When::Always),
        eperm("add_key", libc::SYS_add_key, When::Always),
        eperm("request_key", libc::SYS_request_key, When::Always),
        // A new mount or user namespace can detach the mounts the policy is made of.
        eperm("mount", libc::SYS_mount, When::Always),
        eperm("umount2", libc::SYS_umount2, When::Always),
        eperm("pivot_root", libc::SYS_pivot_root, When::Always),
        eperm("setns", libc::SYS_setns, When::Always),
        eperm("open_tree", SYS_OPEN_TREE, When::Always),
        eperm("move_mount", SYS_MOVE_MOUNT, When::Always),
        eperm("fsopen", SYS_FSOPEN, When::Always),
        eperm("fsconfig", SYS_FSCONFIG, When::Always),
        eperm("fsmount", SYS_FSMOUNT, When::Always),
        eperm("fspick", SYS_FSPICK, When::Always),
        eperm("mount_setattr", SYS_MOUNT_SETATTR, When::Always),
        eperm("open_tree_attr", SYS_OPEN_TREE_ATTR, When::Always),
        // clone3 passes its flags in memory a filter cannot read. ENOSYS makes libc and language
        // runtimes fall back to clone(2), which the rules below check.
        Denial {
            name: "clone3",
            nr: SYS_CLONE3,
            when: When::Always,
            errno: libc::ENOSYS,
        },
        eperm(
            "ioctl",
            libc::SYS_ioctl,
            When::Arg1Is(u64::from(libc::TIOCSTI as u32)),
        ),
    ];
    for flag in CLONE_NAMESPACES {
        denials.push(eperm("clone", libc::SYS_clone, When::Arg0HasFlag(flag)));
    }
    for flag in CLONE_NAMESPACES.into_iter().chain([CLONE_NEWTIME]) {
        denials.push(eperm("unshare", libc::SYS_unshare, When::Arg0HasFlag(flag)));
    }
    if !net.unix_sockets {
        denials.push(eperm(
            "socket",
            libc::SYS_socket,
            When::Arg0Is(libc::AF_UNIX as u64),
        ));
        // Every socketpair is a Unix socket pair.
        denials.push(eperm("socketpair", libc::SYS_socketpair, When::Always));
    }
    if net.isolated {
        // The families a network namespace fences. Anything else (vsock, bluetooth, ...) can
        // leave the sandbox without passing the proxies.
        let fenced = [
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_UNIX,
        ];
        denials.push(eperm(
            "socket",
            libc::SYS_socket,
            When::Arg0NotIn(fenced.iter().map(|&af| af as u64).collect()),
        ));
    }
    if net.deny_bind {
        if !net.bind_notified {
            denials.push(eperm("bind", libc::SYS_bind, When::Always));
        }
        // listen too: listening on an unbound socket binds it to an ephemeral port.
        denials.push(eperm("listen", libc::SYS_listen, When::Always));
    }
    denials
}

/// Installs the filters on this thread. Sets `no_new_privs`, which seccomp requires.
pub fn apply(net: NetRules) -> Result<()> {
    for program in compile(&denials(net))? {
        seccompiler::apply_filter(&program).map_err(unavailable)?;
    }
    Ok(())
}

/// Installs a filter that hands every native `bind` to a seccomp user-notification listener,
/// and returns the listener (close-on-exec). The listener's holder answers each call; once it
/// closes, the kernel fails `bind` with `ENOSYS`. Needs Linux 5.0, and fails with `EBUSY` when a
/// filter installed earlier, by a container runtime for example, already has a listener.
/// Other ABIs pass this filter, and the arch check and x32 filter of [`apply`] refuse them.
pub fn notify_bind() -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    let mut program = notify_bind_program();
    let prog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl and seccomp read only `prog`, which points at `program`, alive for the call.
    // seccomp needs no_new_privs, which `apply` sets too.
    let fd = unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &raw const prog,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: with NEW_LISTENER, seccomp returns a new descriptor that nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

/// `SECCOMP_RET_USER_NOTIF` for the native `bind`, `SECCOMP_RET_ALLOW` for everything else.
fn notify_bind_program() -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    const ARCH_OFFSET: u32 = 4;
    const NR_OFFSET: u32 = 0;
    let ld = |k| libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k, jt, jf| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let ret = |k| libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    vec![
        ld(ARCH_OFFSET),
        jeq(AUDIT_ARCH, 0, 3),
        ld(NR_OFFSET),
        jeq(libc::SYS_bind as u32, 0, 1),
        ret(libc::SECCOMP_RET_USER_NOTIF),
        ret(libc::SECCOMP_RET_ALLOW),
    ]
}

fn unavailable(err: impl std::fmt::Display) -> Error {
    Error::sandbox_unavailable(format!("seccomp refused the filter: {err}"))
}

/// One program per errno, and on x86_64 the x32 one.
fn compile(denials: &[Denial]) -> Result<Vec<BpfProgram>> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(unavailable)?;
    // `None` is an unconditional denial, which seccompiler writes as an empty rule list.
    let mut by_errno: BTreeMap<i32, BTreeMap<i64, Option<Vec<SeccompRule>>>> = BTreeMap::new();
    for denial in denials {
        let rules = by_errno
            .entry(denial.errno)
            .or_default()
            .entry(denial.nr)
            .or_insert_with(|| Some(Vec::new()));
        match (rule(&denial.when).map_err(unavailable)?, rules) {
            (Some(rule), Some(rules)) => rules.push(rule),
            (None, rules) => *rules = None,
            (Some(_), None) => {}
        }
    }
    let mut programs = Vec::new();
    for (errno, rules) in by_errno {
        let rules = rules
            .into_iter()
            .map(|(nr, rules)| (nr, rules.unwrap_or_default()))
            .collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno as u32),
            arch,
        )
        .map_err(unavailable)?;
        programs.push(BpfProgram::try_from(filter).map_err(unavailable)?);
    }
    if cfg!(target_arch = "x86_64") {
        programs.push(deny_x32());
    }
    Ok(programs)
}

fn rule(when: &When) -> std::result::Result<Option<SeccompRule>, seccompiler::BackendError> {
    let arg = |index, op, value| SeccompCondition::new(index, SeccompCmpArgLen::Dword, op, value);
    let conditions = match when {
        When::Always => return Ok(None),
        When::Arg0HasFlag(flag) => vec![arg(0, SeccompCmpOp::MaskedEq(*flag), *flag)?],
        When::Arg0Is(value) => vec![arg(0, SeccompCmpOp::Eq, *value)?],
        When::Arg1Is(value) => vec![arg(1, SeccompCmpOp::Eq, *value)?],
        When::Arg0NotIn(values) => values
            .iter()
            .map(|value| arg(0, SeccompCmpOp::Ne, *value))
            .collect::<std::result::Result<_, _>>()?,
    };
    SeccompRule::new(conditions).map(Some)
}

/// `ENOSYS` for every x32 system call: on x86_64, a number with bit 30 set.
fn deny_x32() -> BpfProgram {
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const ARCH_OFFSET: u32 = 4;
    const NR_OFFSET: u32 = 0;
    let ld = |k| seccompiler::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |op: u32, k, jt, jf| seccompiler::sock_filter {
        code: (libc::BPF_JMP | op | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let ret = |k| seccompiler::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    vec![
        ld(ARCH_OFFSET),
        jump(libc::BPF_JEQ, AUDIT_ARCH_X86_64, 0, 2),
        ld(NR_OFFSET),
        jump(libc::BPF_JSET, X32_SYSCALL_BIT, 0, 1),
        ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        ret(libc::SECCOMP_RET_ALLOW),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(net: NetRules) -> Vec<String> {
        denials(net)
            .iter()
            .filter(|d| !matches!(d.when, When::Always) || d.errno != libc::EPERM)
            .map(|d| format!("{} {:?} {}", d.name, d.when, d.errno))
            .collect()
    }

    #[test]
    fn conditional_rules_follow_the_network_policy() {
        let host_open = names(NetRules {
            isolated: false,
            unix_sockets: true,
            deny_bind: false,
            bind_notified: false,
        });
        assert_eq!(host_open.len(), 1 + 1 + 7 + 8);
        assert_eq!(host_open[0], "clone3 Always 38");
        assert_eq!(host_open[1], "ioctl Arg1Is(21522) 1");
        assert_eq!(host_open[2], "clone Arg0HasFlag(131072) 1");
        assert_eq!(host_open[16], "unshare Arg0HasFlag(128) 1");

        let isolated_closed = denials(NetRules {
            isolated: true,
            unix_sockets: false,
            deny_bind: true,
            bind_notified: false,
        });
        let tail: Vec<(&str, When)> = isolated_closed[isolated_closed.len() - 5..]
            .iter()
            .map(|d| (d.name, d.when.clone()))
            .collect();
        assert_eq!(
            tail,
            [
                ("socket", When::Arg0Is(1)),
                ("socketpair", When::Always),
                ("socket", When::Arg0NotIn(vec![2, 10, 16, 1])),
                ("bind", When::Always),
                ("listen", When::Always),
            ]
        );

        let notified = denials(NetRules {
            isolated: true,
            unix_sockets: false,
            deny_bind: true,
            bind_notified: true,
        });
        let tail: Vec<&str> = notified[notified.len() - 2..]
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(tail, ["socket", "listen"]);
    }

    #[test]
    fn the_notify_filter_hands_on_the_native_bind_only() {
        let program = notify_bind_program();
        let k: Vec<u32> = program.iter().map(|insn| insn.k).collect();
        let arch = if cfg!(target_arch = "x86_64") {
            0xc000_003e
        } else {
            0xc000_00b7
        };
        assert_eq!(
            k,
            [
                4,
                arch,
                0,
                libc::SYS_bind as u32,
                libc::SECCOMP_RET_USER_NOTIF,
                libc::SECCOMP_RET_ALLOW
            ]
        );
        assert_eq!((program[1].jt, program[1].jf), (0, 3));
        assert_eq!((program[3].jt, program[3].jf), (0, 1));
    }

    #[test]
    fn every_table_compiles() {
        for bits in 0..16 {
            let net = NetRules {
                isolated: bits & 1 != 0,
                unix_sockets: bits & 2 != 0,
                deny_bind: bits & 4 != 0,
                bind_notified: bits & 8 != 0,
            };
            let programs = compile(&denials(net)).unwrap();
            let expected = if cfg!(target_arch = "x86_64") { 3 } else { 2 };
            assert_eq!(programs.len(), expected, "{net:?}");
        }
    }
}
