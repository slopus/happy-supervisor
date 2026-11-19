//! The Windows sandbox (policy.md): a pool of dedicated local accounts, file ACEs that name the
//! leased account's own group, a restricted token, persistent WFP filters keyed on network
//! groups, and a Job Object. Ported in part from Codex's `windows-sandbox-rs` (Apache-2.0; see
//! NOTICE); each derived file says what it took.
//!
//! An operation runs as three processes:
//!
//! 1. The broker, `<exe> __sandbox`, as the supervisor's own account, in the exec's Job Object.
//!    It reads the [`Job`], leases an account, adds the ACEs the policy needs for that account's
//!    group, and starts the runner with CreateProcessWithLogonW, which std cannot do. When the
//!    runner exits, it revokes the ACEs.
//! 2. The runner, `<exe> __sandbox runner`, as the leased account, in the broker's own Job
//!    Object. It restricts its own token and starts the command with it, or performs the file
//!    operation impersonating it.
//! 3. The command.
//!
//! `install-sandbox` (an administrator, once) creates the accounts, groups and filters.

mod acl;
mod broker;
mod install;
mod lease;
mod net;
mod runner;
mod token;
mod win;

use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{Error, Result};
use crate::helper::Job;
use crate::policy::Layer;
use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};

pub use install::{InstallArgs, install_main};

use super::{Endpoint, Placeholders, Plan, Prepared};

/// Windows 10 1809 and Server 2019.
const MIN_BUILD: u32 = 17763;

const GAPS: &[&str] = &[
    "the sandbox reads as a separate unprivileged account: under read.default deny it can still read what any local user can (the Windows and Program Files directories and other world-readable data), and under read.default allow it cannot read the supervisor account's private files (its profile) unless read.allow lists them",
    "under write.default allow the sandbox writes what an unprivileged local account may write, plus write.allow",
    "under write.default deny the token is write-restricted, and Windows gives a restricted token no Schannel credentials: TLS through Schannel (curl.exe, PowerShell and .NET) fails with SEC_E_NO_CREDENTIALS, while programs with their own TLS (OpenSSL, rustls, Go, Node, Python) work",
    "an ACE is added at each policy path and inherited below it; a file or directory below with inheritance disabled or its own explicit ACE keeps that",
    "unixSockets false is not enforced: AF_UNIX sockets can be created and connected in directories the policy lets the sandbox use",
    "localBind false blocks TCP listen; UDP sockets can still be bound",
    "in isolated mode the sandbox can connect to every loopback port in the proxy port range, which includes other commands' proxies",
    "in isolated mode with localBind the sandbox can connect to every loopback port, including the host's own local services, since its own listeners cannot be told apart from them",
    "in isolated mode names still resolve: the DNS Client service queries the network for the sandbox, so a lookup can carry data out",
    "a command that makes a sandbox network group deny-only in a restricted token of its own escapes the network filters",
    "processes started through system services (WMI, Task Scheduler) leave the Job Object",
    "the sandbox can read the supervisor binary, which it runs as",
    "the sandbox shares the supervisor's window station and desktop",
];

pub fn probe() -> SandboxInfo {
    let status = match check_installed() {
        Ok(()) => SandboxStatus::Available,
        Err(reason) => SandboxStatus::Unavailable { reason },
    };
    let gaps = match status {
        SandboxStatus::Available => GAPS.iter().map(|gap| gap.to_string()).collect(),
        SandboxStatus::Unavailable { .. } => Vec::new(),
    };
    SandboxInfo {
        mechanism: Mechanism::Windows,
        status,
        baseline_read: super::baseline_read(),
        gaps,
    }
}

fn check_installed() -> std::result::Result<(), String> {
    let build = os_build();
    if build < MIN_BUILD {
        return Err(format!(
            "Windows build {build} is older than {MIN_BUILD} (Windows 10 1809, Server 2019)"
        ));
    }
    let install = install::Install::load().map_err(|err| {
        format!(
            "the sandbox is not installed ({err}): run `happy-supervisor install-sandbox` as an administrator, as the account that runs the supervisor"
        )
    })?;
    if install.version != install::VERSION {
        return Err(format!(
            "the sandbox was installed by another version (setup {}, this one needs {}): run `happy-supervisor install-sandbox` again",
            install.version,
            install::VERSION
        ));
    }
    let slot = install
        .slots
        .first()
        .ok_or("the sandbox install has no accounts")?;
    let password = slot.password().map_err(|err| {
        format!(
            "cannot read the sandbox account's password ({err}): the supervisor must run as the account that ran install-sandbox"
        )
    })?;
    token::logon(&slot.account, &password).map_err(|err| err.to_string())?;
    Ok(())
}

fn os_build() -> u32 {
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(info: *mut OSVERSIONINFOW) -> i32;
    }
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a valid OSVERSIONINFOW with its size set.
    unsafe { RtlGetVersion(&mut info) };
    info.dwBuildNumber
}

/// The loopback ports isolated commands may reach: where their proxies must listen.
pub fn proxy_ports() -> Option<RangeInclusive<u16>> {
    install::Install::load()
        .ok()
        .map(|install| install.proxy_ports())
}

pub fn prepare(plan: &Plan, _job: &Job) -> Result<Prepared> {
    check_installed().map_err(Error::sandbox_unavailable)?;
    if let Some(net) = &plan.net {
        let ports = proxy_ports()
            .ok_or_else(|| Error::sandbox_unavailable("the sandbox has no proxy ports"))?;
        for endpoint in [&net.http, &net.socks] {
            let reachable = matches!(endpoint, Endpoint::Tcp(addr)
                if addr.ip().is_loopback() && ports.contains(&addr.port()));
            if !reachable {
                return Err(Error::sandbox_unavailable(format!(
                    "the command proxy at {endpoint:?} is outside the sandbox's proxy ports {ports:?}"
                )));
            }
        }
    }
    let policy = plan.policy;
    let missing: Vec<PathBuf> = policy
        .layers()
        .into_iter()
        .filter(|layer| !layer.exists && !(layer.read && layer.write))
        .map(|layer| layer.path)
        .collect();
    let placeholders = Placeholders::create(
        &super::placeholder_records(policy.state_dir()),
        &missing,
        |path| policy.can_write(path),
    )?;
    let mut command = Command::new(plan.exe);
    command.arg(HELPER_ARG);
    for path in placeholders.paths() {
        command.arg(PLACEHOLDER_ARG).arg(path);
    }
    Ok(Prepared {
        command,
        placeholders,
        netns: None,
    })
}

const HELPER_ARG: &str = "__sandbox";
const RUNNER_ARG: &str = "runner";
const PLACEHOLDER_ARG: &str = "--placeholder";

/// The `__sandbox` entry point on Windows: the broker, or with `runner` the runner.
pub fn helper_main() -> ! {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    if args.first().is_some_and(|arg| arg == RUNNER_ARG) {
        runner::main()
    }
    let mut placeholders = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match (arg.to_str(), args.next()) {
            (Some(PLACEHOLDER_ARG), Some(path)) => placeholders.push(PathBuf::from(path)),
            _ => {
                eprintln!("happy-supervisor __sandbox: unexpected argument {arg:?}");
                std::process::exit(crate::helper::EXIT_BAD_JOB)
            }
        }
    }
    broker::main(&placeholders)
}

/// Where each layer's ACE goes: the path itself when it exists, else the placeholder made for
/// it. A missing path with neither needs nothing: the sandbox cannot create it.
fn targets(layers: Vec<Layer>, placeholders: &[PathBuf]) -> Vec<(PathBuf, acl::Access)> {
    layers
        .into_iter()
        .filter_map(|layer| {
            let want = acl::Access {
                read: layer.read,
                write: layer.write,
            };
            if layer.path.exists() {
                return Some((layer.path, want));
            }
            placeholders
                .iter()
                .find(|placeholder| layer.path.starts_with(placeholder))
                .map(|placeholder| (placeholder.clone(), want))
        })
        .collect()
}
