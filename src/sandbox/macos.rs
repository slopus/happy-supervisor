//! Seatbelt (`sandbox-exec`) backend (docs/policy.md, macOS: Seatbelt). The profile is pure
//! text built from the job's [`ResolvedPolicy`], so it is unit-tested on every Unix.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use crate::error::{Error, Result};
use crate::helper::Job;
use crate::policy::{GrantKind, ResolvedPolicy, Rights};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Mach services the C library reaches for: user and group lookups, logging, notifications,
/// and DNS through mDNSResponder.
const MACH_SERVICES: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.logger",
    "com.apple.system.notification_center",
    "com.apple.logd",
    "com.apple.dnssd.service",
];

/// System symlinks programs open by name. Grants are canonical (`/private/tmp`, `/dev/fd/0`),
/// and following a symlink needs its metadata.
const SYSTEM_SYMLINKS: [&str; 6] = [
    "/etc",
    "/tmp",
    "/var",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
];

#[cfg(target_os = "macos")]
pub fn probe() -> crate::protocol::SandboxInfo {
    use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};
    let status = match run_true() {
        Ok(()) => SandboxStatus::Available,
        Err(reason) => SandboxStatus::Unavailable { reason },
    };
    let gaps = match status {
        SandboxStatus::Available => GAPS.iter().map(|gap| gap.to_string()).collect(),
        SandboxStatus::Unavailable { .. } => Vec::new(),
    };
    SandboxInfo {
        mechanism: Mechanism::Seatbelt,
        status,
        baseline_read: super::baseline_read(),
        gaps,
    }
}

/// What every profile allows whatever the policy says (policy.md, macOS: Seatbelt).
#[cfg(target_os = "macos")]
const GAPS: [&str; 1] =
    ["the metadata (not the listing or contents) of every directory above a grant is readable"];

/// Runs `/usr/bin/true` through `sandbox-exec` and the helper, granted only that file.
#[cfg(target_os = "macos")]
fn run_true() -> std::result::Result<(), String> {
    use std::collections::BTreeMap;
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;

    use crate::helper::{JobOp, encode_job, install_status_fd, parse_exec_status};
    use crate::policy::Policy;
    use crate::protocol::{AbsPath, Argv};

    let text = |err: Error| err.to_string();
    let io = |err: std::io::Error| err.to_string();
    let policy =
        Policy::new(vec!["/usr/bin/true".to_string()], vec![], false, false).map_err(text)?;
    let job = Job {
        // The probe has no state directory. `/var/empty` exists and is empty, so the deny rule
        // is rendered and parsed like a real one.
        policy: ResolvedPolicy::resolve(&policy, Path::new("/var/empty")),
        op: JobOp::Exec {
            argv: Argv::try_from(vec!["/usr/bin/true".to_string()]).map_err(text)?,
            cwd: AbsPath::try_from("/").map_err(text)?,
            env: BTreeMap::new(),
        },
    };
    let (mut status_reader, status_writer) = std::io::pipe().map_err(io)?;
    let status_fd = status_writer.as_raw_fd();
    let mut command = prepare(&job).map_err(text)?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: install_status_fd is async-signal-safe and runs in the forked child.
    unsafe {
        command.pre_exec(move || install_status_fd(status_fd));
    }
    let mut child = command
        .spawn()
        .map_err(|err| format!("{SANDBOX_EXEC} could not start: {err}"))?;
    drop(status_writer);
    let _ = child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(&encode_job(&job));
    let mut status = Vec::new();
    status_reader.read_to_end(&mut status).map_err(io)?;
    let output = child.wait_with_output().map_err(io)?;
    parse_exec_status(&status).map_err(|err| format!("a sandboxed true did not start: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "a sandboxed true failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// `/usr/bin/sandbox-exec -p <profile> <helper> __sandbox`.
pub fn prepare(job: &Job) -> Result<Command> {
    // Seatbelt matches real paths, so the helper is granted, and run, by its canonical path.
    let helper = std::fs::canonicalize(crate::helper::exe()?)?;
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-p")
        .arg(profile(&job.policy, &helper)?)
        .arg(&helper)
        .arg("__sandbox");
    Ok(command)
}

/// The SBPL profile for `policy`. Seatbelt applies the last matching rule, so the state
/// directory's deny comes after every grant.
fn profile(policy: &ResolvedPolicy, helper: &Path) -> Result<String> {
    let mut out = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-fork)\n\
         (allow signal (target same-sandbox))\n\
         (allow process-info* (target same-sandbox))\n\
         (allow sysctl-read)\n",
    );
    // dyld reads `/` before it loads anything, so no program starts without it.
    out.push_str("(allow file-read-data file-read-metadata (literal \"/\"))\n");
    writeln!(
        out,
        "(allow file-read* file-map-executable process-exec (literal {}))",
        quote(helper)?
    )
    .expect("writing to a String");

    // The ancestors of each grant expose their own metadata, not their listing, so `realpath`
    // and `pwd -P` work (they stat each component, and `/Volumes` crosses a mount point).
    let mut ancestors = BTreeSet::new();
    for grant in policy.grants() {
        ancestors.extend(
            grant
                .path
                .ancestors()
                .skip(1)
                .filter(|a| a.parent().is_some()),
        );
        let filter = match grant.kind {
            GrantKind::Directory => "subpath",
            GrantKind::File => "literal",
        };
        let path = quote(&grant.path)?;
        let ops = match grant.rights {
            Rights::Read => "file-read* file-map-executable process-exec",
            Rights::ReadWrite => "file-read* file-write* file-map-executable process-exec",
        };
        writeln!(out, "(allow {ops} ({filter} {path}))").expect("writing to a String");
        if grant.rights == Rights::ReadWrite && policy.unix_sockets() {
            writeln!(
                out,
                "(allow network-bind (local unix-socket ({filter} {path})))"
            )
            .expect("writing to a String");
        }
    }
    out.push_str("(allow file-read-metadata");
    for link in SYSTEM_SYMLINKS {
        write!(out, " (literal \"{link}\")").expect("writing to a String");
    }
    for ancestor in ancestors {
        write!(out, " (literal {})", quote(ancestor)?).expect("writing to a String");
    }
    out.push_str(")\n");

    out.push_str("(allow mach-lookup");
    for name in MACH_SERVICES {
        write!(out, " (global-name \"{name}\")").expect("writing to a String");
    }
    out.push_str(")\n");
    out.push_str(
        "(allow network-outbound)
",
    );
    if policy.local_bind() {
        out.push_str("(allow network-bind network-inbound (local ip))\n");
    }

    writeln!(
        out,
        "(deny file-read* file-write* file-map-executable process-exec (subpath {}))",
        quote(policy.hidden())?
    )
    .expect("writing to a String");
    Ok(out)
}

/// `path` as an SBPL string literal. Control characters are refused rather than escaped, so a
/// path can never end the string or the rule.
fn quote(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| Error::invalid_params(format!("sandbox path {path:?} is not UTF-8")))?;
    if text.chars().any(char::is_control) {
        return Err(Error::invalid_params(format!(
            "sandbox path {text:?} has a control character"
        )));
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn policy(local_bind: bool, unix_sockets: bool) -> ResolvedPolicy {
        serde_json::from_value(serde_json::json!({
            "grants": [
                { "path": "/dev/null", "kind": "File", "rights": "ReadWrite" },
                { "path": "/usr", "kind": "Directory", "rights": "Read" },
                { "path": "/Users/me/repo", "kind": "Directory", "rights": "ReadWrite" },
                { "path": "/Users/me/repo/say \"hi\"\\.txt", "kind": "File", "rights": "Read" },
            ],
            "ignored": ["/missing"],
            "hidden": "/Users/me/.happy",
            "local_bind": local_bind,
            "unix_sockets": unix_sockets,
        }))
        .unwrap()
    }

    #[test]
    fn full_profile() {
        let text = profile(&policy(true, true), Path::new("/opt/hs/happy-supervisor")).unwrap();
        assert_eq!(
            text,
            r#"(version 1)
(deny default)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow file-read-data file-read-metadata (literal "/"))
(allow file-read* file-map-executable process-exec (literal "/opt/hs/happy-supervisor"))
(allow file-read* file-write* file-map-executable process-exec (literal "/dev/null"))
(allow network-bind (local unix-socket (literal "/dev/null")))
(allow file-read* file-map-executable process-exec (subpath "/usr"))
(allow file-read* file-write* file-map-executable process-exec (subpath "/Users/me/repo"))
(allow network-bind (local unix-socket (subpath "/Users/me/repo")))
(allow file-read* file-map-executable process-exec (literal "/Users/me/repo/say \"hi\"\\.txt"))
(allow file-read-metadata (literal "/etc") (literal "/tmp") (literal "/var") (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr") (literal "/Users") (literal "/Users/me") (literal "/Users/me/repo") (literal "/dev"))
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.system.logger") (global-name "com.apple.system.notification_center") (global-name "com.apple.logd") (global-name "com.apple.dnssd.service"))
(allow network-outbound)
(allow network-bind network-inbound (local ip))
(deny file-read* file-write* file-map-executable process-exec (subpath "/Users/me/.happy"))
"#
        );
    }

    #[test]
    fn binding_rules_follow_the_flags() {
        let text = profile(&policy(false, false), Path::new("/hs")).unwrap();
        let binds: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("network-bind"))
            .collect();
        assert_eq!(binds, [] as [&str; 0]);

        let text = profile(&policy(false, true), Path::new("/hs")).unwrap();
        let binds: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("network-bind"))
            .collect();
        assert_eq!(
            binds,
            [
                r#"(allow network-bind (local unix-socket (literal "/dev/null")))"#,
                r#"(allow network-bind (local unix-socket (subpath "/Users/me/repo")))"#,
            ]
        );
    }

    #[test]
    fn unusable_paths_are_invalid_params() {
        let err = profile(&policy(false, false), Path::new("/a\nb")).unwrap_err();
        assert_eq!(
            err,
            Error::invalid_params(r#"sandbox path "/a\nb" has a control character"#)
        );
        use std::os::unix::ffi::OsStrExt as _;
        let latin1 = Path::new(std::ffi::OsStr::from_bytes(b"/caf\xe9"));
        let err = profile(&policy(false, false), latin1).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidParams);
        assert_eq!(err.message, r#"sandbox path "/caf\xE9" is not UTF-8"#);
    }
}
