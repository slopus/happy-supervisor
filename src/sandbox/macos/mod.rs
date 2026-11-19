//! Seatbelt (`sandbox-exec`) backend (policy.md). The profile is pure text built from the
//! [`ResolvedPolicy`] and the command's proxies, so it is unit-tested on every Unix.
//!
//! Seatbelt applies the last rule that matches an operation. The profile therefore states the
//! policy's defaults first, then its entries from the shallowest path to the deepest, so the
//! most specific entry wins, and the fixed rules (devices, the state directory) last.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{Endpoint, NetPlan, Plan, Prepared};
use crate::error::{Error, Result};
use crate::helper::Job;
use crate::policy::{Default, Network, ResolvedPolicy};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

const BASE: &str = include_str!("base.sbpl");
const DEVICES: &str = include_str!("devices.sbpl");
const NETWORK_SERVICES: &str = include_str!("network.sbpl");

/// Reading a path also lets the command map it executable and run it.
const READ_OPS: &str = "file-read* file-map-executable process-exec";
const WRITE_OPS: &str = "file-write*";

/// Where the C library sends every name lookup.
const MDNS_SOCKET: &str = "/private/var/run/mDNSResponder";

/// Symlinks into `/private` that programs open by name. Rules use the real paths, and following
/// a symlink needs its metadata.
const SYSTEM_SYMLINKS: [&str; 3] = ["/etc", "/tmp", "/var"];

/// What every profile allows whatever the policy says (policy.md, macOS).
const GAPS: [&str; 2] = [
    "the metadata (not the listing or contents) of every directory above a grant is readable",
    "with isolated networking and localBind, a listener may bind any local address and accept connections from other hosts, and the command cannot connect to its own listeners",
];

#[cfg(target_os = "macos")]
pub fn probe() -> crate::protocol::SandboxInfo {
    use crate::protocol::{Mechanism, SandboxInfo, SandboxStatus};
    let (status, gaps) = match run_true() {
        Ok(()) => (
            SandboxStatus::Available,
            GAPS.iter().map(|gap| gap.to_string()).collect(),
        ),
        Err(reason) => (SandboxStatus::Unavailable { reason }, Vec::new()),
    };
    SandboxInfo {
        mechanism: Mechanism::Seatbelt,
        status,
        baseline_read: super::baseline_read(),
        gaps,
    }
}

/// Runs `/usr/bin/true` through `sandbox-exec` and the helper, with only that file readable
/// and no network.
#[cfg(target_os = "macos")]
fn run_true() -> std::result::Result<(), String> {
    use std::collections::BTreeMap;
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;

    use crate::helper::{JobOp, encode_job, install_status_fd, parse_exec_status};
    use crate::policy::{Policy, rules};
    use crate::protocol::{AbsPath, Argv};

    let text = |err: Error| err.to_string();
    let io = |err: std::io::Error| err.to_string();
    let policy = Policy {
        read: rules(Default::Deny, &["/usr/bin/true"], &[]),
        write: rules(Default::Deny, &[], &[]),
        network: Network::Host {
            local_bind: false,
            unix_sockets: false,
        },
    };
    // The probe has no state directory. `/var/empty` exists and is empty, so the deny rule is
    // rendered and parsed like a real one.
    let job = Job {
        policy: ResolvedPolicy::resolve(&policy, Path::new("/var/empty")).map_err(text)?,
        op: JobOp::Exec {
            argv: Argv::try_from(vec!["/usr/bin/true".to_string()]).map_err(text)?,
            cwd: AbsPath::try_from("/").map_err(text)?,
            env: BTreeMap::new(),
        },
    };
    let exe = crate::helper::exe().map_err(text)?;
    let plan = Plan {
        policy: &job.policy,
        net: None,
        exe: &exe,
    };
    let (mut status_reader, status_writer) = std::io::pipe().map_err(io)?;
    let status_fd = status_writer.as_raw_fd();
    let mut command = prepare(&plan, &job).map_err(text)?.command;
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

/// `/usr/bin/sandbox-exec -p <profile> <helper> __sandbox`. Seatbelt matches paths, so a deny
/// entry that does not exist needs no placeholder.
pub fn prepare(plan: &Plan, _job: &Job) -> Result<Prepared> {
    // Seatbelt matches real paths, so the helper is allowed, and run, by its canonical path.
    let helper = std::fs::canonicalize(plan.exe)?;
    let net = Net::new(plan.policy.network(), plan.net.as_ref())?;
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-p")
        .arg(profile(plan.policy, net, &helper)?)
        .arg(&helper)
        .arg("__sandbox");
    Ok(Prepared::command(command))
}

/// The network a profile allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Net {
    Host {
        local_bind: bool,
        unix_sockets: bool,
    },
    /// Outbound TCP to the command proxy's two loopback ports and nothing else.
    Isolated {
        proxy_ports: [u16; 2],
        local_bind: bool,
        unix_sockets: bool,
    },
}

impl Net {
    fn new(network: &Network, proxies: Option<&NetPlan>) -> Result<Net> {
        match (network, proxies) {
            (
                &Network::Host {
                    local_bind,
                    unix_sockets,
                },
                _,
            ) => Ok(Net::Host {
                local_bind,
                unix_sockets,
            }),
            (
                &Network::Isolated {
                    local_bind,
                    unix_sockets,
                    ..
                },
                Some(NetPlan { http, socks }),
            ) => Ok(Net::Isolated {
                proxy_ports: [loopback_port(http)?, loopback_port(socks)?],
                local_bind,
                unix_sockets,
            }),
            (Network::Isolated { .. }, None) => Err(Error::sandbox_unavailable(
                "isolated networking needs the command proxy",
            )),
        }
    }
}

/// Seatbelt names a remote TCP endpoint only as `localhost:<port>` or `*:<port>`.
fn loopback_port(endpoint: &Endpoint) -> Result<u16> {
    match endpoint {
        Endpoint::Tcp(addr) if addr.ip().is_loopback() => Ok(addr.port()),
        other => Err(Error::sandbox_unavailable(format!(
            "Seatbelt can let a command reach a proxy on loopback TCP only, not {other:?}"
        ))),
    }
}

/// One path rule. `read: None` leaves reads to the rules before it.
#[derive(Debug, PartialEq, Eq)]
struct PathRule {
    path: PathBuf,
    read: Option<bool>,
    write: bool,
}

/// The policy's entries as Seatbelt rules, shallowest first; equal depths keep the policy's
/// order, so the deny of a tied path stays after its allow.
///
/// A write-denied entry that does not exist is enforced by its path alone. If a directory above
/// it is missing too, a command could build that directory elsewhere and rename it into place,
/// planting the denied path. The first missing directory is therefore write-denied when its
/// parent is writable, which is where Linux and Windows put a placeholder.
fn path_rules(policy: &ResolvedPolicy) -> Vec<PathRule> {
    let mut rules: Vec<PathRule> = policy
        .layers()
        .into_iter()
        .map(|layer| PathRule {
            path: real_path(&layer.path),
            read: Some(layer.read),
            write: layer.write,
        })
        .collect();
    let mut placeholders = BTreeSet::new();
    for rule in &rules {
        let first = first_missing(&rule.path);
        if !rule.write
            && first != rule.path
            && first.parent().is_some_and(|p| policy.can_write(p))
            && !rules.iter().any(|other| other.path == first)
        {
            placeholders.insert(first);
        }
    }
    rules.extend(placeholders.into_iter().map(|path| PathRule {
        path,
        read: None,
        write: false,
    }));
    rules.sort_by_key(|rule| rule.path.components().count());
    rules
}

/// `path` with its deepest existing ancestor canonicalized, so `/tmp/x` is `/private/tmp/x`
/// whether or not `x` exists.
fn real_path(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    for ancestor in path.ancestors() {
        if let Ok(real) = std::fs::canonicalize(ancestor) {
            return rest.iter().rev().fold(real, |acc, name| acc.join(name));
        }
        if let Some(name) = ancestor.file_name() {
            rest.push(name);
        }
    }
    path.to_path_buf()
}

/// The shallowest component of `path` that does not exist (`path` itself when only it is
/// missing).
fn first_missing(path: &Path) -> PathBuf {
    path.ancestors()
        .take_while(|ancestor| !ancestor.exists())
        .last()
        .unwrap_or(path)
        .to_path_buf()
}

fn profile(policy: &ResolvedPolicy, net: Net, helper: &Path) -> Result<String> {
    let mut out = String::from(BASE);
    let verb = |allowed: bool| if allowed { "allow" } else { "deny" };

    out.push_str("\n; filesystem: the policy's defaults, then its entries by depth\n");
    let read_default = policy.read_default() == Default::Allow;
    let write_default = policy.write_default() == Default::Allow;
    writeln!(out, "({} {READ_OPS})", verb(read_default)).expect("writing to a String");
    writeln!(out, "({} {WRITE_OPS})", verb(write_default)).expect("writing to a String");
    let rules = path_rules(policy);
    for rule in &rules {
        let path = quote(&rule.path)?;
        if let Some(read) = rule.read {
            writeln!(out, "({} {READ_OPS} (subpath {path}))", verb(read))
                .expect("writing to a String");
        }
        writeln!(out, "({} {WRITE_OPS} (subpath {path}))", verb(rule.write))
            .expect("writing to a String");
    }

    // dyld reads `/` before it loads anything. `realpath` and `pwd -P` stat every component
    // of a path, so the directories above a readable entry show their metadata.
    out.push_str("(allow file-read-data file-read-metadata (literal \"/\"))\n");
    let ancestors: BTreeSet<&Path> = rules
        .iter()
        .filter(|rule| rule.read == Some(true))
        .flat_map(|rule| rule.path.ancestors().skip(1))
        .filter(|ancestor| ancestor.parent().is_some())
        .collect();
    out.push_str("(allow file-read-metadata");
    for link in SYSTEM_SYMLINKS {
        write!(out, " (literal \"{link}\")").expect("writing to a String");
    }
    for ancestor in ancestors {
        write!(out, " (literal {})", quote(ancestor)?).expect("writing to a String");
    }
    out.push_str(")\n");
    writeln!(out, "(allow {READ_OPS} (literal {}))", quote(helper)?).expect("writing to a String");

    out.push('\n');
    out.push_str(DEVICES);
    out.push('\n');
    out.push_str(NETWORK_SERVICES);
    out.push('\n');
    network(&mut out, net);

    out.push_str("\n; fixed denies, last so nothing above reopens them\n");
    let state = policy.state_dir();
    writeln!(
        out,
        "(deny {READ_OPS} {WRITE_OPS} (subpath {}))",
        quote(state)?
    )
    .expect("writing to a String");
    // Seatbelt matches paths, not files: renaming a directory above a write-denied path would
    // carry the path out from under its rule. Codex protects the same directories.
    let protected: BTreeSet<&Path> = rules
        .iter()
        .filter(|rule| !rule.write)
        .map(|rule| rule.path.as_path())
        .chain([state])
        .flat_map(|path| path.ancestors().skip(1))
        .filter(|ancestor| policy.can_write(ancestor))
        .collect();
    for dir in protected {
        writeln!(
            out,
            "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal {})))",
            quote(dir)?
        )
        .expect("writing to a String");
    }
    // F_MAKECOMPRESSED (80) and F_TRANSFEREXTENTS (110) change a file through a read-only
    // descriptor without a file-write check (Codex, seatbelt.rs).
    out.push_str("(deny system-fcntl (fcntl-command 80 110))\n");
    Ok(out)
}

fn network(out: &mut String, net: Net) {
    out.push_str("; network\n");
    match net {
        Net::Host {
            local_bind,
            unix_sockets,
        } => {
            out.push_str("(allow network*)\n");
            if !local_bind {
                out.push_str("(deny network-bind network-inbound (local ip))\n");
            }
            if !unix_sockets {
                out.push_str("(deny network* (local unix-socket))\n");
                out.push_str("(deny network* (remote unix-socket))\n");
                // Name lookups go through this socket, and host networking includes them.
                writeln!(
                    out,
                    "(allow network-outbound (remote unix-socket (path-literal \"{MDNS_SOCKET}\")))"
                )
                .expect("writing to a String");
            }
        }
        Net::Isolated {
            proxy_ports,
            local_bind,
            unix_sockets,
        } => {
            out.push_str("(deny network*)\n");
            for port in proxy_ports {
                writeln!(
                    out,
                    "(allow network-outbound (remote tcp \"localhost:{port}\"))"
                )
                .expect("writing to a String");
            }
            // A local filter cannot name an address: Seatbelt's "localhost" there matches every
            // local address, so loopback-only binding is not expressible (probe gaps).
            if local_bind {
                out.push_str("(allow network-bind network-inbound (local ip))\n");
            }
            if unix_sockets {
                out.push_str("(allow network* (local unix-socket))\n");
                out.push_str("(allow network* (remote unix-socket))\n");
            }
            // Names resolve in the proxy only.
            writeln!(
                out,
                "(deny network-outbound (remote unix-socket (path-literal \"{MDNS_SOCKET}\")))"
            )
            .expect("writing to a String");
            out.push_str("(deny mach-lookup (global-name \"com.apple.dnssd.service\"))\n");
        }
    }
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
    use std::net::SocketAddr;

    use super::*;
    use crate::error::ErrorKind;
    use crate::policy::{HostRules, Policy, rules};

    fn repo_policy() -> ResolvedPolicy {
        let policy = Policy {
            read: rules(
                Default::Deny,
                &["/usr", "/Users/me/repo"],
                &["/Users/me/repo/secret"],
            ),
            write: rules(
                Default::Deny,
                &["/Users/me/repo"],
                &["/Users/me/repo/.git/hooks", "/Users/me/repo/secret"],
            ),
            network: Network::Host {
                local_bind: false,
                unix_sockets: false,
            },
        };
        ResolvedPolicy::resolve(&policy, Path::new("/Users/me/.happy")).unwrap()
    }

    fn host(local_bind: bool, unix_sockets: bool) -> Net {
        Net::Host {
            local_bind,
            unix_sockets,
        }
    }

    fn isolated(local_bind: bool, unix_sockets: bool) -> Net {
        Net::Isolated {
            proxy_ports: [3128, 1080],
            local_bind,
            unix_sockets,
        }
    }

    #[test]
    fn full_profile() {
        let text = profile(
            &repo_policy(),
            host(false, false),
            Path::new("/opt/hs/happy-supervisor"),
        )
        .unwrap();
        let expected = format!(
            r#"{BASE}
; filesystem: the policy's defaults, then its entries by depth
(deny file-read* file-map-executable process-exec)
(deny file-write*)
(allow file-read* file-map-executable process-exec (subpath "/usr"))
(deny file-write* (subpath "/usr"))
(deny file-read* file-map-executable process-exec (subpath "/Users/me/.happy"))
(deny file-write* (subpath "/Users/me/.happy"))
(allow file-read* file-map-executable process-exec (subpath "/Users/me/repo"))
(allow file-write* (subpath "/Users/me/repo"))
(deny file-read* file-map-executable process-exec (subpath "/Users/me/repo/secret"))
(deny file-write* (subpath "/Users/me/repo/secret"))
(allow file-read* file-map-executable process-exec (subpath "/Users/me/repo/.git/hooks"))
(deny file-write* (subpath "/Users/me/repo/.git/hooks"))
(allow file-read-data file-read-metadata (literal "/"))
(allow file-read-metadata (literal "/etc") (literal "/tmp") (literal "/var") (literal "/Users") (literal "/Users/me") (literal "/Users/me/repo") (literal "/Users/me/repo/.git"))
(allow file-read* file-map-executable process-exec (literal "/opt/hs/happy-supervisor"))

{DEVICES}
{NETWORK_SERVICES}
; network
(allow network*)
(deny network-bind network-inbound (local ip))
(deny network* (local unix-socket))
(deny network* (remote unix-socket))
(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))

; fixed denies, last so nothing above reopens them
(deny file-read* file-map-executable process-exec file-write* (subpath "/Users/me/.happy"))
(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal "/Users/me/repo")))
(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal "/Users/me/repo/.git")))
(deny system-fcntl (fcntl-command 80 110))
"#
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn allow_defaults_with_deny_holes() {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir(home.join(".ssh")).unwrap();
        let at = |rel: &str| home.join(rel).to_str().unwrap().to_string();
        let policy = Policy {
            read: rules(Default::Allow, &[&at(".ssh/known_hosts")], &[&at(".ssh")]),
            write: rules(Default::Allow, &[&at(".ssh/known_hosts")], &[&at(".ssh")]),
            network: Network::Host {
                local_bind: true,
                unix_sockets: true,
            },
        };
        let policy = ResolvedPolicy::resolve(&policy, &home.join(".happy")).unwrap();
        let text = profile(&policy, host(true, true), Path::new("/hs")).unwrap();
        let start = text.find("; filesystem").unwrap();
        let end = text.find("(allow file-read-data").unwrap();
        assert_eq!(
            text[start..end].replace(home.to_str().unwrap(), "~"),
            r#"; filesystem: the policy's defaults, then its entries by depth
(allow file-read* file-map-executable process-exec)
(allow file-write*)
(deny file-read* file-map-executable process-exec (subpath "~/.happy"))
(deny file-write* (subpath "~/.happy"))
(deny file-read* file-map-executable process-exec (subpath "~/.ssh"))
(deny file-write* (subpath "~/.ssh"))
(allow file-read* file-map-executable process-exec (subpath "~/.ssh/known_hosts"))
(allow file-write* (subpath "~/.ssh/known_hosts"))
"#
        );
        let fixed = &text[text.find("; fixed denies").unwrap()..];
        let protected: Vec<String> = home
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|dir| {
                format!(
                    "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal {:?})))\n",
                    dir
                )
            })
            .collect();
        assert_eq!(
            fixed.replace(home.to_str().unwrap(), "~"),
            format!(
                "; fixed denies, last so nothing above reopens them\n\
                 (deny file-read* file-map-executable process-exec file-write* (subpath \"~/.happy\"))\n\
                 {}(deny system-fcntl (fcntl-command 80 110))\n",
                protected.concat().replace(home.to_str().unwrap(), "~")
            )
        );
    }

    fn network_text(net: Net) -> String {
        let mut out = String::new();
        network(&mut out, net);
        out
    }

    #[test]
    fn network_rules() {
        assert_eq!(
            network_text(host(true, true)),
            "; network\n(allow network*)\n"
        );
        assert_eq!(
            network_text(host(false, true)),
            "; network\n(allow network*)\n(deny network-bind network-inbound (local ip))\n"
        );
        assert_eq!(
            network_text(isolated(false, false)),
            r#"; network
(deny network*)
(allow network-outbound (remote tcp "localhost:3128"))
(allow network-outbound (remote tcp "localhost:1080"))
(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
(deny mach-lookup (global-name "com.apple.dnssd.service"))
"#
        );
        assert_eq!(
            network_text(isolated(true, true)),
            r#"; network
(deny network*)
(allow network-outbound (remote tcp "localhost:3128"))
(allow network-outbound (remote tcp "localhost:1080"))
(allow network-bind network-inbound (local ip))
(allow network* (local unix-socket))
(allow network* (remote unix-socket))
(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
(deny mach-lookup (global-name "com.apple.dnssd.service"))
"#
        );
    }

    #[test]
    fn isolated_networking_needs_loopback_tcp_proxies() {
        let isolated = Network::Isolated {
            egress: HostRules {
                default: Default::Deny,
                allow: vec![],
                deny: vec![],
            },
            ports: None,
            local_bind: false,
            unix_sockets: true,
        };
        let tcp = |addr: &str| Endpoint::Tcp(addr.parse::<SocketAddr>().unwrap());
        let plan = |http, socks| NetPlan { http, socks };
        assert_eq!(
            Net::new(
                &isolated,
                Some(&plan(tcp("127.0.0.1:5001"), tcp("[::1]:5002")))
            )
            .unwrap(),
            Net::Isolated {
                proxy_ports: [5001, 5002],
                local_bind: false,
                unix_sockets: true,
            }
        );
        assert_eq!(
            Net::new(&isolated, None).unwrap_err(),
            Error::sandbox_unavailable("isolated networking needs the command proxy")
        );
        assert_eq!(
            Net::new(
                &isolated,
                Some(&plan(tcp("10.0.0.1:5001"), tcp("127.0.0.1:5002")))
            )
            .unwrap_err(),
            Error::sandbox_unavailable(
                "Seatbelt can let a command reach a proxy on loopback TCP only, not Tcp(10.0.0.1:5001)"
            )
        );
        assert_eq!(
            Net::new(
                &isolated,
                Some(&plan(tcp("127.0.0.1:5001"), Endpoint::Unix("/s".into())))
            )
            .unwrap_err(),
            Error::sandbox_unavailable(
                "Seatbelt can let a command reach a proxy on loopback TCP only, not Unix(\"/s\")"
            )
        );
        let host = Network::Host {
            local_bind: true,
            unix_sockets: false,
        };
        assert_eq!(
            Net::new(&host, None).unwrap(),
            super::tests::host(true, false)
        );
    }

    #[test]
    fn missing_deny_entries_write_deny_their_first_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let policy = Policy {
            read: rules(Default::Allow, &[], &[]),
            write: rules(
                Default::Deny,
                &[root.to_str().unwrap()],
                &[
                    root.join("new/hooks").to_str().unwrap(),
                    root.join("gone").to_str().unwrap(),
                ],
            ),
            network: Network::Host {
                local_bind: false,
                unix_sockets: false,
            },
        };
        let policy = ResolvedPolicy::resolve(&policy, &root.join("state")).unwrap();
        let rules: Vec<(PathBuf, Option<bool>, bool)> = path_rules(&policy)
            .into_iter()
            .map(|rule| (rule.path, rule.read, rule.write))
            .collect();
        assert_eq!(
            rules,
            [
                (root.clone(), Some(true), true),
                (root.join("gone"), Some(true), false),
                (root.join("state"), Some(false), false),
                (root.join("new"), None, false),
                (root.join("new/hooks"), Some(true), false),
            ]
        );
    }

    #[test]
    fn tmp_entries_use_the_real_path() {
        assert_eq!(
            real_path(Path::new("/tmp/does-not-exist/x")),
            std::fs::canonicalize("/tmp")
                .unwrap()
                .join("does-not-exist/x")
        );
    }

    #[test]
    fn unusable_paths_are_invalid_params() {
        let policy = repo_policy();
        let err = profile(&policy, host(false, false), Path::new("/a\nb")).unwrap_err();
        assert_eq!(
            err,
            Error::invalid_params(r#"sandbox path "/a\nb" has a control character"#)
        );
        use std::os::unix::ffi::OsStrExt as _;
        let latin1 = Path::new(std::ffi::OsStr::from_bytes(b"/caf\xe9"));
        let err = profile(&policy, host(false, false), latin1).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidParams);
        assert_eq!(err.message, r#"sandbox path "/caf\xE9" is not UTF-8"#);
    }
}
