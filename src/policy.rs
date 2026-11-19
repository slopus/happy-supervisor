//! The sandbox policy (docs/policy.md): the validated wire [`Policy`], and the
//! [`ResolvedPolicy`] an operation actually runs under.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The most entries one `allow` or `deny` list may hold.
pub const MAX_POLICY_ENTRIES: usize = 1024;

/// What applies to a path or host that no entry matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Default {
    Allow,
    Deny,
}

/// `filesystem.read` or `filesystem.write`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub default: Default,
    pub allow: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
}

/// `network.egress`: host patterns (policy.md, Network).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRules {
    pub default: Default,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Network {
    Host {
        local_bind: bool,
        unix_sockets: bool,
    },
    Isolated {
        egress: HostRules,
        /// `None` is any port. Required on the wire, as `null`.
        #[serde(deserialize_with = "Option::deserialize")]
        ports: Option<Vec<u16>>,
        local_bind: bool,
        unix_sockets: bool,
    },
}

impl Network {
    pub fn local_bind(&self) -> bool {
        match self {
            Network::Host { local_bind, .. } | Network::Isolated { local_bind, .. } => *local_bind,
        }
    }

    pub fn unix_sockets(&self) -> bool {
        match self {
            Network::Host { unix_sockets, .. } | Network::Isolated { unix_sockets, .. } => {
                *unix_sockets
            }
        }
    }
}

/// A policy as the control plane sent it. Deserializing validates it; a value built in code is
/// validated by [`Policy::validate`], which [`ResolvedPolicy::resolve`] calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PolicyWire", into = "PolicyWire")]
pub struct Policy {
    pub read: RuleSet,
    pub write: RuleSet,
    pub network: Network,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    filesystem: FilesystemWire,
    network: Network,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemWire {
    read: RuleSet,
    write: RuleSet,
}

impl TryFrom<PolicyWire> for Policy {
    type Error = Error;

    fn try_from(wire: PolicyWire) -> Result<Policy> {
        let policy = Policy {
            read: wire.filesystem.read,
            write: wire.filesystem.write,
            network: wire.network,
        };
        policy.validate()?;
        Ok(policy)
    }
}

impl From<Policy> for PolicyWire {
    fn from(policy: Policy) -> PolicyWire {
        PolicyWire {
            filesystem: FilesystemWire {
                read: policy.read,
                write: policy.write,
            },
            network: policy.network,
        }
    }
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        for (name, rules) in [("read", &self.read), ("write", &self.write)] {
            for (list, paths) in [("allow", &rules.allow), ("deny", &rules.deny)] {
                check_len(&format!("{name}.{list}"), paths.len())?;
                for path in paths {
                    validate_path(path)?;
                }
            }
        }
        if let Network::Isolated { egress, ports, .. } = &self.network {
            for (list, hosts) in [("allow", &egress.allow), ("deny", &egress.deny)] {
                check_len(&format!("egress.{list}"), hosts.len())?;
                for host in hosts {
                    validate_host_pattern(host)?;
                }
            }
            if ports.as_ref().is_some_and(|ports| ports.contains(&0)) {
                return Err(Error::invalid_params("policy ports cannot contain 0"));
            }
        }
        let by_name = |path: &Path| path.to_path_buf();
        check_contradiction(
            &Rules::new(&self.read, by_name),
            &Rules::new(&self.write, by_name),
        )
    }
}

fn check_len(list: &str, len: usize) -> Result<()> {
    if len > MAX_POLICY_ENTRIES {
        return Err(Error::invalid_params(format!(
            "policy {list} has {len} entries, at most {MAX_POLICY_ENTRIES} are allowed"
        )));
    }
    Ok(())
}

/// Absolute and normalized: no `.`, `..` or empty components, no NUL. One trailing separator is
/// allowed. Checked on the string, because `Path::components` silently normalizes `a//b` and
/// `a/./b`.
fn validate_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    let bad = |why: &str| Err(Error::invalid_params(format!("policy path {text:?} {why}")));
    if path.to_str().is_none() {
        return bad("is not UTF-8");
    }
    if text.contains('\0') {
        return bad("contains NUL");
    }
    if !path.is_absolute() {
        return bad("is not absolute");
    }
    let body = text.strip_suffix(std::path::is_separator).unwrap_or(&text);
    // The first piece is the root (empty) or a Windows prefix such as `C:`.
    for component in body.split(std::path::is_separator).skip(1) {
        match component {
            "" => return bad("has an empty component"),
            "." | ".." => return bad("is not normalized"),
            _ => {}
        }
    }
    Ok(())
}

/// An exact DNS name, `*.` and a DNS name, or an IP literal (IPv6 with or without brackets).
fn validate_host_pattern(pattern: &str) -> Result<()> {
    if ip_literal(pattern).is_some() {
        return Ok(());
    }
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    if is_dns_name(name) {
        return Ok(());
    }
    Err(Error::invalid_params(format!(
        "policy host {pattern:?} is not a DNS name, *.name or an IP address"
    )))
}

fn is_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn ip_literal(text: &str) -> Option<IpAddr> {
    let bare = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text);
    bare.parse().ok()
}

/// Whether `rules` let a connection to `host` through: the most specific matching pattern
/// decides, deny on a tie, and `default` when none matches. An exact name is more specific than
/// any `*.` pattern that matches it, and a longer suffix more than a shorter one. An IP host
/// matches only the same IP literal.
pub fn host_allowed(rules: &HostRules, host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let most_specific = |patterns: &[String]| {
        patterns
            .iter()
            .filter_map(|pattern| host_match(pattern, host))
            .max()
    };
    match (most_specific(&rules.allow), most_specific(&rules.deny)) {
        (Some(allow), Some(deny)) => allow > deny,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => rules.default == Default::Allow,
    }
}

/// How specific `pattern` is for `host` (the labels it names, one more for an exact match), or
/// `None` when it does not match.
fn host_match(pattern: &str, host: &str) -> Option<usize> {
    if let Some(ip) = ip_literal(host) {
        return (ip_literal(pattern) == Some(ip)).then_some(usize::MAX);
    }
    let labels = |name: &str| name.split('.').count();
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            let cut = host.len().checked_sub(suffix.len() + 1)?;
            let below = cut > 0
                && host.as_bytes()[cut] == b'.'
                && host[cut + 1..].eq_ignore_ascii_case(suffix);
            below.then(|| labels(suffix))
        }
        None => pattern.eq_ignore_ascii_case(host).then(|| labels(host) + 1),
    }
}

/// What an operation runs under, decided once at the dispatcher from the request's `access`.
// One per operation, moved a few times: boxing the policy would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Confinement {
    Raw,
    Sandboxed(ResolvedPolicy),
}

/// One rule set with its entries keyed by path: `true` allows. Deny wins over allow on the same
/// path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Rules {
    default: Default,
    entries: BTreeMap<PathBuf, bool>,
}

impl Rules {
    fn new(set: &RuleSet, resolve: impl Fn(&Path) -> PathBuf) -> Rules {
        let mut entries = BTreeMap::new();
        for path in &set.allow {
            entries.insert(resolve(path), true);
        }
        for path in &set.deny {
            entries.insert(resolve(path), false);
        }
        Rules {
            default: set.default,
            entries,
        }
    }

    /// The decision of the entry that is the longest whole-component prefix of `path`.
    fn allows(&self, path: &Path) -> bool {
        self.entry(path).unwrap_or(self.default == Default::Allow)
    }

    /// The decision of the deepest entry at or above `path`, or `None` when the default decides.
    fn entry(&self, path: &Path) -> Option<bool> {
        path.ancestors()
            .find_map(|ancestor| self.entries.get(ancestor).copied())
    }
}

/// A path a `read.deny` entry decides but the write rules allow. A read default never
/// contradicts: writing implies reading. The decisions only change at an entry, and a path below
/// an entry that no deeper entry names is decided like the entry, so checking every entry covers
/// every path.
fn check_contradiction(read: &Rules, write: &Rules) -> Result<()> {
    for path in read.entries.keys().chain(write.entries.keys()) {
        if write.allows(path) && read.entry(path) == Some(false) {
            return Err(Error::invalid_params(format!(
                "policy denies reading {} but allows writing it",
                path.display()
            )));
        }
    }
    Ok(())
}

/// One rule as the mechanisms apply it: the decision at `path`, which holds below it until a
/// deeper layer says otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layer {
    pub path: PathBuf,
    pub read: bool,
    pub write: bool,
    /// Whether the path existed when the policy was resolved.
    pub exists: bool,
}

/// A policy resolved against the filesystem when the operation starts: entries with their
/// symlinks resolved, and the state directory denied for reading and writing.
///
/// It is computed once in the supervisor and sent to the helper inside the [`Job`], so the parent
/// and the helper see the same rules.
///
/// [`Job`]: crate::helper::Job
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    read: Rules,
    write: Rules,
    network: Network,
    state_dir: PathBuf,
    layers: Vec<Layer>,
}

impl ResolvedPolicy {
    /// Validates `policy` and resolves its entries: an existing path to its canonical form, a
    /// missing one to its deepest existing ancestor's canonical form plus the rest of its name.
    /// Entries at or inside the state directory are dropped and the state directory is denied.
    pub fn resolve(policy: &Policy, state_dir: &Path) -> Result<ResolvedPolicy> {
        policy.validate()?;
        let state_dir = resolve_path(state_dir);
        let mut read = Rules::new(&policy.read, resolve_path);
        let mut write = Rules::new(&policy.write, resolve_path);
        for rules in [&mut read, &mut write] {
            rules
                .entries
                .retain(|path, _| !path.starts_with(&state_dir));
            rules.entries.insert(state_dir.clone(), false);
        }
        check_contradiction(&read, &write)?;
        let mut resolved = ResolvedPolicy {
            read,
            write,
            network: policy.network.clone(),
            state_dir,
            layers: Vec::new(),
        };
        resolved.layers = resolved.compute_layers();
        Ok(resolved)
    }

    fn compute_layers(&self) -> Vec<Layer> {
        let mut paths: Vec<&PathBuf> = self.read.entries.keys().collect();
        paths.extend(self.write.entries.keys());
        paths.sort_by_key(|path| (path.components().count(), path.as_path()));
        paths.dedup();
        paths
            .into_iter()
            .map(|path| Layer {
                path: path.clone(),
                read: self.can_read(path),
                write: self.can_write(path),
                exists: std::fs::symlink_metadata(path).is_ok(),
            })
            .collect()
    }

    /// Whether the policy lets an operation read `path`, a canonical path. Writing implies
    /// reading.
    pub fn can_read(&self, path: &Path) -> bool {
        self.read.allows(path) || self.write.allows(path)
    }

    /// Whether the policy lets an operation write `path`, a canonical path.
    pub fn can_write(&self, path: &Path) -> bool {
        self.write.allows(path)
    }

    /// Every rule as a [`Layer`], sorted by depth and then path: the order in which mechanisms
    /// where a later, deeper rule overrides (bwrap mounts, Seatbelt) apply them. The state
    /// directory is one of them.
    pub fn layers(&self) -> Vec<Layer> {
        self.layers.clone()
    }

    pub fn read_default(&self) -> Default {
        self.read.default
    }

    pub fn write_default(&self) -> Default {
        self.write.default
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    /// The canonical state directory. Never readable or writable, whatever the policy says.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Lets the operation read one existing file the policy did not list: the CA bundle of a
    /// command with a credential proxy (proxy.md). A missing file, or one inside the state
    /// directory, is not allowed.
    pub fn allow_read_file(&mut self, path: &Path) {
        let Ok(canonical) = std::fs::canonicalize(path) else {
            return;
        };
        if canonical.starts_with(&self.state_dir) || !canonical.is_file() {
            return;
        }
        self.read.entries.insert(canonical, true);
        self.layers = self.compute_layers();
    }

    /// The policy as the v1 backends (Landlock, the v1 Seatbelt profile) enforce it: allowed
    /// paths only. Until the v2 backends land, they run a policy only when it has that shape:
    /// both defaults deny, nothing denied below an allowed path except the state directory, and
    /// host networking.
    pub fn grants(&self) -> Result<Vec<Grant>> {
        let unsupported =
            |why: &str| Err(Error::sandbox_unavailable(format!("this backend {why}")));
        if self.read.default == Default::Allow || self.write.default == Default::Allow {
            return unsupported("cannot enforce an allow default");
        }
        if matches!(self.network, Network::Isolated { .. }) {
            return unsupported("cannot isolate the network");
        }
        let mut grants: BTreeMap<PathBuf, (GrantKind, Rights)> = BTreeMap::new();
        for layer in &self.layers {
            if layer.path == self.state_dir {
                continue;
            }
            let parent = layer.path.parent();
            let parent_read = parent.is_some_and(|p| self.can_read(p));
            let parent_write = parent.is_some_and(|p| self.can_write(p));
            if (parent_read && !layer.read) || (parent_write && !layer.write) {
                return unsupported("cannot deny a path below an allowed one");
            }
            if !layer.read {
                continue;
            }
            let Ok(canonical) = std::fs::canonicalize(&layer.path) else {
                continue;
            };
            let kind = if canonical.is_dir() {
                GrantKind::Directory
            } else {
                GrantKind::File
            };
            let rights = if layer.write {
                Rights::ReadWrite
            } else {
                Rights::Read
            };
            add_grant(&mut grants, canonical, kind, rights);
        }
        for (path, rights) in V1_DEVICES {
            if Path::new(path).exists() {
                add_grant(&mut grants, PathBuf::from(path), GrantKind::File, rights);
            }
        }
        Ok(grants
            .into_iter()
            .map(|(path, (kind, rights))| Grant { path, kind, rights })
            .collect())
    }
}

/// The canonical form of `path`, or of its deepest existing ancestor followed by the rest.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    for ancestor in path.ancestors().skip(1) {
        if let Ok(canonical) = std::fs::canonicalize(ancestor) {
            let rest = path
                .strip_prefix(ancestor)
                .expect("an ancestor is a prefix");
            return canonical.join(rest);
        }
    }
    path.to_path_buf()
}

/// The device nodes the v1 backends grant every sandbox.
const V1_DEVICES: [(&str, Rights); 4] = [
    ("/dev/null", Rights::ReadWrite),
    ("/dev/zero", Rights::Read),
    ("/dev/random", Rights::Read),
    ("/dev/urandom", Rights::Read),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Rights {
    Read,
    /// Write implies read.
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantKind {
    /// Covers the directory and everything below it.
    Directory,
    /// Covers that file only.
    File,
}

/// One canonical, existing path a v1 backend lets an operation use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub path: PathBuf,
    pub kind: GrantKind,
    pub rights: Rights,
}

fn add_grant(
    grants: &mut BTreeMap<PathBuf, (GrantKind, Rights)>,
    path: PathBuf,
    kind: GrantKind,
    rights: Rights,
) {
    let entry = grants.entry(path).or_insert((kind, rights));
    entry.1 = entry.1.max(rights);
}

/// A rule set from path strings, for tests.
pub fn rules(default: Default, allow: &[&str], deny: &[&str]) -> RuleSet {
    RuleSet {
        default,
        allow: allow.iter().map(PathBuf::from).collect(),
        deny: deny.iter().map(PathBuf::from).collect(),
    }
}

/// A policy that allows reading `read` and writing `write`, denies everything else, and uses
/// host networking: the shape every v1 policy had.
pub fn allow_list<R, W>(
    read: impl IntoIterator<Item = R>,
    write: impl IntoIterator<Item = W>,
    local_bind: bool,
    unix_sockets: bool,
) -> Policy
where
    R: AsRef<Path>,
    W: AsRef<Path>,
{
    let write: Vec<PathBuf> = write
        .into_iter()
        .map(|p| p.as_ref().to_path_buf())
        .collect();
    let mut readable: Vec<PathBuf> = read.into_iter().map(|p| p.as_ref().to_path_buf()).collect();
    readable.extend(write.iter().cloned());
    Policy {
        read: RuleSet {
            default: Default::Deny,
            allow: readable,
            deny: Vec::new(),
        },
        write: RuleSet {
            default: Default::Deny,
            allow: write,
            deny: Vec::new(),
        },
        network: Network::Host {
            local_bind,
            unix_sockets,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn host_network() -> Network {
        Network::Host {
            local_bind: false,
            unix_sockets: false,
        }
    }

    fn policy(read: RuleSet, write: RuleSet) -> Policy {
        Policy {
            read,
            write,
            network: host_network(),
        }
    }

    fn rejection(path: &str) -> String {
        let p = policy(
            rules(Default::Deny, &[path], &[]),
            rules(Default::Deny, &[], &[]),
        );
        let err = p.validate().unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidParams);
        err.message
    }

    #[cfg(unix)]
    #[test]
    fn path_rules() {
        assert_eq!(rejection("usr"), r#"policy path "usr" is not absolute"#);
        assert_eq!(rejection(""), r#"policy path "" is not absolute"#);
        assert_eq!(
            rejection("/a/../b"),
            r#"policy path "/a/../b" is not normalized"#
        );
        assert_eq!(
            rejection("/a/./b"),
            r#"policy path "/a/./b" is not normalized"#
        );
        assert_eq!(
            rejection("/a//b"),
            r#"policy path "/a//b" has an empty component"#
        );
        assert_eq!(rejection("/a\0b"), r#"policy path "/a\0b" contains NUL"#);
        let fine = policy(
            rules(Default::Deny, &["/", "/usr", "/home/me/repo/", "/tmp"], &[]),
            rules(Default::Deny, &["/tmp"], &[]),
        );
        assert_eq!(fine.validate(), Ok(()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_rules() {
        assert_eq!(
            rejection(r"\Users"),
            r#"policy path "\\Users" is not absolute"#
        );
        assert_eq!(
            rejection(r"C:\a\..\b"),
            r#"policy path "C:\\a\\..\\b" is not normalized"#
        );
        assert_eq!(
            rejection("C:/a//b"),
            r#"policy path "C:/a//b" has an empty component"#
        );
    }

    #[test]
    fn lists_are_capped() {
        let many: Vec<String> = (0..1025).map(|i| format!("/p{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let p = policy(
            rules(Default::Allow, &[], &[]),
            rules(Default::Deny, &[], &many),
        );
        assert_eq!(
            p.validate(),
            Err(Error::invalid_params(
                "policy write.deny has 1025 entries, at most 1024 are allowed"
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_wire_shape_is_policy_mds() {
        let literal = serde_json::json!({
          "filesystem": {
            "read":  { "default": "allow", "allow": [], "deny": ["/home/me/.ssh", "/home/me/.aws"] },
            "write": { "default": "deny",  "allow": ["/home/me/repo", "/tmp/job-17"], "deny": ["/home/me/repo/.git/hooks"] }
          },
          "network": {
            "mode": "isolated",
            "egress": { "default": "deny", "allow": ["github.com", "*.githubusercontent.com"], "deny": [] },
            "ports": [443, 22],
            "localBind": false,
            "unixSockets": false
          }
        });
        let parsed: Policy = serde_json::from_value(literal.clone()).unwrap();
        assert_eq!(
            parsed,
            Policy {
                read: rules(Default::Allow, &[], &["/home/me/.ssh", "/home/me/.aws"]),
                write: rules(
                    Default::Deny,
                    &["/home/me/repo", "/tmp/job-17"],
                    &["/home/me/repo/.git/hooks"]
                ),
                network: Network::Isolated {
                    egress: HostRules {
                        default: Default::Deny,
                        allow: vec!["github.com".into(), "*.githubusercontent.com".into()],
                        deny: vec![],
                    },
                    ports: Some(vec![443, 22]),
                    local_bind: false,
                    unix_sockets: false,
                },
            }
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), literal);

        let host: Network = serde_json::from_value(
            serde_json::json!({ "mode": "host", "localBind": true, "unixSockets": true }),
        )
        .unwrap();
        assert_eq!(
            host,
            Network::Host {
                local_bind: true,
                unix_sockets: true
            }
        );
    }

    #[test]
    fn every_field_is_required_and_no_other_is_allowed() {
        let error = |value: serde_json::Value| {
            serde_json::from_value::<Policy>(value)
                .unwrap_err()
                .to_string()
        };
        let fs = serde_json::json!({
            "read":  { "default": "allow", "allow": [], "deny": [] },
            "write": { "default": "deny",  "allow": [], "deny": [] }
        });
        let host = serde_json::json!({ "mode": "host", "localBind": true, "unixSockets": true });
        assert!(error(serde_json::json!({ "filesystem": fs })).contains("missing field `network`"));
        let no_ports = serde_json::json!({
            "mode": "isolated",
            "egress": { "default": "deny", "allow": [], "deny": [] },
            "localBind": false, "unixSockets": false
        });
        assert!(
            error(serde_json::json!({ "filesystem": fs, "network": no_ports }))
                .contains("missing field `ports`")
        );
        let extra = serde_json::json!({ "mode": "host", "localBind": true, "unixSockets": true, "ports": null });
        assert!(
            error(serde_json::json!({ "filesystem": fs, "network": extra }))
                .contains("unknown field `ports`")
        );
        let no_deny = serde_json::json!({
            "read":  { "default": "allow", "allow": [] },
            "write": { "default": "deny",  "allow": [], "deny": [] }
        });
        assert!(
            error(serde_json::json!({ "filesystem": no_deny, "network": host }))
                .contains("missing field `deny`")
        );
        let any_port = serde_json::json!({
            "mode": "isolated",
            "egress": { "default": "deny", "allow": [], "deny": [] },
            "ports": null, "localBind": false, "unixSockets": false
        });
        let parsed: Policy =
            serde_json::from_value(serde_json::json!({ "filesystem": fs, "network": any_port }))
                .unwrap();
        assert!(matches!(
            parsed.network,
            Network::Isolated { ports: None, .. }
        ));
        let bad_host = serde_json::json!({
            "mode": "isolated",
            "egress": { "default": "deny", "allow": ["git*.com"], "deny": [] },
            "ports": null, "localBind": false, "unixSockets": false
        });
        assert!(
            error(serde_json::json!({ "filesystem": fs, "network": bad_host }))
                .contains(r#"policy host "git*.com" is not a DNS name, *.name or an IP address"#)
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_most_specific_entry_wins_and_deny_wins_a_tie() {
        // Paths under a directory that does not exist resolve to themselves on every system.
        let p = policy(
            rules(
                Default::Deny,
                &["/hs-nowhere/me", "/x"],
                &["/hs-nowhere/me/.ssh", "/x"],
            ),
            rules(Default::Deny, &[], &[]),
        );
        let resolved = ResolvedPolicy::resolve(&p, Path::new("/nonexistent/state")).unwrap();
        let read = |path: &str| resolved.can_read(Path::new(path));
        assert!(read("/hs-nowhere/me/repo/a.rs"));
        assert!(read("/hs-nowhere/me"));
        assert!(!read("/hs-nowhere/me/.ssh/id_ed25519"));
        assert!(read("/hs-nowhere/me/.sshx"));
        assert!(!read("/etc/passwd"));
        assert!(!read("/x/y"));
        assert!(!read("/nonexistent/state/key"));
    }

    #[cfg(unix)]
    #[test]
    fn writing_implies_reading_and_the_contradiction_is_invalid() {
        let p = policy(
            rules(Default::Deny, &[], &[]),
            rules(Default::Deny, &["/work"], &[]),
        );
        let resolved = ResolvedPolicy::resolve(&p, Path::new("/nonexistent/state")).unwrap();
        assert!(resolved.can_read(Path::new("/work/a")));
        assert!(!resolved.can_read(Path::new("/elsewhere")));
        let p = policy(
            rules(Default::Deny, &[], &[]),
            rules(Default::Allow, &[], &[]),
        );
        let resolved = ResolvedPolicy::resolve(&p, Path::new("/nonexistent/state")).unwrap();
        assert!(resolved.can_read(Path::new("/anything")));
        assert!(!resolved.can_read(Path::new("/nonexistent/state/key")));
        let p = policy(
            rules(Default::Allow, &[], &["/work"]),
            rules(Default::Allow, &[], &[]),
        );
        assert_eq!(
            p.validate(),
            Err(Error::invalid_params(
                "policy denies reading /work but allows writing it"
            ))
        );
        let p = policy(
            rules(Default::Allow, &[], &["/hs-nowhere/me/.ssh"]),
            rules(Default::Deny, &["/hs-nowhere/me"], &[]),
        );
        assert_eq!(
            p.validate(),
            Err(Error::invalid_params(
                "policy denies reading /hs-nowhere/me/.ssh but allows writing it"
            ))
        );
        let p = policy(
            rules(Default::Allow, &[], &["/hs-nowhere/me/.ssh"]),
            rules(Default::Deny, &["/hs-nowhere/me"], &["/hs-nowhere/me/.ssh"]),
        );
        let resolved = ResolvedPolicy::resolve(&p, Path::new("/nonexistent/state")).unwrap();
        assert!(resolved.can_write(Path::new("/hs-nowhere/me/a")));
        assert!(resolved.can_read(Path::new("/hs-nowhere/me/a")));
        assert!(!resolved.can_read(Path::new("/hs-nowhere/me/.ssh/k")));
        assert!(!resolved.can_write(Path::new("/hs-nowhere/me/.ssh/k")));
    }

    #[cfg(unix)]
    #[test]
    fn resolution_follows_symlinks_denies_the_state_dir_and_orders_layers() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (repo, state) = (root.join("repo"), root.join("state"));
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::create_dir(&state).unwrap();
        std::os::unix::fs::symlink(&repo, root.join("link")).unwrap();
        let s = |p: &Path| p.to_str().unwrap().to_string();
        let (root_s, link, missing, inside, hooks) = (
            s(&root),
            s(&root.join("link")),
            s(&root.join("link/missing/deeper")),
            s(&state.join("keys")),
            s(&repo.join(".git/hooks")),
        );
        let p = policy(
            rules(Default::Deny, &[&root_s, &inside], &[]),
            rules(Default::Deny, &[&link, &missing], &[&hooks]),
        );

        let resolved = ResolvedPolicy::resolve(&p, &root.join("state")).unwrap();

        assert_eq!(resolved.state_dir(), state);
        let layer = |path: PathBuf, read, write, exists| Layer {
            path,
            read,
            write,
            exists,
        };
        let depth = root.components().count();
        let mut expected = vec![
            layer(root.clone(), true, false, true),
            layer(repo.clone(), true, true, true),
            layer(state.clone(), false, false, true),
            layer(repo.join(".git/hooks"), true, false, false),
            layer(repo.join("missing/deeper"), true, true, false),
        ];
        expected.sort_by_key(|l| (l.path.components().count() - depth, l.path.clone()));
        assert_eq!(resolved.layers(), expected);
        assert!(resolved.can_write(&repo.join("src/main.rs")));
        assert!(!resolved.can_write(&repo.join(".git/hooks/pre-commit")));
        assert!(resolved.can_read(&repo.join(".git/hooks/pre-commit")));
        assert!(!resolved.can_read(&state.join("keys")));
        assert_eq!(
            (resolved.read_default(), resolved.write_default()),
            (Default::Deny, Default::Deny)
        );
        assert_eq!(resolved.network(), &host_network());
    }

    #[cfg(unix)]
    #[test]
    fn one_file_can_be_allowed_for_reading() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (private, public) = (root.join("private"), root.join("public"));
        std::fs::create_dir(&private).unwrap();
        std::fs::create_dir(&public).unwrap();
        let bundle = public.join("ca-bundle.pem");
        std::fs::write(&bundle, b"pem").unwrap();
        std::fs::write(private.join("proxy-ca.key"), b"key").unwrap();
        let p = policy(
            rules(Default::Deny, &[], &[]),
            rules(Default::Deny, &[], &[]),
        );
        let mut resolved = ResolvedPolicy::resolve(&p, &private).unwrap();

        resolved.allow_read_file(&bundle);
        resolved.allow_read_file(&private.join("proxy-ca.key"));
        resolved.allow_read_file(&public.join("missing.pem"));
        resolved.allow_read_file(&public);
        assert!(resolved.can_read(&bundle));
        assert!(!resolved.can_write(&bundle));
        assert!(!resolved.can_read(&public.join("other.pem")));
        assert!(!resolved.can_read(&private.join("proxy-ca.key")));
        let paths: Vec<PathBuf> = resolved.layers().into_iter().map(|l| l.path).collect();
        assert_eq!(paths, [private, bundle]);
    }

    #[cfg(unix)]
    #[test]
    fn v1_backends_get_grants_only_for_allow_lists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join("repo")).unwrap();
        let repo = root.join("repo");
        let (root_s, repo_s) = (root.to_str().unwrap(), repo.to_str().unwrap());
        let state = root.join("state");
        let list = allow_list([root_s], [repo_s], false, false);
        let grants = ResolvedPolicy::resolve(&list, &state)
            .unwrap()
            .grants()
            .unwrap();
        let ours: Vec<(PathBuf, GrantKind, Rights)> = grants
            .into_iter()
            .filter(|g| !g.path.starts_with("/dev"))
            .map(|g| (g.path, g.kind, g.rights))
            .collect();
        assert_eq!(
            ours,
            [
                (root.clone(), GrantKind::Directory, Rights::Read),
                (repo.clone(), GrantKind::Directory, Rights::ReadWrite),
            ]
        );
        let nested = policy(
            rules(Default::Deny, &[root_s], &[repo_s]),
            rules(Default::Deny, &[], &[]),
        );
        let refused = ResolvedPolicy::resolve(&nested, &state).unwrap().grants();
        assert_eq!(
            refused,
            Err(Error::sandbox_unavailable(
                "this backend cannot deny a path below an allowed one"
            ))
        );
    }

    #[test]
    fn hosts_match_the_most_specific_pattern() {
        let rules = HostRules {
            default: Default::Deny,
            allow: vec![
                "github.com".into(),
                "*.githubusercontent.com".into(),
                "*.example.com".into(),
                "10.0.0.1".into(),
                "[::1]".into(),
            ],
            deny: vec!["*.evil.example.com".into(), "github.com".into()],
        };
        let cases = [
            ("github.com", false),
            ("raw.githubusercontent.com", true),
            ("RAW.GitHubUserContent.com.", true),
            ("githubusercontent.com", false),
            ("xgithubusercontent.com", false),
            ("a.example.com", true),
            ("a.evil.example.com", false),
            ("evil.example.com", true),
            ("10.0.0.1", true),
            ("10.0.0.2", false),
            ("::1", true),
            ("[0:0::1]", true),
            ("other.org", false),
        ];
        for (host, allowed) in cases {
            assert_eq!(host_allowed(&rules, host), allowed, "{host}");
        }
        let open = HostRules {
            default: Default::Allow,
            allow: vec![],
            deny: vec!["*.tracker.net".into(), "1.2.3.4".into()],
        };
        assert!(host_allowed(&open, "anything.org"));
        assert!(!host_allowed(&open, "a.tracker.net"));
        assert!(!host_allowed(&open, "1.2.3.4"));
        assert!(host_allowed(&open, "tracker.net"));
    }
}
