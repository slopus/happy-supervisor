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
    pub allow: Vec<HostEntry>,
    pub deny: Vec<HostEntry>,
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

/// One `egress.allow` or `egress.deny` entry (policy.md, Network).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum HostEntry {
    /// Exactly this DNS name, lowercase.
    Name(String),
    /// `*.suffix`: every name under `suffix`, not `suffix` itself.
    Suffix(String),
    /// An address prefix. A bare IP literal is the prefix of its full length.
    Prefix(Prefix),
}

impl HostEntry {
    /// How specific the entry is for the DNS name `host` (the labels it names, one more for an
    /// exact name), or `None` when it does not match.
    fn name_match(&self, host: &str) -> Option<usize> {
        let labels = |name: &str| name.split('.').count();
        match self {
            HostEntry::Name(name) => name.eq_ignore_ascii_case(host).then(|| labels(name) + 1),
            HostEntry::Suffix(suffix) => {
                let cut = host.len().checked_sub(suffix.len() + 1)?;
                let below = cut > 0
                    && host.as_bytes()[cut] == b'.'
                    && host[cut + 1..].eq_ignore_ascii_case(suffix);
                below.then(|| labels(suffix))
            }
            HostEntry::Prefix(_) => None,
        }
    }

    /// The prefix length when the entry is a prefix containing `ip`.
    fn address_match(&self, ip: IpAddr) -> Option<usize> {
        match self {
            HostEntry::Prefix(prefix) => prefix.contains(ip).then_some(prefix.len.into()),
            HostEntry::Name(_) | HostEntry::Suffix(_) => None,
        }
    }
}

impl TryFrom<String> for HostEntry {
    type Error = Error;

    fn try_from(entry: String) -> Result<HostEntry> {
        if let Some(prefix) = Prefix::parse(&entry)? {
            return Ok(HostEntry::Prefix(prefix));
        }
        let lower = entry.to_ascii_lowercase();
        match lower.strip_prefix("*.") {
            Some(suffix) if is_dns_name(suffix) => Ok(HostEntry::Suffix(suffix.to_owned())),
            None if is_dns_name(&lower) => Ok(HostEntry::Name(lower)),
            _ => Err(Error::invalid_params(format!(
                "policy host {entry:?} is not a DNS name, *.name, an IP address or a prefix"
            ))),
        }
    }
}

impl TryFrom<&str> for HostEntry {
    type Error = Error;

    fn try_from(entry: &str) -> Result<HostEntry> {
        HostEntry::try_from(entry.to_owned())
    }
}

impl From<HostEntry> for String {
    fn from(entry: HostEntry) -> String {
        match entry {
            HostEntry::Name(name) => name,
            HostEntry::Suffix(suffix) => format!("*.{suffix}"),
            HostEntry::Prefix(prefix) => prefix.to_string(),
        }
    }
}

/// An IPv4 or IPv6 network: `network/len`, with no bits set below `len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    network: IpAddr,
    len: u8,
}

impl Prefix {
    /// `a.b.c.d/n`, `v6/n`, or a bare IP literal (IPv6 with or without brackets). `None` when
    /// `text` is not an address at all. An IPv4-mapped IPv6 prefix becomes the IPv4 one.
    fn parse(text: &str) -> Result<Option<Prefix>> {
        let bad = |why: String| Error::invalid_params(format!("policy host {text:?} {why}"));
        let (network, len) = match text.split_once('/') {
            None => match ip_literal(text) {
                Some(ip) => (ip, None),
                None => return Ok(None),
            },
            Some((address, len)) => {
                let Ok(address) = address.parse::<IpAddr>() else {
                    return Err(bad("is not an IP address and a prefix length".into()));
                };
                let len = len
                    .parse::<u8>()
                    .ok()
                    .filter(|len| *len <= max_len(address))
                    .ok_or_else(|| {
                        bad(format!(
                            "has a prefix length that is not 0 to {}",
                            max_len(address)
                        ))
                    })?;
                (address, Some(len))
            }
        };
        let mut len = len.unwrap_or(max_len(network));
        let network = match network {
            IpAddr::V6(v6) if len >= 96 => match v6.to_ipv4_mapped() {
                Some(v4) => {
                    len -= 96;
                    IpAddr::V4(v4)
                }
                None => network,
            },
            _ => network,
        };
        let prefix = Prefix { network, len };
        if prefix.host_bits(network) != 0 {
            return Err(bad(format!(
                "has bits set below its prefix length; the network is {}",
                Prefix {
                    network: prefix.masked(),
                    len
                }
            )));
        }
        Ok(Some(prefix))
    }

    /// Whether `ip` (IPv4-mapped counts as IPv4) is in the network.
    pub fn contains(self, ip: IpAddr) -> bool {
        let bits = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        let ip = ip.to_canonical();
        if self.network.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let shift = u32::from(max_len(ip) - self.len);
        (bits(ip) ^ bits(self.network))
            .checked_shr(shift)
            .unwrap_or(0)
            == 0
    }

    fn host_bits(self, ip: IpAddr) -> u128 {
        let shift = u32::from(max_len(ip) - self.len);
        let mask = 1u128.checked_shl(shift).unwrap_or(0).wrapping_sub(1);
        match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)) & mask,
            IpAddr::V6(v6) => u128::from(v6) & mask,
        }
    }

    fn masked(self) -> IpAddr {
        let host = self.host_bits(self.network);
        match self.network {
            IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & !(host as u32)).into()),
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !host).into()),
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.len == max_len(self.network) {
            write!(f, "{}", self.network)
        } else {
            write!(f, "{}/{}", self.network, self.len)
        }
    }
}

fn max_len(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
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
    bare.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

impl HostRules {
    /// Whether a connection to `host` may go on to be resolved: a DNS name is decided by the
    /// name entries alone, an IP literal by the prefixes alone. The most specific matching entry
    /// decides, deny on a tie, and `default` when none matches.
    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host);
        match ip_literal(host) {
            Some(ip) => self.address(ip),
            None => self.decide(|entry| entry.name_match(host)),
        }
        .unwrap_or(self.default == Default::Allow)
    }

    /// What the prefixes decide for one address of an allowed host: `Some(true)` lets it
    /// through even if it is internal, `Some(false)` drops it, and `None` (no prefix contains
    /// it) leaves it to the internal-address filter.
    pub fn address(&self, ip: IpAddr) -> Option<bool> {
        self.decide(|entry| entry.address_match(ip))
    }

    fn decide(&self, specificity: impl Fn(&HostEntry) -> Option<usize>) -> Option<bool> {
        let most_specific = |entries: &[HostEntry]| entries.iter().filter_map(&specificity).max();
        match (most_specific(&self.allow), most_specific(&self.deny)) {
            (Some(allow), Some(deny)) => Some(allow > deny),
            (Some(_), None) => Some(true),
            (None, Some(_)) => Some(false),
            (None, None) => None,
        }
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
        let Ok(canonical) = canonicalize(path) else {
            return;
        };
        if canonical.starts_with(&self.state_dir) || !canonical.is_file() {
            return;
        }
        self.read.entries.insert(canonical, true);
        self.layers = self.compute_layers();
    }
}

/// The canonical form of `path`, or of its deepest existing ancestor followed by the rest: how
/// policy entries are resolved, and how a path is checked against them.
pub fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = canonicalize(path) {
        return canonical;
    }
    for ancestor in path.ancestors().skip(1) {
        if let Ok(canonical) = canonicalize(ancestor) {
            let rest = path
                .strip_prefix(ancestor)
                .expect("an ancestor is a prefix");
            return canonical.join(rest);
        }
    }
    path.to_path_buf()
}

/// `std::fs::canonicalize`, without the `\\?\` prefix Windows adds to a plain drive path: the
/// resolved paths reach messages and the environment, where people write `C:\...`.
pub fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    let plain_drive = |rest: &&str| {
        let drive = rest.as_bytes();
        drive.len() >= 3 && drive[0].is_ascii_alphabetic() && &drive[1..3] == b":\\"
    };
    let stripped = canonical
        .to_str()
        .and_then(|s| s.strip_prefix(r"\\?\"))
        .filter(plain_drive);
    match stripped {
        Some(rest) if cfg!(windows) => Ok(PathBuf::from(rest)),
        _ => Ok(canonical),
    }
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

    #[cfg(windows)]
    #[test]
    fn resolved_windows_paths_have_no_verbatim_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        let missing = format!(r"{dir}\missing\deeper");
        let p = policy(
            rules(Default::Deny, &[dir, &missing], &[]),
            rules(Default::Deny, &[], &[]),
        );
        let resolved = ResolvedPolicy::resolve(&p, &tmp.path().join("state")).unwrap();
        for layer in resolved.layers() {
            let text = layer.path.to_str().unwrap().to_string();
            assert!(!text.starts_with(r"\\?\"), "{text}");
            assert_eq!(text.as_bytes()[1..3], *b":\\", "{text}");
        }
        assert!(resolved.can_read(&resolve_path(&tmp.path().join("x"))));
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
                        allow: vec![
                            HostEntry::Name("github.com".into()),
                            HostEntry::Suffix("githubusercontent.com".into()),
                        ],
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
            error(serde_json::json!({ "filesystem": fs, "network": bad_host })).contains(
                r#"policy host "git*.com" is not a DNS name, *.name, an IP address or a prefix"#
            )
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

    fn hosts(default: Default, allow: &[&str], deny: &[&str]) -> HostRules {
        let entries = |list: &[&str]| -> Vec<HostEntry> {
            list.iter()
                .map(|entry| HostEntry::try_from(*entry).unwrap())
                .collect()
        };
        HostRules {
            default,
            allow: entries(allow),
            deny: entries(deny),
        }
    }

    #[test]
    fn hosts_match_the_most_specific_pattern() {
        let rules = hosts(
            Default::Deny,
            &[
                "github.com",
                "*.githubusercontent.com",
                "*.example.com",
                "10.0.0.1",
                "[::1]",
            ],
            &["*.evil.example.com", "GitHub.com"],
        );
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
            ("::ffff:10.0.0.1", true),
            ("other.org", false),
        ];
        for (host, allowed) in cases {
            assert_eq!(rules.allows_host(host), allowed, "{host}");
        }
        let open = hosts(Default::Allow, &[], &["*.tracker.net", "1.2.3.4"]);
        assert!(open.allows_host("anything.org"));
        assert!(!open.allows_host("a.tracker.net"));
        assert!(!open.allows_host("1.2.3.4"));
        assert!(open.allows_host("tracker.net"));
    }

    #[test]
    fn prefixes_decide_addresses_and_never_names() {
        let rules = hosts(
            Default::Deny,
            &[
                "10.0.0.0/8",
                "10.1.2.3",
                "2001:db8::/32",
                "api.corp.example",
            ],
            &["10.1.0.0/16", "2001:db8:bad::/48", "0.0.0.0/0"],
        );
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let cases = [
            ("10.9.9.9", Some(true)),
            ("10.1.9.9", Some(false)),
            ("10.1.2.3", Some(true)),
            ("::ffff:10.9.9.9", Some(true)),
            ("192.0.2.1", Some(false)),
            ("2001:db8::1", Some(true)),
            ("2001:db8:bad::1", Some(false)),
            ("2001:db9::1", None),
        ];
        for (address, verdict) in cases {
            assert_eq!(rules.address(ip(address)), verdict, "{address}");
        }
        assert!(rules.allows_host("10.9.9.9"));
        assert!(!rules.allows_host("10.1.9.9"));
        assert!(!rules.allows_host("2001:db9::1"));
        // A name is decided by the names alone, whatever its addresses are.
        assert!(rules.allows_host("api.corp.example"));
        assert!(!rules.allows_host("db.corp.example"));
        assert_eq!(rules.address(ip("10.1.0.1")), Some(false));
    }

    #[test]
    fn host_entries_parse_and_print_canonically() {
        let round = |entry: &str| String::from(HostEntry::try_from(entry).unwrap());
        assert_eq!(round("10.0.0.0/8"), "10.0.0.0/8");
        assert_eq!(round("10.0.0.1/32"), "10.0.0.1");
        assert_eq!(round("[::1]"), "::1");
        assert_eq!(round("2001:DB8::/32"), "2001:db8::/32");
        assert_eq!(round("::ffff:10.0.0.0/104"), "10.0.0.0/8");
        assert_eq!(round("0.0.0.0/0"), "0.0.0.0/0");
        assert_eq!(round("::/0"), "::/0");
        assert_eq!(round("*.Example.COM"), "*.example.com");
        let error = |entry: &str| HostEntry::try_from(entry).unwrap_err().to_string();
        assert_eq!(
            error("10.0.0.1/8"),
            r#"policy host "10.0.0.1/8" has bits set below its prefix length; the network is 10.0.0.0/8"#
        );
        assert_eq!(
            error("10.0.0.0/33"),
            r#"policy host "10.0.0.0/33" has a prefix length that is not 0 to 32"#
        );
        assert_eq!(
            error("example.com/8"),
            r#"policy host "example.com/8" is not an IP address and a prefix length"#
        );
        assert_eq!(
            error("git*.com"),
            r#"policy host "git*.com" is not a DNS name, *.name, an IP address or a prefix"#
        );
    }
}
