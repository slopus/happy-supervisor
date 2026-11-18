//! The sandbox policy (docs/policy.md): the validated wire [`Policy`], and the
//! [`ResolvedPolicy`] an operation actually runs under.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const MAX_POLICY_PATHS: usize = 256;

/// The device nodes every sandbox gets (policy.md, Always granted).
const ALWAYS_GRANTED: [(&str, Rights); 4] = [
    ("/dev/null", Rights::ReadWrite),
    ("/dev/zero", Rights::Read),
    ("/dev/random", Rights::Read),
    ("/dev/urandom", Rights::Read),
];

/// A policy as the control plane sent it. Every value of this type has passed the path rules,
/// because deserializing and [`Policy::new`] both validate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "PolicyWire")]
pub struct Policy {
    read: Vec<String>,
    write: Vec<String>,
    local_bind: bool,
    unix_sockets: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyWire {
    read: Vec<String>,
    write: Vec<String>,
    local_bind: bool,
    unix_sockets: bool,
}

impl TryFrom<PolicyWire> for Policy {
    type Error = Error;

    fn try_from(wire: PolicyWire) -> Result<Policy> {
        Policy::new(wire.read, wire.write, wire.local_bind, wire.unix_sockets)
    }
}

impl Policy {
    pub fn new(
        read: Vec<String>,
        write: Vec<String>,
        local_bind: bool,
        unix_sockets: bool,
    ) -> Result<Policy> {
        for (name, list) in [("read", &read), ("write", &write)] {
            if list.len() > MAX_POLICY_PATHS {
                return Err(Error::invalid_params(format!(
                    "policy {name} has {} paths, at most {MAX_POLICY_PATHS} are allowed",
                    list.len()
                )));
            }
            for path in list {
                validate_path(path)?;
            }
        }
        Ok(Policy {
            read,
            write,
            local_bind,
            unix_sockets,
        })
    }

    pub fn read(&self) -> &[String] {
        &self.read
    }

    pub fn write(&self) -> &[String] {
        &self.write
    }

    pub fn local_bind(&self) -> bool {
        self.local_bind
    }

    pub fn unix_sockets(&self) -> bool {
        self.unix_sockets
    }
}

/// Absolute and normalized: no `.`, `..` or empty components, no NUL. One trailing separator is
/// allowed. Checked on the string, because `Path::components` silently normalizes `a//b` and
/// `a/./b`.
fn validate_path(path: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::invalid_params(format!("policy path {path:?} {why}")));
    if path.contains('\0') {
        return bad("contains NUL");
    }
    if !Path::new(path).is_absolute() {
        return bad("is not absolute");
    }
    let body = path.strip_suffix(std::path::is_separator).unwrap_or(path);
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

/// What an operation runs under, decided once at the dispatcher from the request's `access`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Confinement {
    Raw,
    Sandboxed(ResolvedPolicy),
}

impl Confinement {
    /// The `ignoredPaths` of an `exec.start` result. Empty for raw access.
    pub fn ignored_paths(&self) -> &[String] {
        match self {
            Confinement::Raw => &[],
            Confinement::Sandboxed(policy) => policy.ignored(),
        }
    }
}

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

/// One canonical, existing path an operation may use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub path: PathBuf,
    pub kind: GrantKind,
    pub rights: Rights,
}

impl Grant {
    /// Whether this grant covers `path`, a canonical path.
    pub fn covers(&self, path: &Path) -> bool {
        match self.kind {
            GrantKind::Directory => path.starts_with(&self.path),
            GrantKind::File => path == self.path,
        }
    }
}

/// A policy resolved against the filesystem when the operation starts: canonical grants that
/// exist, the policy paths that did not, and the canonical state directory no grant may reach.
///
/// It is computed once in the supervisor and sent to the helper inside the [`Job`], so the parent
/// (macOS profile, `ignoredPaths`, watch filtering) and the child (Landlock) see the same grants.
///
/// [`Job`]: crate::helper::Job
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    grants: Vec<Grant>,
    ignored: Vec<String>,
    hidden: PathBuf,
    local_bind: bool,
    unix_sockets: bool,
}

impl ResolvedPolicy {
    /// Canonicalizes every policy path. Missing ones go to `ignored`, in policy order (read list,
    /// then write list, each once). A path granted twice keeps the stronger rights. Grants at or
    /// inside `hidden` are dropped. The always-granted device nodes are added when they exist.
    /// Grants come out sorted by path.
    pub fn resolve(policy: &Policy, hidden: &Path) -> ResolvedPolicy {
        let hidden = std::fs::canonicalize(hidden).unwrap_or_else(|_| hidden.to_path_buf());
        let mut grants: BTreeMap<PathBuf, (GrantKind, Rights)> = BTreeMap::new();
        let mut ignored: Vec<String> = Vec::new();

        let requested = policy
            .read
            .iter()
            .map(|p| (p, Rights::Read))
            .chain(policy.write.iter().map(|p| (p, Rights::ReadWrite)));
        for (path, rights) in requested {
            let Ok(canonical) = std::fs::canonicalize(path) else {
                if !ignored.contains(path) {
                    ignored.push(path.clone());
                }
                continue;
            };
            if canonical.starts_with(&hidden) {
                continue;
            }
            let kind = if canonical.is_dir() {
                GrantKind::Directory
            } else {
                GrantKind::File
            };
            add_grant(&mut grants, canonical, kind, rights);
        }
        for (path, rights) in ALWAYS_GRANTED {
            if Path::new(path).exists() {
                add_grant(&mut grants, PathBuf::from(path), GrantKind::File, rights);
            }
        }

        ResolvedPolicy {
            grants: grants
                .into_iter()
                .map(|(path, (kind, rights))| Grant { path, kind, rights })
                .collect(),
            ignored,
            hidden,
            local_bind: policy.local_bind,
            unix_sockets: policy.unix_sockets,
        }
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// The policy paths that did not exist and grant nothing.
    pub fn ignored(&self) -> &[String] {
        &self.ignored
    }

    /// The canonical state directory. Never readable or writable, whatever the grants say.
    pub fn hidden(&self) -> &Path {
        &self.hidden
    }

    pub fn local_bind(&self) -> bool {
        self.local_bind
    }

    pub fn unix_sockets(&self) -> bool {
        self.unix_sockets
    }

    /// Whether the policy lets an operation read `path`, a canonical path.
    pub fn can_read(&self, path: &Path) -> bool {
        !path.starts_with(&self.hidden) && self.grants.iter().any(|g| g.covers(path))
    }

    /// Whether the policy lets an operation write `path`, a canonical path.
    pub fn can_write(&self, path: &Path) -> bool {
        !path.starts_with(&self.hidden)
            && self
                .grants
                .iter()
                .any(|g| g.rights == Rights::ReadWrite && g.covers(path))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[cfg(unix)]
    fn policy(read: &[&str], write: &[&str]) -> Result<Policy> {
        Policy::new(
            read.iter().map(|s| s.to_string()).collect(),
            write.iter().map(|s| s.to_string()).collect(),
            false,
            false,
        )
    }

    fn rejection(path: &str) -> String {
        let err = Policy::new(vec![path.to_string()], vec![], false, false).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidParams);
        err.message
    }

    #[cfg(unix)]
    #[test]
    fn path_rules() {
        assert_eq!(
            policy(&["/", "/usr", "/home/me/repo/"], &["/tmp"])
                .unwrap()
                .read()
                .len(),
            3
        );
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
            rejection("/a/.."),
            r#"policy path "/a/.." is not normalized"#
        );
        assert_eq!(
            rejection("/a//b"),
            r#"policy path "/a//b" has an empty component"#
        );
        assert_eq!(
            rejection("/a//"),
            r#"policy path "/a//" has an empty component"#
        );
        assert_eq!(rejection("/a\0b"), r#"policy path "/a\0b" contains NUL"#);
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
            rejection(r"C:\a\\b"),
            r#"policy path "C:\\a\\\\b" has an empty component"#
        );
        assert_eq!(
            rejection("C:/a//b"),
            r#"policy path "C:/a//b" has an empty component"#
        );
        let trailing = Policy::new(vec![r"C:\Users\me\".to_string()], vec![], false, false);
        assert_eq!(trailing.unwrap().read(), [r"C:\Users\me\"]);
    }

    #[cfg(unix)]
    #[test]
    fn list_length_is_capped() {
        let many: Vec<String> = (0..257).map(|i| format!("/p{i}")).collect();
        let err = Policy::new(vec![], many, false, false).unwrap_err();
        assert_eq!(
            err,
            Error::invalid_params("policy write has 257 paths, at most 256 are allowed")
        );
        let enough: Vec<String> = (0..256).map(|i| format!("/p{i}")).collect();
        assert_eq!(
            Policy::new(enough, vec![], false, false)
                .unwrap()
                .read()
                .len(),
            256
        );
    }

    #[cfg(unix)]
    #[test]
    fn wire_policy_requires_every_field_and_no_others() {
        let ok: Policy = serde_json::from_str(
            r#"{"read":["/usr"],"write":[],"localBind":true,"unixSockets":false}"#,
        )
        .unwrap();
        assert_eq!(
            (ok.read(), ok.write(), ok.local_bind(), ok.unix_sockets()),
            (&["/usr".to_string()][..], &[][..], true, false)
        );
        let missing = serde_json::from_str::<Policy>(r#"{"read":[],"write":[],"localBind":true}"#);
        assert!(
            missing
                .unwrap_err()
                .to_string()
                .contains("missing field `unixSockets`")
        );
        let extra = serde_json::from_str::<Policy>(
            r#"{"read":[],"write":[],"localBind":true,"unixSockets":false,"net":true}"#,
        );
        assert!(
            extra
                .unwrap_err()
                .to_string()
                .contains("unknown field `net`")
        );
        let invalid = serde_json::from_str::<Policy>(
            r#"{"read":["rel"],"write":[],"localBind":true,"unixSockets":false}"#,
        );
        assert!(
            invalid
                .unwrap_err()
                .to_string()
                .contains(r#"policy path "rel" is not absolute"#)
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_against_a_real_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let repo = root.join("repo");
        let state = root.join("state");
        std::fs::create_dir_all(repo.join("target")).unwrap();
        std::fs::create_dir(&state).unwrap();
        std::fs::write(state.join("credentials.json"), b"{}").unwrap();
        std::fs::write(root.join("notes.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(&repo, root.join("link")).unwrap();

        let s = |p: &Path| p.to_str().unwrap().to_string();
        let missing = s(&root.join("missing"));
        let policy = Policy::new(
            vec![
                s(&root),
                s(&root.join("link")),
                missing.clone(),
                s(&root.join("notes.txt")),
                s(&state.join("credentials.json")),
            ],
            vec![s(&repo.join("target")), missing.clone(), s(&repo)],
            true,
            false,
        )
        .unwrap();

        let resolved = ResolvedPolicy::resolve(&policy, &state);

        let mut expected = vec![
            Grant {
                path: root.clone(),
                kind: GrantKind::Directory,
                rights: Rights::Read,
            },
            Grant {
                path: root.join("notes.txt"),
                kind: GrantKind::File,
                rights: Rights::Read,
            },
            Grant {
                path: repo.clone(),
                kind: GrantKind::Directory,
                rights: Rights::ReadWrite,
            },
            Grant {
                path: repo.join("target"),
                kind: GrantKind::Directory,
                rights: Rights::ReadWrite,
            },
        ];
        for (path, rights) in ALWAYS_GRANTED {
            expected.push(Grant {
                path: PathBuf::from(path),
                kind: GrantKind::File,
                rights,
            });
        }
        expected.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(resolved.grants(), expected);
        assert_eq!(resolved.ignored(), [missing]);
        assert_eq!(resolved.hidden(), state);
        assert_eq!(
            (resolved.local_bind(), resolved.unix_sockets()),
            (true, false)
        );

        assert!(resolved.can_read(&root.join("anything/below")));
        assert!(!resolved.can_write(&root.join("notes.txt")));
        assert!(resolved.can_write(&repo.join("src/main.rs")));
        assert!(resolved.can_read(&repo.join("src/main.rs")));
        assert!(!resolved.can_read(&state));
        assert!(!resolved.can_read(&state.join("credentials.json")));
        assert!(resolved.can_read(&root.join("statefile")));
        assert!(resolved.can_write(Path::new("/dev/null")));
        assert!(!resolved.can_write(Path::new("/dev/zero")));
        assert!(!resolved.can_read(Path::new("/dev/sda")));
    }

    #[cfg(unix)]
    #[test]
    fn file_grant_covers_only_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::write(root.join("a"), b"").unwrap();
        let policy = Policy::new(
            vec![],
            vec![root.join("a").to_str().unwrap().into()],
            false,
            false,
        )
        .unwrap();
        let resolved = ResolvedPolicy::resolve(&policy, &root.join("state"));
        assert!(resolved.can_write(&root.join("a")));
        assert!(!resolved.can_read(&root.join("a/b")));
        assert!(!resolved.can_read(&root.join("ab")));
        assert!(!resolved.can_read(&root));
    }

    #[cfg(unix)]
    #[test]
    fn confinement_reports_ignored_paths() {
        assert_eq!(Confinement::Raw.ignored_paths(), [] as [String; 0]);
        let policy = policy(&["/definitely/not/here"], &[]).unwrap();
        let resolved = ResolvedPolicy::resolve(&policy, Path::new("/nonexistent-state"));
        assert_eq!(
            Confinement::Sandboxed(resolved).ignored_paths(),
            ["/definitely/not/here".to_string()]
        );
    }
}
