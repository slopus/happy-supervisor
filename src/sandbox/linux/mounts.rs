//! The policy's filesystem rules as bubblewrap mounts (policy.md, Filesystem).
//!
//! The sandbox's root starts as the host root bound read-only or read-write, or as bubblewrap's
//! empty root, by what the policy says about `/`. Every rule path then gets the mount for what
//! the policy says about it, shallowest first, so a deeper rule's mount lands on top of a
//! shallower one's, the way the most specific rule wins. A path the policy hides becomes an empty
//! read-only directory (a tmpfs, remounted read-only once everything below it is mounted) or an
//! empty read-only file (`/dev/null`).

use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::policy::ResolvedPolicy;
use crate::sandbox::placeholders::{Placeholder, PlaceholderKind};

/// What a path, and everything below it no deeper mount covers, is inside the sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Hidden,
    ReadOnly,
    ReadWrite,
}

impl Access {
    pub fn of(policy: &ResolvedPolicy, path: &Path) -> Access {
        if policy.can_write(path) {
            Access::ReadWrite
        } else if policy.can_read(path) {
            Access::ReadOnly
        } else {
            Access::Hidden
        }
    }
}

/// One bubblewrap mount of a path onto itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mount {
    /// `--bind` or `--ro-bind` of the host path.
    Bind { path: PathBuf, writable: bool },
    /// `--tmpfs`, then `--remount-ro` after every mount below it.
    EmptyDir(PathBuf),
    /// `--ro-bind /dev/null`, which a bind mount makes `nodev`: opening it fails with `EACCES`.
    EmptyFile(PathBuf),
    /// `--ro-bind-fd`: the host file the supervisor opened, bound by descriptor, so bubblewrap
    /// needs no access to the path it came from (the proxy sockets in the private state
    /// directory, when bubblewrap runs as the workload user).
    BindFd { fd: RawFd, path: PathBuf },
    /// `--symlink`: a symlink at the top of an empty root, copied from the host's, such as
    /// `/bin -> usr/bin`. The policy names canonical paths, so it never mounts these itself.
    Symlink { path: PathBuf, target: PathBuf },
}

impl Mount {
    fn path(&self) -> &Path {
        match self {
            Mount::Bind { path, .. }
            | Mount::BindFd { path, .. }
            | Mount::EmptyDir(path)
            | Mount::EmptyFile(path)
            | Mount::Symlink { path, .. } => path,
        }
    }
}

/// The whole filesystem of one sandbox.
#[derive(Debug, PartialEq, Eq)]
pub struct Mounts {
    pub root: Access,
    /// Shallowest first.
    pub mounts: Vec<Mount>,
}

/// The paths with a rule of their own: the policy's, and the state directory.
fn rule_paths(policy: &ResolvedPolicy) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = policy
        .layers()
        .into_iter()
        .map(|layer| layer.path)
        .collect();
    paths.push(policy.state_dir().to_path_buf());
    paths.retain(|path| {
        // The sandbox's /dev and /proc are its own (policy.md, Fixed rules).
        path.parent().is_some() && !path.starts_with("/dev") && !path.starts_with("/proc")
    });
    paths.sort_by_key(|path| path.components().count());
    paths.dedup();
    paths
}

/// The rule paths that do not exist and that the operation may not write: where a placeholder
/// must stand if the operation could create them.
pub fn missing_denies(policy: &ResolvedPolicy) -> Vec<PathBuf> {
    rule_paths(policy)
        .into_iter()
        .filter(|path| {
            Access::of(policy, path) != Access::ReadWrite
                && std::fs::symlink_metadata(path).is_err()
        })
        .collect()
}

impl Mounts {
    /// The mounts for `policy`, with `placeholders` standing in for missing denied paths, and
    /// `extra` host files (the helper binary) and `by_fd` opened ones (the proxy sockets) bound
    /// read-only on top of everything.
    pub fn new(
        policy: &ResolvedPolicy,
        placeholders: &[Placeholder],
        extra: &[PathBuf],
        by_fd: &[(RawFd, PathBuf)],
    ) -> Result<Mounts> {
        let mut mounts = Vec::new();
        for path in rule_paths(policy) {
            let access = Access::of(policy, &path);
            let parent = path.parent().expect("rule paths are not the root");
            if access == Access::of(policy, parent) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_symlink() {
                return Err(Error::sandbox_unavailable(format!(
                    "policy path {} became a symlink",
                    path.display()
                )));
            }
            mounts.push(match access {
                Access::Hidden if meta.is_dir() => Mount::EmptyDir(path),
                Access::Hidden => Mount::EmptyFile(path),
                Access::ReadOnly => Mount::Bind {
                    path,
                    writable: false,
                },
                Access::ReadWrite => Mount::Bind {
                    path,
                    writable: true,
                },
            });
        }
        for placeholder in placeholders {
            mounts.push(match placeholder.kind {
                PlaceholderKind::Dir => Mount::EmptyDir(placeholder.path.clone()),
                PlaceholderKind::File => Mount::EmptyFile(placeholder.path.clone()),
            });
        }
        // A stable sort keeps the extras after a rule at the same path.
        mounts.sort_by_key(|mount| mount.path().components().count());
        for path in extra {
            mounts.push(Mount::Bind {
                path: path.clone(),
                writable: false,
            });
        }
        for (fd, path) in by_fd {
            mounts.push(Mount::BindFd {
                fd: *fd,
                path: path.clone(),
            });
        }
        let root = Access::of(policy, Path::new("/"));
        if root == Access::Hidden {
            mounts.extend(root_symlinks(policy));
        }
        Ok(Mounts { root, mounts })
    }

    /// The bubblewrap arguments, in order.
    pub fn args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        let mut push = |items: &[&std::ffi::OsStr]| args.extend(items.iter().map(|s| s.into()));
        match self.root {
            Access::ReadWrite => push(&["--bind".as_ref(), "/".as_ref(), "/".as_ref()]),
            Access::ReadOnly => push(&["--ro-bind".as_ref(), "/".as_ref(), "/".as_ref()]),
            Access::Hidden => {}
        }
        for mount in &self.mounts {
            match mount {
                Mount::Bind { path, writable } => {
                    let flag = if *writable { "--bind" } else { "--ro-bind" };
                    push(&[flag.as_ref(), path.as_os_str(), path.as_os_str()]);
                }
                Mount::BindFd { fd, path } => {
                    let fd = fd.to_string();
                    push(&["--ro-bind-fd".as_ref(), fd.as_ref(), path.as_os_str()])
                }
                Mount::EmptyDir(path) => push(&["--tmpfs".as_ref(), path.as_os_str()]),
                Mount::EmptyFile(path) => {
                    push(&["--ro-bind".as_ref(), "/dev/null".as_ref(), path.as_os_str()])
                }
                Mount::Symlink { path, target } => {
                    push(&["--symlink".as_ref(), target.as_os_str(), path.as_os_str()])
                }
            }
        }
        push(&[
            "--dev".as_ref(),
            "/dev".as_ref(),
            "--proc".as_ref(),
            "/proc".as_ref(),
        ]);
        if self.root == Access::Hidden {
            push(&["--remount-ro".as_ref(), "/".as_ref()]);
        }
        for mount in &self.mounts {
            if let Mount::EmptyDir(path) = mount {
                push(&["--remount-ro".as_ref(), path.as_os_str()]);
            }
        }
        args
    }
}

/// The host's top-level symlinks whose targets the policy lets the operation read.
fn root_symlinks(policy: &ResolvedPolicy) -> Vec<Mount> {
    let Ok(entries) = std::fs::read_dir("/") else {
        return Vec::new();
    };
    let mut symlinks: Vec<Mount> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let target = std::fs::read_link(&path).ok()?;
            let resolved = std::fs::canonicalize(&path).ok()?;
            (Access::of(policy, &resolved) != Access::Hidden)
                .then_some(Mount::Symlink { path, target })
        })
        .collect();
    symlinks.sort_by(|a, b| a.path().cmp(b.path()));
    symlinks
}
