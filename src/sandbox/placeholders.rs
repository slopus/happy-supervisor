//! Placeholders for deny paths that do not exist (policy.md, Paths that do not exist).
//!
//! A mechanism that confines by path (a bubblewrap mount, a Windows ACL) needs something at the
//! path to act on. For a missing deny path whose first missing component the operation could
//! create, [`Placeholders::create`] makes that component: an empty read-only directory when the
//! deny path lies below it, an empty read-only file when it is the deny path itself.
//!
//! Concurrent operations share a placeholder: the process-wide registry counts its users, and the
//! last one to drop removes it, only if it is still empty and still the same inode. Each
//! placeholder also has a record file under the state directory until it is removed, so
//! [`Placeholders::sweep`] can remove what a crashed node left behind.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlaceholderKind {
    File,
    Dir,
}

/// A placeholder one operation uses: the path to confine in place of the missing deny paths
/// below or at it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placeholder {
    pub path: PathBuf,
    pub kind: PlaceholderKind,
}

/// The placeholders one operation uses. Dropping it releases them.
#[derive(Debug, Default)]
pub struct Placeholders {
    held: Vec<Placeholder>,
    records: PathBuf,
}

/// Which file a placeholder is, so one replaced by someone else is never removed. While the node
/// runs, the pin keeps the inode from being reused; after a crash, the birth time tells apart a
/// new file that reused a removed one's inode, as far as timestamps are fine-grained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileId {
    volume: u64,
    index: u64,
    born_ns: Option<u128>,
}

fn born_ns(meta: &std::fs::Metadata) -> Option<u128> {
    let born = meta.created().ok()?;
    Some(born.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos())
}

/// What `<records>/<sha1 of the path>.json` holds.
#[derive(Debug, Serialize, Deserialize)]
struct Record {
    path: PathBuf,
    kind: PlaceholderKind,
    id: FileId,
}

struct Shared {
    kind: PlaceholderKind,
    id: FileId,
    /// Held open so the inode cannot be freed and reused by a file that replaced it.
    _pin: std::fs::File,
    users: usize,
}

static REGISTRY: Mutex<BTreeMap<PathBuf, Shared>> = Mutex::new(BTreeMap::new());

fn registry() -> MutexGuard<'static, BTreeMap<PathBuf, Shared>> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Placeholders {
    /// Makes or shares a placeholder for each path in `missing_deny` whose first missing
    /// component lies in a directory `writable` says the operation may change. Records go in
    /// `records`, which is created if needed. On an error nothing stays held.
    pub fn create(
        records: &Path,
        missing_deny: &[PathBuf],
        writable: impl Fn(&Path) -> bool,
    ) -> io::Result<Placeholders> {
        let mut placeholders = Placeholders {
            held: Vec::new(),
            records: records.to_path_buf(),
        };
        let mut registry = registry();
        for deny in missing_deny {
            let Some(placeholder) = placeholders.place(&mut registry, deny, &writable)? else {
                continue;
            };
            if placeholders.held.contains(&placeholder) {
                continue;
            }
            if let Some(shared) = registry.get_mut(&placeholder.path) {
                shared.users += 1;
            }
            placeholders.held.push(placeholder);
        }
        Ok(placeholders)
    }

    /// Every placeholder this operation uses.
    pub fn held(&self) -> &[Placeholder] {
        &self.held
    }

    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.held
            .iter()
            .map(|placeholder| placeholder.path.as_path())
    }

    /// Removes the placeholders recorded under `records` by an earlier run of the node. Call it
    /// once at startup, before any operation holds a placeholder.
    pub fn sweep(records: &Path) -> io::Result<()> {
        let entries = match std::fs::read_dir(records) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        let registry = registry();
        for entry in entries.flatten() {
            let file = entry.path();
            let record = std::fs::read(&file)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok());
            if let Some(record) = record
                && !registry.contains_key(&record.path)
            {
                remove_if_ours(&record.path, record.kind, record.id);
            }
            std::fs::remove_file(&file)?;
        }
        Ok(())
    }

    /// The placeholder that keeps `deny` from being created, made if needed. `None` when the
    /// operation could not create `deny` anyway, or `deny` exists by now and is not a placeholder.
    fn place(
        &self,
        registry: &mut BTreeMap<PathBuf, Shared>,
        deny: &Path,
        writable: &impl Fn(&Path) -> bool,
    ) -> io::Result<Option<Placeholder>> {
        let mut existing = deny;
        while std::fs::symlink_metadata(existing).is_err() {
            match existing.parent() {
                Some(parent) => existing = parent,
                None => return Ok(None),
            }
        }
        if let Some(shared) = registry.get(existing) {
            return Ok(Some(Placeholder {
                path: existing.to_path_buf(),
                kind: shared.kind,
            }));
        }
        // Nothing can be created below a file or through a symlink here.
        if existing == deny || !std::fs::symlink_metadata(existing)?.is_dir() || !writable(existing)
        {
            return Ok(None);
        }
        let first_missing = deny
            .strip_prefix(existing)
            .ok()
            .and_then(|rest| rest.components().next())
            .map(|component| existing.join(component))
            .expect("an existing ancestor is a proper prefix");
        let kind = if first_missing == deny {
            PlaceholderKind::File
        } else {
            PlaceholderKind::Dir
        };
        make(&first_missing, kind)?;
        let (id, pin) = match pin(&first_missing).and_then(|pin| Ok((file_id(&pin)?, pin))) {
            Ok(pinned) => pinned,
            Err(err) => {
                let _ = remove_unchecked(&first_missing, kind);
                return Err(err);
            }
        };
        let record = Record {
            path: first_missing.clone(),
            kind,
            id,
        };
        if let Err(err) = self.write_record(&record) {
            remove_if_ours(&first_missing, kind, id);
            return Err(err);
        }
        registry.insert(
            first_missing.clone(),
            Shared {
                kind,
                id,
                _pin: pin,
                users: 0,
            },
        );
        Ok(Some(Placeholder {
            path: first_missing,
            kind,
        }))
    }

    fn write_record(&self, record: &Record) -> io::Result<()> {
        std::fs::create_dir_all(&self.records)?;
        let json = serde_json::to_vec(record).map_err(io::Error::other)?;
        std::fs::write(record_path(&self.records, &record.path), json)
    }
}

impl Drop for Placeholders {
    fn drop(&mut self) {
        let mut registry = registry();
        for placeholder in self.held.iter().rev() {
            let Some(shared) = registry.get_mut(&placeholder.path) else {
                continue;
            };
            shared.users -= 1;
            if shared.users > 0 {
                continue;
            }
            if let Some(shared) = registry.remove(&placeholder.path) {
                remove_if_ours(&placeholder.path, shared.kind, shared.id);
            }
            let _ = std::fs::remove_file(record_path(&self.records, &placeholder.path));
        }
    }
}

fn record_path(records: &Path, placeholder: &Path) -> PathBuf {
    let digest = Sha1::digest(placeholder.as_os_str().as_encoded_bytes());
    let name: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    records.join(format!("{name}.json"))
}

/// Creates an empty read-only file or directory at `path`, failing if anything is there.
fn make(path: &Path, kind: PlaceholderKind) -> io::Result<()> {
    match kind {
        PlaceholderKind::Dir => std::fs::create_dir(path)?,
        PlaceholderKind::File => drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
        ),
    }
    let mut permissions = std::fs::symlink_metadata(path)?.permissions();
    set_read_only(&mut permissions, kind);
    std::fs::set_permissions(path, permissions)
}

fn remove_unchecked(path: &Path, kind: PlaceholderKind) -> io::Result<()> {
    match kind {
        PlaceholderKind::Dir => std::fs::remove_dir(path),
        PlaceholderKind::File => std::fs::remove_file(path),
    }
}

#[cfg(unix)]
fn set_read_only(permissions: &mut std::fs::Permissions, _kind: PlaceholderKind) {
    use std::os::unix::fs::PermissionsExt as _;
    permissions.set_mode(permissions.mode() & 0o555);
}

/// On Windows a read-only directory cannot be removed, and the sandbox ACL denies the placeholder
/// anyway, so only files get the attribute.
#[cfg(windows)]
fn set_read_only(permissions: &mut std::fs::Permissions, kind: PlaceholderKind) {
    if kind == PlaceholderKind::File {
        permissions.set_readonly(true);
    }
}

/// Removes the placeholder at `path` if it is still the file `id`, still empty, and of `kind`.
fn remove_if_ours(path: &Path, kind: PlaceholderKind, id: FileId) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if pin(path).and_then(|file| file_id(&file)).ok() != Some(id) {
        return;
    }
    match kind {
        // Fails, and keeps it, when anything was put inside.
        PlaceholderKind::Dir if meta.is_dir() => {
            let _ = std::fs::remove_dir(path);
        }
        PlaceholderKind::File if meta.is_file() && meta.len() == 0 => {
            if cfg!(windows) {
                let mut permissions = meta.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(path, permissions);
            }
            let _ = std::fs::remove_file(path);
        }
        _ => {}
    }
}

#[cfg(target_os = "linux")]
const PIN_FLAGS: i32 = libc::O_PATH | libc::O_NOFOLLOW;
// Placeholders are readable to their owner, so a plain read-only open works where O_PATH is
// missing.
#[cfg(all(unix, not(target_os = "linux")))]
const PIN_FLAGS: i32 = libc::O_NOFOLLOW;

/// Opens `path` itself, not what a symlink there points to, without reading or writing it.
#[cfg(unix)]
fn pin(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(PIN_FLAGS)
        .open(path)
}

#[cfg(windows)]
fn pin(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn file_id(file: &std::fs::File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = file.metadata()?;
    Ok(FileId {
        volume: meta.dev(),
        index: meta.ino(),
        born_ns: born_ns(&meta),
    })
}

#[cfg(windows)]
fn file_id(file: &std::fs::File) -> io::Result<FileId> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is valid; the call only writes into it.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for the duration of the call and `info` is a valid out pointer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileId {
        volume: u64::from(info.dwVolumeSerialNumber),
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        born_ns: born_ns(&file.metadata()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tree {
        _tmp: tempfile::TempDir,
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Tree {
            let tmp = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(tmp.path()).unwrap();
            std::fs::create_dir(root.join("repo")).unwrap();
            std::fs::create_dir(root.join("readonly")).unwrap();
            Tree { _tmp: tmp, root }
        }

        fn create(&self, deny: &[&str]) -> io::Result<Placeholders> {
            let deny: Vec<PathBuf> = deny.iter().map(|p| self.root.join(p)).collect();
            let repo = self.root.join("repo");
            Placeholders::create(&self.root.join("records"), &deny, |p| p.starts_with(&repo))
        }

        fn records(&self) -> usize {
            std::fs::read_dir(self.root.join("records"))
                .map(|entries| entries.count())
                .unwrap_or(0)
        }
    }

    fn held(placeholders: &Placeholders, root: &Path) -> Vec<(String, PlaceholderKind)> {
        placeholders
            .held()
            .iter()
            .map(|p| {
                let relative = p.path.strip_prefix(root).unwrap();
                let parts: Vec<&str> = relative.iter().map(|c| c.to_str().unwrap()).collect();
                (parts.join("/"), p.kind)
            })
            .collect()
    }

    #[test]
    fn makes_the_first_missing_component_only_where_writable() {
        let tree = Tree::new();
        let placeholders = tree
            .create(&[
                "repo/.git/hooks",
                "repo/.git/config",
                "repo/.env",
                "readonly/.ssh",
                "elsewhere/x",
            ])
            .unwrap();
        assert_eq!(
            held(&placeholders, &tree.root),
            [
                ("repo/.git".to_string(), PlaceholderKind::Dir),
                ("repo/.env".to_string(), PlaceholderKind::File),
            ]
        );
        let git = tree.root.join("repo/.git");
        assert!(git.is_dir());
        assert_eq!(std::fs::read_dir(&git).unwrap().count(), 0);
        #[cfg(unix)]
        assert!(std::fs::metadata(&git).unwrap().permissions().readonly());
        assert!(
            std::fs::metadata(tree.root.join("repo/.env"))
                .unwrap()
                .permissions()
                .readonly()
        );
        assert_eq!(std::fs::read(tree.root.join("repo/.env")).unwrap(), b"");
        assert!(!tree.root.join("readonly/.ssh").exists());
        assert_eq!(tree.records(), 2);

        drop(placeholders);
        assert!(!git.exists());
        assert!(!tree.root.join("repo/.env").exists());
        assert_eq!(tree.records(), 0);
    }

    #[test]
    fn concurrent_operations_share_one_placeholder() {
        let tree = Tree::new();
        let first = tree.create(&["repo/.git/hooks"]).unwrap();
        let second = tree.create(&["repo/.git/hooks", "repo/.git/x/y"]).unwrap();
        assert_eq!(
            held(&second, &tree.root),
            [("repo/.git".to_string(), PlaceholderKind::Dir)]
        );
        drop(first);
        assert!(tree.root.join("repo/.git").is_dir());
        drop(second);
        assert!(!tree.root.join("repo/.git").exists());
    }

    #[test]
    fn a_changed_or_replaced_placeholder_is_kept() {
        let tree = Tree::new();
        let file = tree.create(&["repo/.env"]).unwrap();
        let env = tree.root.join("repo/.env");
        std::fs::remove_file(&env).unwrap();
        std::fs::write(&env, b"").unwrap();
        drop(file);
        assert!(env.exists());

        let dir = tree.create(&["repo/out/deny"]).unwrap();
        let out = tree.root.join("repo/out");
        let mut permissions = std::fs::metadata(&out).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(&out, permissions).unwrap();
        std::fs::write(out.join("kept"), b"k").unwrap();
        drop(dir);
        assert!(out.join("kept").exists());
        assert_eq!(tree.records(), 0);
    }

    #[test]
    fn existing_deny_paths_get_no_placeholder() {
        let tree = Tree::new();
        std::fs::write(tree.root.join("repo/present"), b"x").unwrap();
        std::fs::write(tree.root.join("repo/file"), b"x").unwrap();
        let placeholders = tree.create(&["repo/present", "repo/file/below"]).unwrap();
        assert_eq!(held(&placeholders, &tree.root), []);
        assert_eq!(tree.records(), 0);
    }

    #[test]
    fn sweep_removes_what_a_crashed_run_left() {
        let tree = Tree::new();
        let placeholders = tree.create(&["repo/.git/hooks", "repo/.env"]).unwrap();
        std::mem::forget(placeholders);
        registry().retain(|path, _| !path.starts_with(&tree.root));
        assert!(tree.root.join("repo/.git").exists());
        assert_eq!(tree.records(), 2);

        Placeholders::sweep(&tree.root.join("records")).unwrap();
        assert!(!tree.root.join("repo/.git").exists());
        assert!(!tree.root.join("repo/.env").exists());
        assert_eq!(tree.records(), 0);
    }
}
