//! Watching for changes (`watch.*`). Owned by the files track; the scaffold froze the
//! signatures.
//!
//! Each watch has two halves. The OS half is a notify watcher (inotify, FSEvents or
//! ReadDirectoryChangesW) whose handler turns each event into what was [`Seen`]: changed paths,
//! the entries of a new directory, an overflow, or the root going away ([`Observer`]). The
//! reporting half is one task that owns a [`WatchState`]: the scope it reports (canonical root,
//! the path as the control plane wrote it, the sandbox filter) and the batch being collected.
//! The OS half runs in the supervisor, or, with a workload user, in a helper process as that user
//! (docs/architecture.md, Watching).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::Workload;
use crate::link::Outbox;
use crate::policy::{Confinement, ResolvedPolicy};
use crate::protocol::{
    AbsPath, Change, ChangeKind, MAX_CHANGES_PER_EVENT, MAX_WATCHES, WatchId, WatchStartParams,
};

/// How long changes are collected before they are sent.
const BATCH_WINDOW: Duration = Duration::from_millis(100);

/// The most entries a new directory is scanned for. A bigger one is reported as `overflow`.
const MAX_SCANNED_ENTRIES: usize = 10_000;

/// OS events waiting for the watch's task. When it is full, events are lost and the watch
/// reports `overflow`.
const QUEUED_EVENTS: usize = 4096;

/// After [`crate::helper::HELPER_ARG`]: run one watch's OS half as this process's user
/// ([`helper_main`]).
pub const HELPER_WATCH_ARG: &str = "watch";

type Registry = Arc<Mutex<HashMap<WatchId, Running>>>;

/// Every watch of this node. Watches outlive connections. A sandboxed watch reports only
/// changes its [`ResolvedPolicy::can_read`](crate::policy::ResolvedPolicy::can_read) allows.
pub struct WatchManager {
    outbox: Outbox,
    watches: Registry,
    /// Serializes starts, so the ID and count checks hold until the new watch is registered.
    starting: tokio::sync::Mutex<()>,
    serial: AtomicU64,
}

/// A registered watch. Dropping it stops the OS half and the task.
struct Running {
    /// Tells this watch from a later one that reuses its ID.
    serial: u64,
    _source: Source,
    task: tokio::task::JoinHandle<()>,
}

/// Where the OS half runs. Held for its drop, which stops it.
enum Source {
    Watcher {
        _watcher: RecommendedWatcher,
    },
    /// The helper, killed on drop, with its stdin, whose end tells it to exit.
    #[cfg(unix)]
    Helper {
        _child: tokio::process::Child,
    },
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl WatchManager {
    pub fn new(outbox: Outbox) -> WatchManager {
        WatchManager {
            outbox,
            watches: Registry::default(),
            starting: tokio::sync::Mutex::new(()),
            serial: AtomicU64::new(0),
        }
    }

    /// Starts a watch. With `workload`, its OS half runs in a helper as that user, so the OS
    /// checks what it may watch and list as that user.
    pub async fn start(
        &self,
        params: WatchStartParams,
        confinement: Confinement,
        workload: Option<Arc<Workload>>,
    ) -> Result<()> {
        let _starting = self.starting.lock().await;
        {
            let watches = lock(&self.watches);
            if watches.contains_key(&params.watch_id) {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    format!("watch {} already exists", params.watch_id),
                ));
            }
            if watches.len() >= MAX_WATCHES {
                return Err(Error::too_large(format!(
                    "this node already has {MAX_WATCHES} watches"
                )));
            }
        }

        let WatchStartParams {
            watch_id,
            path,
            recursive,
        } = params;
        let (sender, seen) = mpsc::channel(QUEUED_EVENTS);
        let lost = Arc::new(AtomicBool::new(false));
        let (scope, source) = match workload {
            None => {
                let lost = lost.clone();
                let report = move |batch: Vec<Seen>| {
                    if !batch.is_empty() && sender.try_send(batch).is_err() {
                        lost.store(true, Ordering::Relaxed);
                    }
                };
                // A recursive watch walks the whole tree, so it starts on a blocking thread.
                tokio::task::spawn_blocking(move || open(&path, recursive, confinement, report))
                    .await
                    .map_err(|err| {
                        Error::new(ErrorKind::Io, format!("watch.start failed: {err}"))
                    })??
            }
            #[cfg(unix)]
            Some(workload) => {
                open_in_helper(&path, recursive, confinement, &workload, sender).await?
            }
            #[cfg(windows)]
            Some(workload) => match *workload {},
        };

        let state = WatchState::new(watch_id.clone(), scope, self.outbox.clone());
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        // The task unregisters itself when its root goes away, so it is spawned under the lock
        // and cannot look before it is registered.
        let mut watches = lock(&self.watches);
        let task = tokio::spawn(run(state, seen, lost, self.watches.clone(), serial));
        watches.insert(
            watch_id,
            Running {
                serial,
                _source: source,
                task,
            },
        );
        Ok(())
    }

    pub fn stop(&self, watch_id: &WatchId) -> Result<()> {
        let running = lock(&self.watches).remove(watch_id);
        match running {
            Some(running) => {
                drop(running);
                Ok(())
            }
            None => Err(Error::not_found(format!("watch {watch_id} does not exist"))),
        }
    }

    /// The active watches, for `node.ready`.
    pub fn ids(&self) -> Vec<WatchId> {
        let mut ids: Vec<WatchId> = lock(&self.watches).keys().cloned().collect();
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        ids
    }
}

fn lock(watches: &Registry) -> MutexGuard<'_, HashMap<WatchId, Running>> {
    watches.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Resolves the root, checks it against the policy, and starts the OS watch in this process.
fn open(
    path: &AbsPath,
    recursive: bool,
    confinement: Confinement,
    report: impl FnMut(Vec<Seen>) + Send + 'static,
) -> Result<(Scope, Source)> {
    let root = canonical_root(path)?;
    let filter = filter(path, &root, confinement)?;
    let watcher = start_os(path, root.clone(), recursive, report)?;
    Ok((
        scope(path, root, filter),
        Source::Watcher { _watcher: watcher },
    ))
}

fn canonical_root(path: &AbsPath) -> Result<PathBuf> {
    crate::policy::canonicalize(path.as_path()).map_err(|err| {
        let err = Error::from(err);
        Error::new(err.kind, format!("{}: {}", path.as_str(), err.message))
    })
}

/// A sandboxed watch's filter: its policy, which must let it read the root.
fn filter(path: &AbsPath, root: &Path, confinement: Confinement) -> Result<Option<ResolvedPolicy>> {
    match confinement {
        Confinement::Raw => Ok(None),
        Confinement::Sandboxed(policy) if policy.can_read(root) => Ok(Some(policy)),
        Confinement::Sandboxed(_) => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{}: not readable by the policy", path.as_str()),
        )),
    }
}

fn scope(path: &AbsPath, root: PathBuf, filter: Option<ResolvedPolicy>) -> Scope {
    Scope {
        shown: path.as_path().components().collect(),
        root,
        filter,
    }
}

/// Starts the OS watch on the canonical `root`, reporting what it sees to `report` from
/// notify's thread.
fn start_os(
    path: &AbsPath,
    root: PathBuf,
    recursive: bool,
    mut report: impl FnMut(Vec<Seen>) + Send + 'static,
) -> Result<RecommendedWatcher> {
    let identity = identity(&root).ok_or_else(|| Error::not_found(path.as_str()))?;
    let observer = Observer {
        root: root.clone(),
        identity,
        recursive,
    };
    // Following symlinks would watch, and report, paths outside the canonical root.
    let config = notify::Config::default().with_follow_symlinks(false);
    let handler = move |event| report(observer.observe(event));
    let mut watcher = RecommendedWatcher::new(handler, config).map_err(watch_error)?;
    let mode = if recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    watcher.watch(&root, mode).map_err(watch_error)?;
    Ok(watcher)
}

/// What a watch helper is asked to do, on its stdin.
#[cfg(unix)]
#[derive(Serialize, Deserialize)]
struct HelperWatch {
    path: AbsPath,
    recursive: bool,
}

/// The helper's first frame: the canonical root it watches, or why it could not.
#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum HelperStarted {
    Ok(#[serde(with = "path_bytes")] PathBuf),
    Err(Error),
}

/// Starts the OS half in a helper running as `workload`, which reports each event's [`Seen`]
/// as a frame on its stdout until its stdin closes. The policy is checked here, on the root the
/// helper resolved as that user.
#[cfg(unix)]
async fn open_in_helper(
    path: &AbsPath,
    recursive: bool,
    confinement: Confinement,
    workload: &Workload,
    sender: mpsc::Sender<Vec<Seen>>,
) -> Result<(Scope, Source)> {
    use tokio::io::AsyncWriteExt as _;

    let mut command = std::process::Command::new(crate::helper::exe()?);
    command.args([crate::helper::HELPER_ARG, HELPER_WATCH_ARG]);
    crate::identity::run_as(&mut command, Some(workload), None)?;
    let mut command = tokio::process::Command::from(command);
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let job = HelperWatch {
        path: path.clone(),
        recursive,
    };
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    // A helper that dies early closes its stdin, and then sends no first frame.
    let _ = stdin.write_all(&crate::helper::encode_frame(&job)).await;
    let gone = || Error::new(ErrorKind::Io, "the watch helper exited before it started");
    let root = match crate::helper::read_frame_async(&mut stdout).await {
        Ok(Some(HelperStarted::Ok(root))) => root,
        Ok(Some(HelperStarted::Err(err))) => return Err(err),
        Ok(None) => return Err(gone()),
        Err(err) => return Err(err),
    };
    let filter = filter(path, &root, confinement)?;
    tokio::spawn(async move {
        loop {
            let batch = match crate::helper::read_frame_async(&mut stdout).await {
                Ok(Some(batch)) => batch,
                // Stopped: the helper was killed and its task is gone.
                Ok(None) | Err(_) if sender.is_closed() => return,
                Ok(None) | Err(_) => vec![Seen::Failed],
            };
            let failed = batch.iter().any(|seen| matches!(seen, Seen::Failed));
            if sender.send(batch).await.is_err() || failed {
                return;
            }
        }
    });
    // The helper exits when its stdin closes, so the child keeps it.
    child.stdin = Some(stdin);
    Ok((scope(path, root, filter), Source::Helper { _child: child }))
}

/// `happy-supervisor __sandbox watch`: the OS half of one watch, as the workload user the
/// parent made this process. Reads a [`HelperWatch`], replies [`HelperStarted`], then writes
/// one frame of [`Seen`] per OS event until stdin closes.
#[cfg(unix)]
pub fn helper_main() -> ! {
    use std::io::{Read as _, Write as _};

    let mut stdin = std::io::stdin().lock();
    let job: HelperWatch = match crate::helper::read_frame(&mut stdin) {
        Ok(job) => job,
        Err(err) => {
            eprintln!("happy-supervisor __sandbox watch: {err}");
            std::process::exit(crate::helper::EXIT_BAD_JOB)
        }
    };
    let write = |frame: Vec<u8>| {
        let mut stdout = std::io::stdout().lock();
        if stdout
            .write_all(&frame)
            .and_then(|()| stdout.flush())
            .is_err()
        {
            // The supervisor is gone.
            std::process::exit(0);
        }
    };
    let report = move |batch: Vec<Seen>| {
        if !batch.is_empty() {
            write(crate::helper::encode_frame(&batch));
        }
    };
    let started = canonical_root(&job.path).and_then(|root| {
        start_os(&job.path, root.clone(), job.recursive, report).map(|watcher| (root, watcher))
    });
    let _watcher = match started {
        Ok((root, watcher)) => {
            write(crate::helper::encode_frame(&HelperStarted::Ok(root)));
            watcher
        }
        Err(err) => {
            write(crate::helper::encode_frame(&HelperStarted::Err(err)));
            std::process::exit(0)
        }
    };
    // Watch until the supervisor closes stdin or exits.
    let _ = stdin.read_to_end(&mut Vec::new());
    std::process::exit(0)
}

fn watch_error(err: notify::Error) -> Error {
    let paths: Vec<String> = err.paths.iter().map(|p| p.display().to_string()).collect();
    let kind = match &err.kind {
        notify::ErrorKind::Io(io) => Error::from(std::io::Error::from(io.kind())).kind,
        notify::ErrorKind::PathNotFound => ErrorKind::NotFound,
        _ => ErrorKind::Io,
    };
    let message = match &err.kind {
        notify::ErrorKind::Io(io) => io.to_string(),
        notify::ErrorKind::MaxFilesWatch => "the OS limit on watched files is reached".to_string(),
        notify::ErrorKind::Generic(message) => message.clone(),
        other => format!("{other:?}"),
    };
    if paths.is_empty() {
        Error::new(kind, message)
    } else {
        Error::new(kind, format!("{}: {message}", paths.join(", ")))
    }
}

/// The identity of the file at `path`, so a root that was removed and made again is noticed.
#[cfg(unix)]
fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::symlink_metadata(path).ok().map(|_| (0, 0))
}

async fn run(
    mut state: WatchState,
    mut seen: mpsc::Receiver<Vec<Seen>>,
    lost: Arc<AtomicBool>,
    watches: Registry,
    serial: u64,
) {
    'watching: loop {
        let batch = match state.deadline() {
            Some(deadline) => tokio::select! {
                batch = seen.recv() => batch,
                () = tokio::time::sleep_until(deadline) => {
                    state.flush();
                    continue;
                }
            },
            None => seen.recv().await,
        };
        let Some(batch) = batch else {
            return;
        };
        if lost.swap(false, Ordering::Relaxed) {
            state.overflow();
        }
        let now = Instant::now();
        for seen in batch {
            if state.take(seen, now) == Flow::Ended {
                break 'watching;
            }
        }
    }
    let mut registry = lock(&watches);
    let ours = registry
        .get(&state.watch_id)
        .is_some_and(|running| running.serial == serial);
    let running = if ours {
        registry.remove(&state.watch_id)
    } else {
        None
    };
    drop(registry);
    drop(running);
}

/// What the OS half saw, before the policy and batching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Seen {
    Changed {
        kind: ChangeKind,
        #[cfg_attr(unix, serde(with = "path_bytes"))]
        path: PathBuf,
    },
    /// Changes were lost.
    Overflow,
    /// The root was removed, or replaced by another file.
    RootGone,
    /// The watch helper exited or wrote garbage. The watch is over.
    Failed,
}

/// A path as its bytes, so a name that is not UTF-8 crosses from the helper intact.
#[cfg(unix)]
mod path_bytes {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};

    use serde::{Deserialize as _, Deserializer, Serializer};

    use crate::protocol::Bytes;

    pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(path.as_os_str().as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        let bytes = Bytes::deserialize(deserializer)?;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(
            bytes.into_vec(),
        )))
    }
}

/// The OS half's view of one watch: what an event means, which needs the filesystem as the
/// watching user sees it.
struct Observer {
    /// The canonical watched path. The OS reports changes under it.
    root: PathBuf,
    identity: (u64, u64),
    recursive: bool,
}

impl Observer {
    fn observe(&self, event: notify::Result<notify::Event>) -> Vec<Seen> {
        let Ok(event) = event else {
            return vec![Seen::Overflow];
        };
        if event.need_rescan() {
            return vec![Seen::Overflow];
        }
        let mut seen = Vec::new();
        let mut root_touched = false;
        for (kind, path) in changes(&event) {
            root_touched |= self.root.starts_with(&path);
            let new_dir = kind == ChangeKind::Created && self.recursive && path != self.root;
            seen.push(Seen::Changed {
                kind,
                path: path.clone(),
            });
            if new_dir {
                self.scan(&path, &mut seen);
            }
        }
        if root_touched && identity(&self.root) != Some(self.identity) {
            seen.push(Seen::RootGone);
        }
        seen
    }

    /// Reports what a new directory already holds. Entries made before the OS watched the
    /// directory (inotify adds a watch only after seeing it created), or moved in with it, raise
    /// no event of their own. Symlinks are reported, not followed.
    fn scan(&self, dir: &Path, seen: &mut Vec<Seen>) {
        let mut stack = vec![dir.to_path_buf()];
        let mut scanned = 0;
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                scanned += 1;
                if scanned > MAX_SCANNED_ENTRIES {
                    seen.push(Seen::Overflow);
                    return;
                }
                let path = entry.path();
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(path.clone());
                }
                seen.push(Seen::Changed {
                    kind: ChangeKind::Created,
                    path,
                });
            }
        }
    }
}

/// What a watch reports, and how its paths are shown.
struct Scope {
    /// The canonical watched path.
    root: PathBuf,
    /// The watched path as `watch.start` gave it. Changes are reported under it.
    shown: PathBuf,
    /// A sandboxed watch reports only what its policy can read.
    filter: Option<ResolvedPolicy>,
}

impl Scope {
    /// The change to report for `path`, an OS path under the root, or `None` when the policy
    /// cannot read it.
    fn change(&self, kind: ChangeKind, path: &Path) -> Option<Change> {
        let relative = path.strip_prefix(&self.root).ok()?;
        if let Some(policy) = &self.filter
            && !policy.can_read(path)
        {
            return None;
        }
        let shown = if relative.as_os_str().is_empty() {
            self.shown.clone()
        } else {
            self.shown.join(relative)
        };
        Some(Change {
            kind,
            path: shown.to_string_lossy().into_owned(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Watching,
    /// The root was removed, or the helper failed. The final event is queued and the watch is
    /// over.
    Ended,
}

/// One watch's reporting state: idle, or collecting a batch until its deadline.
struct WatchState {
    watch_id: WatchId,
    scope: Scope,
    outbox: Outbox,
    pending: Option<Batch>,
}

struct Batch {
    changes: Vec<Change>,
    deadline: Instant,
}

impl WatchState {
    fn new(watch_id: WatchId, scope: Scope, outbox: Outbox) -> WatchState {
        WatchState {
            watch_id,
            scope,
            outbox,
            pending: None,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.pending.as_ref().map(|batch| batch.deadline)
    }

    fn take(&mut self, seen: Seen, now: Instant) -> Flow {
        match seen {
            Seen::Changed { kind, path } => {
                if let Some(change) = self.scope.change(kind, &path) {
                    self.push(change, now);
                }
            }
            Seen::Overflow => self.overflow(),
            Seen::RootGone => {
                let root = self.scope.root.clone();
                if let Some(change) = self.scope.change(ChangeKind::Removed, &root) {
                    self.push(change, now);
                }
                self.flush();
                return Flow::Ended;
            }
            Seen::Failed => {
                tracing::warn!("watch {}: its helper exited; ending it", self.watch_id);
                self.overflow();
                return Flow::Ended;
            }
        }
        Flow::Watching
    }

    fn push(&mut self, change: Change, now: Instant) {
        let batch = self.pending.get_or_insert_with(|| Batch {
            changes: Vec::new(),
            deadline: now + BATCH_WINDOW,
        });
        // Writes arrive as many identical events. The last one for a path is enough.
        let last = batch.changes.iter().rev().find(|c| c.path == change.path);
        if last.is_some_and(|last| last.kind == change.kind) {
            return;
        }
        batch.changes.push(change);
        if batch.changes.len() == MAX_CHANGES_PER_EVENT {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if let Some(batch) = self.pending.take() {
            self.outbox
                .watch_changes(self.watch_id.clone(), batch.changes);
        }
    }

    /// Changes were lost. The rescan `overflow` asks for covers the batch too.
    fn overflow(&mut self) {
        self.pending = None;
        self.outbox.watch_overflow(self.watch_id.clone());
    }
}

/// The changes one notify event stands for.
fn changes(event: &notify::Event) -> Vec<(ChangeKind, PathBuf)> {
    let kind = match event.kind {
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            ChangeKind::Created
        }
        EventKind::Remove(_) => ChangeKind::Removed,
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => ChangeKind::Renamed,
        // inotify sends the `From` and `To` halves on their own too.
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => return Vec::new(),
        // FSEvents does not say which side of a rename a path was on, so ask the filesystem.
        EventKind::Modify(ModifyKind::Name(_)) => {
            return event
                .paths
                .iter()
                .map(|path| {
                    let kind = if std::fs::symlink_metadata(path).is_ok() {
                        ChangeKind::Created
                    } else {
                        ChangeKind::Renamed
                    };
                    (kind, path.clone())
                })
                .collect();
        }
        EventKind::Modify(_) | EventKind::Any => ChangeKind::Modified,
        EventKind::Access(_) | EventKind::Other => return Vec::new(),
    };
    event
        .paths
        .iter()
        .map(|path| (kind, path.clone()))
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use notify::event::{CreateKind, DataChange, Flag, RemoveKind};
    use serde_json::{Value, json};

    use super::*;
    use crate::link::{ManualClock, NodeIdentity, Role, Session};
    use crate::policy::allow_list;
    use crate::protocol::{Frame, SessionId, WatchEvent, Welcome};
    use crate::wire;

    /// A node session with `node.ready` sent, so queued events can be drained as frames.
    fn session() -> (Session, Outbox) {
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (mut session, outbox) = Session::new(Role::Node(identity), ManualClock::new(0));
        session.connected();
        let welcome = Frame::Welcome(Welcome {
            session: SessionId(uuid::Uuid::from_u128(1)),
            resumed: false,
            cursor: None,
            resume_window_ms: 1000,
        });
        session.receive(&wire::frame(
            uuid::Uuid::from_u128(2),
            &wire::to_cbor(&welcome),
        ));
        let info = serde_json::from_value(json!({
            "installationId": "tz4a98xxat96iws9zmbrgj3a", "name": "box", "hostname": "box",
            "supervisorVersion": "0.1.0",
            "os": { "family": "linux", "name": null, "version": null, "kernelVersion": null, "arch": "x86_64" },
            "cpu": { "model": null, "physicalCores": null, "logicalCores": 1 },
            "memory": { "totalBytes": 1, "swapTotalBytes": 0 },
            "disks": [], "gpus": [],
            "sandbox": { "mechanism": "none", "available": false, "reason": "test", "baselineRead": [] },
            "identity": { "supervisorUser": "me", "workloadUser": null, "root": false },
            "limits": { "memoryBytes": false, "processes": false, "cpuSeconds": true },
            "defaultEnv": {}, "collectedAtMs": 0
        }))
        .unwrap();
        session.ready(info, vec![], vec![]).unwrap();
        events(&mut session);
        (session, outbox)
    }

    /// The bodies of the `watch.event`s transmitted since the last call.
    fn events(session: &mut Session) -> Vec<Value> {
        std::iter::from_fn(|| session.poll_transmit())
            .filter_map(|payload| {
                match wire::from_cbor(wire::split(&payload).unwrap().1).unwrap() {
                    Frame::Msg(msg) if msg.kind == "watch.event" => {
                        let event: WatchEvent = wire::from_value(msg.body).unwrap();
                        Some(serde_json::to_value(event).unwrap())
                    }
                    _ => None,
                }
            })
            .collect()
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        observer: Observer,
        state: WatchState,
        session: Session,
    }

    impl Fixture {
        /// Both halves of a watch on one OS event, as `run` does.
        fn observe(&mut self, event: notify::Result<notify::Event>, now: Instant) -> Flow {
            for seen in self.observer.observe(event) {
                if self.state.take(seen, now) == Flow::Ended {
                    return Flow::Ended;
                }
            }
            Flow::Watching
        }
    }

    fn fixture(filter: impl FnOnce(&Path) -> Option<ResolvedPolicy>) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap().join("repo");
        std::fs::create_dir(&root).unwrap();
        let (session, outbox) = session();
        let observer = Observer {
            root: root.clone(),
            identity: identity(&root).unwrap(),
            recursive: true,
        };
        let scope = Scope {
            root: root.clone(),
            shown: PathBuf::from("/shown/repo"),
            filter: filter(&root),
        };
        let state = WatchState::new(WatchId::try_from("w-1").unwrap(), scope, outbox);
        Fixture {
            _tmp: tmp,
            root,
            observer,
            state,
            session,
        }
    }

    fn event(kind: EventKind, paths: &[&Path]) -> notify::Result<notify::Event> {
        let mut event = notify::Event::new(kind);
        for path in paths {
            event = event.add_path(path.to_path_buf());
        }
        Ok(event)
    }

    fn created(path: &Path) -> notify::Result<notify::Event> {
        event(EventKind::Create(CreateKind::File), &[path])
    }

    #[test]
    fn changes_are_batched_until_the_deadline_and_shown_under_the_requested_path() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        let a = f.root.join("src/a.rs");
        let written = EventKind::Modify(ModifyKind::Data(DataChange::Any));

        assert_eq!(f.observe(created(&a), t0), Flow::Watching);
        f.observe(event(written, &[&a]), t0);
        f.observe(event(written, &[&a]), t0);
        let closed = EventKind::Access(notify::event::AccessKind::Close(
            notify::event::AccessMode::Write,
        ));
        f.observe(event(closed, &[&a]), t0);
        f.observe(event(EventKind::Remove(RemoveKind::File), &[&a]), t0);
        assert_eq!(f.state.deadline(), Some(t0 + Duration::from_millis(100)));
        assert_eq!(events(&mut f.session), [] as [Value; 0]);

        f.state.flush();
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "created", "path": "/shown/repo/src/a.rs" },
                { "kind": "modified", "path": "/shown/repo/src/a.rs" },
                { "kind": "removed", "path": "/shown/repo/src/a.rs" },
            ] })]
        );
        assert_eq!(f.state.deadline(), None);
    }

    #[test]
    fn a_full_batch_goes_out_at_once_and_the_rest_waits() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        for i in 0..300 {
            f.observe(created(&f.root.join(format!("f{i}"))), t0);
        }
        let sent = events(&mut f.session);
        assert_eq!(sent.len(), 1);
        let changes = sent[0]["changes"].as_array().unwrap();
        assert_eq!(changes.len(), 256);
        assert_eq!(changes[255]["path"], "/shown/repo/f255");

        let later = t0 + Duration::from_millis(30);
        f.observe(created(&f.root.join("late")), later);
        // The batch started with change 257, at t0.
        assert_eq!(f.state.deadline(), Some(t0 + Duration::from_millis(100)));
        f.state.flush();
        let sent = events(&mut f.session);
        let changes = sent[0]["changes"].as_array().unwrap();
        assert_eq!(changes.len(), 45);
        assert_eq!(changes[44]["path"], "/shown/repo/late");
    }

    #[test]
    fn renames_report_the_old_path_renamed_and_the_new_one_created() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        let (old, new) = (f.root.join("old"), f.root.join("new"));
        let name = |mode| EventKind::Modify(ModifyKind::Name(mode));
        f.observe(event(name(RenameMode::From), &[&old]), t0);
        f.observe(event(name(RenameMode::To), &[&new]), t0);
        f.observe(event(name(RenameMode::Both), &[&old, &new]), t0);
        // FSEvents: one side exists afterwards, the other does not.
        std::fs::write(&new, b"").unwrap();
        f.observe(event(name(RenameMode::Any), &[&old, &new]), t0);
        f.state.flush();
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "renamed", "path": "/shown/repo/old" },
                { "kind": "created", "path": "/shown/repo/new" },
            ] })]
        );
    }

    #[test]
    fn a_new_directory_is_scanned_for_what_it_already_holds() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        let dir = f.root.join("new");
        std::fs::create_dir_all(dir.join("deeper")).unwrap();
        std::fs::write(dir.join("deeper/f"), b"").unwrap();
        f.observe(event(EventKind::Create(CreateKind::Folder), &[&dir]), t0);
        f.state.flush();
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "created", "path": "/shown/repo/new" },
                { "kind": "created", "path": "/shown/repo/new/deeper" },
                { "kind": "created", "path": "/shown/repo/new/deeper/f" },
            ] })]
        );

        f.observer.recursive = false;
        f.observe(event(EventKind::Create(CreateKind::Folder), &[&dir]), t0);
        f.state.flush();
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "created", "path": "/shown/repo/new" },
            ] })]
        );
    }

    #[test]
    fn a_directory_too_big_to_scan_is_an_overflow() {
        let mut f = fixture(|_| None);
        let dir = f.root.join("big");
        std::fs::create_dir(&dir).unwrap();
        for i in 0..=MAX_SCANNED_ENTRIES {
            std::fs::write(dir.join(i.to_string()), b"").unwrap();
        }
        f.observe(
            event(EventKind::Create(CreateKind::Folder), &[&dir]),
            Instant::now(),
        );
        let sent = events(&mut f.session);
        assert_eq!(sent.len(), 40, "39 full batches, then the overflow");
        assert_eq!(sent[39], json!({ "watchId": "w-1", "overflow": true }));
        assert_eq!(f.state.deadline(), None);
    }

    #[test]
    fn a_rescan_or_an_error_drops_the_batch_for_overflow() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        f.observe(created(&f.root.join("a")), t0);
        let rescan = notify::Event::new(EventKind::Other).set_flag(Flag::Rescan);
        f.observe(Ok(rescan), t0);
        assert_eq!(f.state.deadline(), None);
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "overflow": true })]
        );

        f.observe(Err(notify::Error::generic("inotify broke")), t0);
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "overflow": true })]
        );
    }

    #[test]
    fn a_sandboxed_watch_never_reports_what_the_policy_cannot_read() {
        let mut f = fixture(|root| {
            let state = root.join(".state");
            std::fs::create_dir(&state).unwrap();
            let policy = allow_list([root], [] as [&str; 0], false, false);
            Some(ResolvedPolicy::resolve(&policy, &state).unwrap())
        });
        let t0 = Instant::now();
        f.observe(created(&f.root.join(".state")), t0);
        f.observe(created(&f.root.join(".state/credentials.json")), t0);
        f.observe(created(&f.root.join("visible")), t0);
        f.observe(created(Path::new("/elsewhere/x")), t0);
        f.state.flush();
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "created", "path": "/shown/repo/visible" },
            ] })]
        );
    }

    #[test]
    fn removing_the_root_sends_a_final_removed_change_and_ends() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        f.observe(created(&f.root.join("a")), t0);
        // Another event on the root while it exists changes nothing.
        let touched = EventKind::Modify(ModifyKind::Metadata(notify::event::MetadataKind::Any));
        assert_eq!(f.observe(event(touched, &[&f.root]), t0), Flow::Watching);

        std::fs::remove_dir_all(&f.root).unwrap();
        let removed = event(EventKind::Remove(RemoveKind::Folder), &[&f.root]);
        assert_eq!(f.observe(removed, t0), Flow::Ended);
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "created", "path": "/shown/repo/a" },
                { "kind": "modified", "path": "/shown/repo" },
                { "kind": "removed", "path": "/shown/repo" },
            ] })]
        );
    }

    #[test]
    fn a_root_moved_away_and_made_again_counts_as_removed() {
        let mut f = fixture(|_| None);
        let t0 = Instant::now();
        std::fs::rename(&f.root, f.root.with_file_name("moved")).unwrap();
        std::fs::create_dir(&f.root).unwrap();
        let renamed = EventKind::Modify(ModifyKind::Name(RenameMode::From));
        assert_eq!(f.observe(event(renamed, &[&f.root]), t0), Flow::Ended);
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "renamed", "path": "/shown/repo" },
                { "kind": "removed", "path": "/shown/repo" },
            ] })]
        );
    }
}
