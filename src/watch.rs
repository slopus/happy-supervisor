//! Watching for changes (`watch.*`). Owned by the files track; the scaffold froze the
//! signatures.
//!
//! Each watch is a notify watcher (inotify, FSEvents or ReadDirectoryChangesW) feeding a bounded
//! channel, and one task that turns its events into batched `watch.event`s. The task owns a
//! [`WatchState`]: the scope it reports (canonical root, the path as the control plane wrote it,
//! the sandbox filter) and the batch being collected. Watches run in the supervisor itself, not
//! in the sandbox helper (docs/architecture.md, Watching).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::error::{Error, ErrorKind, Result};
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

/// A registered watch. Dropping it stops the OS watch and the task.
struct Running {
    /// Tells this watch from a later one that reuses its ID.
    serial: u64,
    _watcher: RecommendedWatcher,
    task: tokio::task::JoinHandle<()>,
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

    pub async fn start(&self, params: WatchStartParams, confinement: Confinement) -> Result<()> {
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
        let (sender, events) = mpsc::channel(QUEUED_EVENTS);
        let lost = Arc::new(AtomicBool::new(false));
        let handler_lost = lost.clone();
        let handler = move |event| {
            if sender.try_send(event).is_err() {
                handler_lost.store(true, Ordering::Relaxed);
            }
        };
        // A recursive watch walks the whole tree, so it runs on a blocking thread.
        let (scope, watcher) =
            tokio::task::spawn_blocking(move || open(&path, recursive, confinement, handler))
                .await
                .map_err(|err| Error::new(ErrorKind::Io, format!("watch.start failed: {err}")))??;

        let state = WatchState::new(watch_id.clone(), scope, self.outbox.clone());
        let serial = self.serial.fetch_add(1, Ordering::Relaxed);
        // The task unregisters itself when its root goes away, so it is spawned under the lock
        // and cannot look before it is registered.
        let mut watches = lock(&self.watches);
        let task = tokio::spawn(run(state, events, lost, self.watches.clone(), serial));
        watches.insert(
            watch_id,
            Running {
                serial,
                _watcher: watcher,
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

/// Resolves the root, checks it against the policy, and starts the OS watch.
fn open(
    path: &AbsPath,
    recursive: bool,
    confinement: Confinement,
    handler: impl notify::EventHandler,
) -> Result<(Scope, RecommendedWatcher)> {
    let at = |err: std::io::Error| {
        let err = Error::from(err);
        Error::new(err.kind, format!("{}: {}", path.as_str(), err.message))
    };
    let root = std::fs::canonicalize(path.as_path()).map_err(at)?;
    let filter = match confinement {
        Confinement::Raw => None,
        Confinement::Sandboxed(policy) => {
            if !policy.can_read(&root) {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("{}: not readable by the policy", path.as_str()),
                ));
            }
            Some(policy)
        }
    };
    let identity = identity(&root).ok_or_else(|| Error::not_found(path.as_str()))?;

    // Following symlinks would watch, and report, paths outside the canonical root.
    let config = notify::Config::default().with_follow_symlinks(false);
    let mut watcher = RecommendedWatcher::new(handler, config).map_err(watch_error)?;
    let mode = if recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    watcher.watch(&root, mode).map_err(watch_error)?;

    let scope = Scope {
        shown: path.as_path().components().collect(),
        root,
        identity,
        recursive,
        filter,
    };
    Ok((scope, watcher))
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
    mut events: mpsc::Receiver<notify::Result<notify::Event>>,
    lost: Arc<AtomicBool>,
    watches: Registry,
    serial: u64,
) {
    loop {
        let event = match state.deadline() {
            Some(deadline) => tokio::select! {
                event = events.recv() => event,
                () = tokio::time::sleep_until(deadline) => {
                    state.flush();
                    continue;
                }
            },
            None => events.recv().await,
        };
        let Some(event) = event else {
            return;
        };
        if lost.swap(false, Ordering::Relaxed) {
            state.overflow();
        }
        if state.observe(event, Instant::now()) == Flow::Ended {
            break;
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

/// What a watch reports, and how its paths are shown.
struct Scope {
    /// The canonical watched path. The OS reports changes under it.
    root: PathBuf,
    /// The watched path as `watch.start` gave it. Changes are reported under it.
    shown: PathBuf,
    identity: (u64, u64),
    recursive: bool,
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

    fn root_is_gone(&self) -> bool {
        identity(&self.root) != Some(self.identity)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Watching,
    /// The root was removed. The final event is queued and the watch is over.
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

    fn observe(&mut self, event: notify::Result<notify::Event>, now: Instant) -> Flow {
        let Ok(event) = event else {
            self.overflow();
            return Flow::Watching;
        };
        if event.need_rescan() {
            self.overflow();
            return Flow::Watching;
        }
        let mut root_touched = false;
        for (kind, path) in changes(&event) {
            root_touched |= self.scope.root.starts_with(&path);
            if let Some(change) = self.scope.change(kind, &path) {
                self.push(change, now);
            }
            if kind == ChangeKind::Created && self.scope.recursive && path != self.scope.root {
                self.scan(&path, now);
            }
        }
        if root_touched && self.scope.root_is_gone() {
            let root = self.scope.root.clone();
            if let Some(change) = self.scope.change(ChangeKind::Removed, &root) {
                self.push(change, now);
            }
            self.flush();
            return Flow::Ended;
        }
        Flow::Watching
    }

    /// Reports what a new directory already holds. Entries made before the OS watched the
    /// directory (inotify adds a watch only after seeing it created), or moved in with it, raise
    /// no event of their own. Symlinks are reported, not followed.
    fn scan(&mut self, dir: &Path, now: Instant) {
        let mut stack = vec![dir.to_path_buf()];
        let mut scanned = 0;
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                scanned += 1;
                if scanned > MAX_SCANNED_ENTRIES {
                    self.overflow();
                    return;
                }
                let path = entry.path();
                if let Some(change) = self.scope.change(ChangeKind::Created, &path) {
                    self.push(change, now);
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(path);
                }
            }
        }
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
            "sandbox": { "mechanism": "none", "available": false, "reason": "test", "landlockAbi": null, "baselineRead": [] },
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
        state: WatchState,
        session: Session,
    }

    fn fixture(filter: impl FnOnce(&Path) -> Option<ResolvedPolicy>) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap().join("repo");
        std::fs::create_dir(&root).unwrap();
        let (session, outbox) = session();
        let scope = Scope {
            root: root.clone(),
            shown: PathBuf::from("/shown/repo"),
            identity: identity(&root).unwrap(),
            recursive: true,
            filter: filter(&root),
        };
        let state = WatchState::new(WatchId::try_from("w-1").unwrap(), scope, outbox);
        Fixture {
            _tmp: tmp,
            root,
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

        assert_eq!(f.state.observe(created(&a), t0), Flow::Watching);
        f.state.observe(event(written, &[&a]), t0);
        f.state.observe(event(written, &[&a]), t0);
        let closed = EventKind::Access(notify::event::AccessKind::Close(
            notify::event::AccessMode::Write,
        ));
        f.state.observe(event(closed, &[&a]), t0);
        f.state
            .observe(event(EventKind::Remove(RemoveKind::File), &[&a]), t0);
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
            f.state.observe(created(&f.root.join(format!("f{i}"))), t0);
        }
        let sent = events(&mut f.session);
        assert_eq!(sent.len(), 1);
        let changes = sent[0]["changes"].as_array().unwrap();
        assert_eq!(changes.len(), 256);
        assert_eq!(changes[255]["path"], "/shown/repo/f255");

        let later = t0 + Duration::from_millis(30);
        f.state.observe(created(&f.root.join("late")), later);
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
        f.state.observe(event(name(RenameMode::From), &[&old]), t0);
        f.state.observe(event(name(RenameMode::To), &[&new]), t0);
        f.state
            .observe(event(name(RenameMode::Both), &[&old, &new]), t0);
        // FSEvents: one side exists afterwards, the other does not.
        std::fs::write(&new, b"").unwrap();
        f.state
            .observe(event(name(RenameMode::Any), &[&old, &new]), t0);
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
        f.state
            .observe(event(EventKind::Create(CreateKind::Folder), &[&dir]), t0);
        f.state.flush();
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "created", "path": "/shown/repo/new" },
                { "kind": "created", "path": "/shown/repo/new/deeper" },
                { "kind": "created", "path": "/shown/repo/new/deeper/f" },
            ] })]
        );

        f.state.scope.recursive = false;
        f.state
            .observe(event(EventKind::Create(CreateKind::Folder), &[&dir]), t0);
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
        f.state.observe(
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
        f.state.observe(created(&f.root.join("a")), t0);
        let rescan = notify::Event::new(EventKind::Other).set_flag(Flag::Rescan);
        f.state.observe(Ok(rescan), t0);
        assert_eq!(f.state.deadline(), None);
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "overflow": true })]
        );

        f.state
            .observe(Err(notify::Error::generic("inotify broke")), t0);
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
        f.state.observe(created(&f.root.join(".state")), t0);
        f.state
            .observe(created(&f.root.join(".state/credentials.json")), t0);
        f.state.observe(created(&f.root.join("visible")), t0);
        f.state.observe(created(Path::new("/elsewhere/x")), t0);
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
        f.state.observe(created(&f.root.join("a")), t0);
        // Another event on the root while it exists changes nothing.
        let touched = EventKind::Modify(ModifyKind::Metadata(notify::event::MetadataKind::Any));
        assert_eq!(
            f.state.observe(event(touched, &[&f.root]), t0),
            Flow::Watching
        );

        std::fs::remove_dir_all(&f.root).unwrap();
        let removed = event(EventKind::Remove(RemoveKind::Folder), &[&f.root]);
        assert_eq!(f.state.observe(removed, t0), Flow::Ended);
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
        assert_eq!(f.state.observe(event(renamed, &[&f.root]), t0), Flow::Ended);
        assert_eq!(
            events(&mut f.session),
            [json!({ "watchId": "w-1", "changes": [
                { "kind": "renamed", "path": "/shown/repo" },
                { "kind": "removed", "path": "/shown/repo" },
            ] })]
        );
    }
}
