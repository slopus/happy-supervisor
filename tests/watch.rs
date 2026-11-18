//! `watch.*` against the real OS watcher (inotify, FSEvents). Events are read off a node
//! session as the control plane would receive them. OS delivery timing varies, so every wait is
//! bounded and every assertion looks for changes rather than an exact event sequence.
// The helpers serve the Unix-only tests too.
#![cfg_attr(windows, allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use happy_supervisor::link::{ManualClock, NodeIdentity, Role, Session};
use happy_supervisor::policy::{Confinement, Policy, ResolvedPolicy};
use happy_supervisor::protocol::{
    AbsPath, Frame, SessionId, WatchEvent, WatchId, WatchStartParams, Welcome,
};
use happy_supervisor::watch::WatchManager;
use happy_supervisor::wire;
use happy_supervisor::{Error, ErrorKind};
use serde_json::{Value, json};

const PATIENCE: Duration = Duration::from_secs(10);

/// The control plane's view: the `watch.event` bodies the node transmitted.
struct Peer {
    session: Session,
    events: Vec<Value>,
}

impl Peer {
    fn new() -> (Peer, WatchManager) {
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (mut session, _) = Session::new(Role::Node(identity), ManualClock::new(0));
        session.connected(wire::Wire::Plain);
        let welcome = Frame::Welcome(Welcome {
            session: SessionId(uuid::Uuid::from_u128(1)),
            resumed: false,
            cursor: None,
            resume_window_ms: 1000,
        });
        session.receive(&wire::to_cbor(&welcome));
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
        let manager = WatchManager::new(session.outbox());
        let mut peer = Peer {
            session,
            events: Vec::new(),
        };
        peer.drain();
        peer.events.clear();
        (peer, manager)
    }

    fn drain(&mut self) {
        while let Some(payload) = self.session.poll_transmit() {
            if let Frame::Msg(msg) = wire::from_cbor(&payload).unwrap()
                && msg.kind == "watch.event"
            {
                let event: WatchEvent = wire::from_value(msg.body).unwrap();
                self.events.push(serde_json::to_value(event).unwrap());
            }
        }
    }

    /// Every change reported so far, as `(kind, path)`.
    fn changes(&self) -> Vec<(String, String)> {
        self.events
            .iter()
            .filter_map(|event| event["changes"].as_array())
            .flatten()
            .map(|c| {
                let field = |name: &str| c[name].as_str().unwrap().to_string();
                (field("kind"), field("path"))
            })
            .collect()
    }

    fn saw(&self, kind: &str, path: &Path) -> bool {
        let path = path.to_str().unwrap();
        self.changes().iter().any(|(k, p)| k == kind && p == path)
    }

    /// Waits, at most [`PATIENCE`], until `done` holds.
    async fn wait(&mut self, what: &str, done: impl Fn(&Peer) -> bool) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            self.drain();
            if done(self) {
                return;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("no {what} within {PATIENCE:?}; events: {:#?}", self.events);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits until the watch on `dir` reports, by writing probe files into it. FSEvents may
    /// start delivering a moment after the watch is set up.
    async fn wait_live(&mut self, dir: &Path) {
        let started = tokio::time::Instant::now();
        let mut probes = Vec::new();
        loop {
            let probe = dir.join(format!(".probe-{}", probes.len()));
            std::fs::write(&probe, b"").unwrap();
            probes.push(probe);
            for _ in 0..20 {
                self.drain();
                if probes.iter().any(|probe| self.saw("created", probe)) {
                    self.events.clear();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(started.elapsed() < PATIENCE, "the watch never reported");
        }
    }

    async fn wait_for(&mut self, kind: &str, path: &Path) {
        let what = format!("{kind} {}", path.display());
        self.wait(&what, |peer| peer.saw(kind, path)).await;
    }
}

fn id(id: &str) -> WatchId {
    WatchId::try_from(id).unwrap()
}

fn params(watch_id: &str, path: &Path, recursive: bool) -> WatchStartParams {
    WatchStartParams {
        watch_id: id(watch_id),
        path: AbsPath::try_from(path.to_str().unwrap()).unwrap(),
        recursive,
    }
}

/// A fresh directory with the path the test should watch. On macOS the temp dir is under the
/// `/var` symlink, so watching it checks that changes come back under the path as given.
fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    (tmp, root)
}

#[tokio::test]
async fn reports_created_modified_renamed_and_removed() {
    let (_tmp, root) = tempdir();
    let (mut peer, manager) = Peer::new();
    manager
        .start(params("w-1", &root, true), Confinement::Raw)
        .await
        .unwrap();
    peer.wait_live(&root).await;
    assert_eq!(manager.ids(), [id("w-1")]);

    let a = root.join("a.txt");
    std::fs::write(&a, b"one").unwrap();
    peer.wait_for("created", &a).await;

    let mut file = std::fs::OpenOptions::new().append(true).open(&a).unwrap();
    std::io::Write::write_all(&mut file, b"two").unwrap();
    drop(file);
    peer.wait_for("modified", &a).await;

    let b = root.join("b.txt");
    std::fs::rename(&a, &b).unwrap();
    peer.wait_for("renamed", &a).await;
    peer.wait_for("created", &b).await;

    std::fs::remove_file(&b).unwrap();
    peer.wait_for("removed", &b).await;

    let deep = root.join("sub").join("deeper").join("f");
    std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
    std::fs::write(&deep, b"").unwrap();
    peer.wait_for("created", &deep).await;

    for event in &peer.events {
        assert_eq!(event["watchId"], "w-1");
        let path = root.to_str().unwrap();
        for change in event["changes"].as_array().unwrap() {
            assert!(
                change["path"].as_str().unwrap().starts_with(path),
                "{change}"
            );
        }
    }
    manager.stop(&id("w-1")).unwrap();
    assert_eq!(manager.ids(), [] as [WatchId; 0]);
}

#[tokio::test]
async fn a_non_recursive_watch_reports_only_direct_children() {
    let (_tmp, root) = tempdir();
    std::fs::create_dir(root.join("sub")).unwrap();
    let (mut peer, manager) = Peer::new();
    manager
        .start(params("w-1", &root, false), Confinement::Raw)
        .await
        .unwrap();
    peer.wait_live(&root).await;

    std::fs::write(root.join("sub").join("hidden"), b"").unwrap();
    let sentinel = root.join("sentinel");
    std::fs::write(&sentinel, b"").unwrap();
    peer.wait_for("created", &sentinel).await;
    let deep = root.join("sub").join("hidden");
    assert!(
        !peer
            .changes()
            .iter()
            .any(|(_, p)| p == deep.to_str().unwrap())
    );
}

#[tokio::test]
async fn many_changes_arrive_in_events_of_at_most_256() {
    let (_tmp, root) = tempdir();
    let (mut peer, manager) = Peer::new();
    manager
        .start(params("w-1", &root, true), Confinement::Raw)
        .await
        .unwrap();
    peer.wait_live(&root).await;

    let files: Vec<PathBuf> = (0..1000).map(|i| root.join(format!("f{i:04}"))).collect();
    for file in &files {
        std::fs::write(file, b"").unwrap();
    }
    // Under load FSEvents drops events and says so ("user dropped"), which the node reports as
    // `overflow`. That is a correct outcome too.
    let overflowed = |peer: &Peer| peer.events.iter().any(|e| e["overflow"] == true);
    peer.wait("all 1000 created, or overflow", |peer| {
        overflowed(peer) || files.iter().all(|f| peer.saw("created", f))
    })
    .await;
    let sizes: Vec<usize> = peer
        .events
        .iter()
        .filter_map(|e| e["changes"].as_array().map(Vec::len))
        .collect();
    assert!(sizes.iter().all(|&n| n <= 256), "{sizes:?}");
    if overflowed(&peer) {
        eprintln!("the OS dropped events; batches before that: {sizes:?}");
    } else {
        assert!(sizes.len() >= 4, "{sizes:?}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_sandboxed_watch_hides_the_state_directory() {
    let (_tmp, root) = tempdir();
    let state = root.join(".state");
    std::fs::create_dir(&state).unwrap();
    let canonical = std::fs::canonicalize(&root).unwrap();
    let policy = Policy::new(vec![canonical.display().to_string()], vec![], false, false);
    let resolved = ResolvedPolicy::resolve(&policy.unwrap(), &state);
    let (mut peer, manager) = Peer::new();
    manager
        .start(params("w-1", &root, true), Confinement::Sandboxed(resolved))
        .await
        .unwrap();
    peer.wait_live(&root).await;

    std::fs::write(state.join("credentials.json"), b"{}").unwrap();
    let sentinel = root.join("visible");
    std::fs::write(&sentinel, b"").unwrap();
    peer.wait_for("created", &sentinel).await;
    let leaked: Vec<_> = peer
        .changes()
        .into_iter()
        .filter(|(_, p)| p.contains(".state"))
        .collect();
    assert_eq!(leaked, [] as [(String, String); 0]);
}

#[cfg(unix)]
#[tokio::test]
async fn a_sandboxed_watch_needs_a_readable_root() {
    let (_tmp, root) = tempdir();
    std::fs::create_dir(root.join("granted")).unwrap();
    std::fs::create_dir(root.join("secret")).unwrap();
    let canonical = std::fs::canonicalize(&root).unwrap();
    let policy = Policy::new(
        vec![canonical.join("granted").display().to_string()],
        vec![],
        false,
        false,
    );
    let resolved = ResolvedPolicy::resolve(&policy.unwrap(), &root.join("state"));
    let (_peer, manager) = Peer::new();
    let secret = root.join("secret");
    assert_eq!(
        manager
            .start(
                params("w-1", &secret, true),
                Confinement::Sandboxed(resolved)
            )
            .await,
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("{}: not readable by the policy", secret.display())
        ))
    );
    assert_eq!(manager.ids(), [] as [WatchId; 0]);
}

#[cfg(unix)]
#[tokio::test]
async fn removing_the_root_ends_the_watch() {
    let (_tmp, root) = tempdir();
    let watched = root.join("watched");
    std::fs::create_dir_all(watched.join("inner")).unwrap();
    std::fs::write(watched.join("inner/f"), b"").unwrap();
    let (mut peer, manager) = Peer::new();
    manager
        .start(params("w-1", &watched, true), Confinement::Raw)
        .await
        .unwrap();
    peer.wait_live(&watched).await;

    std::fs::remove_dir_all(&watched).unwrap();
    peer.wait_for("removed", &watched).await;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !manager.ids().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the watch is still listed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let last = peer.events.last().unwrap()["changes"].as_array().unwrap();
    assert_eq!(
        last.last().unwrap(),
        &json!({ "kind": "removed", "path": watched.to_str().unwrap() })
    );
    assert_eq!(
        manager.stop(&id("w-1")),
        Err(Error::not_found("watch w-1 does not exist"))
    );

    // The ID is free again.
    std::fs::create_dir(&watched).unwrap();
    manager
        .start(params("w-1", &watched, true), Confinement::Raw)
        .await
        .unwrap();
    assert_eq!(manager.ids(), [id("w-1")]);
}

#[tokio::test]
async fn ids_are_unique_and_a_node_holds_64_watches() {
    let (_tmp, root) = tempdir();
    let (_peer, manager) = Peer::new();
    for i in 0..64 {
        manager
            .start(params(&format!("w-{i:02}"), &root, false), Confinement::Raw)
            .await
            .unwrap();
    }
    assert_eq!(manager.ids().len(), 64);
    assert_eq!(manager.ids()[0], id("w-00"));
    assert_eq!(manager.ids()[63], id("w-63"));

    assert_eq!(
        manager
            .start(params("w-00", &root, false), Confinement::Raw)
            .await,
        Err(Error::new(
            ErrorKind::AlreadyExists,
            "watch w-00 already exists"
        ))
    );
    assert_eq!(
        manager
            .start(params("w-64", &root, false), Confinement::Raw)
            .await,
        Err(Error::too_large("this node already has 64 watches"))
    );

    manager.stop(&id("w-10")).unwrap();
    manager
        .start(params("w-64", &root, false), Confinement::Raw)
        .await
        .unwrap();
    assert_eq!(manager.ids().len(), 64);
}

#[cfg(unix)]
#[tokio::test]
async fn start_needs_an_existing_path_and_stop_a_known_watch() {
    let (_tmp, root) = tempdir();
    let (_peer, manager) = Peer::new();
    let missing = root.join("missing");
    assert_eq!(
        manager
            .start(params("w-1", &missing, true), Confinement::Raw)
            .await,
        Err(Error::not_found(format!(
            "{}: No such file or directory (os error 2)",
            missing.display()
        )))
    );
    assert_eq!(
        manager.stop(&id("w-1")),
        Err(Error::not_found("watch w-1 does not exist"))
    );
}
