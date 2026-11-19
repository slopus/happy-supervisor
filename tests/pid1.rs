//! The supervisor as PID 1, a container's entry point (src/init.rs): it reaps the processes its
//! commands leave behind, and exits as the supervisor does.
#![cfg(target_os = "linux")]

use std::process::Stdio;
use std::time::Duration;

use happy_supervisor::Controller;
use happy_supervisor::protocol::{Event, ExitStatus};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");
const TOKEN: &str = "tok_pid1_test";
const WAIT: Duration = Duration::from_secs(30);

/// The PIDs whose parent is `pid`, as the host sees them.
fn children(pid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .flatten()
    {
        let list = std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
        found.extend(list.split_whitespace().map(|p| p.parse::<u32>().unwrap()));
    }
    found
}

/// `pid`'s state letter (`S`, `R`, `Z`, ...), or `None` once it is gone.
fn state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.chars().next()
}

/// Every zombie at or below `pid`.
fn zombies(pid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let mut queue = vec![pid];
    while let Some(pid) = queue.pop() {
        if state(pid) == Some('Z') {
            found.push(pid);
        }
        queue.extend(children(pid));
    }
    found
}

async fn exited(
    ctl: &Controller,
    events: &mut happy_supervisor::controller::Events,
    body: serde_json::Value,
) {
    let exec_id = body["execId"].as_str().unwrap().to_string();
    let _: serde_json::Value = ctl.command("exec.start", body).await.unwrap();
    loop {
        match tokio::time::timeout(WAIT, events.next()).await.unwrap() {
            Some(Event::ExecExit(exit)) if exit.exec_id.as_str() == exec_id => {
                assert_eq!(exit.exit, ExitStatus::Exited { code: 0 }, "{exec_id}");
                return;
            }
            Some(_) => {}
            None => panic!("the events ended"),
        }
    }
}

#[tokio::test]
async fn as_pid_1_it_reaps_what_its_commands_leave_behind() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    let socket = dir.path().join("node.sock");
    // bubblewrap's --as-pid-1 makes the supervisor PID 1 of a new PID namespace, as a container
    // entry point is; the user namespace lets the supervisor's own bubblewrap nest inside it.
    let mut outer = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--as-pid-1",
            "--die-with-parent",
        ])
        .args([
            "--bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--", BIN, "serve",
        ])
        .arg("--listen")
        .arg(format!("unix:{}", socket.display()))
        .arg("--token-file")
        .arg(&token)
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(outer.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(WAIT, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("serve exited before listening");
    assert!(line.starts_with("listening "), "{line}");

    let [init] = children(outer.id().unwrap())[..] else {
        panic!("bubblewrap has no single child");
    };
    let status = std::fs::read_to_string(format!("/proc/{init}/status")).unwrap();
    let nspid = status.lines().find(|l| l.starts_with("NSpid:")).unwrap();
    assert!(nspid.ends_with("\t1"), "{nspid}");

    let ctl = Controller::connect(&format!("unix:{}", socket.display()), TOKEN)
        .await
        .unwrap();
    let mut events = ctl.events();
    for n in 0..3 {
        // The shell exits first, so its background sleep is reparented to PID 1.
        exited(
            &ctl,
            &mut events,
            serde_json::json!({ "execId": format!("raw-{n}"), "argv": ["/bin/sh", "-c", "sleep 0.2 &"],
                                "cwd": "/", "env": {}, "access": { "mode": "raw" } }),
        )
        .await;
        // bubblewrap's PID-namespace init outlives the bubblewrap the supervisor waits for.
        exited(
            &ctl,
            &mut events,
            serde_json::json!({ "execId": format!("sandboxed-{n}"), "argv": ["/bin/true"],
                "cwd": "/", "env": {}, "access": { "mode": "sandboxed", "policy": {
                    "filesystem": {
                        "read": { "default": "allow", "allow": [], "deny": [] },
                        "write": { "default": "deny", "allow": [], "deny": [] } },
                    "network": { "mode": "host", "localBind": false, "unixSockets": false } } } }),
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut left = zombies(init);
    for _ in 0..50 {
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        left = zombies(init);
    }
    assert_eq!(left, Vec::<u32>::new(), "zombies under PID 1");

    // SIGTERM to PID 1 reaches the supervisor, which stops, and PID 1 exits as it did.
    // SAFETY: kill has no memory effects.
    unsafe { libc::kill(init as libc::pid_t, libc::SIGTERM) };
    let exit = tokio::time::timeout(WAIT, outer.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(0));
}
