//! The one outbound notification queue (docs/api.md, Event delivery).
//!
//! Producers (exec, watch) hold cloneable [`Events`] handles and never block. The connection
//! holds the single [`EventReceiver`] and drains it, across reconnects. The queue is bounded by
//! a byte budget: each queued notification costs its payload bytes plus [`OVERHEAD`].
//!
//! When an `exec.output` chunk does not fit, it is dropped and its size is added to the
//! `droppedBytes` of the next chunk of that stream that is queued. If the process exits first,
//! an empty chunk carrying the count is queued just before `exec.exit`.
//!
//! When a watch's changes do not fit, they are dropped and an `overflow: true` event for that
//! watch is queued in their place. Until that marker is received, further changes of the watch
//! are discarded too, because the rescan the marker asks for covers them.
//!
//! `exec.timedOut`, `exec.exit`, the flush chunks before an exit, and overflow markers are always
//! queued, even past the budget. There is at most one of each per process or watch at a time.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use crate::protocol::{
    Base64Bytes, Change, ExecExit, ExecId, ExecOutput, ExecTimedOut, ExitStatus, Notification,
    Stream, TimeoutAction, True, WatchEvent, WatchEventBody, WatchId,
};

/// The fixed cost of one queued notification, on top of its payload bytes.
pub const OVERHEAD: usize = 64;

/// Creates a queue holding at most `capacity_bytes` of droppable notifications.
pub fn channel(capacity_bytes: usize) -> (Events, EventReceiver) {
    let shared = Arc::new(Shared {
        queue: Mutex::new(Queue {
            items: VecDeque::new(),
            used: 0,
            capacity: capacity_bytes,
            dropped: HashMap::new(),
            overflow_queued: HashSet::new(),
        }),
        ready: Notify::new(),
    });
    (
        Events {
            shared: shared.clone(),
        },
        EventReceiver { shared },
    )
}

#[derive(Clone)]
pub struct Events {
    shared: Arc<Shared>,
}

pub struct EventReceiver {
    shared: Arc<Shared>,
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Notify,
}

impl Shared {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct Queue {
    items: VecDeque<Notification>,
    used: usize,
    capacity: usize,
    /// Output bytes dropped since the last queued chunk of that stream.
    dropped: HashMap<(ExecId, Stream), u64>,
    /// Watches whose overflow marker is queued and not yet received.
    overflow_queued: HashSet<WatchId>,
}

fn cost(notification: &Notification) -> usize {
    OVERHEAD
        + match notification {
            Notification::ExecOutput(output) => output.data.0.len(),
            Notification::WatchEvent(WatchEvent {
                body: WatchEventBody::Changes { changes },
                ..
            }) => changes.iter().map(|c| c.path.len() + 16).sum(),
            Notification::WatchEvent(_)
            | Notification::ExecExit(_)
            | Notification::ExecTimedOut(_)
            | Notification::Hello(_) => 0,
        }
}

impl Queue {
    fn fits(&self, notification: &Notification) -> bool {
        self.used + cost(notification) <= self.capacity
    }

    fn push(&mut self, notification: Notification) {
        self.used += cost(&notification);
        self.items.push_back(notification);
    }

    fn overflow(&mut self, watch_id: WatchId) {
        if self.overflow_queued.insert(watch_id.clone()) {
            self.push(Notification::WatchEvent(WatchEvent {
                watch_id,
                body: WatchEventBody::Overflow { overflow: True },
            }));
        }
    }

    fn pop(&mut self) -> Option<Notification> {
        let notification = self.items.pop_front()?;
        self.used -= cost(&notification);
        if let Notification::WatchEvent(WatchEvent {
            watch_id,
            body: WatchEventBody::Overflow { .. },
        }) = &notification
        {
            self.overflow_queued.remove(watch_id);
        }
        Some(notification)
    }
}

impl Events {
    fn update(&self, f: impl FnOnce(&mut Queue)) {
        f(&mut self.shared.queue());
        self.shared.ready.notify_one();
    }

    /// Queues one chunk of process output. The exec track keeps chunks at most
    /// [`MAX_OUTPUT_CHUNK_BYTES`](crate::protocol::MAX_OUTPUT_CHUNK_BYTES).
    pub fn exec_output(&self, exec_id: ExecId, stream: Stream, data: Vec<u8>) {
        self.update(|queue| {
            let mut output = ExecOutput {
                exec_id,
                stream,
                data: Base64Bytes(data),
                dropped_bytes: 0,
            };
            let key = (output.exec_id.clone(), stream);
            let notification = Notification::ExecOutput(output.clone());
            if queue.fits(&notification) {
                output.dropped_bytes = queue.dropped.remove(&key).unwrap_or(0);
                queue.push(Notification::ExecOutput(output));
            } else {
                *queue.dropped.entry(key).or_default() += output.data.0.len() as u64;
            }
        });
    }

    /// Queues that a timeout elapsed. After a `background` action the exec track stops calling
    /// [`Events::exec_output`] for the process.
    pub fn exec_timed_out(&self, exec_id: ExecId, action: TimeoutAction, log_bytes: u64) {
        self.update(|queue| {
            queue.push(Notification::ExecTimedOut(ExecTimedOut {
                exec_id,
                action,
                log_bytes,
            }))
        });
    }

    /// Queues a process's exit, after a flush chunk for any stream with dropped output.
    pub fn exec_exit(&self, exec_id: ExecId, exit: ExitStatus, log_bytes: u64) {
        self.update(|queue| {
            for stream in [Stream::Stdout, Stream::Stderr] {
                if let Some(dropped_bytes) = queue.dropped.remove(&(exec_id.clone(), stream)) {
                    queue.push(Notification::ExecOutput(ExecOutput {
                        exec_id: exec_id.clone(),
                        stream,
                        data: Base64Bytes::default(),
                        dropped_bytes,
                    }));
                }
            }
            queue.push(Notification::ExecExit(ExecExit {
                exec_id,
                exit,
                log_bytes,
            }));
        });
    }

    /// Queues one batch of changes. The watch track keeps batches at most
    /// [`MAX_CHANGES_PER_EVENT`](crate::protocol::MAX_CHANGES_PER_EVENT) long.
    pub fn watch_changes(&self, watch_id: WatchId, changes: Vec<Change>) {
        if changes.is_empty() {
            return;
        }
        self.update(|queue| {
            if queue.overflow_queued.contains(&watch_id) {
                return;
            }
            let notification = Notification::WatchEvent(WatchEvent {
                watch_id: watch_id.clone(),
                body: WatchEventBody::Changes { changes },
            });
            if queue.fits(&notification) {
                queue.push(notification);
            } else {
                queue.overflow(watch_id);
            }
        });
    }

    /// Queues `overflow: true` for a watch whose OS queue overflowed.
    pub fn watch_overflow(&self, watch_id: WatchId) {
        self.update(|queue| queue.overflow(watch_id));
    }
}

impl EventReceiver {
    pub fn try_recv(&mut self) -> Option<Notification> {
        self.shared.queue().pop()
    }

    /// Waits for the next notification. Cancel-safe: nothing is lost if the future is dropped.
    pub async fn recv(&mut self) -> Notification {
        loop {
            if let Some(notification) = self.try_recv() {
                return notification;
            }
            self.shared.ready.notified().await;
        }
    }

    /// Puts a received notification back at the front, for one the connection failed to send.
    pub fn requeue(&mut self, notification: Notification) {
        let mut queue = self.shared.queue();
        queue.used += cost(&notification);
        if let Notification::WatchEvent(WatchEvent {
            watch_id,
            body: WatchEventBody::Overflow { .. },
        }) = &notification
        {
            queue.overflow_queued.insert(watch_id.clone());
        }
        queue.items.push_front(notification);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ChangeKind;

    fn exec(id: &str) -> ExecId {
        ExecId::try_from(id).unwrap()
    }

    fn watch(id: &str) -> WatchId {
        WatchId::try_from(id).unwrap()
    }

    fn output(id: &str, stream: Stream, data: &[u8], dropped_bytes: u64) -> Notification {
        Notification::ExecOutput(ExecOutput {
            exec_id: exec(id),
            stream,
            data: Base64Bytes(data.to_vec()),
            dropped_bytes,
        })
    }

    fn change(path: &str) -> Change {
        Change {
            kind: ChangeKind::Modified,
            path: path.to_string(),
        }
    }

    fn changes(id: &str, paths: &[&str]) -> Notification {
        Notification::WatchEvent(WatchEvent {
            watch_id: watch(id),
            body: WatchEventBody::Changes {
                changes: paths.iter().map(|p| change(p)).collect(),
            },
        })
    }

    fn overflow(id: &str) -> Notification {
        Notification::WatchEvent(WatchEvent {
            watch_id: watch(id),
            body: WatchEventBody::Overflow { overflow: True },
        })
    }

    fn exit(id: &str, exit: ExitStatus, log_bytes: u64) -> Notification {
        Notification::ExecExit(ExecExit {
            exec_id: exec(id),
            exit,
            log_bytes,
        })
    }

    fn drain(rx: &mut EventReceiver) -> Vec<Notification> {
        std::iter::from_fn(|| rx.try_recv()).collect()
    }

    #[test]
    fn dropped_output_is_counted_on_the_next_chunk_of_that_stream() {
        let (events, mut rx) = channel(300);
        events.exec_output(exec("e"), Stream::Stdout, vec![b'a'; 100]); // 164 used
        events.exec_output(exec("e"), Stream::Stdout, vec![b'b'; 100]); // 328 > 300: dropped
        events.exec_output(exec("e"), Stream::Stderr, vec![b'c'; 50]); // 278: fits
        assert_eq!(
            rx.try_recv(),
            Some(output("e", Stream::Stdout, &[b'a'; 100], 0))
        );
        events.exec_output(exec("e"), Stream::Stdout, b"tail".to_vec());
        assert_eq!(
            drain(&mut rx),
            [
                output("e", Stream::Stderr, &[b'c'; 50], 0),
                output("e", Stream::Stdout, b"tail", 100),
            ]
        );
    }

    #[test]
    fn exit_is_never_dropped_and_flushes_dropped_counts_first() {
        let (events, mut rx) = channel(100);
        events.exec_output(exec("e"), Stream::Stderr, vec![0; 40]); // 104 > 100: dropped
        events.exec_output(exec("e"), Stream::Stderr, vec![0; 2]); // 66: fits, carries 40
        events.exec_output(exec("e"), Stream::Stdout, vec![0; 30]); // 160: dropped
        events.exec_output(exec("e"), Stream::Stdout, vec![0; 7]); // 137: dropped
        events.exec_timed_out(exec("f"), TimeoutAction::Kill, 5);
        events.exec_exit(exec("e"), ExitStatus::Exited { code: 3 }, 79);
        events.exec_exit(exec("f"), ExitStatus::TimedOut, 5);
        assert_eq!(
            drain(&mut rx),
            [
                output("e", Stream::Stderr, &[0; 2], 40),
                Notification::ExecTimedOut(ExecTimedOut {
                    exec_id: exec("f"),
                    action: TimeoutAction::Kill,
                    log_bytes: 5,
                }),
                output("e", Stream::Stdout, b"", 37),
                exit("e", ExitStatus::Exited { code: 3 }, 79),
                exit("f", ExitStatus::TimedOut, 5),
            ]
        );
        events.exec_exit(exec("e"), ExitStatus::Signaled { signal: 9 }, 0);
        assert_eq!(
            drain(&mut rx),
            [exit("e", ExitStatus::Signaled { signal: 9 }, 0)]
        );
    }

    #[test]
    fn dropped_changes_become_one_overflow_marker() {
        // One change of "/a" costs 64 + 2 + 16 = 82.
        let (events, mut rx) = channel(150);
        events.watch_changes(watch("w"), vec![change("/a")]);
        events.watch_changes(watch("w"), vec![change("/b")]); // 164 > 150: overflow
        events.watch_changes(watch("w"), vec![change("/c")]); // marker queued: discarded
        events.watch_overflow(watch("w")); // marker queued: nothing new
        events.watch_changes(watch("v"), vec![]); // empty: nothing
        assert_eq!(drain(&mut rx), [changes("w", &["/a"]), overflow("w")]);
        events.watch_changes(watch("w"), vec![change("/d")]);
        events.watch_overflow(watch("w"));
        assert_eq!(drain(&mut rx), [changes("w", &["/d"]), overflow("w")]);
    }

    #[test]
    fn requeued_notification_comes_back_first() {
        let (events, mut rx) = channel(1000);
        events.watch_overflow(watch("w"));
        events.exec_exit(exec("e"), ExitStatus::TimedOut, 0);
        let first = rx.try_recv().unwrap();
        assert_eq!(first, overflow("w"));
        rx.requeue(first);
        events.watch_changes(watch("w"), vec![change("/x")]); // marker queued again: discarded
        assert_eq!(
            drain(&mut rx),
            [overflow("w"), exit("e", ExitStatus::TimedOut, 0)]
        );
    }

    #[test]
    fn budget_is_freed_when_received() {
        let (events, mut rx) = channel(2 * (OVERHEAD + 10));
        for _ in 0..3 {
            events.exec_output(exec("e"), Stream::Stdout, vec![1; 10]);
        }
        assert_eq!(drain(&mut rx).len(), 2);
        events.exec_output(exec("e"), Stream::Stdout, vec![2; 10]);
        assert_eq!(drain(&mut rx), [output("e", Stream::Stdout, &[2; 10], 10)]);
    }

    #[tokio::test]
    async fn recv_waits_for_a_producer() {
        let (events, mut rx) = channel(1000);
        let producer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            events.exec_exit(exec("late"), ExitStatus::Exited { code: 0 }, 2);
        });
        assert_eq!(
            rx.recv().await,
            exit("late", ExitStatus::Exited { code: 0 }, 2)
        );
        producer.await.unwrap();
    }
}
