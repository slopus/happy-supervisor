//! Running commands (`exec.*`). Owned by the exec track; the scaffold froze the signatures.
//!
//! Each started process gets two reader threads (stdout, stderr) and one waiter thread, and a
//! sandboxed one whose binds the sandbox reports a third reader. The readers append to the
//! process's [`Output`] and stream chunks, or send `net.bindDenied`, through the [`Outbox`]. The
//! waiter reports the exit once every reader is done. The [`Table`] maps IDs to [`Phase`]s.
//! Locks are always taken table first, then a process's output.

pub(crate) mod log;

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use self::log::{FileLog, Log, MemoryLog};
use crate::error::{Error, ErrorKind, Result};
use crate::identity::Workload;
use crate::link::Outbox;
use crate::policy::{Confinement, Network, ResolvedPolicy};
use crate::process::{self, Tree};
use crate::protocol::{
    AbsPath, Argv, Bytes, ExecId, ExecLogParams, ExecLogResult, ExecResizeParams, ExecStartParams,
    ExecStartResult, ExecState, ExecSummary, ExecWriteParams, ExitStatus, KillSignal, Limits,
    LogSpec, MAX_EXEC_LOG_READ_BYTES, MAX_EXEC_WRITE_BYTES, MAX_OUTPUT_CHUNK_BYTES,
    MEMORY_LOG_BUDGET_BYTES, NetBindDenied, RETAINED_EXITED_EXECS, Stream, Timeout, TimeoutAction,
    TtySize,
};
use crate::proxy::egress::{Admit, CommandProxy, Limiter};
use crate::sandbox::{BindReports, NetPlan, NetnsControl, Placeholders};

#[cfg(target_os = "linux")]
pub use crate::apt::AptGate;
/// A system command's socket for installing with apt, which only Linux has (apt.rs).
#[cfg(not(target_os = "linux"))]
pub enum AptGate {}

/// What `exec.write` with `eof` sends to a terminal: Ctrl-D, its default end-of-file character.
const EOF_CHARACTER: u8 = 0x04;

/// After a process exits, how long its output may stay silent before the exit is reported
/// without waiting for the pipes to close. Processes it left behind can hold them open forever.
const DRAIN_IDLE: Duration = Duration::from_millis(100);

/// Every command of this node, running or recently exited. Commands outlive connections.
pub struct ExecManager {
    inner: Arc<Inner>,
}

struct Inner {
    outbox: Outbox,
    table: Mutex<Table>,
    memory_budget: u64,
}

#[derive(Default)]
struct Table {
    execs: HashMap<ExecId, Entry>,
    /// Orders starts (for listing) and exits (for forgetting the oldest).
    next_seq: u64,
}

struct Entry {
    started: u64,
    phase: Phase,
}

enum Phase {
    /// Being spawned. The ID is taken, and a memory log's limit is reserved.
    Starting {
        memory_reserved: u64,
    },
    Running(Running),
    Exited {
        exit: ExitStatus,
        output: Arc<Mutex<Output>>,
        ended: u64,
    },
    /// The start failed. The ID stays taken, no exit follows, and it is not listed.
    Failed {
        ended: u64,
    },
}

struct Running {
    tree: Tree,
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    /// The terminal's master side, with `tty`: input goes here instead of `stdin`.
    terminal: Option<Arc<File>>,
    output: Arc<Mutex<Output>>,
    memory_reserved: u64,
    timer: Option<tokio::task::AbortHandle>,
    /// The `kill` timeout action fired; the exit is `timedOut`.
    timed_out: bool,
    /// The process exited and is being reaped. Its group may no longer be signalled.
    reaping: bool,
    /// The command's credential proxy. Dropped with this phase, so the proxy stops at the exit.
    _proxy: Option<CommandProxy>,
    /// The sandbox's placeholders, kept until the exit like the proxy.
    _placeholders: Option<Placeholders>,
    /// How `tcp.open` reaches the process's ports. `None`: its policy forbids binding them.
    tunnel: Option<TunnelRoute>,
}

/// What [`crate::sandbox::prepare`] returned besides the command.
type Held = (Placeholders, Option<NetnsControl>, Option<BindReports>);

/// How `tcp.open` with a process's `execId` reaches `127.0.0.1` as the process sees it
/// (tunnels.md).
#[derive(Clone, Debug)]
pub enum TunnelRoute {
    /// The process shares the node's loopback.
    Loopback,
    /// The process has its own network namespace.
    Netns(Arc<NetnsControl>),
}

impl Phase {
    fn ended(&self) -> Option<u64> {
        match self {
            Phase::Exited { ended, .. } | Phase::Failed { ended } => Some(*ended),
            Phase::Starting { .. } | Phase::Running(_) => None,
        }
    }

    fn memory_reserved(&self) -> u64 {
        match self {
            Phase::Starting { memory_reserved } => *memory_reserved,
            Phase::Running(running) => running.memory_reserved,
            Phase::Exited { .. } | Phase::Failed { .. } => 0,
        }
    }
}

/// One process's log and whether its output is still streamed.
struct Output {
    log: Log,
    /// Cleared by the `background` timeout action.
    streaming: bool,
    /// Set once the exit is reported. Later output is neither logged nor streamed.
    closed: bool,
    /// Chunks the log failed to record. The first failure is logged, the rest only counted.
    failed_appends: u64,
}

/// The command's stdio: pipes, with stdin open for `exec.write` or empty, or a terminal.
#[derive(Clone, Copy, Debug)]
enum Io {
    Pipes { stdin: bool },
    Tty(#[cfg_attr(windows, expect(dead_code, reason = "Windows rejects tty"))] TtySize),
}

impl Io {
    #[cfg(unix)]
    fn terminal(self) -> Option<TtySize> {
        match self {
            Io::Tty(size) => Some(size),
            Io::Pipes { .. } => None,
        }
    }
}

/// What bounds a command: its `limits`, and on Linux the cgroup that enforces `memoryBytes` and
/// `processes`. A sandboxed command joins the cgroup from inside the sandbox
/// (`sandbox::Plan::cgroup`), so bubblewrap and the helper do not count.
#[derive(Clone, Copy)]
struct Bounds<'a> {
    limits: &'a Limits,
    cgroup: Option<&'a process::Cgroup>,
}

/// A spawned child before it is registered.
struct Spawned {
    child: Child,
    tree: Tree,
    /// The master side of its terminal, with `tty`.
    terminal: Option<File>,
}

impl ExecManager {
    pub fn new(outbox: Outbox) -> ExecManager {
        ExecManager::with_memory_budget(outbox, MEMORY_LOG_BUDGET_BYTES)
    }

    fn with_memory_budget(outbox: Outbox, memory_budget: u64) -> ExecManager {
        ExecManager {
            inner: Arc::new(Inner {
                outbox,
                table: Mutex::default(),
                memory_budget,
            }),
        }
    }

    /// Starts a command. Sandboxed ones go through `sandbox::prepare` and the helper.
    ///
    /// `proxy` is the command's running credential proxy when `exec.start` asked for one
    /// (`params.proxy` is then taken). Its `env()` replaces the same names in `params.env`. The
    /// command holds it until it exits, and a failed start drops it, which stops the proxy.
    ///
    /// `user` is who the command runs as (identity.rs); `None` runs it as the supervisor.
    ///
    /// `apt` is a system command's socket for installing with apt (apt.rs). It serves the
    /// command's session from the spawn, and closes as soon as the process exits, before its
    /// output ends.
    pub async fn start(
        &self,
        params: ExecStartParams,
        confinement: Confinement,
        proxy: Option<CommandProxy>,
        user: Option<Arc<Workload>>,
        apt: Option<AptGate>,
    ) -> Result<ExecStartResult> {
        let exec_id = params.exec_id.clone();
        let memory_reserved = match params.log {
            LogSpec::Memory { .. } => params.log.limit_bytes(),
            LogSpec::File { .. } => 0,
        };
        self.inner.reserve(&exec_id, memory_reserved)?;
        let inner = self.inner.clone();
        let runtime = tokio::runtime::Handle::current();
        // Spawning and registering run to completion on a blocking thread, so a cancelled
        // caller cannot leave a process running unregistered.
        let started = tokio::task::spawn_blocking(move || {
            let result = inner.launch(params, &confinement, proxy, user.as_deref(), apt, &runtime);
            if result.is_err() {
                inner.fail(&exec_id);
            }
            result.map(|pid| ExecStartResult { exec_id, pid })
        });
        started
            .await
            .map_err(|err| Error::new(ErrorKind::Io, format!("exec.start failed: {err}")))?
    }

    /// How `tcp.open` reaches the ports of `exec_id`: `not_found` unless it is running,
    /// `permission_denied` when its policy does not let it bind ports.
    pub fn tunnel_route(&self, exec_id: &ExecId) -> Result<TunnelRoute> {
        let not_running = || Error::not_found(format!("{exec_id} is not running"));
        match self.inner.entry_phase(exec_id, |phase| match phase {
            Phase::Running(running) => Some(running.tunnel.clone()),
            _ => None,
        }) {
            Ok(Some(Some(route))) => Ok(route),
            Ok(Some(None)) => Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("{exec_id}'s policy does not allow localBind"),
            )),
            Ok(None) | Err(_) => Err(not_running()),
        }
    }

    pub async fn write(&self, params: ExecWriteParams) -> Result<()> {
        let ExecWriteParams { exec_id, data, eof } = params;
        if data.as_slice().len() > MAX_EXEC_WRITE_BYTES {
            return Err(Error::too_large(format!(
                "exec.write data is {} bytes, at most {MAX_EXEC_WRITE_BYTES} are allowed",
                data.as_slice().len()
            )));
        }
        let (stdin, terminal) = self
            .inner
            .entry_phase(&exec_id, |phase| match phase {
                Phase::Running(running) => Some((running.stdin.clone(), running.terminal.clone())),
                _ => None,
            })?
            .ok_or_else(|| Error::invalid_params(format!("{exec_id} is not running")))?;
        tokio::task::spawn_blocking(move || {
            if let Some(terminal) = terminal {
                let mut terminal = &*terminal;
                terminal.write_all(data.as_slice())?;
                if eof {
                    terminal.write_all(&[EOF_CHARACTER])?;
                }
                return Ok(());
            }
            let mut stdin = lock(&stdin);
            let Some(pipe) = stdin.as_mut() else {
                return Err(Error::invalid_params(format!(
                    "{exec_id} has no open stdin"
                )));
            };
            pipe.write_all(data.as_slice())?;
            if eof {
                *stdin = None;
            }
            Ok(())
        })
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("exec.write failed: {err}")))?
    }

    /// Sets the size of a `tty` process's terminal.
    pub fn resize(&self, params: ExecResizeParams) -> Result<()> {
        let ExecResizeParams { exec_id, size } = params;
        let terminal = self
            .inner
            .entry_phase(&exec_id, |phase| match phase {
                Phase::Running(running) => Ok(running.terminal.clone()),
                _ => Err(Error::invalid_params(format!("{exec_id} is not running"))),
            })??
            .ok_or_else(|| Error::invalid_params(format!("{exec_id} has no terminal")))?;
        #[cfg(unix)]
        process::pty::resize(&terminal, size)?;
        #[cfg(not(unix))]
        let _ = (terminal, size);
        Ok(())
    }

    /// Signals the command's process group or Job Object and returns at once.
    pub fn kill(&self, exec_id: &ExecId, signal: KillSignal) -> Result<()> {
        self.inner.entry_phase(exec_id, |phase| match phase {
            Phase::Running(running) if !running.reaping => {
                running.tree.signal(signal).map_err(Error::from)
            }
            _ => Ok(()),
        })?
    }

    /// Reads a process's output log (api.md, `exec.log` and Output logs).
    pub async fn log(&self, params: ExecLogParams) -> Result<ExecLogResult> {
        let length = params.length.unwrap_or(MAX_EXEC_LOG_READ_BYTES);
        if length > MAX_EXEC_LOG_READ_BYTES {
            return Err(Error::too_large(format!(
                "exec.log length is {length}, at most {MAX_EXEC_LOG_READ_BYTES} are allowed"
            )));
        }
        let output = self
            .inner
            .entry_phase(&params.exec_id, |phase| match phase {
                Phase::Running(running) => Some(running.output.clone()),
                Phase::Exited { output, .. } => Some(output.clone()),
                Phase::Starting { .. } | Phase::Failed { .. } => None,
            })?;
        let Some(output) = output else {
            return Ok(ExecLogResult {
                data: Bytes::new(Vec::new()),
                offset: 0,
                total_bytes: 0,
                retained: Vec::new(),
            });
        };
        let read =
            tokio::task::spawn_blocking(move || lock(&output).log.read(params.offset, length))
                .await
                .map_err(|err| Error::new(ErrorKind::Io, format!("exec.log failed: {err}")))??;
        Ok(ExecLogResult {
            data: Bytes::new(read.data),
            offset: read.offset,
            total_bytes: read.total,
            retained: read.retained,
        })
    }

    /// Running commands and the most recent exited ones, for `exec.list` and `node.ready`.
    pub fn list(&self) -> Vec<ExecSummary> {
        let table = lock(&self.inner.table);
        let mut listed: Vec<(u64, ExecSummary)> = table
            .execs
            .iter()
            .filter_map(|(exec_id, entry)| {
                let (state, output) = match &entry.phase {
                    Phase::Running(running) => (ExecState::Running, &running.output),
                    Phase::Exited { exit, output, .. } => {
                        (ExecState::Exited { exit: *exit }, output)
                    }
                    Phase::Starting { .. } | Phase::Failed { .. } => return None,
                };
                let summary = ExecSummary {
                    exec_id: exec_id.clone(),
                    state,
                    log_bytes: lock(output).log.total(),
                };
                Some((entry.started, summary))
            })
            .collect();
        listed.sort_by_key(|(started, _)| *started);
        listed.into_iter().map(|(_, summary)| summary).collect()
    }

    /// Kills every running command. Called when the supervisor exits normally.
    pub async fn shutdown(&self) {
        let table = lock(&self.inner.table);
        for entry in table.execs.values() {
            if let Phase::Running(running) = &entry.phase
                && !running.reaping
                && let Err(err) = running.tree.signal(KillSignal::Kill)
            {
                tracing::warn!("killing a command at shutdown failed: {err}");
            }
        }
    }
}

impl Inner {
    /// Takes `exec_id` for a start, and makes room for its memory log (api.md, Output logs).
    fn reserve(&self, exec_id: &ExecId, memory_reserved: u64) -> Result<()> {
        let mut table = lock(&self.table);
        if table.execs.contains_key(exec_id) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("{exec_id} is already in use"),
            ));
        }
        let started = table.next_seq();
        let running: u64 = table
            .execs
            .values()
            .map(|e| e.phase.memory_reserved())
            .sum();
        if running + memory_reserved > self.memory_budget {
            let ended = table.next_seq();
            table.execs.insert(
                exec_id.clone(),
                Entry {
                    started,
                    phase: Phase::Failed { ended },
                },
            );
            self.forget_oldest(&mut table);
            return Err(Error::too_large(format!(
                "running processes already reserve {running} bytes of memory log, and \
                 {memory_reserved} more would pass the node's {} byte budget",
                self.memory_budget
            )));
        }
        let mut exited: Vec<(u64, &Arc<Mutex<Output>>, u64)> = table
            .execs
            .values()
            .filter_map(|entry| match &entry.phase {
                Phase::Exited { output, ended, .. } => match &lock(output).log {
                    Log::Memory(log) => Some((*ended, output, log.held_bytes())),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        exited.sort_by_key(|(ended, _, _)| *ended);
        let mut used = running + memory_reserved + exited.iter().map(|e| e.2).sum::<u64>();
        for (_, output, held) in exited {
            if used <= self.memory_budget {
                break;
            }
            let mut output = lock(output);
            output.log = Log::Discarded {
                total: output.log.total(),
            };
            used -= held;
        }
        table.execs.insert(
            exec_id.clone(),
            Entry {
                started,
                phase: Phase::Starting { memory_reserved },
            },
        );
        Ok(())
    }

    fn fail(&self, exec_id: &ExecId) {
        let mut table = lock(&self.table);
        let ended = table.next_seq();
        if let Some(entry) = table.execs.get_mut(exec_id) {
            entry.phase = Phase::Failed { ended };
        }
        self.forget_oldest(&mut table);
    }

    /// Forgets the oldest ended processes beyond the most recent [`RETAINED_EXITED_EXECS`].
    fn forget_oldest(&self, table: &mut Table) {
        let mut ended: Vec<(u64, ExecId)> = table
            .execs
            .iter()
            .filter_map(|(id, entry)| entry.phase.ended().map(|seq| (seq, id.clone())))
            .collect();
        if ended.len() <= RETAINED_EXITED_EXECS {
            return;
        }
        ended.sort();
        for (_, exec_id) in &ended[..ended.len() - RETAINED_EXITED_EXECS] {
            table.execs.remove(exec_id);
        }
    }

    fn entry_phase<T>(&self, exec_id: &ExecId, f: impl FnOnce(&mut Phase) -> T) -> Result<T> {
        let mut table = lock(&self.table);
        match table.execs.get_mut(exec_id) {
            Some(entry) => Ok(f(&mut entry.phase)),
            None => Err(Error::not_found(format!("no process {exec_id}"))),
        }
    }

    /// Spawns the process and registers it as running. Returns its pid. Blocking.
    fn launch(
        self: &Arc<Self>,
        params: ExecStartParams,
        confinement: &Confinement,
        proxy: Option<CommandProxy>,
        workload: Option<&Workload>,
        mut apt: Option<AptGate>,
        runtime: &tokio::runtime::Handle,
    ) -> Result<u32> {
        let ExecStartParams {
            exec_id,
            argv,
            cwd,
            mut env,
            stdin,
            timeout,
            log,
            proxy: _,
            tty,
            limits,
        } = params;
        let unsupported = limits.unsupported(&process::limit_support());
        if !unsupported.is_empty() {
            let names: Vec<String> = unsupported.iter().map(|n| format!("limits.{n}")).collect();
            return Err(Error::sandbox_unavailable(format!(
                "this node cannot enforce {} (NodeInfo limits)",
                names.join(" or ")
            )));
        }
        let io = match tty {
            Some(size) => Io::Tty(size),
            None => Io::Pipes { stdin },
        };
        #[cfg(windows)]
        if let Io::Tty(_) = io {
            return Err(Error::invalid_params("tty is not supported on Windows yet"));
        }
        if let Some(proxy) = &proxy {
            env.extend(proxy.env(&crate::helper::exe()?));
        }
        let program = resolve_program(argv.program(), &env)?;
        let log = open_log(&log, confinement, workload)?;
        let cgroup = process::Cgroup::create(&limits)?;
        let bounds = Bounds {
            limits: &limits,
            cgroup: cgroup.as_ref(),
        };
        let (
            Spawned {
                mut child,
                tree,
                terminal,
            },
            placeholders,
            tunnel,
            binds,
        ) = match confinement {
            Confinement::Raw => (
                spawn_raw(&program, &argv, &cwd, &env, io, workload, bounds)?,
                None,
                Some(TunnelRoute::Loopback),
                None,
            ),
            Confinement::Sandboxed(policy) => {
                let net = match (policy.network(), &proxy) {
                    (Network::Isolated { .. }, Some(proxy)) => Some(NetPlan {
                        http: proxy.http.clone(),
                        socks: proxy.socks.clone(),
                    }),
                    _ => None,
                };
                let mut resolved = vec![program.to_string_lossy().into_owned()];
                resolved.extend(argv.args().iter().cloned());
                let op = crate::helper::JobOp::Exec {
                    argv: Argv::try_from(resolved)?,
                    cwd: cwd.clone(),
                    env,
                    limits,
                };
                let (spawned, (placeholders, netns, binds)) =
                    spawn_sandboxed(policy, net, op, io, workload, bounds)?;
                let tunnel = policy.network().local_bind().then(|| match netns {
                    Some(netns) => TunnelRoute::Netns(Arc::new(netns)),
                    None => TunnelRoute::Loopback,
                });
                (spawned, Some(placeholders), tunnel, binds)
            }
        };

        let output = Arc::new(Mutex::new(Output {
            log,
            streaming: true,
            closed: false,
            failed_appends: 0,
        }));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        // A terminal is one stream; its reader gets a handle of its own.
        let terminal_reader = terminal.as_ref().map(File::try_clone).transpose()?;
        let pipes: Vec<(Stream, Box<dyn Read + Send>)> = match terminal_reader {
            Some(reader) => vec![(Stream::Stdout, boxed(reader))],
            None => vec![
                (Stream::Stdout, boxed(child.stdout.take().expect("piped"))),
                (Stream::Stderr, boxed(child.stderr.take().expect("piped"))),
            ],
        };
        let mut readers = pipes.len();
        for (stream, pipe) in pipes {
            let reader = Reader {
                outbox: self.outbox.clone(),
                exec_id: exec_id.clone(),
                stream,
                output: output.clone(),
                done: done_tx.clone(),
            };
            let spawned = std::thread::Builder::new()
                .name(format!("exec-{stream:?}"))
                .spawn(move || reader.run(pipe));
            if let Err(err) = spawned {
                let _ = tree.signal(KillSignal::Kill);
                let _ = child.wait();
                return Err(err.into());
            }
        }
        if let Some(binds) = binds {
            let outbox = self.outbox.clone();
            let exec_id = exec_id.clone();
            let done = done_tx.clone();
            let spawned = std::thread::Builder::new()
                .name("exec-binds".to_string())
                .spawn(move || report_binds(&binds, &outbox, &exec_id, &done));
            if let Err(err) = spawned {
                let _ = tree.signal(KillSignal::Kill);
                let _ = child.wait();
                return Err(err.into());
            }
            readers += 1;
        }
        drop(done_tx);

        let pid = child.id();
        // The process leads its session, whose processes alone the socket serves.
        if let Some(gate) = &mut apt {
            #[cfg(target_os = "linux")]
            gate.serve(pid, runtime);
            #[cfg(not(target_os = "linux"))]
            match *gate {}
        }
        let stdin = Arc::new(Mutex::new(child.stdin.take()));
        let mut table = lock(&self.table);
        let waiter = Waiter {
            inner: self.clone(),
            exec_id: exec_id.clone(),
            output: output.clone(),
            done: done_rx,
            readers,
            cgroup,
            apt,
        };
        if let Err(err) = std::thread::Builder::new()
            .name("exec-wait".to_string())
            .spawn(move || waiter.run(child))
        {
            let _ = tree.signal(KillSignal::Kill);
            return Err(err.into());
        }
        let entry = table
            .execs
            .get_mut(&exec_id)
            .expect("a starting process stays in the table");
        let memory_reserved = entry.phase.memory_reserved();
        let timer = timeout.map(|timeout| {
            let inner = self.clone();
            let exec_id = exec_id.clone();
            let output = output.clone();
            runtime
                .spawn(async move {
                    tokio::time::sleep(Duration::from_millis(timeout.ms)).await;
                    inner.time_out(&exec_id, &output, timeout);
                })
                .abort_handle()
        });
        entry.phase = Phase::Running(Running {
            tree,
            stdin,
            terminal: terminal.map(Arc::new),
            output,
            memory_reserved,
            timer,
            timed_out: false,
            reaping: false,
            _proxy: proxy,
            _placeholders: placeholders,
            tunnel,
        });
        Ok(pid)
    }

    /// Applies a timeout's action, if the process it was set for still runs.
    fn time_out(&self, exec_id: &ExecId, output: &Arc<Mutex<Output>>, timeout: Timeout) {
        let mut table = lock(&self.table);
        let Some(running) = table.running(exec_id, output) else {
            return;
        };
        let mut out = lock(output);
        self.outbox
            .exec_timed_out(exec_id.clone(), timeout.action, out.log.total());
        match timeout.action {
            TimeoutAction::Kill => {
                running.timed_out = true;
                if let Err(err) = running.tree.signal(KillSignal::Kill) {
                    tracing::warn!("killing {exec_id} after its timeout failed: {err}");
                }
            }
            TimeoutAction::Background => out.streaming = false,
        }
    }
}

impl Table {
    fn next_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// The running process `exec_id` whose output is `output`, not a later one with that ID.
    fn running(&mut self, exec_id: &ExecId, output: &Arc<Mutex<Output>>) -> Option<&mut Running> {
        match self.execs.get_mut(exec_id).map(|entry| &mut entry.phase) {
            Some(Phase::Running(running))
                if Arc::ptr_eq(&running.output, output) && !running.reaping =>
            {
                Some(running)
            }
            _ => None,
        }
    }
}

fn boxed(pipe: impl Read + Send + 'static) -> Box<dyn Read + Send> {
    Box::new(pipe)
}

/// Copies one output stream into the log and, while streaming, to the control plane.
struct Reader {
    outbox: Outbox,
    exec_id: ExecId,
    stream: Stream,
    output: Arc<Mutex<Output>>,
    done: Sender<()>,
}

impl Reader {
    fn run(self, mut pipe: Box<dyn Read + Send>) {
        let mut buf = vec![0; MAX_OUTPUT_CHUNK_BYTES];
        loop {
            let n = match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                // A terminal's master reads EIO once every slave descriptor is closed.
                #[cfg(unix)]
                Err(err) if err.raw_os_error() == Some(libc::EIO) => break,
                Err(err) => {
                    tracing::warn!("reading {} {:?} failed: {err}", self.exec_id, self.stream);
                    break;
                }
            };
            let mut output = lock(&self.output);
            if output.closed {
                continue;
            }
            if let Err(err) = output.log.append(&buf[..n]) {
                if output.failed_appends == 0 {
                    tracing::warn!("writing the log of {} failed: {err}", self.exec_id);
                }
                output.failed_appends += 1;
            }
            if output.streaming {
                self.outbox
                    .exec_output(self.exec_id.clone(), self.stream, buf[..n].to_vec());
            }
        }
        let _ = self.done.send(());
    }
}

/// Sends `net.bindDenied` for every bind the process's sandbox refused, rate-limited like
/// `net.denied` (20 a second, the rest counted in `dropped`), until the sandbox closes its end. Each report reaches it before the command learns of the refusal, so the
/// waiter's drain sends it before the exit.
fn report_binds(binds: &BindReports, outbox: &Outbox, exec_id: &ExecId, done: &Sender<()>) {
    let mut limiter = Limiter::default();
    while let Some(addr) = binds.next() {
        if let Admit::Send { dropped } = limiter.admit(Instant::now()) {
            outbox.net_bind_denied(NetBindDenied {
                exec_id: exec_id.clone(),
                host: addr.ip().to_string(),
                port: addr.port(),
                dropped,
            });
        }
    }
    let _ = done.send(());
}

/// Waits for a process to exit and reports it after its output.
struct Waiter {
    inner: Arc<Inner>,
    exec_id: ExecId,
    output: Arc<Mutex<Output>>,
    done: Receiver<()>,
    /// The readers that signal `done` when they finish: the output's, and the bind reports'.
    readers: usize,
    /// The command's cgroup, for `memoryBytes` and `processes` on Linux. Removed after the exit.
    cgroup: Option<process::Cgroup>,
    /// A system command's apt socket, closed at the exit, so what the command left running
    /// cannot install while its output drains.
    apt: Option<AptGate>,
}

impl Waiter {
    fn run(mut self, mut child: Child) {
        if let Err(err) = process::wait_exit(&child) {
            tracing::warn!("waiting for {} failed: {err}", self.exec_id);
        }
        // Closes a system command's apt socket.
        self.apt = None;
        if let Some(running) = lock(&self.inner.table).running(&self.exec_id, &self.output) {
            running.reaping = true;
        }
        let status = child.wait();
        self.drain();

        let mut table = lock(&self.inner.table);
        let ended = table.next_seq();
        let Some(entry) = table.execs.get_mut(&self.exec_id) else {
            return;
        };
        let Phase::Running(running) = &mut entry.phase else {
            return;
        };
        if let Some(timer) = running.timer.take() {
            timer.abort();
        }
        let out_of_memory = self
            .cgroup
            .as_ref()
            .is_some_and(process::Cgroup::out_of_memory);
        let exit = match (running.timed_out, status) {
            (true, _) => ExitStatus::TimedOut,
            (false, _) if out_of_memory => ExitStatus::MemoryLimit,
            (false, Ok(status)) => process::exit_status(status),
            (false, Err(err)) => {
                tracing::warn!("reaping {} failed: {err}", self.exec_id);
                ExitStatus::Exited { code: -1 }
            }
        };
        {
            let mut output = lock(&self.output);
            output.closed = true;
            if output.failed_appends > 1 {
                tracing::warn!(
                    "{} chunks of {} output were not logged",
                    output.failed_appends,
                    self.exec_id
                );
            }
            if let Log::Memory(log) = &mut output.log {
                log.shrink();
            }
            self.inner
                .outbox
                .exec_exit(self.exec_id.clone(), exit, output.log.total());
        }
        entry.phase = Phase::Exited {
            exit,
            output: self.output.clone(),
            ended,
        };
        self.inner.forget_oldest(&mut table);
    }

    /// Waits for every reader to reach the end of its pipe, or for the output to stay silent
    /// for [`DRAIN_IDLE`].
    fn drain(&self) {
        let mut open = self.readers;
        let mut seen = lock(&self.output).log.total();
        while open > 0 {
            match self.done.recv_timeout(DRAIN_IDLE) {
                Ok(()) => open -= 1,
                Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {
                    let total = lock(&self.output).log.total();
                    if total == seen {
                        return;
                    }
                    seen = total;
                }
            }
        }
    }
}

/// `argv[0]` as a path: absolute as given, or a bare name found in `env.PATH`.
fn resolve_program(program: &str, env: &BTreeMap<String, String>) -> Result<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if path.components().count() != 1 {
        return Err(Error::invalid_params(format!(
            "argv[0] {program:?} must be an absolute path or a bare name"
        )));
    }
    let search = env
        .iter()
        .find(|(key, _)| {
            if cfg!(windows) {
                key.eq_ignore_ascii_case("PATH")
            } else {
                *key == "PATH"
            }
        })
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    std::env::split_paths(search)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| candidates(&dir, program, env))
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| Error::not_found(format!("{program} is not in PATH {search:?}")))
}

#[cfg(unix)]
fn candidates(dir: &Path, program: &str, _env: &BTreeMap<String, String>) -> Vec<PathBuf> {
    vec![dir.join(program)]
}

/// `name`, then `name` with each `PATHEXT` extension, as `cmd.exe` searches.
#[cfg(windows)]
fn candidates(dir: &Path, program: &str, env: &BTreeMap<String, String>) -> Vec<PathBuf> {
    let extensions = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("PATHEXT"))
        .map_or(".COM;.EXE;.BAT;.CMD", |(_, value)| value.as_str());
    std::iter::once(dir.join(program))
        .chain(
            extensions
                .split(';')
                .filter(|ext| !ext.is_empty())
                .map(|ext| dir.join(format!("{program}{ext}"))),
        )
        .collect()
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Creates the process's log. A file log under a sandbox must be writable by its policy. With a
/// workload user, that user creates it.
fn open_log(spec: &LogSpec, confinement: &Confinement, workload: Option<&Workload>) -> Result<Log> {
    match spec {
        LogSpec::Memory { .. } => Ok(Log::Memory(MemoryLog::new(spec.limit_bytes()))),
        LogSpec::File { path, .. } => {
            if let Confinement::Sandboxed(policy) = confinement {
                check_log_writable(policy, path.as_path())?;
            }
            let (place, file) = match workload {
                None => log::Place::create(path.as_path())?,
                #[cfg(unix)]
                Some(workload) => workload.create_log(path)?,
                #[cfg(windows)]
                Some(workload) => match *workload {},
            };
            Ok(Log::File(FileLog::new(place, file, spec.limit_bytes())))
        }
    }
}

fn check_log_writable(policy: &ResolvedPolicy, path: &Path) -> Result<()> {
    let canonical = crate::policy::resolve_path(path);
    if policy.can_write(&canonical) {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::PermissionDenied,
        format!(
            "the policy does not let the log {} be written",
            path.display()
        ),
    ))
}

fn spawn_raw(
    program: &Path,
    argv: &Argv,
    cwd: &AbsPath,
    env: &BTreeMap<String, String>,
    io: Io,
    workload: Option<&Workload>,
    bounds: Bounds<'_>,
) -> Result<Spawned> {
    if !cwd.as_path().is_dir() {
        return Err(Error::not_found(format!(
            "cwd {} is not an existing directory",
            cwd.as_str()
        )));
    }
    let mut command = Command::new(program);
    #[cfg(unix)]
    std::os::unix::process::CommandExt::arg0(&mut command, argv.program());
    command.args(argv.args());
    // A workload user enters `cwd` itself, after becoming that user.
    if workload.is_none() {
        command.current_dir(cwd.as_path());
    }
    command
        .env_clear()
        .envs(env)
        .stdin(match io {
            Io::Pipes { stdin: true } => Stdio::piped(),
            Io::Pipes { stdin: false } | Io::Tty(_) => Stdio::null(),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::isolate(&mut command);
    #[cfg(unix)]
    process::default_interrupt(&mut command);
    #[cfg(unix)]
    process::limit(&mut command, bounds.limits);
    // Before `run_as`: the workload user may not write to the supervisor's cgroups.
    if let Some(cgroup) = bounds.cgroup {
        cgroup.join(&mut command);
    }
    #[cfg(unix)]
    let pty = io.terminal().map(process::pty::Pty::open).transpose()?;
    #[cfg(unix)]
    if let Some(pty) = &pty {
        pty.attach(&mut command, false)?;
    }
    #[cfg(unix)]
    if let (Some(workload), Some(pty)) = (workload, &pty) {
        pty.give_to(workload)?;
    }
    crate::identity::run_as(&mut command, workload, Some(cwd.as_path()))?;
    let child = process::spawn(command).map_err(|err| {
        let message = format!("cannot run {}: {err}", program.display());
        Error::new(Error::from(err).kind, message)
    })?;
    let spawned = adopt(child, bounds.limits)?;
    #[cfg(unix)]
    return Ok(Spawned {
        terminal: pty.map(|pty| pty.master),
        ..spawned
    });
    #[cfg(not(unix))]
    Ok(spawned)
}

/// Unix applied `limits` before exec ([`process::limit`]); a Windows Job Object takes them here.
fn adopt(mut child: Child, limits: &Limits) -> Result<Spawned> {
    #[cfg(unix)]
    let tree = {
        let _ = limits;
        Tree::adopt(&child)
    };
    #[cfg(windows)]
    let tree = Tree::adopt(&child, limits);
    match tree {
        Ok(tree) => Ok(Spawned {
            child,
            tree,
            terminal: None,
        }),
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(err.into())
        }
    }
}

/// Runs the sandbox helper with the job, an exec `op`, on its stdin, and waits on the status
/// pipe until the helper has exec'd the command or reported why it could not.
fn spawn_sandboxed(
    policy: &ResolvedPolicy,
    net: Option<NetPlan>,
    op: crate::helper::JobOp,
    io: Io,
    workload: Option<&Workload>,
    bounds: Bounds<'_>,
) -> Result<(Spawned, Held)> {
    let job = crate::helper::Job {
        policy: policy.clone(),
        op,
    };
    let exe = crate::helper::exe()?;
    let plan = crate::sandbox::Plan {
        policy,
        net,
        exe: &exe,
        #[cfg(target_os = "linux")]
        cgroup: bounds.cgroup.map(process::Cgroup::procs),
    };
    let prepared = crate::sandbox::prepare(&plan, &job)?;
    let frame = crate::helper::encode_job(&job);
    let spawned = spawn_helper(prepared.command, &frame, io, workload, bounds.limits)?;
    Ok((
        spawned,
        (prepared.placeholders, prepared.netns, prepared.binds),
    ))
}

/// With `tty`, the terminal is the helper's stdout and stderr and its controlling terminal; the
/// helper makes it the command's stdin too, once it has read the job.
/// `limits` apply to the helper too: with bubblewrap, to bubblewrap and the helper's own
/// processes in the sandbox.
#[cfg(unix)]
fn spawn_helper(
    mut command: Command,
    frame: &[u8],
    io: Io,
    workload: Option<&Workload>,
    limits: &Limits,
) -> Result<Spawned> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;

    let (mut status, status_writer) = std::io::pipe()?;
    let status_fd = status_writer.as_raw_fd();
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::isolate(&mut command);
    // SAFETY: install_status_fd is async-signal-safe and meant for exactly this closure.
    unsafe {
        command.pre_exec(move || crate::helper::install_status_fd(status_fd));
    }
    let pty = io.terminal().map(process::pty::Pty::open).transpose()?;
    if let Some(pty) = &pty {
        pty.attach(&mut command, true)?;
    }
    if let (Some(workload), Some(pty)) = (workload, &pty) {
        pty.give_to(workload)?;
    }
    crate::identity::run_as(&mut command, workload, None)?;
    process::limit(&mut command, limits);
    // bubblewrap's `--die-with-parent` would end it with the thread that started it.
    let child = process::spawn(command);
    drop(status_writer);
    let Spawned {
        mut child, tree, ..
    } = adopt(child?, limits)?;

    let mut pipe = child.stdin.take().expect("stdin is piped");
    // A helper that dies early closes its stdin; the status pipe then says why.
    let _ = pipe.write_all(frame);
    if let Io::Pipes { stdin: true } = io {
        child.stdin = Some(pipe);
    } else {
        drop(pipe);
    }
    let mut report = Vec::new();
    status.read_to_end(&mut report)?;
    if let Err(err) = crate::helper::parse_exec_status(&report) {
        let _ = child.wait();
        return Err(err);
    }
    Ok(Spawned {
        child,
        tree,
        terminal: pty.map(|pty| pty.master),
    })
}

/// Windows passes the status pipe's write end by duplicating it into the suspended helper and
/// telling it the handle in a preamble on stdin (`helper::STATUS_MAGIC`).
/// `limits` are not the broker's: they travel in the job, and the broker puts them on the job of
/// the runner, which runs the command (sandbox/windows/broker.rs).
#[cfg(windows)]
fn spawn_helper(
    mut command: Command,
    frame: &[u8],
    io: Io,
    workload: Option<&Workload>,
    limits: &Limits,
) -> Result<Spawned> {
    if let Some(workload) = workload {
        match *workload {}
    }
    let (mut status, status_writer) = std::io::pipe()?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process::isolate(&mut command);
    let mut child = command.spawn()?;
    let preamble = match process::status_preamble(&child, status_writer) {
        Ok(preamble) => preamble,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err.into());
        }
    };
    let _ = limits;
    let Spawned {
        mut child, tree, ..
    } = adopt(child, &Limits::default())?;

    let mut pipe = child.stdin.take().expect("stdin is piped");
    // A helper that dies early closes its stdin; the status pipe then says why.
    let _ = pipe
        .write_all(&preamble)
        .and_then(|()| pipe.write_all(frame));
    if let Io::Pipes { stdin: true } = io {
        child.stdin = Some(pipe);
    } else {
        drop(pipe);
    }
    let mut report = Vec::new();
    status.read_to_end(&mut report)?;
    if let Err(err) = crate::helper::parse_exec_status(&report) {
        let _ = child.wait();
        return Err(err);
    }
    Ok(Spawned {
        child,
        tree,
        terminal: None,
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, unix))]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::link::{ManualClock, NodeIdentity, Role, Session};

    fn manager(memory_budget: u64) -> ExecManager {
        let identity = NodeIdentity {
            node_id: "n_1".to_string(),
            installation_id: "tz4a98xxat96iws9zmbrgj3a".to_string(),
        };
        let (_session, outbox) = Session::new(Role::Node(identity), ManualClock::new(0));
        ExecManager::with_memory_budget(outbox, memory_budget)
    }

    fn id(text: &str) -> ExecId {
        ExecId::try_from(text).unwrap()
    }

    fn sh(exec_id: &str, script: &str, log_limit: u64) -> ExecStartParams {
        serde_json::from_value(json!({
            "execId": exec_id, "argv": ["/bin/sh", "-c", script], "cwd": "/", "env": {},
            "log": { "kind": "memory", "limitBytes": log_limit },
        }))
        .unwrap()
    }

    async fn exited(manager: &ExecManager, exec_id: &str) {
        for _ in 0..500 {
            let done = manager
                .list()
                .iter()
                .any(|s| s.exec_id.as_str() == exec_id && s.state != ExecState::Running);
            if done {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{exec_id} did not exit");
    }

    async fn log_of(manager: &ExecManager, exec_id: &str) -> (Vec<u8>, u64, usize) {
        let params = ExecLogParams {
            exec_id: id(exec_id),
            offset: 0,
            length: None,
        };
        let read = manager.log(params).await.unwrap();
        (read.data.into_vec(), read.total_bytes, read.retained.len())
    }

    #[tokio::test]
    async fn memory_logs_share_a_budget_and_the_oldest_exited_ones_go_first() {
        let manager = manager(45);
        let raw = || Confinement::Raw;
        manager
            .start(sh("a", "sleep 30", 16), raw(), None, None, None)
            .await
            .unwrap();
        manager
            .start(sh("d", "printf 0123456789", 16), raw(), None, None, None)
            .await
            .unwrap();
        exited(&manager, "d").await;
        manager
            .start(sh("e", "printf abcdefghij", 16), raw(), None, None, None)
            .await
            .unwrap();
        exited(&manager, "e").await;

        let err = manager
            .start(sh("big", "true", 30), raw(), None, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::TooLarge);
        manager
            .start(sh("f", "true", 16), raw(), None, None, None)
            .await
            .unwrap();
        assert_eq!(log_of(&manager, "d").await, (vec![], 10, 0));
        assert_eq!(log_of(&manager, "e").await, (b"abcdefghij".to_vec(), 10, 1));

        let err = manager
            .start(sh("big", "true", 1), raw(), None, None, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::AlreadyExists);
        manager.kill(&id("a"), KillSignal::Kill).unwrap();
        exited(&manager, "a").await;
    }

    #[tokio::test]
    async fn the_helper_status_pipe_reports_a_failed_exec_and_a_successful_one() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status");
        let reported = Error::not_found("no such program");
        std::fs::write(&status, crate::wire::to_cbor(&reported)).unwrap();
        let mut fails = Command::new("/bin/sh");
        fails.args(["-c", r#"cat "$0" >&3; exit 127"#]).arg(&status);
        let err = spawn_helper(
            fails,
            b"frame",
            Io::Pipes { stdin: false },
            None,
            &Limits::default(),
        )
        .err()
        .unwrap();
        assert_eq!(err, Error::not_found("no such program"));

        let mut execs = Command::new("/bin/sh");
        execs.args(["-c", "exec 3>&-; dd bs=5 count=1 >/dev/null 2>&1; exec cat"]);
        let Spawned { mut child, .. } = spawn_helper(
            execs,
            b"frame",
            Io::Pipes { stdin: true },
            None,
            &Limits::default(),
        )
        .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"after the job")
            .unwrap();
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "after the job");
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn bare_names_are_found_in_the_given_path_only() {
        let env = |path: &str| BTreeMap::from([("PATH".to_string(), path.to_string())]);
        assert_eq!(
            resolve_program("sh", &env("/nonexistent:/bin")).unwrap(),
            PathBuf::from("/bin/sh")
        );
        assert_eq!(
            resolve_program("sh", &BTreeMap::new()).unwrap_err(),
            Error::not_found("sh is not in PATH \"\"")
        );
        assert_eq!(
            resolve_program("sh", &env("relative:/nonexistent"))
                .unwrap_err()
                .kind,
            ErrorKind::NotFound
        );
        assert_eq!(
            resolve_program("bin/sh", &env("/")).unwrap_err().kind,
            ErrorKind::InvalidParams
        );
        assert_eq!(
            resolve_program("/no/such", &env("/bin")).unwrap(),
            PathBuf::from("/no/such")
        );
    }
}
