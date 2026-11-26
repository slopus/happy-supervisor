//! Running the supervisor (docs/boot.md, Running): one child at a time, verified before each
//! start, restarted with backoff when it exits on its own, and replaced on its request by
//! another version, which becomes current only once it connects. One that exits or does not
//! connect in time is stopped and the version before it started again.

use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{ChildStdin, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::channel::{FromSupervisor, State, Status, ToSupervisor};
use crate::fetch::{Fetcher, Phase};
use crate::release;
use crate::store::{self, Store};

/// Set in the supervisor's environment to boot's process ID: the supervisor speaks the channel
/// on its stdin and stdout, and accepts `node.upgrade`.
pub const BOOT_ENV: &str = "HAPPY_SUPERVISOR_BOOT";
/// The supervisor's exit code once the control plane revoked its credential, which boot passes
/// on (api.md, Connection).
pub const REVOKED: i32 = 3;

pub struct Config {
    pub store: Store,
    pub fetcher: Fetcher,
    /// The supervisor's arguments, as `run --state-dir <dir>`.
    pub args: Vec<OsString>,
    /// How long a new version has to connect before boot goes back to the one before.
    pub connect_within: Duration,
    /// How long the supervisor has to exit once asked to.
    pub stop_within: Duration,
    /// The first and the longest wait before restarting a supervisor that exited; a run of
    /// `steady` resets it.
    pub backoff: (Duration, Duration),
    pub steady: Duration,
}

impl Config {
    pub fn new(store: Store, fetcher: Fetcher, args: Vec<OsString>) -> Config {
        Config {
            store,
            fetcher,
            args,
            connect_within: Duration::from_secs(120),
            stop_within: Duration::from_secs(10),
            backoff: (Duration::from_secs(1), Duration::from_secs(30)),
            steady: Duration::from_secs(60),
        }
    }
}

enum Event {
    /// A line of a child's stdout, by its generation.
    Line(u64, String),
    Phase(String, Phase),
    Fetched(String, Result<PathBuf, String>),
}

struct Child {
    process: std::process::Child,
    stdin: Option<ChildStdin>,
    generation: u64,
    started: Instant,
}

/// A new version starting: it becomes current when it connects by `deadline`.
struct Candidate {
    version: String,
    deadline: Instant,
    /// The version to go back to.
    fallback: String,
}

struct Boot {
    config: Arc<Config>,
    events: mpsc::Sender<Event>,
    status: Status,
    generation: u64,
    child: Option<Child>,
    candidate: Option<Candidate>,
    /// The version being fetched, and one asked for meanwhile.
    fetching: Option<String>,
    pending: Option<String>,
    backoff: Duration,
    restart_at: Option<Instant>,
}

/// Runs the supervisor until it exits with [`REVOKED`], which is returned; `Err` when no
/// verified build can be started at all.
pub fn run(config: Config) -> Result<i32, String> {
    let store = &config.store;
    let io = |err: std::io::Error| format!("{}: {err}", store.dir().display());
    let mut state = store.state().map_err(io)?;
    let current = match state.current.clone() {
        Some(current) => current,
        None => {
            let latest = config.fetcher.latest()?;
            config.fetcher.fetch(store, &latest, |_| {})?;
            state.current = Some(latest.clone());
            store.save(&state).map_err(io)?;
            latest
        }
    };
    let (events, incoming) = mpsc::channel();
    let mut boot = Boot {
        events,
        status: Status {
            boot_version: env!("CARGO_PKG_VERSION"),
            running: Some(current),
            previous: state.previous,
            target: None,
            state: State::Idle,
            error: None,
            restarts: 0,
            last_exit: None,
        },
        backoff: config.backoff.0,
        config: Arc::new(config),
        generation: 0,
        child: None,
        candidate: None,
        fetching: None,
        pending: None,
        restart_at: None,
    };
    boot.start()?;
    loop {
        match incoming.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => boot.handle(event),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => unreachable!("boot holds a sender"),
        }
        if let Some(code) = boot.poll()? {
            return Ok(code);
        }
    }
}

impl Boot {
    fn running(&self) -> &str {
        self.status.running.as_deref().expect("a version runs")
    }

    fn send_status(&mut self) {
        let line = ToSupervisor::Status(&self.status).line();
        if let Some(stdin) = self.child.as_mut().and_then(|child| child.stdin.as_mut()) {
            // A supervisor that is gone or does not read is noticed when it exits.
            let _ = stdin.write_all(line.as_bytes());
        }
    }

    /// Verifies `running` and starts it. A copy that no longer verifies is downloaded again.
    fn start(&mut self) -> Result<(), String> {
        let version = self.running().to_owned();
        let config = &self.config;
        let path = match config.store.verified(&version) {
            Ok(path) => path,
            Err(err) => {
                eprintln!("happy-supervisor-boot: {err}; downloading {version} again");
                config.fetcher.fetch(&config.store, &version, |_| {})?;
                config.store.verified(&version)?
            }
        };
        self.generation += 1;
        let generation = self.generation;
        let mut process = Command::new(&path)
            .args(&config.args)
            .env(BOOT_ENV, std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("{version}: cannot start {}: {err}", path.display()))?;
        let stdout = process.stdout.take().expect("stdout is piped");
        let events = self.events.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if events.send(Event::Line(generation, line)).is_err() {
                    break;
                }
            }
        });
        self.child = Some(Child {
            stdin: process.stdin.take(),
            process,
            generation,
            started: Instant::now(),
        });
        self.send_status();
        Ok(())
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Line(generation, line) => {
                if self.child.as_ref().map(|child| child.generation) != Some(generation) {
                    return;
                }
                match FromSupervisor::parse(&line) {
                    Some(FromSupervisor::Upgrade { version }) => self.upgrade(version),
                    Some(FromSupervisor::Connected {}) => self.connected(),
                    // Anything else the supervisor prints is its own output.
                    None => println!("{line}"),
                }
            }
            Event::Phase(version, phase) => {
                let state = match phase {
                    Phase::Downloading => State::Downloading,
                    Phase::Verifying => State::Verifying,
                };
                if self.fetching.as_deref() == Some(&version)
                    && self.pending.is_none()
                    && self.status.state != state
                {
                    self.status.state = state;
                    self.send_status();
                }
            }
            Event::Fetched(version, result) => {
                self.fetching = None;
                if let Some(pending) = self.pending.take().filter(|p| *p != version) {
                    self.fetch(pending);
                    return;
                }
                match result {
                    Ok(_) => self.switch(version),
                    Err(err) => self.fail(err),
                }
            }
        }
    }

    fn fail(&mut self, error: String) {
        eprintln!("happy-supervisor-boot: {error}");
        self.status.state = State::Failed;
        self.status.error = Some(error);
        self.send_status();
    }

    fn upgrade(&mut self, version: String) {
        if let Err(err) = release::check_version(&version) {
            return self.fail(err);
        }
        self.status.target = Some(version.clone());
        self.status.error = None;
        if self.fetching.is_some() {
            self.pending = Some(version);
            self.send_status();
            return;
        }
        if version == self.running() && self.candidate.is_none() {
            self.status.target = None;
            self.status.state = State::Idle;
            self.send_status();
            return;
        }
        self.fetch(version);
    }

    fn fetch(&mut self, version: String) {
        self.fetching = Some(version.clone());
        self.status.target = Some(version.clone());
        self.status.state = State::Downloading;
        self.send_status();
        let config = self.config.clone();
        let events = self.events.clone();
        std::thread::spawn(move || {
            let result = config.fetcher.fetch(&config.store, &version, |phase| {
                let _ = events.send(Event::Phase(version.clone(), phase));
            });
            let _ = events.send(Event::Fetched(version, result));
        });
    }

    /// Stops the running version and starts `version` in its place, until it connects.
    fn switch(&mut self, version: String) {
        self.status.state = State::Starting;
        self.send_status();
        self.stop();
        let running = self.status.running.replace(version.clone());
        // A candidate replaced before it connected never became the one to go back to.
        let fallback = match self.candidate.take() {
            Some(candidate) => candidate.fallback,
            None => running.expect("a version ran"),
        };
        self.candidate = Some(Candidate {
            version,
            deadline: Instant::now() + self.config.connect_within,
            fallback,
        });
        self.status.restarts = 0;
        self.status.last_exit = None;
        if let Err(err) = self.start() {
            self.roll_back(err);
        }
    }

    fn connected(&mut self) {
        self.backoff = self.config.backoff.0;
        let Some(candidate) = self.candidate.take() else {
            return;
        };
        let store = &self.config.store;
        let state = store::State {
            current: Some(candidate.version.clone()),
            previous: Some(candidate.fallback.clone()),
        };
        if let Err(err) = store.save(&state) {
            // It runs, but would not after a restart of boot: say so, and keep it running.
            eprintln!(
                "happy-supervisor-boot: cannot record {}: {err}",
                candidate.version
            );
        }
        store.prune(&[&candidate.version, &candidate.fallback]);
        self.status.previous = Some(candidate.fallback);
        if self.pending.is_none() && self.fetching.is_none() {
            self.status.target = None;
            self.status.state = State::Idle;
        }
        self.send_status();
    }

    /// The candidate failed for `reason`: stops it and starts the version before it.
    fn roll_back(&mut self, reason: String) {
        let candidate = self.candidate.take().expect("a candidate");
        self.stop();
        self.status.running = Some(candidate.fallback);
        self.status.state = State::Failed;
        self.status.error = Some(reason.clone());
        eprintln!(
            "happy-supervisor-boot: {reason}; starting {} again",
            self.running()
        );
        if let Err(err) = self.start() {
            eprintln!("happy-supervisor-boot: {err}");
            self.restart_at = Some(Instant::now() + self.backoff);
        }
    }

    /// Asks the child to exit: its stdin closes, after every status line sent, and on Unix
    /// `SIGTERM` follows halfway through `stop_within`, for a supervisor that does not read it.
    /// Kills it when it has not exited by then.
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        drop(child.stdin.take());
        let wait = |child: &mut Child, within: Duration| {
            let deadline = Instant::now() + within;
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.process.try_wait() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        };
        if wait(&mut child, self.config.stop_within / 2) {
            return;
        }
        #[cfg(unix)]
        if let Ok(pid) = i32::try_from(child.process.id()) {
            // SAFETY: kill has no memory effects; the child is not reaped yet, so the PID is its.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if wait(&mut child, self.config.stop_within / 2) {
            return;
        }
        let _ = child.process.kill();
        let _ = child.process.wait();
    }

    /// Notices an exited child and deadlines. `Some(code)` when boot should exit.
    fn poll(&mut self) -> Result<Option<i32>, String> {
        let now = Instant::now();
        if let Some(candidate) = &self.candidate
            && now >= candidate.deadline
        {
            let reason = format!(
                "{} did not connect within {} s",
                candidate.version,
                self.config.connect_within.as_secs()
            );
            self.roll_back(reason);
        }
        if let Some(child) = &mut self.child {
            let Some(exit) = child.process.try_wait().map_err(|err| err.to_string())? else {
                return Ok(None);
            };
            let ran = child.started.elapsed();
            self.child = None;
            if let Some(candidate) = &self.candidate {
                let reason = format!(
                    "{} {} before it connected",
                    candidate.version,
                    describe(exit)
                );
                self.roll_back(reason);
                return Ok(None);
            }
            if exit.code() == Some(REVOKED) {
                return Ok(Some(REVOKED));
            }
            eprintln!(
                "happy-supervisor-boot: {} {}",
                self.running(),
                describe(exit)
            );
            self.status.restarts += 1;
            self.status.last_exit = Some(describe(exit));
            if ran >= self.config.steady {
                self.backoff = self.config.backoff.0;
            }
            self.restart_at = Some(now + self.backoff);
            self.backoff = (self.backoff * 2).min(self.config.backoff.1);
            return Ok(None);
        }
        if let Some(at) = self.restart_at
            && now >= at
        {
            self.restart_at = None;
            if let Err(err) = self.start() {
                eprintln!("happy-supervisor-boot: {err}");
                self.restart_at = Some(now + self.backoff);
                self.backoff = (self.backoff * 2).min(self.config.backoff.1);
            }
        }
        Ok(None)
    }
}

/// How a child exited, as status reports it.
fn describe(exit: ExitStatus) -> String {
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&exit) {
        return format!("killed by signal {signal}");
    }
    match exit.code() {
        Some(code) => format!("exited with code {code}"),
        None => "exited".to_owned(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::fetch::tests::Server;
    use crate::testkit::Signer;

    /// A release server, a boot directory, and fake supervisors: shell scripts that log each
    /// status line they read to `log`.
    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        server: Server,
        signer: Signer,
    }

    impl Fixture {
        fn new() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            Fixture {
                root: dir.path().to_owned(),
                _dir: dir,
                server: Server::start(),
                signer: Signer::new(),
            }
        }

        /// Releases `version` as a script that runs `body` with `$LOG` and `$DIR` set.
        fn release(&self, version: &str, body: &str) {
            let script = format!(
                "#!/bin/sh\nLOG='{root}/log' DIR='{root}'\n{body}\n",
                root = self.root.display()
            );
            self.server
                .release(&self.signer, version, script.as_bytes());
        }

        fn config(&self) -> Config {
            let store = Store::open(self.root.join("boot"), vec![self.signer.public()]).unwrap();
            let fetcher = Fetcher::new(&self.server.base).unwrap();
            let mut config = Config::new(store, fetcher, vec!["run".into()]);
            config.connect_within = Duration::from_secs(2);
            config.stop_within = Duration::from_secs(2);
            config.backoff = (Duration::from_millis(10), Duration::from_millis(100));
            config
        }

        /// Installs `version` as current, as `happy-supervisor-boot install` does.
        fn install(&self, config: &Config, version: &str) {
            config
                .fetcher
                .fetch(&config.store, version, |_| {})
                .unwrap();
            config
                .store
                .save(&store::State {
                    current: Some(version.into()),
                    previous: None,
                })
                .unwrap();
        }

        fn log(&self) -> Vec<String> {
            let log = std::fs::read_to_string(self.root.join("log")).unwrap_or_default();
            log.lines().map(str::to_owned).collect()
        }
    }

    /// Says it connected, asks once for `version`, then logs status lines; exits 3 on one that
    /// matches `until`.
    fn asks_for(version: &str, until: &str) -> String {
        format!(
            r#"echo '{{"connected":{{}}}}'
if [ ! -e "$DIR/asked" ]; then : > "$DIR/asked"; echo '{{"upgrade":{{"version":"{version}"}}}}'; fi
while read -r line; do echo "1.0.0 $line" >> "$LOG"; case "$line" in *{until}*) exit 3;; esac; done"#
        )
    }

    fn status(fields: &str) -> String {
        format!(r#"{{"status":{{"bootVersion":"0.1.0",{fields}}}}}"#)
    }

    fn run_boot(config: Config) -> i32 {
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || done.send(run(config)));
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("boot finishes")
            .unwrap()
    }

    #[test]
    fn an_upgrade_downloads_verifies_starts_and_keeps_the_version_that_connects() {
        let f = Fixture::new();
        f.release("1.0.0", &asks_for("2.0.0", "never"));
        f.release(
            "2.0.0",
            r#"echo '{"connected":{}}'
while read -r line; do echo "2.0.0 $line" >> "$LOG"; case "$line" in *'"state":"idle"'*) exit 3;; esac; done"#,
        );
        let config = f.config();
        f.install(&config, "1.0.0");
        let boot = f.root.join("boot");
        assert_eq!(run_boot(config), REVOKED);
        assert_eq!(
            f.log(),
            [
                format!(
                    "1.0.0 {}",
                    status(
                        r#""running":"1.0.0","previous":null,"target":null,"state":"idle","restarts":0"#
                    )
                ),
                format!(
                    "1.0.0 {}",
                    status(
                        r#""running":"1.0.0","previous":null,"target":"2.0.0","state":"downloading","restarts":0"#
                    )
                ),
                format!(
                    "1.0.0 {}",
                    status(
                        r#""running":"1.0.0","previous":null,"target":"2.0.0","state":"verifying","restarts":0"#
                    )
                ),
                format!(
                    "1.0.0 {}",
                    status(
                        r#""running":"1.0.0","previous":null,"target":"2.0.0","state":"starting","restarts":0"#
                    )
                ),
                format!(
                    "2.0.0 {}",
                    status(
                        r#""running":"2.0.0","previous":null,"target":"2.0.0","state":"starting","restarts":0"#
                    )
                ),
                format!(
                    "2.0.0 {}",
                    status(
                        r#""running":"2.0.0","previous":"1.0.0","target":null,"state":"idle","restarts":0"#
                    )
                ),
            ]
        );
        assert_eq!(
            std::fs::read_to_string(boot.join("state.json")).unwrap(),
            r#"{"current":"2.0.0","previous":"1.0.0"}"#
        );
    }

    fn rolls_back(version: &str, body: &str, error: &str) {
        let f = Fixture::new();
        f.release("1.0.0", &asks_for(version, "'\"state\":\"failed\"'"));
        f.release(version, body);
        let config = f.config();
        f.install(&config, "1.0.0");
        assert_eq!(run_boot(config), REVOKED);
        let log = f.log();
        assert_eq!(
            log.last().unwrap(),
            &format!(
                "1.0.0 {}",
                status(&format!(
                    r#""running":"1.0.0","previous":null,"target":"{version}","state":"failed","error":"{error}","restarts":0"#
                ))
            )
        );
        assert_eq!(
            std::fs::read_to_string(f.root.join("boot/state.json")).unwrap(),
            r#"{"current":"1.0.0","previous":null}"#
        );
    }

    #[test]
    fn a_version_that_exits_before_it_connects_is_replaced_by_the_one_before() {
        rolls_back(
            "3.0.0",
            "exit 1",
            "3.0.0 exited with code 1 before it connected",
        );
    }

    #[test]
    fn a_version_that_does_not_connect_in_time_is_replaced_by_the_one_before() {
        rolls_back(
            "4.0.0",
            "while read -r line; do :; done",
            "4.0.0 did not connect within 2 s",
        );
    }

    #[test]
    fn an_unsigned_build_is_never_started() {
        let f = Fixture::new();
        f.release("1.0.0", &asks_for("5.0.0", "'\"state\":\"failed\"'"));
        f.release("5.0.0", "echo started > \"$DIR/5\"");
        f.server.put(
            &format!("releases/5.0.0/{}", release::FILE),
            "#!/bin/sh\necho started > \"$DIR/5\"\n# changed",
        );
        let config = f.config();
        f.install(&config, "1.0.0");
        assert_eq!(run_boot(config), REVOKED);
        assert_eq!(
            f.log().last().unwrap(),
            &format!(
                "1.0.0 {}",
                status(&format!(
                    r#""running":"1.0.0","previous":null,"target":"5.0.0","state":"failed","error":"5.0.0: the downloaded {} is not the signed build","restarts":0"#,
                    release::FILE
                ))
            )
        );
        assert!(!f.root.join("5").exists());
        assert!(!f.root.join("boot/versions/5.0.0").exists());
    }

    #[test]
    fn a_crash_restarts_a_build_verified_again_and_downloaded_again_when_changed() {
        let f = Fixture::new();
        // The first run changes its own file and crashes; the second sees the restart counted.
        f.release(
            "1.0.0",
            r#"if [ ! -e "$DIR/crashed" ]; then : > "$DIR/crashed"; echo '# changed' >> "$0"; exit 1; fi
echo '{"connected":{}}'
while read -r line; do echo "1.0.0 $line" >> "$LOG"; exit 3; done"#,
        );
        let config = f.config();
        f.install(&config, "1.0.0");
        let binary = f.root.join("boot/versions/1.0.0").join(store::BINARY);
        assert_eq!(run_boot(config), REVOKED);
        assert_eq!(
            f.log(),
            [format!(
                "1.0.0 {}",
                status(
                    r#""running":"1.0.0","previous":null,"target":null,"state":"idle","restarts":1,"lastExit":"exited with code 1""#
                )
            )]
        );
        // Downloaded again: the file is as released, without the line the first run added.
        let script = std::fs::read_to_string(&binary).unwrap();
        assert!(script.ends_with("exit 3; done\n"), "{script}");
    }
}
