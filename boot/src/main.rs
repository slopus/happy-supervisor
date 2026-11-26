use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use happy_supervisor_boot::fetch::{DEFAULT_BASE, Fetcher};
use happy_supervisor_boot::release::{self, release_keys};
use happy_supervisor_boot::store::{State, Store};
use happy_supervisor_boot::supervise::{self, Config};

const USAGE: &str = "usage:
  happy-supervisor-boot run --dir <boot dir> [--base <url>] -- <supervisor arguments>...
      Run the supervisor until the control plane revokes it (exit code 3).
  happy-supervisor-boot install --dir <boot dir> [--base <url>] [--version <version>]
      Download, verify and make current a version (default: the latest release), and print
      the path of its binary.
  happy-supervisor-boot --version";

struct Args {
    command: String,
    dir: PathBuf,
    base: String,
    version: Option<String>,
    rest: Vec<OsString>,
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let command = args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .ok_or(USAGE)?;
    let (mut dir, mut base, mut version) = (None, DEFAULT_BASE.to_owned(), None);
    let mut rest = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| format!("{} needs a value", arg.to_string_lossy()))
        };
        match arg.to_str() {
            Some("--dir") => dir = Some(PathBuf::from(value()?)),
            Some("--base") => base = value()?,
            Some("--version") if command == "install" => version = Some(value()?),
            Some("--") if command == "run" => {
                rest = args.by_ref().collect();
            }
            _ => {
                return Err(format!(
                    "unknown argument {}\n{USAGE}",
                    arg.to_string_lossy()
                ));
            }
        }
    }
    let dir = dir.ok_or_else(|| format!("--dir is required\n{USAGE}"))?;
    Ok(Args {
        command,
        dir,
        base,
        version,
        rest,
    })
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    if args.peek().is_some_and(|arg| arg == "--version") {
        println!("happy-supervisor-boot {}", happy_supervisor_boot::VERSION);
        return ExitCode::SUCCESS;
    }
    match parse(args).and_then(run) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("happy-supervisor-boot: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<ExitCode, String> {
    let store = Store::open(args.dir.clone(), release_keys())
        .map_err(|err| format!("{}: {err}", args.dir.display()))?;
    let fetcher = Fetcher::new(&args.base)?;
    match args.command.as_str() {
        "run" => {
            if args.rest.is_empty() {
                return Err(format!("run needs the supervisor's arguments\n{USAGE}"));
            }
            let code = supervise::run(Config::new(store, fetcher, args.rest))?;
            Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
        }
        "install" => {
            let version = match args.version {
                Some(version) => version,
                None => fetcher.latest()?,
            };
            release::check_version(&version)?;
            let path = fetcher.fetch(&store, &version, |_| {})?;
            let io = |err: std::io::Error| format!("{}: {err}", args.dir.display());
            let state = store.state().map_err(io)?;
            let previous = match state.current {
                Some(current) if current != version => Some(current),
                _ => state.previous,
            };
            store
                .save(&State {
                    current: Some(version.clone()),
                    previous: previous.clone(),
                })
                .map_err(io)?;
            let keep: Vec<&str> = [Some(version.as_str()), previous.as_deref()]
                .into_iter()
                .flatten()
                .collect();
            store.prune(&keep);
            println!("{}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(USAGE.to_owned()),
    }
}
