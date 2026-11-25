use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use happy_supervisor::client::{self, RunExit};
use happy_supervisor::identity::{self, Identity};
use happy_supervisor::state::StateDir;
use happy_supervisor::{Error, ErrorKind, enroll, helper, node_info, sandbox, serve};

/// The argument that makes this binary an isolated command's SSH `ProxyCommand` (proxy.md).
const CONNECT_ARG: &str = "__connect";

#[derive(Parser)]
#[command(
    version,
    about = "Runs commands and file operations for a trusted control plane"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Exchange a join token for node credentials.
    Join {
        /// The full join endpoint the control plane handed out with the token.
        #[arg(long)]
        url: String,
        /// A file holding the single-use join token, or `-` for one line of stdin. Without it, the
        /// token comes from `HAPPY_JOIN_TOKEN`. It is never an argument, which `ps` would show.
        #[arg(long)]
        token_file: Option<String>,
        /// The node name. Defaults to the hostname.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// As for `run`.
        #[arg(long)]
        workload_user: Option<String>,
    },
    /// Connect to the control plane and serve it until revoked or interrupted.
    Run {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Run every command, file operation and watch as this user (Unix, supervisor running
        /// as root). Overrides `private/workload-user` in the state directory. Required on Linux
        /// when the supervisor runs as root.
        #[arg(long)]
        workload_user: Option<String>,
    },
    /// Listen for a control plane instead of dialing one (docs/serve.md). Prints
    /// `listening <addr>` once connections are accepted.
    Serve {
        /// `IP:PORT` (port 0 picks one) or `unix:PATH`.
        #[arg(long)]
        listen: String,
        /// A file holding the token clients must present, or `-` for one line of stdin.
        #[arg(long)]
        token_file: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// As for `run`.
        #[arg(long)]
        workload_user: Option<String>,
    },
    /// Create the Windows sandbox's accounts and firewall filters. Run once, as an
    /// administrator, as the account that runs the supervisor.
    #[cfg(windows)]
    InstallSandbox(sandbox::windows::InstallArgs),
    /// Enable, disable or show system access, `{"mode": "system"}`: commands and file operations
    /// as the account that installs system-wide software (docs/policy.md, System access).
    /// Enabling and disabling need root.
    System {
        #[command(subcommand)]
        action: SystemAction,
        #[arg(long, global = true)]
        state_dir: Option<PathBuf>,
    },
    /// Print this node's NodeInfo as JSON.
    Info {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// As for `run`.
        #[arg(long)]
        workload_user: Option<String>,
    },
}

#[derive(Subcommand)]
enum SystemAction {
    /// Run system access as `--user`, else root on Linux and Homebrew's owner on macOS (root
    /// without Homebrew).
    Enable {
        #[arg(long)]
        user: Option<String>,
    },
    /// Refuse system access from the next request on.
    Disable,
    /// Print the account system access runs as, or that it is disabled.
    Status,
}

fn main() -> ExitCode {
    // The helper must start before any runtime or thread exists (docs/architecture.md).
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == helper::HELPER_ARG)
    {
        helper::main();
    }
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == CONNECT_ARG)
    {
        return happy_supervisor::connect::main(std::env::args().skip(2));
    }
    let cli = Cli::parse();
    // Before the runtime starts any thread: forking is safe only while there is one.
    #[cfg(unix)]
    if matches!(cli.command, Command::Run { .. } | Command::Serve { .. }) {
        happy_supervisor::init::reap_as_pid1();
    }
    #[cfg(windows)]
    if let Command::InstallSandbox(args) = cli.command {
        return sandbox::windows::install_main(args);
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("happy-supervisor: cannot start the runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli.command)) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("happy-supervisor: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Opens the state directory and checks, before anything else runs, that the supervisor may
/// run its work as the user it would (identity.rs). Then, before it starts any process, takes
/// over a cgroup delegated to it for the limits (process/cgroups.rs).
fn open_state(
    dir: Option<PathBuf>,
    workload_user: Option<String>,
) -> happy_supervisor::Result<StateDir> {
    let state = StateDir::open(dir)?.with_workload_user(workload_user);
    Identity::resolve(state.workload_user()?.as_deref())?;
    happy_supervisor::init_limits();
    Ok(state)
}

/// The join token, from `--token-file` or else `HAPPY_JOIN_TOKEN`.
fn join_token(file: Option<&str>) -> happy_supervisor::Result<String> {
    if let Some(file) = file {
        return serve::read_token(file);
    }
    match std::env::var("HAPPY_JOIN_TOKEN") {
        Ok(token) if !token.is_empty() => Ok(token),
        _ => Err(Error::invalid_params(
            "join needs the join token in HAPPY_JOIN_TOKEN, or --token-file (- for stdin)",
        )),
    }
}

async fn run(command: Command) -> happy_supervisor::Result<ExitCode> {
    match command {
        Command::Join {
            url,
            token_file,
            name,
            state_dir,
            workload_user,
        } => {
            let token = join_token(token_file.as_deref())?;
            let state = open_state(state_dir, workload_user)?;
            let credentials = enroll::join(&url, &token, name, &state).await?;
            println!(
                "joined as {}, endpoint {}",
                credentials.node_id, credentials.endpoint
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            state_dir,
            workload_user,
        } => match client::run(open_state(state_dir, workload_user)?).await? {
            RunExit::Revoked => {
                eprintln!("happy-supervisor: the control plane revoked this node's credential");
                Ok(ExitCode::from(3))
            }
            RunExit::Interrupted => Ok(ExitCode::SUCCESS),
        },
        Command::Serve {
            listen,
            token_file,
            state_dir,
            workload_user,
        } => {
            let listen = listen.parse()?;
            let token = serve::read_token(&token_file)?;
            let state = open_state(state_dir, workload_user)?;
            let listening = |addr: String| {
                use std::io::Write as _;
                println!("listening {addr}");
                let _ = std::io::stdout().flush();
            };
            serve::serve_until(state, listen, token, listening, client::shutdown_signal()).await?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(windows)]
        Command::InstallSandbox(_) => unreachable!("handled before the runtime starts"),
        Command::System { action, state_dir } => {
            let state = StateDir::existing(state_dir)?;
            match action {
                SystemAction::Enable { user } => {
                    let access = identity::enable_system(&state, user)?;
                    println!("system access enabled: it runs as {}", access.user);
                }
                SystemAction::Disable => {
                    state.store_system(None)?;
                    println!("system access disabled");
                }
                SystemAction::Status => match state.system()? {
                    Some(access) => println!("system access enabled: it runs as {}", access.user),
                    None => println!("system access disabled"),
                },
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Info {
            state_dir,
            workload_user,
        } => {
            let state = open_state(state_dir, workload_user)?;
            let info = tokio::task::spawn_blocking(move || {
                let installation_id = state.installation_id()?;
                let name = state.credentials()?.map(|c| c.name);
                let sandbox = sandbox::probe();
                let identity = Identity::open(&state)?;
                Ok::<_, Error>(node_info::collect(
                    &installation_id,
                    name.as_deref(),
                    &sandbox,
                    &identity,
                ))
            })
            .await
            .map_err(|err| Error::new(ErrorKind::Io, err.to_string()))??;
            println!(
                "{}",
                serde_json::to_string_pretty(&info).expect("NodeInfo serializes")
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
