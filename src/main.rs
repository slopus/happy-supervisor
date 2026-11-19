use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use happy_supervisor::client::{self, RunExit};
use happy_supervisor::identity::Identity;
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
        /// The single-use join token.
        #[arg(long)]
        token: String,
        /// The node name. Defaults to the hostname.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Connect to the control plane and serve it until revoked or interrupted.
    Run {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Run every command, file operation and watch as this user (Unix, supervisor running
        /// as root). Overrides `private/workload-user` in the state directory.
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
    /// Print this node's NodeInfo as JSON.
    Info {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
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

async fn run(command: Command) -> happy_supervisor::Result<ExitCode> {
    match command {
        Command::Join {
            url,
            token,
            name,
            state_dir,
        } => {
            let state = StateDir::open(state_dir)?;
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
        } => match client::run(StateDir::open(state_dir)?.with_workload_user(workload_user)).await?
        {
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
            let state = StateDir::open(state_dir)?.with_workload_user(workload_user);
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
        Command::Info { state_dir } => {
            let state = StateDir::open(state_dir)?;
            let info = tokio::task::spawn_blocking(move || {
                let installation_id = state.installation_id()?;
                let name = state.credentials()?.map(|c| c.name);
                let sandbox = sandbox::probe();
                let identity = Identity::resolve(state.workload_user()?.as_deref())?;
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
