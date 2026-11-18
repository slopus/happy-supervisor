use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use happy_supervisor::client::{self, RunExit};
use happy_supervisor::dispatch::Node;
use happy_supervisor::state::StateDir;
use happy_supervisor::{enroll, helper};

/// The argument that makes this binary the sandbox helper.
const HELPER_ARG: &str = "__sandbox";

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
        /// The control plane, `https://host[:port]`.
        #[arg(long)]
        server: String,
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
    },
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
        .is_some_and(|arg| arg == HELPER_ARG)
    {
        helper::main();
    }
    let cli = Cli::parse();
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
            server,
            token,
            name,
            state_dir,
        } => {
            let state = StateDir::open(state_dir)?;
            let credentials = enroll::join(&server, &token, name, &state).await?;
            println!("joined {} as {}", credentials.server, credentials.node_id);
            Ok(ExitCode::SUCCESS)
        }
        Command::Run { state_dir } => match client::run(StateDir::open(state_dir)?).await? {
            RunExit::Revoked => {
                eprintln!("happy-supervisor: the control plane revoked this node's credential");
                Ok(ExitCode::from(3))
            }
            RunExit::Interrupted => Ok(ExitCode::SUCCESS),
        },
        Command::Info { state_dir } => {
            let state = StateDir::open(state_dir)?;
            let (node, _events) = tokio::task::spawn_blocking(move || Node::open(state))
                .await
                .map_err(|err| {
                    happy_supervisor::Error::new(happy_supervisor::ErrorKind::Io, err.to_string())
                })??;
            let info = node.info().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&info).expect("NodeInfo serializes")
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
