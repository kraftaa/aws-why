use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "aws-why", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute a command and explain AWS failures.
    Run {
        /// Emit one JSON diagnostic object for a failed command.
        #[arg(long)]
        json: bool,

        /// Maximum duration of each follow-up AWS diagnostic call.
        #[arg(long, default_value_t = 5)]
        diagnostic_timeout: u64,

        /// The command to execute. Place `--` before it.
        #[arg(last = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            json,
            diagnostic_timeout,
            command,
        } => run(command, json, diagnostic_timeout),
    }
}

fn run(command: Vec<String>, json: bool, diagnostic_timeout: u64) -> ExitCode {
    let result = match aws_why::runner::run_user_command(&command, !json) {
        Ok(result) => result,
        Err(error) => {
            let _ = writeln!(
                io::stderr(),
                "aws-why: could not execute {}: {error}",
                command[0]
            );
            return ExitCode::from(126);
        }
    };

    if result.exit_code == 0 {
        if json {
            let _ = io::stdout().write_all(&result.stdout);
            let _ = io::stderr().write_all(&result.stderr);
        }
        return ExitCode::SUCCESS;
    }

    let report = aws_why::analyze(&result, Duration::from_secs(diagnostic_timeout));
    let write_result = if json {
        aws_why::output::write_json(&report)
    } else {
        aws_why::output::write_human(&report)
    };
    if let Err(error) = write_result {
        let _ = writeln!(io::stderr(), "aws-why: could not write diagnostic: {error}");
    }
    ExitCode::from(result.exit_code.clamp(1, 255) as u8)
}
