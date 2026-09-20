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
    let mut result = match aws_why::runner::run_user_command(&command, !json) {
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
            let _ = result.replay_stdout();
        }
        let _ = result.replay_stderr();
        warn_if_truncated(&result);
        return ExitCode::SUCCESS;
    }

    let report = aws_why::analyze(&result, Duration::from_secs(diagnostic_timeout));
    if !json && report.failure_kind != aws_why::model::FailureKind::Authorization {
        let _ = result.replay_stderr();
    }
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

fn warn_if_truncated(result: &aws_why::runner::CommandRun) {
    if result.stdout_truncated {
        let _ = writeln!(
            io::stderr(),
            "aws-why: command stdout exceeded the 64 MiB --json replay limit and was truncated"
        );
    }
    if result.stderr_replay_truncated {
        let _ = writeln!(
            io::stderr(),
            "aws-why: command stderr exceeded the 8 MiB replay limit and was truncated"
        );
    }
}
