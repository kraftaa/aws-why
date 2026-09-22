use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use aws_why::aws::AwsCommandContext;
use aws_why::model::{AwsIdentity, Decision, PermissionReport};

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

        /// Include identity session, evidence, credential source, and diagnostic notes.
        #[arg(long, conflicts_with = "json")]
        verbose: bool,

        /// Mask account, principal, session, resource, policy, and request identifiers.
        #[arg(long)]
        redact: bool,

        /// Maximum duration of each follow-up AWS diagnostic call.
        #[arg(long, default_value_t = 5)]
        diagnostic_timeout: u64,

        /// The command to execute. Place `--` before it.
        #[arg(last = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Check credentials and show which aws-why diagnostics are available.
    Doctor {
        #[command(flatten)]
        options: DoctorOptions,
    },

    /// Safely simulate whether an IAM action is allowed for one or more resources.
    Can {
        /// IAM action to evaluate, for example s3:GetObject.
        action: String,

        /// Resource ARN to evaluate. Repeat for multiple resources; defaults to *.
        #[arg(long = "resource", value_name = "ARN")]
        resources: Vec<String>,

        #[command(flatten)]
        options: SimulationOptions,
    },

    /// Show a simulated permission matrix for an AWS service and resource.
    Permissions {
        /// IAM service prefix, for example s3, ec2, or secretsmanager.
        #[arg(long)]
        service: String,

        /// Limit the matrix to an action. Repeat to select multiple actions.
        #[arg(long = "action", value_name = "ACTION")]
        actions: Vec<String>,

        /// Resource ARN to evaluate. Repeat for multiple resources; defaults to *.
        #[arg(long = "resource", value_name = "ARN")]
        resources: Vec<String>,

        #[command(flatten)]
        options: SimulationOptions,
    },
}

#[derive(Debug, Args)]
struct SimulationOptions {
    /// Emit one JSON report on stdout.
    #[arg(long)]
    json: bool,

    /// AWS CLI executable or absolute path.
    #[arg(long, default_value = "aws")]
    aws_cli: String,

    /// AWS CLI profile used for identity discovery and simulation.
    #[arg(long)]
    profile: Option<String>,

    /// AWS region passed to diagnostic AWS CLI calls.
    #[arg(long)]
    region: Option<String>,

    /// IAM user or role ARN to simulate instead of the current principal.
    #[arg(long, value_name = "ARN")]
    principal: Option<String>,

    /// Maximum duration of each AWS or service-reference call.
    #[arg(long, default_value_t = 10)]
    diagnostic_timeout: u64,
}

#[derive(Debug, Args)]
struct DoctorOptions {
    /// Emit one JSON report on stdout.
    #[arg(long)]
    json: bool,

    /// Mask account, principal, and session identifiers.
    #[arg(long)]
    redact: bool,

    /// AWS CLI executable or absolute path.
    #[arg(long, default_value = "aws")]
    aws_cli: String,

    /// AWS CLI profile used for capability checks.
    #[arg(long)]
    profile: Option<String>,

    /// AWS region passed to capability checks.
    #[arg(long)]
    region: Option<String>,

    /// Maximum duration of each AWS capability check.
    #[arg(long, default_value_t = 10)]
    diagnostic_timeout: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            json,
            verbose,
            redact,
            diagnostic_timeout,
            command,
        } => run(command, json, verbose, redact, diagnostic_timeout),
        Commands::Doctor { options } => doctor(options),
        Commands::Can {
            action,
            resources,
            options,
        } => can(action, resources, options),
        Commands::Permissions {
            service,
            actions,
            resources,
            options,
        } => permissions(service, actions, resources, options),
    }
}

fn can(action: String, resources: Vec<String>, options: SimulationOptions) -> ExitCode {
    let action = match aws_why::permissions::normalize_action(&action, None) {
        Ok(action) => action,
        Err(error) => return simulation_error(error),
    };
    let service = action
        .split_once(':')
        .map(|(service, _)| service.to_owned());
    let resources = match aws_why::permissions::normalize_resources(resources) {
        Ok(resources) => resources,
        Err(error) => return simulation_error(error),
    };
    let report = match simulate_report(vec![action], resources, service, &options, false) {
        Ok(report) => report,
        Err(error) => return simulation_error(error),
    };
    let allowed = report
        .authorization
        .iter()
        .all(|result| result.decision == Decision::Allowed);
    if let Err(error) = write_permission_report(&report, options.json) {
        return simulation_error(format!("Could not write permission report: {error}"));
    }
    if allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

fn permissions(
    service: String,
    requested_actions: Vec<String>,
    resources: Vec<String>,
    options: SimulationOptions,
) -> ExitCode {
    let service = match aws_why::permissions::normalize_service(&service) {
        Ok(service) => service,
        Err(error) => return simulation_error(error),
    };
    let fetched_catalog = requested_actions.is_empty();
    let actions = if fetched_catalog {
        match aws_why::permissions::fetch_service_actions(
            &service,
            Duration::from_secs(options.diagnostic_timeout),
        ) {
            Ok(actions) => actions,
            Err(error) => return simulation_error(error),
        }
    } else {
        let mut actions = Vec::with_capacity(requested_actions.len());
        for action in requested_actions {
            match aws_why::permissions::normalize_action(&action, Some(&service)) {
                Ok(action) => actions.push(action),
                Err(error) => return simulation_error(error),
            }
        }
        actions.sort_unstable();
        actions.dedup();
        actions
    };
    let resources = match aws_why::permissions::normalize_resources(resources) {
        Ok(resources) => resources,
        Err(error) => return simulation_error(error),
    };
    let report = match simulate_report(actions, resources, Some(service), &options, fetched_catalog)
    {
        Ok(report) => report,
        Err(error) => return simulation_error(error),
    };
    if let Err(error) = write_permission_report(&report, options.json) {
        return simulation_error(format!("Could not write permission report: {error}"));
    }
    ExitCode::SUCCESS
}

fn simulate_report(
    actions: Vec<String>,
    resources: Vec<String>,
    service: Option<String>,
    options: &SimulationOptions,
    fetched_catalog: bool,
) -> Result<PermissionReport, String> {
    let timeout = Duration::from_secs(options.diagnostic_timeout);
    let context = AwsCommandContext::for_diagnostics(
        options.aws_cli.clone(),
        options.profile.clone(),
        options.region.clone(),
    );
    let identity = if let Some(principal) = &options.principal {
        let identity = AwsIdentity::from_arn(principal)
            .ok_or_else(|| "--principal must be an IAM user or role ARN.".to_owned())?;
        identity
            .policy_source_arn()
            .ok_or_else(|| "--principal must identify an IAM user or role.".to_owned())?;
        identity
    } else {
        aws_why::aws::discover_identity(&context, timeout)?
    };
    let policy_source_arn = identity.policy_source_arn().ok_or_else(|| {
        "The current identity cannot be mapped to an IAM user or role.".to_owned()
    })?;
    let authorization =
        aws_why::aws::simulate_permissions(&context, &identity, &actions, &resources, timeout)?;
    let mut notes = vec![
        "Resource policies are not fetched, and live request context, role session policies, VPC endpoint policies, and resource control policies may change the real result."
            .to_owned(),
    ];
    if fetched_catalog {
        notes.push(
            "Action names came from AWS's current public Service Authorization Reference."
                .to_owned(),
        );
    }
    Ok(PermissionReport::new(
        identity,
        policy_source_arn,
        service,
        authorization,
        notes,
    ))
}

fn write_permission_report(report: &PermissionReport, json: bool) -> io::Result<()> {
    if json {
        aws_why::output::write_permission_json(report)
    } else {
        aws_why::output::write_permission_human(report)
    }
}

fn simulation_error(error: String) -> ExitCode {
    let _ = writeln!(io::stderr(), "aws-why: {error}");
    ExitCode::from(2)
}

fn doctor(options: DoctorOptions) -> ExitCode {
    let timeout = Duration::from_secs(options.diagnostic_timeout);
    let context =
        AwsCommandContext::for_diagnostics(options.aws_cli, options.profile, options.region);
    let identity = match aws_why::aws::discover_identity(&context, timeout) {
        Ok(identity) => identity,
        Err(error) => {
            let error = if options.redact {
                "Could not determine the caller identity (detail redacted).".to_owned()
            } else {
                error
            };
            if options.json {
                let report = serde_json::json!({
                    "result": "not_ready",
                    "credentials": { "available": false, "detail": error },
                    "run_diagnostics": { "available": false },
                    "policy_simulation": { "available": false }
                });
                let _ = serde_json::to_writer_pretty(io::stdout().lock(), &report);
                let _ = writeln!(io::stdout());
            } else {
                let _ = writeln!(io::stdout(), "AWS-WHY DOCTOR\n");
                let _ = writeln!(io::stdout(), "- AWS credentials\n  {error}\n");
                let _ = writeln!(
                    io::stdout(),
                    "NOT READY\n  Fix AWS credentials or profile selection, then run doctor again."
                );
            }
            return ExitCode::from(2);
        }
    };
    let simulation = aws_why::aws::simulate_permissions(
        &context,
        &identity,
        &["sts:GetCallerIdentity".to_owned()],
        &["*".to_owned()],
        timeout,
    );
    let simulation_available = simulation.is_ok();
    let simulation_detail = simulation.err().map(|detail| {
        if options.redact {
            "IAM simulation is unavailable (detail redacted).".to_owned()
        } else {
            detail
        }
    });
    let displayed_identity = if options.redact {
        identity.redacted()
    } else {
        identity.clone()
    };
    if options.json {
        let report = serde_json::json!({
            "result": "ready",
            "identity": displayed_identity,
            "credentials": { "available": true },
            "run_diagnostics": {
                "available": true,
                "detail": "AWS-reported denial causes can be explained without IAM simulation."
            },
            "policy_simulation": {
                "available": simulation_available,
                "detail": simulation_detail
            }
        });
        if serde_json::to_writer_pretty(io::stdout().lock(), &report).is_err() {
            return ExitCode::from(2);
        }
        let _ = writeln!(io::stdout());
    } else {
        let principal = displayed_identity
            .policy_source_arn()
            .unwrap_or_else(|| displayed_identity.arn.clone());
        let _ = writeln!(io::stdout(), "AWS-WHY DOCTOR\n");
        let _ = writeln!(io::stdout(), "+ AWS credentials\n  {principal}\n");
        let _ = writeln!(
            io::stdout(),
            "+ Denial explanations\n  Available. AWS-reported causes do not require IAM simulation.\n"
        );
        if simulation_available {
            let _ = writeln!(
                io::stdout(),
                "+ Permission simulation\n  Available for `can` and `permissions`.\n"
            );
        } else {
            let _ = writeln!(
                io::stdout(),
                "- Permission simulation (optional)\n  Unavailable. `run` still works; `can` and `permissions` require iam:SimulatePrincipalPolicy.\n"
            );
        }
        let _ = writeln!(
            io::stdout(),
            "READY\n  Run: aws-why run -- aws <service> <operation>"
        );
    }
    ExitCode::SUCCESS
}

fn run(
    command: Vec<String>,
    json: bool,
    verbose: bool,
    redact: bool,
    diagnostic_timeout: u64,
) -> ExitCode {
    let mut result = match aws_why::runner::run_user_command(&command, !json && !redact) {
        Ok(result) => result,
        Err(error) => {
            if redact {
                let _ = writeln!(
                    io::stderr(),
                    "aws-why: could not execute wrapped command (detail redacted)"
                );
            } else {
                let _ = writeln!(
                    io::stderr(),
                    "aws-why: could not execute {}: {error}",
                    command[0]
                );
            }
            return ExitCode::from(126);
        }
    };

    if result.exit_code == 0 {
        if json || redact {
            let _ = result.replay_stdout();
        }
        let _ = result.replay_stderr();
        warn_if_truncated(&result);
        return ExitCode::SUCCESS;
    }

    let report = aws_why::analyze(&result, Duration::from_secs(diagnostic_timeout));
    if !json && !redact && report.failure_kind != aws_why::model::FailureKind::Authorization {
        let _ = result.replay_stderr();
    }
    let report = if redact { report.redacted() } else { report };
    let write_result = if json {
        aws_why::output::write_json(&report)
    } else {
        aws_why::output::write_human(&report, verbose)
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
