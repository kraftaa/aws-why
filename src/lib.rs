pub mod aws;
pub mod model;
pub mod output;
pub mod permissions;
pub mod runner;

use std::time::Duration;

use aws::{AwsCommandContext, diagnose_authorization, discover_identity, parse_aws_error};
use model::{AnalysisReport, FailureKind};
use runner::CommandRun;

/// Analyze an already-completed command. Diagnostic AWS calls are made only for
/// authorization failures and only when the wrapped executable is the AWS CLI.
pub fn analyze(run: &CommandRun, diagnostic_timeout: Duration) -> AnalysisReport {
    let mut evidence = parse_aws_error(&run.stderr);
    let failure_kind = evidence
        .as_ref()
        .map(|item| item.failure_kind.clone())
        .unwrap_or(FailureKind::Other);
    let context = AwsCommandContext::from_argv(&run.argv);

    let mut identity = evidence
        .as_ref()
        .and_then(|item| item.principal_arn.as_deref())
        .and_then(model::AwsIdentity::from_arn);
    let mut diagnostic_notes = Vec::new();

    if run.stderr_truncated {
        diagnostic_notes.push(
            "Only the final 1 MiB of command stderr was analyzed; earlier output was truncated."
                .to_owned(),
        );
    }

    if failure_kind == FailureKind::Authorization && context.is_aws_cli() {
        let allow_followups = context.diagnostic_block_reason().is_none();
        if allow_followups {
            match discover_identity(&context, diagnostic_timeout) {
                Ok(discovered) => identity = Some(discovered),
                Err(note) => diagnostic_notes.push(note),
            }
        } else if let Some(reason) = context.diagnostic_block_reason() {
            diagnostic_notes.push(reason.to_owned());
        }

        if let Some(item) = evidence.as_mut() {
            let result = diagnose_authorization(
                &context,
                item,
                identity.as_ref(),
                diagnostic_timeout,
                allow_followups,
            );
            diagnostic_notes.extend(result.notes);
            add_account_mismatch_note(
                &mut diagnostic_notes,
                identity.as_ref(),
                item.resource.as_deref(),
            );
            return AnalysisReport::from_parts(
                run.exit_code,
                failure_kind,
                identity,
                evidence,
                result.authorization,
                diagnostic_notes,
                context.credential_hint(),
            );
        }
    }

    AnalysisReport::from_parts(
        run.exit_code,
        failure_kind,
        identity,
        evidence,
        Vec::new(),
        diagnostic_notes,
        context.credential_hint(),
    )
}

fn add_account_mismatch_note(
    notes: &mut Vec<String>,
    identity: Option<&model::AwsIdentity>,
    resource: Option<&str>,
) {
    let (Some(identity), Some(resource)) = (identity, resource) else {
        return;
    };
    let parts: Vec<&str> = resource.splitn(6, ':').collect();
    let target_account = parts.get(4).copied().unwrap_or_default();
    if target_account.len() == 12
        && target_account
            .chars()
            .all(|character| character.is_ascii_digit())
        && target_account != identity.account_id
    {
        notes.push(format!(
            "Caller account {} differs from target resource account {target_account}; check the selected profile or cross-account access.",
            identity.account_id
        ));
    }
}
