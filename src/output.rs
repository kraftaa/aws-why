use std::io::{self, Write};

use crate::model::{
    AnalysisReport, Confidence, Decision, DenyCause, EvidenceSource, FailureKind, PermissionReport,
    PolicyValidation, PolicyValidationStatus, PrincipalType,
};

pub fn write_json(report: &AnalysisReport) -> io::Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, report)?;
    writeln!(lock)
}

pub fn write_permission_json(report: &PermissionReport) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, report)?;
    writeln!(out)
}

pub fn write_permission_human(report: &PermissionReport) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "SIMULATED PERMISSIONS\n")?;
    writeln!(out, "Identity")?;
    writeln!(out, "  account: {}", report.identity.account_id)?;
    writeln!(out, "  principal: {}", report.identity.display_name())?;
    if let Some(session) = &report.identity.session_name {
        writeln!(out, "  session: {session}")?;
    }
    writeln!(out, "  policy source: {}\n", report.policy_source_arn)?;

    let mut allowed = 0;
    let mut denied = 0;
    let mut unknown = 0;
    let mut current_resource: Option<&str> = None;
    for evaluation in &report.authorization {
        let resource = evaluation.resource.as_deref().unwrap_or("*");
        if current_resource != Some(resource) {
            writeln!(out, "Resource")?;
            writeln!(out, "  {resource}")?;
            current_resource = Some(resource);
        }
        let (label, marker) = match evaluation.decision {
            Decision::Allowed => {
                allowed += 1;
                ("ALLOWED", "+")
            }
            Decision::ExplicitDeny | Decision::ImplicitDeny => {
                denied += 1;
                ("DENIED", "-")
            }
            Decision::Unknown => {
                unknown += 1;
                ("UNKNOWN", "?")
            }
        };
        write!(
            out,
            "  {marker} {:<8} {}",
            label,
            evaluation.action.as_deref().unwrap_or("unknown:Unknown")
        )?;
        if let Some(cause) = &evaluation.cause {
            write!(out, " — {}", cause.label())?;
        }
        writeln!(out)?;
        if let Some(policy) = &evaluation.policy {
            writeln!(out, "              policy: {policy}")?;
        }
        if !evaluation.missing_context.is_empty() {
            writeln!(
                out,
                "              missing context: {}",
                evaluation.missing_context.join(", ")
            )?;
        }
    }
    writeln!(
        out,
        "\nSummary: {allowed} allowed, {denied} denied, {unknown} unknown"
    )?;
    for note in &report.notes {
        writeln!(out, "Note: {note}")?;
    }
    writeln!(
        out,
        "Simulation only: this does not execute the actions or prove a live request will succeed."
    )
}

pub fn write_human(report: &AnalysisReport, verbose: bool) -> io::Result<()> {
    let stderr = io::stderr();
    let mut out = stderr.lock();
    write_human_to(&mut out, report, verbose)
}

pub fn write_human_stdout(report: &AnalysisReport, verbose: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_human_to(&mut out, report, verbose)
}

fn write_human_to(out: &mut impl Write, report: &AnalysisReport, verbose: bool) -> io::Result<()> {
    match report.failure_kind {
        FailureKind::Authorization if verbose => write_authorization_verbose(out, report),
        FailureKind::Authorization => write_authorization_concise(out, report),
        FailureKind::Authentication => {
            writeln!(out, "\nAUTHENTICATION FAILURE\n")?;
            if report.error.as_ref().is_some_and(|error| {
                error.code.contains("Expired") || error.message.to_lowercase().contains("expired")
            }) {
                writeln!(out, "Your AWS session expired.\n")?;
            } else if let Some(error) = &report.error {
                writeln!(out, "{}: {}\n", error.code, error.message)?;
            }
            writeln!(
                out,
                "This is not evidence that an IAM permission is missing."
            )
        }
        FailureKind::Configuration => write_simple(
            out,
            "AWS CONFIGURATION FAILURE",
            report,
            "Fix the local AWS CLI configuration before investigating IAM.",
        ),
        FailureKind::Network => write_simple(
            out,
            "AWS NETWORK FAILURE",
            report,
            "The request did not produce evidence of an IAM denial.",
        ),
        FailureKind::ResourceNotFound => write_simple(
            out,
            "AWS RESOURCE NOT FOUND",
            report,
            "This is not evidence that an IAM permission is missing.",
        ),
        FailureKind::Other => write_simple(
            out,
            "COMMAND FAILED",
            report,
            "aws-why found no reliable evidence of an IAM denial.",
        ),
    }
}

fn write_simple(
    out: &mut impl Write,
    heading: &str,
    report: &AnalysisReport,
    conclusion: &str,
) -> io::Result<()> {
    writeln!(out, "\n{heading}\n")?;
    if let Some(error) = &report.error {
        writeln!(out, "{}: {}\n", error.code, error.message)?;
    }
    writeln!(out, "{conclusion}")
}

fn write_authorization_concise(out: &mut impl Write, report: &AnalysisReport) -> io::Result<()> {
    if report.authorization.is_empty() {
        writeln!(out, "\nACCESS DENIED\n")?;
        if let Some(error) = &report.error {
            writeln!(out, "{}: {}\n", error.code, error.message)?;
        }
        writeln!(out, "Exact denial reason unknown.")?;
        write_important_notes(out, report)?;
        return Ok(());
    }

    if report.authorization.len() == 1 {
        let result = &report.authorization[0];
        write!(out, "\nDENIED")?;
        if let Some(action) = &result.action {
            write!(out, ": {action}")?;
        }
        if let Some(resource) = &result.resource {
            write!(out, " on {resource}")?;
        }
        writeln!(out, "\n")?;
    } else {
        writeln!(
            out,
            "\nDENIED: {} authorization checks\n",
            report.authorization.len()
        )?;
    }

    let has_candidate_policy = report
        .remediation
        .iter()
        .any(|item| item.candidate_policy.is_some());
    if !has_candidate_policy && let Some(identity) = &report.identity {
        let (label, principal) = match identity.principal_type {
            PrincipalType::AssumedRole | PrincipalType::Role => (
                "Role",
                identity
                    .policy_source_arn()
                    .unwrap_or_else(|| identity.arn.clone()),
            ),
            PrincipalType::User => ("User", identity.arn.clone()),
            _ => ("Principal", identity.arn.clone()),
        };
        writeln!(out, "{label}")?;
        writeln!(out, "  {principal}\n")?;
    }

    for (index, result) in report.authorization.iter().enumerate() {
        if report.authorization.len() > 1 {
            writeln!(out, "Request {}", index + 1)?;
            writeln!(
                out,
                "  action: {}",
                result.action.as_deref().unwrap_or("unknown")
            )?;
            writeln!(
                out,
                "  resource: {}\n",
                result.resource.as_deref().unwrap_or("not reported by AWS")
            )?;
        }
        if let Some(cause) = &result.cause {
            writeln!(out, "Reason")?;
            writeln!(out, "  {}", cause.label())?;
            if let Some(policy) = &result.policy {
                writeln!(out, "  policy: {policy}")?;
            }
            writeln!(out)?;
        }

        let recommendation = report.remediation.iter().find(|recommendation| {
            recommendation.action == result.action && recommendation.resource == result.resource
        });
        if let Some(policy) = recommendation.and_then(|item| item.candidate_policy.as_ref()) {
            writeln!(out, "SEND TO YOUR AWS ADMIN")?;
            if let Some(identity) = &report.identity {
                writeln!(
                    out,
                    "  Principal: {}",
                    identity
                        .policy_source_arn()
                        .unwrap_or_else(|| identity.arn.clone())
                )?;
            }
            if let Some(action) = &result.action {
                writeln!(
                    out,
                    "  Missing: {action} on {}",
                    result
                        .resource
                        .as_deref()
                        .unwrap_or("an unreported resource")
                )?;
            }
            writeln!(out, "\n  Candidate policy (administrator review required):")?;
            let rendered = serde_json::to_string_pretty(policy)?;
            for line in rendered.lines() {
                writeln!(out, "    {line}")?;
            }
            writeln!(
                out,
                "\nCandidate only—administrator review required; other policy layers may still deny the request.\n"
            )?;
        } else if let Some(recommendation) = recommendation {
            writeln!(out, "NEXT STEP")?;
            writeln!(out, "  {}\n", recommendation.guidance)?;
        }
        if let Some(validation) = recommendation.and_then(|item| item.policy_validation.as_ref()) {
            write_policy_validation(out, validation)?;
        }
    }
    write_important_notes(out, report)
}

fn write_important_notes(out: &mut impl Write, report: &AnalysisReport) -> io::Result<()> {
    if !report.notes.is_empty() {
        writeln!(out, "Important")?;
        for note in &report.notes {
            writeln!(out, "  {note}")?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn write_authorization_verbose(out: &mut impl Write, report: &AnalysisReport) -> io::Result<()> {
    write!(out, "\nACCESS DENIED")?;
    if report.authorization.len() == 1
        && let Some(action) = &report.authorization[0].action
    {
        write!(out, ": {action}")?;
        if let Some(resource) = &report.authorization[0].resource {
            write!(out, " on {resource}")?;
        }
    }
    writeln!(out, "\n")?;
    if let Some(identity) = &report.identity {
        writeln!(out, "Identity")?;
        writeln!(out, "  account: {}", identity.account_id)?;
        writeln!(out, "  principal: {}", identity.display_name())?;
        if let Some(session) = &identity.session_name {
            writeln!(out, "  session: {session}")?;
        }
        writeln!(out)?;
    }
    for (index, result) in report.authorization.iter().enumerate() {
        if report.authorization.len() > 1 {
            writeln!(out, "Authorization check {}", index + 1)?;
        }
        if report.authorization.len() > 1 {
            if let Some(action) = &result.action {
                writeln!(out, "  action: {action}")?;
            }
            if let Some(resource) = &result.resource {
                writeln!(out, "  resource: {resource}")?;
            }
            writeln!(out)?;
        }
        if let Some(cause) = &result.cause {
            writeln!(out, "Cause")?;
            writeln!(out, "  {}", cause.label())?;
            if let Some(policy) = &result.policy {
                writeln!(out, "  policy: {policy}")?;
            }
            writeln!(out)?;
        }
        if !result.missing_context.is_empty() {
            writeln!(out, "Could not verify runtime context")?;
            for key in &result.missing_context {
                writeln!(out, "  {key}")?;
            }
            writeln!(out)?;
        }
        writeln!(out, "Evidence")?;
        writeln!(
            out,
            "  {} ({})\n",
            source_label(&result.evidence_source),
            confidence_label(&result.confidence)
        )?;
        if result.evidence_source == EvidenceSource::AwsError
            && result.confidence == Confidence::Reported
            && result
                .cause
                .as_ref()
                .is_some_and(|cause| *cause != DenyCause::Unknown)
        {
            writeln!(
                out,
                "AWS already identified this cause; IAM simulation was not required.\n"
            )?;
        }
        if result.decision == Decision::Allowed {
            writeln!(out, "SIMULATION ALLOWS THIS REQUEST")?;
            writeln!(
                out,
                "But the live request failed and could not be fully reproduced."
            )?;
            writeln!(out, "Result: INCOMPLETE\n")?;
        }
    }
    if report.authorization.is_empty() {
        if let Some(error) = &report.error {
            writeln!(out, "AWS error")?;
            writeln!(out, "  {}: {}\n", error.code, error.message)?;
        }
        writeln!(out, "RESULT")?;
        writeln!(out, "  Exact denial reason unknown.\n")?;
    }
    if let Some(source) = &report.credential_source {
        writeln!(out, "Credential source")?;
        writeln!(out, "  {source}\n")?;
    }
    for recommendation in &report.remediation {
        writeln!(out, "What to do next")?;
        writeln!(out, "  {}\n", recommendation.guidance)?;
        if let Some(action) = &recommendation.action {
            writeln!(out, "Administrator handoff")?;
            if let Some(identity) = &report.identity {
                writeln!(
                    out,
                    "  principal: {}",
                    identity
                        .policy_source_arn()
                        .unwrap_or_else(|| identity.arn.clone())
                )?;
            }
            writeln!(out, "  action: {action}")?;
            if let Some(resource) = &recommendation.resource {
                writeln!(out, "  resource: {resource}")?;
            } else {
                writeln!(out, "  resource: not reported by AWS")?;
            }
            writeln!(out)?;
        }
        if let Some(policy) = &recommendation.candidate_policy {
            writeln!(out, "Candidate policy (administrator review required)")?;
            let rendered = serde_json::to_string_pretty(policy)?;
            for line in rendered.lines() {
                writeln!(out, "  {line}")?;
            }
            writeln!(
                out,
                "  This addresses the reported denial only; another policy layer may still block the request.\n"
            )?;
        }
        if let Some(validation) = &recommendation.policy_validation {
            write_policy_validation(out, validation)?;
        }
    }
    if !report.notes.is_empty() {
        writeln!(out, "Notes")?;
        for note in &report.notes {
            writeln!(out, "  {note}")?;
        }
        writeln!(out)?;
    }
    if report.authorization.is_empty()
        || report.authorization.iter().any(|item| {
            item.confidence == Confidence::Incomplete
                || item
                    .cause
                    .as_ref()
                    .is_none_or(|cause| *cause == DenyCause::Unknown)
        })
    {
        writeln!(
            out,
            "aws-why could not obtain complete AWS authorization details."
        )?;
    }
    Ok(())
}

fn write_policy_validation(out: &mut impl Write, validation: &PolicyValidation) -> io::Result<()> {
    writeln!(out, "Policy resource check")?;
    let marker = match validation.status {
        PolicyValidationStatus::Valid => "verified",
        PolicyValidationStatus::Invalid => "mismatch",
        PolicyValidationStatus::Unavailable => "not verified",
    };
    writeln!(out, "  {marker}: {}\n", validation.detail)
}

fn source_label(source: &EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::RequestAuthorizationDetails => "AWS request authorization details",
        EvidenceSource::DecodedAuthorizationMessage => "AWS decoded authorization message",
        EvidenceSource::AwsError => "AWS error response",
        EvidenceSource::PolicySimulation => "IAM policy simulation",
        EvidenceSource::None => "no authorization evidence",
    }
}

fn confidence_label(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Verified => "verified",
        Confidence::Reported => "reported by AWS",
        Confidence::Simulated => "simulated",
        Confidence::Incomplete => "incomplete",
    }
}

#[allow(dead_code)]
fn _cause_is_actionable(cause: &DenyCause) -> bool {
    !matches!(cause, DenyCause::Unknown | DenyCause::Condition)
}
