use std::io::{self, Write};

use crate::model::{
    AnalysisReport, Confidence, Decision, DenyCause, EvidenceSource, FailureKind, PermissionReport,
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

pub fn write_human(report: &AnalysisReport) -> io::Result<()> {
    let stderr = io::stderr();
    let mut out = stderr.lock();
    match report.failure_kind {
        FailureKind::Authorization => write_authorization(&mut out, report),
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
            &mut out,
            "AWS CONFIGURATION FAILURE",
            report,
            "Fix the local AWS CLI configuration before investigating IAM.",
        ),
        FailureKind::Network => write_simple(
            &mut out,
            "AWS NETWORK FAILURE",
            report,
            "The request did not produce evidence of an IAM denial.",
        ),
        FailureKind::ResourceNotFound => write_simple(
            &mut out,
            "AWS RESOURCE NOT FOUND",
            report,
            "This is not evidence that an IAM permission is missing.",
        ),
        FailureKind::Other => write_simple(
            &mut out,
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

fn write_authorization(out: &mut impl Write, report: &AnalysisReport) -> io::Result<()> {
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
