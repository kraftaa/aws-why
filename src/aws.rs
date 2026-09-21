use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use crate::model::{
    AuthorizationResult, AwsErrorEvidence, AwsIdentity, Confidence, Decision, DenyCause,
    EvidenceSource, FailureKind,
};
use crate::runner::run_diagnostic;

#[derive(Debug, Clone, Default)]
pub struct AwsCommandContext {
    executable: Option<String>,
    profile: Option<String>,
    region: Option<String>,
    service: Option<String>,
    no_sign_request: bool,
    explicit_endpoint: bool,
}

impl AwsCommandContext {
    pub fn for_diagnostics(
        executable: String,
        profile: Option<String>,
        region: Option<String>,
    ) -> Self {
        Self {
            executable: Some(executable),
            profile,
            region,
            ..Self::default()
        }
    }

    pub fn from_argv(argv: &[String]) -> Self {
        let Some(executable) = argv.first() else {
            return Self::default();
        };
        let basename = Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(executable);
        if basename != "aws" && basename != "aws.exe" {
            return Self::default();
        }

        let mut context = Self {
            executable: Some(executable.clone()),
            ..Self::default()
        };
        let mut index = 1;
        while index < argv.len() {
            let arg = &argv[index];
            if let Some(value) = arg.strip_prefix("--profile=") {
                context.profile = Some(value.to_owned());
            } else if let Some(value) = arg.strip_prefix("--region=") {
                context.region = Some(value.to_owned());
            } else if arg == "--no-sign-request" {
                context.no_sign_request = true;
            } else if arg == "--endpoint-url" || arg.starts_with("--endpoint-url=") {
                context.explicit_endpoint = true;
                if arg == "--endpoint-url" {
                    index += 1;
                }
            } else if arg == "--profile" || arg == "--region" {
                if let Some(value) = argv.get(index + 1) {
                    if arg == "--profile" {
                        context.profile = Some(value.clone());
                    } else {
                        context.region = Some(value.clone());
                    }
                    index += 1;
                }
            } else if takes_global_value(arg) {
                index += 1;
            } else if !arg.starts_with('-') && context.service.is_none() {
                context.service = Some(arg.clone());
            }
            index += 1;
        }
        context
    }

    pub fn is_aws_cli(&self) -> bool {
        self.executable.is_some()
    }

    pub fn diagnostic_block_reason(&self) -> Option<&'static str> {
        if self.no_sign_request {
            Some("Follow-up diagnostics were skipped because the command used --no-sign-request.")
        } else if self.explicit_endpoint {
            Some("Follow-up diagnostics were skipped because the command used a custom endpoint.")
        } else {
            None
        }
    }

    pub fn credential_hint(&self) -> Option<String> {
        if self.no_sign_request {
            return Some("unsigned request (--no-sign-request)".to_owned());
        }
        self.profile
            .as_ref()
            .map(|profile| format!("AWS CLI --profile {profile}"))
            .or_else(|| {
                std::env::var("AWS_PROFILE")
                    .ok()
                    .map(|value| format!("AWS_PROFILE={value}"))
            })
            .or_else(|| Some("AWS default credential chain".to_owned()))
    }

    fn args_for(&self, command: &[&str]) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(profile) = &self.profile {
            args.push("--profile".into());
            args.push(profile.into());
        }
        if let Some(region) = &self.region {
            args.push("--region".into());
            args.push(region.into());
        }
        args.extend(command.iter().map(OsString::from));
        args
    }

    fn executable(&self) -> Result<&str, String> {
        self.executable
            .as_deref()
            .ok_or_else(|| "the wrapped executable is not the AWS CLI".to_owned())
    }
}

fn takes_global_value(arg: &str) -> bool {
    matches!(
        arg,
        "--endpoint-url"
            | "--ca-bundle"
            | "--output"
            | "--query"
            | "--cli-connect-timeout"
            | "--cli-read-timeout"
            | "--color"
            | "--cli-error-format"
    )
}

pub fn parse_aws_error(raw: &[u8]) -> Option<AwsErrorEvidence> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed_json = serde_json::from_str::<Value>(trimmed).ok();
    let code = parsed_json
        .as_ref()
        .and_then(|value| json_string(value, &["Code", "code", "ErrorCode", "__type"]))
        .map(clean_error_type)
        .or_else(|| capture(trimmed, r"(?i)an error occurred \(([^)]+)\)"))
        .or_else(|| {
            capture(
                trimmed,
                r"(?m)^aws: \[ERROR\]: An error occurred \(([^)]+)\)",
            )
        })
        .or_else(|| known_text_error_code(trimmed))
        .unwrap_or_else(|| "UnknownError".to_owned());
    let message = parsed_json
        .as_ref()
        .and_then(|value| json_string(value, &["Message", "message"]))
        .or_else(|| {
            capture(
                trimmed,
                r"(?s)(?:when calling the [A-Za-z0-9]+ operation|an error occurred \([^)]+\)):\s*(.+)",
            )
        })
        .unwrap_or_else(|| trimmed.to_owned());
    let operation =
        capture(trimmed, r"(?i)when calling the ([A-Za-z0-9]+) operation").or_else(|| {
            parsed_json
                .as_ref()
                .and_then(|value| json_string(value, &["Operation", "operation"]))
        });
    let action = capture(
        &message,
        r"(?i)(?:not authorized to perform|not authorized to perform:|perform action)\s*:?[[:space:]]*([a-z0-9-]+:[A-Za-z0-9*]+)",
    );
    let resource = capture(
        &message,
        r"(?i)(?:on resource(?:s)?|resource)\s*:\s*((?:arn:[^\s,;]+)|\*)",
    )
    .map(trim_sentence_punctuation);
    let principal_arn = capture(
        &message,
        r"(?i)(?:user|principal)\s*:\s*(arn:aws(?:-[a-z]+)*:(?:iam|sts)::[0-9]{12}:[^\s,]+)",
    )
    .map(trim_sentence_punctuation);
    let request_id = parsed_json
        .as_ref()
        .and_then(|value| json_string(value, &["RequestId", "requestId", "RequestID"]))
        .or_else(|| capture(trimmed, r"(?i)request(?:\s+|_)?id\s*[:=]\s*([A-Za-z0-9-]+)"));
    let authorization_id = parsed_json
        .as_ref()
        .and_then(|value| json_string(value, &["AuthorizationId", "authorizationId"]))
        .or_else(|| {
            capture(
                trimmed,
                r"(?i)authorization\s+id(?:entifier)?\s*:\s*([A-Za-z0-9_+=./:-]+)",
            )
        });
    let encoded_authorization_message = parsed_json
        .as_ref()
        .and_then(|value| {
            json_string(
                value,
                &["EncodedAuthorizationMessage", "encodedAuthorizationMessage"],
            )
        })
        .or_else(|| {
            capture(
                trimmed,
                r"(?i)encoded authorization failure message\s*:\s*([A-Za-z0-9_+=./-]+)",
            )
        });
    let (reported_cause, reported_policy) = parse_reported_cause(&message);
    let service = action
        .as_ref()
        .and_then(|item| item.split_once(':'))
        .map(|(prefix, _)| prefix.to_owned());
    let failure_kind = classify_failure(&code, &message);

    Some(AwsErrorEvidence {
        service,
        operation,
        action,
        error_code: code,
        message,
        request_id,
        authorization_id,
        encoded_authorization_message,
        resource,
        principal_arn,
        reported_cause,
        reported_policy,
        failure_kind,
        raw_error: raw.to_vec(),
    })
}

fn classify_failure(code: &str, message: &str) -> FailureKind {
    let normalized = code.rsplit('#').next().unwrap_or(code);
    if matches!(
        normalized,
        "ExpiredToken"
            | "ExpiredTokenException"
            | "InvalidClientTokenId"
            | "UnrecognizedClientException"
            | "NoCredentialsError"
            | "NoCredentialsFound"
            | "AuthFailure"
            | "InvalidSignatureException"
            | "SignatureDoesNotMatch"
            | "RequestExpired"
    ) || message
        .to_lowercase()
        .contains("unable to locate credentials")
    {
        FailureKind::Authentication
    } else if matches!(
        normalized,
        "AccessDenied"
            | "AccessDeniedException"
            | "UnauthorizedOperation"
            | "AuthorizationError"
            | "NotAuthorized"
            | "NotAuthorizedException"
    ) {
        FailureKind::Authorization
    } else if matches!(
        normalized,
        "NoRegion"
            | "ProfileNotFound"
            | "InvalidConfigError"
            | "ParamValidation"
            | "ParameterValidationError"
    ) || message.contains("You must specify a region")
    {
        FailureKind::Configuration
    } else if matches!(
        normalized,
        "EndpointConnectionError"
            | "ConnectTimeoutError"
            | "ReadTimeoutError"
            | "ConnectionClosedError"
            | "SSLValidationError"
    ) || message
        .to_lowercase()
        .contains("could not connect to the endpoint")
    {
        FailureKind::Network
    } else if matches!(
        normalized,
        "NoSuchBucket"
            | "NoSuchKey"
            | "ResourceNotFoundException"
            | "NotFoundException"
            | "NoSuchEntity"
    ) {
        FailureKind::ResourceNotFound
    } else {
        FailureKind::Other
    }
}

fn known_text_error_code(text: &str) -> Option<String> {
    let candidates = [
        "NoCredentialsError",
        "NoRegion",
        "ProfileNotFound",
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "ParameterValidationError",
    ];
    candidates
        .into_iter()
        .find(|candidate| text.contains(candidate))
        .map(str::to_owned)
        .or_else(|| {
            text.contains("Unable to locate credentials")
                .then(|| "NoCredentialsError".to_owned())
        })
}

fn parse_reported_cause(message: &str) -> (Option<DenyCause>, Option<String>) {
    let lower = message.to_lowercase();
    let cause = if lower.contains("permissions boundary") {
        Some(DenyCause::PermissionsBoundary)
    } else if lower.contains("service control policy") {
        Some(DenyCause::ServiceControlPolicy)
    } else if lower.contains("resource control policy") {
        Some(DenyCause::ResourceControlPolicy)
    } else if lower.contains("vpc endpoint policy") {
        Some(DenyCause::VpcEndpointPolicy)
    } else if lower.contains("session policy") {
        Some(DenyCause::SessionPolicy)
    } else if lower.contains("role trust policy") || lower.contains("trust policy") {
        Some(DenyCause::RoleTrustPolicy)
    } else if lower.contains("key policy") && lower.contains("kms") {
        Some(DenyCause::KmsKeyPolicy)
    } else if lower.contains("resource-based policy") || lower.contains("resource policy") {
        Some(DenyCause::ResourcePolicy)
    } else if lower.contains("explicit deny in an identity-based policy") {
        Some(DenyCause::IdentityPolicyExplicitDeny)
    } else if lower.contains("no identity-based policy allows") {
        Some(DenyCause::MissingIdentityAllow)
    } else if lower.contains("condition") {
        Some(DenyCause::Condition)
    } else {
        None
    };
    let policy = Regex::new(
        r"arn:aws(?:-[a-z]+)*:(?:iam|organizations)::[^\s,;]+(?:policy|policy/)[^\s,;.]+",
    )
    .expect("valid regex")
    .find(message)
    .map(|item| trim_sentence_punctuation(item.as_str().to_owned()));
    (cause, policy)
}

pub fn discover_identity(
    context: &AwsCommandContext,
    timeout: Duration,
) -> Result<AwsIdentity, String> {
    let executable = context.executable()?;
    let args = context.args_for(&["sts", "get-caller-identity", "--output", "json"]);
    let output = run_diagnostic(executable, &args, timeout)
        .map_err(|error| format!("Could not determine the caller identity: {error}"))?;
    if output.truncated {
        return Err("AWS caller identity output exceeded the diagnostic limit.".to_owned());
    }
    if !output.success {
        return Err(
            "Could not determine the caller identity with the command's AWS credentials."
                .to_owned(),
        );
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "AWS returned an unreadable caller identity response.".to_owned())?;
    let arn = json_string(&value, &["Arn", "arn"])
        .ok_or_else(|| "AWS caller identity did not include an ARN.".to_owned())?;
    AwsIdentity::from_arn(&arn).ok_or_else(|| "AWS returned an unrecognized caller ARN.".to_owned())
}

#[derive(Debug, Default)]
pub struct Diagnosis {
    pub authorization: Vec<AuthorizationResult>,
    pub notes: Vec<String>,
}

pub fn diagnose_authorization(
    context: &AwsCommandContext,
    error: &mut AwsErrorEvidence,
    identity: Option<&AwsIdentity>,
    timeout: Duration,
    allow_followups: bool,
) -> Diagnosis {
    fill_action_from_operation(context, error);
    let mut diagnosis = Diagnosis::default();

    if allow_followups && let Some(authorization_id) = error.authorization_id.as_deref() {
        match request_authorization_details(context, authorization_id, timeout) {
            Ok(results) if !results.is_empty() => {
                diagnosis.authorization = results;
                return diagnosis;
            }
            Ok(_) => diagnosis.notes.push(
                "AWS authorization details contained no action/resource evaluations.".to_owned(),
            ),
            Err(note) => diagnosis.notes.push(note),
        }
    }

    if allow_followups && let Some(encoded) = error.encoded_authorization_message.as_deref() {
        match decode_authorization_message(context, encoded, timeout) {
            Ok(result) => {
                diagnosis.authorization.push(result);
                return diagnosis;
            }
            Err(note) => diagnosis.notes.push(note),
        }
    }

    if error.reported_cause.is_some() {
        diagnosis.authorization.push(AuthorizationResult {
            action: error.action.clone(),
            resource: error.resource.clone(),
            decision: decision_from_message(&error.message),
            cause: error.reported_cause.clone(),
            policy: error.reported_policy.clone(),
            evidence_source: EvidenceSource::AwsError,
            confidence: Confidence::Reported,
            missing_context: Vec::new(),
        });
        return diagnosis;
    }

    if allow_followups
        && let (Some(identity), Some(action), Some(resource)) =
            (identity, error.action.as_deref(), error.resource.as_deref())
    {
        match simulate(context, identity, action, resource, timeout) {
            Ok(result) => {
                diagnosis.authorization.push(result);
                return diagnosis;
            }
            Err(note) => diagnosis.notes.push(note),
        }
    }

    if error.action.is_some() || error.resource.is_some() {
        diagnosis.authorization.push(AuthorizationResult {
            action: error.action.clone(),
            resource: error.resource.clone(),
            decision: Decision::Unknown,
            cause: Some(DenyCause::Unknown),
            policy: None,
            evidence_source: EvidenceSource::AwsError,
            confidence: Confidence::Incomplete,
            missing_context: Vec::new(),
        });
    }
    diagnosis
}

fn fill_action_from_operation(context: &AwsCommandContext, error: &mut AwsErrorEvidence) {
    if error.action.is_none()
        && let (Some(service), Some(operation)) =
            (context.service.as_deref(), error.operation.as_deref())
        && matches!(service, "s3" | "secretsmanager" | "kms" | "iam" | "sts")
    {
        error.service = Some(service.to_owned());
        error.action = Some(format!("{service}:{operation}"));
    }
}

fn request_authorization_details(
    context: &AwsCommandContext,
    authorization_id: &str,
    timeout: Duration,
) -> Result<Vec<AuthorizationResult>, String> {
    let executable = context.executable()?;
    let args = context.args_for(&[
        "iam-toolbox",
        "get-request-authorization-details",
        "--authorization-id",
        authorization_id,
        "--output",
        "json",
    ]);
    let output = run_diagnostic(executable, &args, timeout)
        .map_err(|error| format!("Could not retrieve AWS authorization details: {error}"))?;
    if output.truncated {
        return Err("AWS authorization details exceeded the diagnostic limit.".to_owned());
    }
    if !output.success {
        return Err(
            "AWS request authorization details were unavailable or not permitted.".to_owned(),
        );
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "AWS returned unreadable authorization details.".to_owned())?;
    Ok(parse_request_authorization_details(&value))
}

fn parse_request_authorization_details(value: &Value) -> Vec<AuthorizationResult> {
    let policy_types: HashMap<String, String> = value
        .get("policies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|policy| {
            Some((
                policy.get("uri")?.as_str()?.to_owned(),
                policy.get("type")?.as_str()?.to_owned(),
            ))
        })
        .collect();
    value
        .get("evaluations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|evaluation| {
            let effect = evaluation
                .get("evaluatedEffect")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let decision = parse_decision(effect);
            let matched = evaluation
                .get("matchedPolicies")
                .and_then(Value::as_array)
                .and_then(|policies| {
                    policies
                        .iter()
                        .find(|policy| {
                            policy
                                .get("matchedStatements")
                                .and_then(Value::as_array)
                                .is_some_and(|statements| {
                                    statements.iter().any(|statement| {
                                        statement
                                            .get("evaluatedEffect")
                                            .and_then(Value::as_str)
                                            .is_some_and(|value| {
                                                value.eq_ignore_ascii_case("EXPLICIT_DENY")
                                            })
                                    })
                                })
                        })
                        .or_else(|| policies.first())
                });
            let policy = matched
                .and_then(|item| item.get("uri"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let cause = policy
                .as_ref()
                .and_then(|uri| policy_types.get(uri))
                .map(|kind| cause_from_policy_type(kind, decision.clone()))
                .or_else(|| (decision != Decision::Allowed).then_some(DenyCause::Unknown));
            AuthorizationResult {
                action: evaluation
                    .get("action")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                resource: evaluation
                    .get("resource")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                decision,
                cause,
                policy,
                evidence_source: EvidenceSource::RequestAuthorizationDetails,
                confidence: Confidence::Verified,
                missing_context: Vec::new(),
            }
        })
        .collect()
}

fn decode_authorization_message(
    context: &AwsCommandContext,
    encoded: &str,
    timeout: Duration,
) -> Result<AuthorizationResult, String> {
    let executable = context.executable()?;
    let args = context.args_for(&[
        "sts",
        "decode-authorization-message",
        "--encoded-message",
        encoded,
        "--output",
        "json",
    ]);
    let output = run_diagnostic(executable, &args, timeout)
        .map_err(|error| format!("Could not decode the AWS authorization message: {error}"))?;
    if output.truncated {
        return Err("Decoded AWS authorization details exceeded the diagnostic limit.".to_owned());
    }
    if !output.success {
        return Err("The encoded AWS authorization message could not be decoded; sts:DecodeAuthorizationMessage might be missing.".to_owned());
    }
    let outer: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "AWS returned an unreadable decoded authorization message.".to_owned())?;
    let decoded = json_string(&outer, &["DecodedMessage", "decodedMessage"])
        .ok_or_else(|| "AWS did not return decoded authorization details.".to_owned())?;
    let value: Value = serde_json::from_str(&decoded)
        .map_err(|_| "AWS returned malformed decoded authorization details.".to_owned())?;
    let explicit = value
        .get("explicitDeny")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let allowed = value
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let context_value = value.get("context").unwrap_or(&value);
    let action = json_string(context_value, &["action"]);
    let resource = json_string(context_value, &["resource"]);
    Ok(AuthorizationResult {
        action,
        resource,
        decision: if allowed {
            Decision::Allowed
        } else if explicit {
            Decision::ExplicitDeny
        } else {
            Decision::ImplicitDeny
        },
        cause: Some(if explicit {
            DenyCause::IdentityPolicyExplicitDeny
        } else {
            DenyCause::Unknown
        }),
        policy: None,
        evidence_source: EvidenceSource::DecodedAuthorizationMessage,
        confidence: Confidence::Verified,
        missing_context: Vec::new(),
    })
}

fn simulate(
    context: &AwsCommandContext,
    identity: &AwsIdentity,
    action: &str,
    resource: &str,
    timeout: Duration,
) -> Result<AuthorizationResult, String> {
    let source = identity
        .policy_source_arn()
        .ok_or_else(|| "IAM simulation does not support this principal type.".to_owned())?;
    let executable = context.executable()?;
    let args = context.args_for(&[
        "iam",
        "simulate-principal-policy",
        "--policy-source-arn",
        &source,
        "--action-names",
        action,
        "--resource-arns",
        resource,
        "--output",
        "json",
    ]);
    let output = run_diagnostic(executable, &args, timeout)
        .map_err(|error| format!("Could not run IAM policy simulation: {error}"))?;
    if output.truncated {
        return Err("IAM policy simulation output exceeded the diagnostic limit.".to_owned());
    }
    if !output.success {
        return Err("IAM policy simulation was unavailable or not permitted.".to_owned());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "AWS returned an unreadable policy simulation.".to_owned())?;
    parse_simulation(&value, action, resource)
        .ok_or_else(|| "IAM policy simulation returned no evaluation result.".to_owned())
}

pub fn simulate_permissions(
    context: &AwsCommandContext,
    identity: &AwsIdentity,
    actions: &[String],
    resources: &[String],
    timeout: Duration,
) -> Result<Vec<AuthorizationResult>, String> {
    let source = identity.policy_source_arn().ok_or_else(|| {
        "IAM simulation supports IAM users and roles, not this principal type.".to_owned()
    })?;
    let executable = context.executable()?;
    let mut results = Vec::new();

    for resource in resources {
        for action_batch in actions.chunks(50) {
            let mut args = context.args_for(&[
                "iam",
                "simulate-principal-policy",
                "--policy-source-arn",
                &source,
                "--action-names",
            ]);
            args.extend(action_batch.iter().map(OsString::from));
            args.push("--resource-arns".into());
            args.push(resource.into());
            args.push("--max-items".into());
            args.push("1000".into());
            args.push("--output".into());
            args.push("json".into());

            let output = run_diagnostic(executable, &args, timeout)
                .map_err(|error| format!("Could not run IAM policy simulation: {error}"))?;
            if output.truncated {
                return Err(
                    "IAM policy simulation output exceeded the diagnostic limit.".to_owned(),
                );
            }
            if !output.success {
                let detail = parse_aws_error(&output.stderr);
                return Err(
                    if detail
                        .as_ref()
                        .is_some_and(|item| item.failure_kind == FailureKind::Authorization)
                    {
                        format!(
                            "IAM denied the simulation request. The caller needs iam:SimulatePrincipalPolicy for {source}."
                        )
                    } else if let Some(detail) = detail {
                        format!("IAM policy simulation failed with {}.", detail.error_code)
                    } else {
                        "IAM policy simulation failed without a readable AWS error.".to_owned()
                    },
                );
            }
            let value: Value = serde_json::from_slice(&output.stdout)
                .map_err(|_| "AWS returned an unreadable policy simulation.".to_owned())?;
            let parsed = parse_simulations(&value);
            if parsed.len() != action_batch.len() {
                return Err(format!(
                    "IAM policy simulation returned {} of {} expected evaluation results.",
                    parsed.len(),
                    action_batch.len()
                ));
            }
            results.extend(parsed);
        }
    }
    Ok(results)
}

fn parse_simulations(value: &Value) -> Vec<AuthorizationResult> {
    value
        .get("EvaluationResults")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|evaluation| {
            let action = evaluation
                .get("EvalActionName")
                .and_then(Value::as_str)
                .unwrap_or("unknown:Unknown");
            let resource = evaluation
                .get("EvalResourceName")
                .and_then(Value::as_str)
                .unwrap_or("*");
            parse_simulation_evaluation(evaluation, action, resource)
        })
        .collect()
}

fn parse_simulation(value: &Value, action: &str, resource: &str) -> Option<AuthorizationResult> {
    let evaluation = value.get("EvaluationResults")?.as_array()?.first()?;
    parse_simulation_evaluation(evaluation, action, resource)
}

fn parse_simulation_evaluation(
    evaluation: &Value,
    action: &str,
    resource: &str,
) -> Option<AuthorizationResult> {
    let decision = parse_decision(evaluation.get("EvalDecision")?.as_str()?);
    let boundary_allows = evaluation
        .pointer("/PermissionsBoundaryDecisionDetail/AllowedByPermissionsBoundary")
        .and_then(Value::as_bool);
    let organization_allows = evaluation
        .pointer("/OrganizationsDecisionDetail/AllowedByOrganizations")
        .and_then(Value::as_bool);
    let matched = evaluation
        .get("MatchedStatements")
        .and_then(Value::as_array)
        .and_then(|items| items.first());
    let policy = matched
        .and_then(|item| item.get("SourcePolicyId"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let policy_type = matched
        .and_then(|item| item.get("SourcePolicyType"))
        .and_then(Value::as_str);
    let missing_context = evaluation
        .get("MissingContextValues")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let cause = if decision == Decision::Allowed {
        None
    } else if boundary_allows == Some(false) {
        Some(DenyCause::PermissionsBoundary)
    } else if organization_allows == Some(false) {
        Some(DenyCause::ServiceControlPolicy)
    } else if !missing_context.is_empty() {
        Some(DenyCause::Condition)
    } else if let Some(kind) = policy_type {
        Some(cause_from_policy_type(kind, decision.clone()))
    } else if decision == Decision::ImplicitDeny {
        Some(DenyCause::MissingIdentityAllow)
    } else {
        Some(DenyCause::Unknown)
    };
    Some(AuthorizationResult {
        action: evaluation
            .get("EvalActionName")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| Some(action.to_owned())),
        resource: evaluation
            .get("EvalResourceName")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| Some(resource.to_owned())),
        decision,
        cause,
        policy,
        evidence_source: EvidenceSource::PolicySimulation,
        confidence: Confidence::Simulated,
        missing_context,
    })
}

fn cause_from_policy_type(kind: &str, decision: Decision) -> DenyCause {
    let lower = kind.to_lowercase();
    if lower.contains("permissions boundary") {
        DenyCause::PermissionsBoundary
    } else if lower.contains("service control") || lower == "scp" {
        DenyCause::ServiceControlPolicy
    } else if lower.contains("resource control") || lower == "rcp" {
        DenyCause::ResourceControlPolicy
    } else if lower.contains("resource") {
        DenyCause::ResourcePolicy
    } else if lower.contains("session") {
        DenyCause::SessionPolicy
    } else if lower.contains("identity") && decision == Decision::ExplicitDeny {
        DenyCause::IdentityPolicyExplicitDeny
    } else if lower.contains("identity") {
        DenyCause::MissingIdentityAllow
    } else {
        DenyCause::Unknown
    }
}

fn decision_from_message(message: &str) -> Decision {
    let lower = message.to_lowercase();
    if lower.contains("explicit deny") {
        Decision::ExplicitDeny
    } else if lower.contains("no ") && lower.contains("policy allows") {
        Decision::ImplicitDeny
    } else {
        Decision::Unknown
    }
}

fn parse_decision(value: &str) -> Decision {
    match value.to_ascii_lowercase().replace('_', "").as_str() {
        "allow" | "allowed" => Decision::Allowed,
        "explicitdeny" => Decision::ExplicitDeny,
        "implicitdeny" => Decision::ImplicitDeny,
        _ => Decision::Unknown,
    }
}

fn capture(text: &str, pattern: &str) -> Option<String> {
    Regex::new(pattern)
        .expect("valid regex")
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|item| item.as_str().trim().to_owned())
}

fn clean_error_type(value: String) -> String {
    value.rsplit('#').next().unwrap_or(&value).to_owned()
}

fn trim_sentence_punctuation(mut value: String) -> String {
    while value.ends_with(['.', ')', ']', '"', '\'']) {
        value.pop();
    }
    value
}

fn json_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(value) = map.get(*key).and_then(Value::as_str) {
                    return Some(value.to_owned());
                }
            }
            map.values().find_map(|value| json_string(value, keys))
        }
        Value::Array(items) => items.iter().find_map(|value| json_string(value, keys)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assumed_role() {
        let identity = AwsIdentity::from_arn(
            "arn:aws:sts::123456789012:assumed-role/team/DataEngineer/example-session",
        )
        .unwrap();
        assert_eq!(identity.account_id, "123456789012");
        assert_eq!(identity.role_name.as_deref(), Some("team/DataEngineer"));
        assert_eq!(identity.session_name.as_deref(), Some("example-session"));
        assert_eq!(
            identity.policy_source_arn().as_deref(),
            Some("arn:aws:iam::123456789012:role/team/DataEngineer")
        );
    }

    #[test]
    fn parses_enhanced_permissions_boundary_error() {
        let raw = br#"upload failed: ./x.csv to s3://prod-data/x.csv An error occurred (AccessDenied) when calling the PutObject operation: User: arn:aws:sts::123456789012:assumed-role/DataEngineer/example-session is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::prod-data/x.csv because no permissions boundary allows the s3:PutObject action"#;
        let error = parse_aws_error(raw).unwrap();
        assert_eq!(error.failure_kind, FailureKind::Authorization);
        assert_eq!(error.operation.as_deref(), Some("PutObject"));
        assert_eq!(error.action.as_deref(), Some("s3:PutObject"));
        assert_eq!(
            error.resource.as_deref(),
            Some("arn:aws:s3:::prod-data/x.csv")
        );
        assert_eq!(error.reported_cause, Some(DenyCause::PermissionsBoundary));
    }

    #[test]
    fn parses_json_error_and_authorization_id() {
        let raw = br#"{
          "Code": "AccessDeniedException",
          "Message": "User: arn:aws:iam::123456789012:user/example-user is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:123456789012:key/abc",
          "RequestId": "request-1",
          "AuthorizationId": "auth-1"
        }"#;
        let error = parse_aws_error(raw).unwrap();
        assert_eq!(error.request_id.as_deref(), Some("request-1"));
        assert_eq!(error.authorization_id.as_deref(), Some("auth-1"));
        assert_eq!(error.action.as_deref(), Some("kms:Decrypt"));
    }

    #[test]
    fn expired_token_is_not_authorization() {
        let raw = b"An error occurred (ExpiredToken) when calling the ListBuckets operation: The security token included in the request is expired";
        let error = parse_aws_error(raw).unwrap();
        assert_eq!(error.failure_kind, FailureKind::Authentication);
    }

    #[test]
    fn parses_cli_context_anywhere() {
        let argv = vec![
            "aws".to_owned(),
            "s3".to_owned(),
            "cp".to_owned(),
            "x".to_owned(),
            "s3://bucket/x".to_owned(),
            "--profile".to_owned(),
            "prod".to_owned(),
            "--region=us-west-2".to_owned(),
        ];
        let context = AwsCommandContext::from_argv(&argv);
        assert_eq!(context.profile.as_deref(), Some("prod"));
        assert_eq!(context.region.as_deref(), Some("us-west-2"));
        assert_eq!(context.service.as_deref(), Some("s3"));
    }

    #[test]
    fn blocks_diagnostics_for_unsigned_and_custom_endpoint_commands() {
        let unsigned = AwsCommandContext::from_argv(&[
            "aws".to_owned(),
            "s3".to_owned(),
            "ls".to_owned(),
            "--no-sign-request".to_owned(),
        ]);
        assert!(unsigned.diagnostic_block_reason().is_some());

        let custom = AwsCommandContext::from_argv(&[
            "aws".to_owned(),
            "--endpoint-url=http://localhost:4566".to_owned(),
            "s3".to_owned(),
            "ls".to_owned(),
        ]);
        assert!(custom.diagnostic_block_reason().is_some());
    }

    #[test]
    fn parses_verified_authorization_details() {
        let value: Value = serde_json::from_str(
            r#"{
              "evaluations": [{
                "action": "s3:PutObject",
                "resource": "arn:aws:s3:::prod/x",
                "evaluatedEffect": "EXPLICIT_DENY",
                "matchedPolicies": [{
                  "uri": "arn:aws:iam::123456789012:policy/Boundary",
                  "matchedStatements": [{"sid":"DenyWrite", "evaluatedEffect":"EXPLICIT_DENY"}]
                }]
              }],
              "policies": [{
                "type": "permissions boundary",
                "uri": "arn:aws:iam::123456789012:policy/Boundary",
                "inline": false,
                "attachedTo": [{"arn":"arn:aws:iam::123456789012:role/DataEngineer"}]
              }]
            }"#,
        )
        .unwrap();
        let results = parse_request_authorization_details(&value);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Decision::ExplicitDeny);
        assert_eq!(results[0].cause, Some(DenyCause::PermissionsBoundary));
        assert_eq!(results[0].confidence, Confidence::Verified);
    }

    #[test]
    fn simulation_allow_is_never_verified() {
        let value: Value = serde_json::from_str(
            r#"{"EvaluationResults":[{"EvalActionName":"s3:GetObject","EvalResourceName":"arn:aws:s3:::b/k","EvalDecision":"allowed","MatchedStatements":[],"MissingContextValues":[]}]}"#,
        )
        .unwrap();
        let result = parse_simulation(&value, "s3:GetObject", "arn:aws:s3:::b/k").unwrap();
        assert_eq!(result.decision, Decision::Allowed);
        assert_eq!(result.cause, None);
        assert_eq!(result.confidence, Confidence::Simulated);
        assert_eq!(result.evidence_source, EvidenceSource::PolicySimulation);
    }
}
