#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn fake_aws() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("aws");
    fs::write(
        &path,
        r#"#!/bin/sh
args="$*"
case "$args" in
  *"sts get-caller-identity"*)
    if [ "${AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:-}" != "true" ]; then
      printf 'diagnostic did not disable custom endpoints\n' >&2
      exit 90
    fi
    printf '%s\n' '{"UserId":"id","Account":"111111111111","Arn":"arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session"}'
    exit 0
    ;;
  *"iam simulate-principal-policy"*)
    case "${FAKE_SIMULATION:-denied}" in
      allowed)
        printf '%s\n' '{"EvaluationResults":[{"EvalActionName":"s3:GetObject","EvalResourceName":"arn:aws:s3:::example/key","EvalDecision":"allowed","MatchedStatements":[{"SourcePolicyId":"ReadPolicy","SourcePolicyType":"IAM Policy"}],"MissingContextValues":[],"PermissionsBoundaryDecisionDetail":{"AllowedByPermissionsBoundary":true},"OrganizationsDecisionDetail":{"AllowedByOrganizations":true}}]}'
        exit 0
        ;;
      matrix)
        printf '%s\n' '{"EvaluationResults":[{"EvalActionName":"s3:GetObject","EvalResourceName":"arn:aws:s3:::example/key","EvalDecision":"allowed","MatchedStatements":[{"SourcePolicyId":"ReadPolicy","SourcePolicyType":"IAM Policy"}],"MissingContextValues":[]},{"EvalActionName":"s3:PutObject","EvalResourceName":"arn:aws:s3:::example/key","EvalDecision":"implicitDeny","MatchedStatements":[],"MissingContextValues":["aws:RequestedRegion"]}]}'
        exit 0
        ;;
      *)
        printf '%s\n' '{"Code":"AccessDenied","Message":"not authorized to perform: iam:SimulatePrincipalPolicy because no identity-based policy allows the iam:SimulatePrincipalPolicy action"}' >&2
        exit 254
        ;;
    esac
    ;;
esac

case "${FAKE_SCENARIO:-success}" in
  success)
    printf 'command output\n'
    exit 0
    ;;
  success_stderr)
    printf 'command output\n'
    printf 'command warning\n' >&2
    exit 0
    ;;
  boundary)
    printf '%s\n' 'An error occurred (AccessDenied) when calling the PutObject operation: User: arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::prod-data/x.csv because no permissions boundary allows the s3:PutObject action' >&2
    exit 254
    ;;
  expired)
    printf '%s\n' 'An error occurred (ExpiredToken) when calling the ListBuckets operation: The security token included in the request is expired' >&2
    exit 254
    ;;
  unknown)
    printf '%s\n' 'An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::prod-data/x.csv' >&2
    exit 254
    ;;
  missing_get)
    printf '%s\n' 'An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:sts::111111111111:assumed-role/AnalyticsDeveloper/example-session is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::company-prod/orders.parquet because no identity-based policy allows the s3:GetObject action' >&2
    exit 254
    ;;
  kms_list)
    printf '%s\n' 'An error occurred (AccessDeniedException) when calling the ListKeys operation: User: arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session is not authorized to perform: kms:ListKeys on resource: * because no identity-based policy allows the kms:ListKeys action' >&2
    exit 254
    ;;
  scp)
    printf '%s\n' 'An error occurred (AccessDenied) when calling the PutObject operation: User: arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::prod-data/x.csv with an explicit deny in a service control policy: arn:aws:organizations::999999999999:policy/o-example/service_control_policy/p-guardrail' >&2
    exit 254
    ;;
  kms_dependency)
    printf '%s\n' 'An error occurred (AccessDeniedException) when calling the GetSecretValue operation: User: arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:111111111111:key/abc because no identity-based policy allows the kms:Decrypt action' >&2
    exit 254
    ;;
  cross_account)
    printf '%s\n' 'An error occurred (AccessDeniedException) when calling the GetSecretValue operation: User: arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session is not authorized to perform: secretsmanager:GetSecretValue on resource: arn:aws:secretsmanager:us-east-1:222222222222:secret:prod because no identity-based policy allows the secretsmanager:GetSecretValue action' >&2
    exit 254
    ;;
  unsigned)
    printf '%s\n' 'An error occurred (AccessDenied) when calling the GetObject operation: not authorized to perform: s3:GetObject on resource: arn:aws:s3:::public-data/x.csv because no identity-based policy allows the s3:GetObject action' >&2
    exit 254
    ;;
  encoded)
    printf '%s\n' 'An error occurred (UnauthorizedOperation) when calling the RunInstances operation: not authorized to perform: ec2:RunInstances because no identity-based policy allows the ec2:RunInstances action. Encoded authorization failure message: SUPERSECRETENCODEDPAYLOAD' >&2
    exit 254
    ;;
esac
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
    directory
}

fn invoke(scenario: &str, json: bool) -> Output {
    invoke_with_args(scenario, json, &[])
}

fn invoke_with_args(scenario: &str, json: bool, extra: &[&str]) -> Output {
    let directory = fake_aws();
    let aws = directory.path().join("aws");
    let mut command = Command::new(env!("CARGO_BIN_EXE_aws-why"));
    command.arg("run");
    if json {
        command.arg("--json");
    }
    command.args([
        "--",
        aws.to_str().unwrap(),
        "s3",
        "cp",
        "x.csv",
        "s3://prod-data/x.csv",
    ]);
    command.args(extra);
    command.env("FAKE_SCENARIO", scenario).output().unwrap()
}

fn invoke_verbose(scenario: &str) -> Output {
    let directory = fake_aws();
    let aws = directory.path().join("aws");
    Command::new(env!("CARGO_BIN_EXE_aws-why"))
        .args([
            "run",
            "--verbose",
            "--",
            aws.to_str().unwrap(),
            "s3",
            "cp",
            "x.csv",
            "s3://prod-data/x.csv",
        ])
        .env("FAKE_SCENARIO", scenario)
        .output()
        .unwrap()
}

#[test]
fn successful_command_is_transparent_and_quiet() {
    let output = invoke("success", false);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"command output\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn successful_json_command_replays_both_streams() {
    let output = invoke("success_stderr", true);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"command output\n");
    assert_eq!(output.stderr, b"command warning\n");
}

#[test]
fn identifies_boundary_from_live_error() {
    let output = invoke("boundary", false);
    assert_eq!(output.status.code(), Some(254));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("DENIED: s3:PutObject"));
    assert!(stderr.contains("s3:PutObject"));
    assert!(stderr.contains("a permissions boundary blocks the action"));
    assert!(stderr.contains("NEXT STEP"));
    assert!(!stderr.contains("Evidence"));
}

#[test]
fn expired_token_is_not_described_as_iam() {
    let output = invoke("expired", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("AUTHENTICATION FAILURE"));
    assert!(stderr.contains("This is not evidence that an IAM permission is missing."));
    assert!(!stderr.contains("ACCESS DENIED\n\nIdentity"));
}

#[test]
fn insufficient_evidence_is_unknown() {
    let output = invoke("unknown", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("the exact denial reason is unknown"));
    assert!(stderr.contains("simulation was unavailable or not permitted"));
}

#[test]
fn points_out_cross_account_profile_mismatch() {
    let output = invoke("cross_account", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(
            "Caller account 111111111111 differs from target resource account 222222222222"
        )
    );
}

#[test]
fn names_missing_s3_permission() {
    let output = invoke("missing_get", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("s3:GetObject"));
    assert!(stderr.contains("no identity-based policy allows the action"));
    assert!(stderr.contains("arn:aws:s3:::company-prod/orders.parquet"));
}

#[test]
fn turns_conclusive_denial_into_an_admin_handoff() {
    let output = invoke("kms_list", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("DENIED: kms:ListKeys on *"));
    assert!(stderr.contains("arn:aws:iam::111111111111:role/DataEngineer"));
    assert!(stderr.contains("ASK YOUR ADMIN FOR"));
    assert!(stderr.contains("\"Action\": \"kms:ListKeys\""));
    assert!(stderr.contains("\"Resource\": \"*\""));
    assert!(!stderr.contains("Evidence"));
    assert!(!stderr.contains("Credential source"));
    assert!(!stderr.contains("session:"));
    assert!(!stderr.contains("could not obtain complete AWS authorization details"));
}

#[test]
fn verbose_mode_keeps_forensic_details() {
    let output = invoke_verbose("kms_list");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("ACCESS DENIED: kms:ListKeys on *"));
    assert!(stderr.contains("session: example-session"));
    assert!(stderr.contains("Evidence"));
    assert!(stderr.contains("AWS error response (reported by AWS)"));
    assert!(stderr.contains("Credential source"));
    assert!(stderr.contains("Administrator handoff"));
}

#[test]
fn identifies_scp_and_does_not_recommend_another_allow() {
    let output = invoke("scp", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("a service control policy blocks the action"));
    assert!(stderr.contains("p-guardrail"));
    assert!(!stderr.contains("add an Allow"));
    assert!(!stderr.contains("Candidate policy"));
}

#[test]
fn identifies_kms_dependency_from_secrets_manager_failure() {
    let output = invoke("kms_dependency", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("kms:Decrypt"));
    assert!(stderr.contains("arn:aws:kms:us-east-1:111111111111:key/abc"));
    assert!(!stderr.contains("secretsmanager:GetSecretValue\n\nResource"));
}

#[test]
fn json_mode_emits_one_machine_readable_failure() {
    let output = invoke("boundary", true);
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["result"], "denied");
    assert_eq!(value["identity"]["role_name"], "DataEngineer");
    assert_eq!(value["authorization"][0]["action"], "s3:PutObject");
    assert_eq!(value["authorization"][0]["cause"], "permissions_boundary");
    assert_eq!(value["authorization"][0]["confidence"], "reported");
    assert_eq!(
        value["remediation"][0]["guidance"],
        "An identity-policy Allow alone will not fix this. Ask the boundary owner to permit the action, then verify the identity policy also allows it."
    );
    assert!(value["remediation"][0]["candidate_policy"].is_null());
}

#[test]
fn unsigned_command_never_triggers_credentialed_diagnostics() {
    let output = invoke_with_args("unsigned", false, &["--no-sign-request"]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("skipped because the command used --no-sign-request"));
    assert!(!stderr.contains("Identity\n"));
    assert!(!stderr.contains("Candidate policy"));
}

#[test]
fn custom_endpoint_command_never_triggers_follow_up_calls() {
    let output = invoke_with_args(
        "unsigned",
        false,
        &["--endpoint-url", "http://localhost:4566"],
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("skipped because the command used a custom endpoint"));
    assert!(!stderr.contains("Identity\n"));
    assert!(!stderr.contains("Candidate policy"));
}

#[test]
fn raw_encoded_authorization_payload_is_not_replayed() {
    let output = invoke("encoded", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("DENIED"));
    assert!(!stderr.contains("SUPERSECRETENCODEDPAYLOAD"));
}

#[test]
fn can_reports_an_allowed_simulation_and_returns_success() {
    let directory = fake_aws();
    let aws = directory.path().join("aws");
    let output = Command::new(env!("CARGO_BIN_EXE_aws-why"))
        .args([
            "can",
            "s3:GetObject",
            "--resource",
            "arn:aws:s3:::example/key",
            "--aws-cli",
            aws.to_str().unwrap(),
        ])
        .env("FAKE_SIMULATION", "allowed")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SIMULATED PERMISSIONS"));
    assert!(stdout.contains("ALLOWED"));
    assert!(stdout.contains("s3:GetObject"));
    assert!(stdout.contains("Simulation only"));
}

#[test]
fn permissions_reports_a_matrix_without_fetching_when_actions_are_given() {
    let directory = fake_aws();
    let aws = directory.path().join("aws");
    let output = Command::new(env!("CARGO_BIN_EXE_aws-why"))
        .args([
            "permissions",
            "--service",
            "s3",
            "--action",
            "GetObject",
            "--action",
            "PutObject",
            "--resource",
            "arn:aws:s3:::example/key",
            "--aws-cli",
            aws.to_str().unwrap(),
        ])
        .env("FAKE_SIMULATION", "matrix")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("s3:GetObject"));
    assert!(stdout.contains("s3:PutObject"));
    assert!(stdout.contains("1 allowed, 1 denied, 0 unknown"));
    assert!(stdout.contains("missing context: aws:RequestedRegion"));
}

#[test]
fn simulation_permission_failure_is_actionable() {
    let directory = fake_aws();
    let aws = directory.path().join("aws");
    let output = Command::new(env!("CARGO_BIN_EXE_aws-why"))
        .args(["can", "s3:GetObject", "--aws-cli", aws.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("needs iam:SimulatePrincipalPolicy"));
}
