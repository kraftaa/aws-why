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
    printf '%s\n' '{"UserId":"id","Account":"111111111111","Arn":"arn:aws:sts::111111111111:assumed-role/DataEngineer/example-session"}'
    exit 0
    ;;
  *"iam simulate-principal-policy"*)
    printf '%s\n' '{"Code":"AccessDenied","Message":"simulation not permitted"}' >&2
    exit 254
    ;;
esac

case "${FAKE_SCENARIO:-success}" in
  success)
    printf 'command output\n'
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
    let directory = fake_aws();
    let aws = directory.path().join("aws");
    let mut command = Command::new(env!("CARGO_BIN_EXE_aws-why"));
    command.arg("run");
    if json {
        command.arg("--json");
    }
    command
        .args([
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
fn identifies_boundary_from_live_error() {
    let output = invoke("boundary", false);
    assert_eq!(output.status.code(), Some(254));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("ACCESS DENIED"));
    assert!(stderr.contains("s3:PutObject"));
    assert!(stderr.contains("a permissions boundary blocks the action"));
    assert!(stderr.contains("AWS error response (reported by AWS)"));
    assert!(!stderr.contains("Not a guess"));
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
    assert!(stderr.contains("incomplete"));
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
fn identifies_scp_and_does_not_recommend_another_allow() {
    let output = invoke("scp", false);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("a service control policy blocks the action"));
    assert!(stderr.contains("p-guardrail"));
    assert!(!stderr.contains("add an Allow"));
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
}
