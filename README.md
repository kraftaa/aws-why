# aws-why

`aws-why` runs an AWS CLI command unchanged. If the command fails, it classifies the failure and explains an authorization denial using the strongest evidence AWS made available.

```console
$ aws-why run -- aws s3 cp test.csv s3://prod-data/test.csv
upload failed: ... AccessDenied ...

ACCESS DENIED

Identity
  account: 123456789012
  principal: DataEngineer
  session: example-session

Failed operation
  s3:PutObject

Resource
  arn:aws:s3:::prod-data/test.csv

Cause
  a permissions boundary blocks the action

Evidence
  AWS error response (reported by AWS)
```

The tool does not treat every AWS failure as IAM. Expired credentials, missing configuration, network errors, and missing resources get distinct results.

## Install and use

The normal installation does not require Rust or Cargo. Install the native executable in an isolated environment with `pipx`:

```console
pipx install aws-why
aws-why run -- aws sts get-caller-identity
aws-why run --json -- aws s3api get-object --bucket example --key report.csv report.csv
```

Or use `uv`:

```console
uv tool install aws-why
```

Release wheels contain the compiled executable; Python is only the distribution mechanism. Wheels are built for macOS on Apple Silicon and Intel, Linux on ARM64 and x86-64, and Windows x86-64.

The command after `--` is executed with exactly the supplied argument vector and inherited environment. `stdin` is inherited; `stdout` and `stderr` are streamed and captured. On success, `aws-why` adds no output. It returns the wrapped command's exit code.

In `--json` mode, successful command output is replayed unchanged. For failures, command output is captured and replaced with one JSON diagnostic object on stdout so CI consumers can parse it reliably.

Each follow-up AWS call has a five-second timeout by default. Change it with `--diagnostic-timeout <seconds>`.

## Evidence hierarchy

`aws-why` stops at the first useful source:

1. AWS `GetRequestAuthorizationDetails`, when the error contains an authorization ID and the API is supported and permitted.
2. An encoded authorization message decoded through STS.
3. The AWS service's denial message.
4. IAM principal-policy simulation when identity, action, and resource are known.
5. `UNKNOWN`.

Every action/resource result has its own evidence source and confidence:

- `verified`: AWS returned the authorization evaluation for the live request.
- `reported`: the live AWS error explicitly named the cause.
- `simulated`: IAM simulation produced the result but did not reproduce the request.
- `incomplete`: there was not enough evidence for an exact cause.

Simulation is never presented as proof that the live request will succeed. It can omit live request conditions, resource policies, endpoint policies, role chaining, and other enforcement layers.

## AWS context and diagnostic permissions

Diagnostic calls use the same process environment plus the wrapped command's explicit `--profile` and `--region`. The tool never prints environment variables, credentials, or decoded authorization payloads. Raw command errors are retained only in memory for the duration of the process.

AWS may require these permissions for stronger explanations:

- `sts:GetCallerIdentity`
- `iam:GetRequestAuthorizationDetails`
- `sts:DecodeAuthorizationMessage`
- `iam:SimulatePrincipalPolicy`

The original command still runs if none of those diagnostic permissions are available; the result simply becomes less specific.

## Current scope

The action/resource parser is intentionally optimized for S3, Secrets Manager, KMS, IAM, and STS. AWS authorization IDs are not currently returned by every service or API. Cross-organization details can also be withheld by AWS. In those cases, `aws-why` reports the known identity/action/resource and says that the exact denial reason is unknown.

`aws-why` recognizes only a direct `aws` executable. Shell pipelines and commands such as `sh -c 'aws ...'` still execute, but follow-up AWS diagnostics are not attempted because their effective AWS context cannot be recovered safely.

## Development

```console
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
maturin build --release --bindings bin
```

The end-to-end tests use a temporary fake AWS executable and never contact AWS.

Tagged releases build platform-specific wheels and publish them through PyPI Trusted Publishing. Before the first public release, configure this repository as a trusted publisher for the `aws-why` PyPI project with environment name `pypi`, add the eventual repository URLs to `pyproject.toml`, and push a tag matching the Cargo version, such as `v0.1.0`.
