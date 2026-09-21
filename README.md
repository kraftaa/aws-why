# aws-why

`aws-why` explains failed AWS CLI commands and safely simulates permissions for IAM actions and resources.

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
aws-why can s3:GetObject --resource arn:aws:s3:::example/report.csv
aws-why permissions --service s3 --resource arn:aws:s3:::example/report.csv
```

Or use `uv`:

```console
uv tool install aws-why
```

Release wheels contain the compiled executable; Python is only the distribution mechanism. Wheels are built for macOS on Apple Silicon and Intel, Linux on ARM64 and x86-64, and Windows x86-64.

## Check permissions safely

`can` evaluates one IAM action against one or more resources without executing that action:

```console
$ aws-why can s3:GetObject --resource arn:aws:s3:::example/report.csv

SIMULATED PERMISSIONS

Identity
  account: 123456789012
  principal: DataEngineer
  session: example-session
  policy source: arn:aws:iam::123456789012:role/DataEngineer

Resource
  arn:aws:s3:::example/report.csv
  + ALLOWED  s3:GetObject

Summary: 1 allowed, 0 denied, 0 unknown
Simulation only: this does not execute the actions or prove a live request will succeed.
```

`can` exits with status `0` when every simulated result is allowed, `3` when any result is denied or unknown, and `2` when identity discovery or simulation fails. Add `--json` for machine-readable output.

`permissions` builds a resource-specific matrix. By default it retrieves the current action inventory from AWS's public Service Authorization Reference and evaluates the actions in bounded batches:

```console
aws-why permissions \
  --service s3 \
  --resource arn:aws:s3:::example/report.csv
```

Limit the matrix to selected actions when you want a shorter result or do not want to fetch the public catalog:

```console
aws-why permissions \
  --service s3 \
  --action GetObject \
  --action PutObject \
  --resource arn:aws:s3:::example/report.csv
```

Repeat `--resource` to compare the same action set across up to 25 resources. Use `--profile`, `--region`, or `--aws-cli` with either simulation command. Advanced users with permission to inspect another identity can pass an IAM user or role ARN through `--principal`.

Both commands use `iam:SimulatePrincipalPolicy`. Simulation evaluates attached identity policies and supported restrictive controls but is not a live request. It does not fetch resource policies, cannot fully reproduce role session policies or request-time context, and does not include every enforcement layer. Missing condition keys are shown in the result instead of being treated as conclusive runtime evidence.

The command after `--` is executed with exactly the supplied argument vector and inherited environment. `stdin` is inherited and human-mode `stdout` is streamed. `stderr` is held in a secure temporary file until the result is classified. On success, `aws-why` adds no output. It returns the wrapped command's exit code.

In `--json` mode, successful command output is replayed from secure temporary files. For failures, command output is replaced with one JSON diagnostic object on stdout so CI consumers can parse it reliably. Replay is capped at 64 MiB for stdout and 8 MiB for stderr; analysis retains only the final 1 MiB of stderr.

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

Diagnostic calls use the same credential environment plus the wrapped command's explicit `--profile` and `--region`, but they ignore configured custom endpoints and always use the normal AWS endpoint resolver. Follow-up calls are skipped entirely when the original command uses `--no-sign-request` or an explicit `--endpoint-url`.

Generated diagnostics redact encoded authorization payloads, common AWS access-key/token formats, and terminal control characters. The wrapped command still runs with its inherited environment and can print any data it chooses—for example, `aws sts get-session-token` prints credentials by design. Do not use `aws-why` to run an untrusted executable, and protect captured CI output as you would ordinary AWS CLI output.

AWS may require these permissions for stronger explanations:

- `sts:GetCallerIdentity`
- `iam:GetRequestAuthorizationDetails`
- `sts:DecodeAuthorizationMessage`
- `iam:SimulatePrincipalPolicy`

The `can` and `permissions` commands require `sts:GetCallerIdentity` and `iam:SimulatePrincipalPolicy`. Service-wide `permissions` also makes an unauthenticated HTTPS request to `servicereference.us-east-1.amazonaws.com`; no AWS credentials are sent to that catalog endpoint. Passing one or more explicit `--action` values skips the catalog request.

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

Tagged releases build platform-specific wheels and publish them through PyPI Trusted Publishing. Configure this repository as a trusted publisher for the `aws-why` PyPI project with environment name `pypi`, require maintainer approval on that GitHub environment, protect release tags, and push a tag matching the Cargo version. The workflow rejects tags that do not match the Cargo package version, and every third-party action is pinned to an immutable commit.
