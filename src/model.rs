use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Authorization,
    Authentication,
    Configuration,
    Network,
    ResourceNotFound,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    AssumedRole,
    Role,
    User,
    Root,
    FederatedUser,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AwsIdentity {
    pub account_id: String,
    pub arn: String,
    pub principal_type: PrincipalType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
}

impl AwsIdentity {
    pub fn from_arn(arn: &str) -> Option<Self> {
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "iam" && parts[2] != "sts" {
            return None;
        }
        let account_id = parts[4].to_owned();
        let resource = parts[5];
        let mut identity = Self {
            account_id,
            arn: arn.to_owned(),
            principal_type: PrincipalType::Unknown,
            role_name: None,
            user_name: None,
            session_name: None,
        };
        if let Some(value) = resource.strip_prefix("assumed-role/") {
            let mut segments: Vec<&str> = value.split('/').collect();
            if segments.len() >= 2 {
                identity.session_name = segments.pop().map(str::to_owned);
                identity.role_name = Some(segments.join("/"));
                identity.principal_type = PrincipalType::AssumedRole;
            }
        } else if let Some(value) = resource.strip_prefix("role/") {
            identity.role_name = Some(value.to_owned());
            identity.principal_type = PrincipalType::Role;
        } else if let Some(value) = resource.strip_prefix("user/") {
            identity.user_name = Some(value.to_owned());
            identity.principal_type = PrincipalType::User;
        } else if let Some(value) = resource.strip_prefix("federated-user/") {
            identity.user_name = Some(value.to_owned());
            identity.principal_type = PrincipalType::FederatedUser;
        } else if resource == "root" {
            identity.principal_type = PrincipalType::Root;
        }
        Some(identity)
    }

    pub fn display_name(&self) -> &str {
        self.role_name
            .as_deref()
            .or(self.user_name.as_deref())
            .unwrap_or(self.arn.as_str())
    }

    pub fn policy_source_arn(&self) -> Option<String> {
        match self.principal_type {
            PrincipalType::AssumedRole => self
                .role_name
                .as_ref()
                .map(|name| format!("arn:aws:iam::{}:role/{name}", self.account_id)),
            PrincipalType::Role | PrincipalType::User => Some(self.arn.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    ExplicitDeny,
    ImplicitDeny,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyCause {
    MissingIdentityAllow,
    IdentityPolicyExplicitDeny,
    PermissionsBoundary,
    ServiceControlPolicy,
    ResourceControlPolicy,
    ResourcePolicy,
    SessionPolicy,
    VpcEndpointPolicy,
    RoleTrustPolicy,
    KmsKeyPolicy,
    Condition,
    Unknown,
}

impl DenyCause {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MissingIdentityAllow => "no identity-based policy allows the action",
            Self::IdentityPolicyExplicitDeny => {
                "an identity-based policy explicitly denies the action"
            }
            Self::PermissionsBoundary => "a permissions boundary blocks the action",
            Self::ServiceControlPolicy => "a service control policy blocks the action",
            Self::ResourceControlPolicy => "a resource control policy blocks the action",
            Self::ResourcePolicy => "a resource-based policy blocks the action",
            Self::SessionPolicy => "a session policy blocks the action",
            Self::VpcEndpointPolicy => "a VPC endpoint policy blocks the action",
            Self::RoleTrustPolicy => "the role trust policy blocks the action",
            Self::KmsKeyPolicy => "the KMS key policy blocks the action",
            Self::Condition => "a policy condition was not satisfied",
            Self::Unknown => "the exact denial reason is unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    RequestAuthorizationDetails,
    DecodedAuthorizationMessage,
    AwsError,
    PolicySimulation,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Verified,
    Reported,
    Simulated,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<DenyCause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    pub evidence_source: EvidenceSource,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_context: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsErrorEvidence {
    pub service: Option<String>,
    pub operation: Option<String>,
    pub action: Option<String>,
    pub error_code: String,
    pub message: String,
    pub request_id: Option<String>,
    pub authorization_id: Option<String>,
    pub encoded_authorization_message: Option<String>,
    pub resource: Option<String>,
    pub principal_arn: Option<String>,
    pub reported_cause: Option<DenyCause>,
    pub reported_policy: Option<String>,
    pub failure_kind: FailureKind,
    pub raw_error: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorSummary {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub result: &'static str,
    pub exit_code: i32,
    pub failure_kind: FailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<AwsIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization: Vec<AuthorizationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl AnalysisReport {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        exit_code: i32,
        failure_kind: FailureKind,
        identity: Option<AwsIdentity>,
        evidence: Option<AwsErrorEvidence>,
        authorization: Vec<AuthorizationResult>,
        notes: Vec<String>,
        credential_source: Option<String>,
    ) -> Self {
        let result = match failure_kind {
            FailureKind::Authorization => "denied",
            FailureKind::Authentication => "authentication_failure",
            FailureKind::Configuration => "configuration_failure",
            FailureKind::Network => "network_failure",
            FailureKind::ResourceNotFound => "not_found",
            FailureKind::Other => "failed",
        };
        let error = evidence.as_ref().map(|item| ErrorSummary {
            code: item.error_code.clone(),
            message: redact_sensitive(&item.message),
            request_id: item.request_id.clone(),
        });
        Self {
            result,
            exit_code,
            failure_kind,
            identity,
            error,
            authorization,
            credential_source,
            notes,
        }
    }
}

fn redact_sensitive(input: &str) -> String {
    let mut output = input.to_owned();
    for marker in [
        "Encoded authorization failure message:",
        "encoded authorization failure message:",
    ] {
        let mut search_from = 0;
        while let Some(relative_start) = output[search_from..].find(marker) {
            let start = search_from + relative_start;
            let after_marker = start + marker.len();
            let leading_space = output[after_marker..]
                .find(|character: char| !character.is_whitespace())
                .unwrap_or(output.len() - after_marker);
            let value_start = after_marker + leading_space;
            let value_end = output[value_start..]
                .find(char::is_whitespace)
                .map(|offset| value_start + offset)
                .unwrap_or(output.len());
            output.replace_range(value_start..value_end, "[REDACTED]");
            search_from = value_start + "[REDACTED]".len();
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive;

    #[test]
    fn redacts_encoded_authorization_payloads() {
        assert_eq!(
            redact_sensitive("Encoded authorization failure message: very-long-token"),
            "Encoded authorization failure message: [REDACTED]"
        );
    }
}
