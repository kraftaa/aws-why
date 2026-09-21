use std::time::Duration;

use serde::Deserialize;

const SERVICE_INDEX_URL: &str =
    "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json";
const SERVICE_REFERENCE_ORIGIN: &str = "https://servicereference.us-east-1.amazonaws.com/";
const SERVICE_REFERENCE_LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct ServiceIndexEntry {
    service: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct ServiceReference {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Actions")]
    actions: Vec<ServiceAction>,
}

#[derive(Debug, Deserialize)]
struct ServiceAction {
    #[serde(rename = "Name")]
    name: String,
}

pub fn normalize_service(service: &str) -> Result<String, String> {
    let normalized = service.to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err(
            "Service must be an IAM service prefix such as s3, ec2, or secretsmanager.".to_owned(),
        );
    }
    Ok(normalized)
}

pub fn normalize_action(action: &str, expected_service: Option<&str>) -> Result<String, String> {
    let normalized = match action.split_once(':') {
        Some((service, name)) => {
            let service = normalize_service(service)?;
            if name.is_empty()
                || !name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
            {
                return Err(format!("Invalid IAM action: {action}"));
            }
            if let Some(expected) = expected_service
                && service != expected
            {
                return Err(format!(
                    "Action {action} does not belong to requested service {expected}."
                ));
            }
            format!("{service}:{name}")
        }
        None => {
            let service = expected_service.ok_or_else(|| {
                format!("Action must include its service prefix, for example s3:{action}.")
            })?;
            if action.is_empty()
                || !action
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
            {
                return Err(format!("Invalid IAM action: {action}"));
            }
            format!("{service}:{action}")
        }
    };
    Ok(normalized)
}

pub fn normalize_resources(resources: Vec<String>) -> Result<Vec<String>, String> {
    if resources.len() > 25 {
        return Err("At most 25 resources can be simulated in one command.".to_owned());
    }
    let resources = if resources.is_empty() {
        vec!["*".to_owned()]
    } else {
        resources
    };
    for resource in &resources {
        if resource.is_empty() || resource.len() > 2048 || resource.chars().any(char::is_control) {
            return Err(
                "Each resource must be * or a non-empty ARN of at most 2048 characters.".to_owned(),
            );
        }
    }
    Ok(resources)
}

pub fn fetch_service_actions(service: &str, timeout: Duration) -> Result<Vec<String>, String> {
    let service = normalize_service(service)?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build();
    let agent: ureq::Agent = config.into();
    let index_body = get_text(&agent, SERVICE_INDEX_URL)?;
    let index: Vec<ServiceIndexEntry> = serde_json::from_str(&index_body)
        .map_err(|_| "AWS returned an unreadable service-reference index.".to_owned())?;
    let entry = index
        .into_iter()
        .find(|entry| entry.service == service)
        .ok_or_else(|| {
            format!("AWS Service Authorization Reference has no service named {service}.")
        })?;
    if !entry.url.starts_with(SERVICE_REFERENCE_ORIGIN) {
        return Err("AWS service-reference index returned an unexpected URL.".to_owned());
    }
    let reference_body = get_text(&agent, &entry.url)?;
    let reference: ServiceReference = serde_json::from_str(&reference_body)
        .map_err(|_| format!("AWS returned unreadable authorization data for {service}."))?;
    if !reference.name.eq_ignore_ascii_case(&service) {
        return Err(
            "AWS service-reference response did not match the requested service.".to_owned(),
        );
    }
    let mut actions = reference
        .actions
        .into_iter()
        .map(|action| format!("{service}:{}", action.name))
        .collect::<Vec<_>>();
    actions.sort_unstable();
    actions.dedup();
    if actions.is_empty() {
        return Err(format!("AWS listed no IAM actions for {service}."));
    }
    Ok(actions)
}

fn get_text(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    let mut response = agent.get(url).call().map_err(|error| {
        format!("Could not retrieve AWS Service Authorization Reference: {error}")
    })?;
    response
        .body_mut()
        .with_config()
        .limit(SERVICE_REFERENCE_LIMIT)
        .read_to_string()
        .map_err(|error| format!("Could not read AWS Service Authorization Reference: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{normalize_action, normalize_service};

    #[test]
    fn normalizes_actions_with_and_without_prefixes() {
        assert_eq!(
            normalize_action("GetObject", Some("s3")).unwrap(),
            "s3:GetObject"
        );
        assert_eq!(
            normalize_action("s3:PutObject", Some("s3")).unwrap(),
            "s3:PutObject"
        );
        assert!(normalize_action("iam:ListUsers", Some("s3")).is_err());
    }

    #[test]
    fn rejects_service_url_injection() {
        assert!(normalize_service("s3/../../example").is_err());
        assert!(normalize_service("S3").is_ok());
    }
}
