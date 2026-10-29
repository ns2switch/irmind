use crate::{CaseId, DomainError};

mod scope;
pub use scope::CaseScope;
pub(crate) use scope::{valid_object_scope, valid_scope_target, valid_scope_time};

#[derive(Clone, Debug)]
pub struct Case {
    pub id: CaseId,
    pub title: String,
    pub severity: Severity,
    pub scope: String,
    pub sealed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(DomainError::InvalidSeverity),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Explicit remote scope. Free-form legacy scope text is always local-only.
/// Deterministic entity extraction from known structured log fields.
pub fn classify_field(key: &str, value: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    if value.is_empty() || value.len() > 512 {
        return None;
    }
    if key.contains("ipaddress") || key == "ip" || key.ends_with("_ip") {
        return Some("ip");
    }
    if key.contains("hostname") || key == "host" || key.ends_with("_host") {
        return Some("host");
    }
    if key.contains("username") || key == "user" || key == "principalid" {
        return Some("user");
    }
    if key == "arn" {
        return Some(if value.contains(":role/") {
            "role"
        } else {
            "identity"
        });
    }
    if key.contains("domain") {
        return Some("domain");
    }
    if key.contains("sha256") || key.contains("sha1") || key == "md5" {
        return Some("hash");
    }
    if key == "accesskeyid" {
        return Some("key");
    }
    if key.contains("accountid") {
        return Some("account");
    }
    None
}
