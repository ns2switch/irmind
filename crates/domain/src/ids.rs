#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CaseId(String);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AgentId(String);

impl AgentId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DomainError::InvalidId);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Actor {
    Analyst,
    Agent(AgentId),
}

impl Actor {
    pub fn as_storage(&self) -> String {
        match self {
            Self::Analyst => "analyst".into(),
            Self::Agent(id) => format!("agent:{}", id.as_str()),
        }
    }
    pub fn parse_storage(value: &str) -> Result<Self, DomainError> {
        if value == "analyst" {
            return Ok(Self::Analyst);
        }
        value
            .strip_prefix("agent:")
            .map(AgentId::parse)
            .transpose()?
            .map(Self::Agent)
            .ok_or(DomainError::InvalidId)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Attended,
    Unattended,
}

impl CaseId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.len() != 36 || !value.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Err(DomainError::InvalidId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidId,
    UnknownTool,
    InvalidApproval,
    InvalidPolicy,
    InvalidScope,
    InvalidSeverity,
    UnknownAuditEvent,
}
