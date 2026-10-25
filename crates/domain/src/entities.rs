use crate::{BTreeMap, BTreeSet, CaseId, DomainError};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseScope {
    LocalOnly,
    Remote {
        sources: BTreeSet<String>,
        accounts: BTreeSet<String>,
        hosts: BTreeSet<String>,
        from: String,
        to: String,
    },
}

impl CaseScope {
    /// Format: v1;sources=source1,source2;accounts=id1;hosts=host1;from=...Z;to=...Z.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let Some(rest) = value.strip_prefix("v1;") else {
            return Ok(Self::LocalOnly);
        };
        let parts = rest.split(';').collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(DomainError::InvalidScope);
        }
        let fields = parts
            .iter()
            .map(|part| part.split_once('=').ok_or(DomainError::InvalidScope))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if fields.len() != 5
            || fields
                .keys()
                .any(|key| !matches!(*key, "sources" | "accounts" | "hosts" | "from" | "to"))
        {
            return Err(DomainError::InvalidScope);
        }
        let sources = parse_scope_set(fields.get("sources").ok_or(DomainError::InvalidScope)?)?;
        let accounts = parse_scope_set(fields.get("accounts").ok_or(DomainError::InvalidScope)?)?;
        let hosts = parse_scope_set(fields.get("hosts").ok_or(DomainError::InvalidScope)?)?;
        let from = *fields.get("from").ok_or(DomainError::InvalidScope)?;
        let to = *fields.get("to").ok_or(DomainError::InvalidScope)?;
        if sources.is_empty()
            || (accounts.is_empty() && hosts.is_empty())
            || !valid_scope_time(from)
            || !valid_scope_time(to)
            || from > to
        {
            return Err(DomainError::InvalidScope);
        }
        Ok(Self::Remote {
            sources,
            accounts,
            hosts,
            from: from.to_owned(),
            to: to.to_owned(),
        })
    }

    pub fn contains(
        &self,
        source: &str,
        account: Option<&str>,
        host: Option<&str>,
        from: &str,
        to: &str,
    ) -> bool {
        let Self::Remote {
            sources,
            accounts,
            hosts,
            from: scope_from,
            to: scope_to,
        } = self
        else {
            return false;
        };
        sources.contains(source)
            && match account {
                Some(value) => accounts.contains(value),
                None => accounts.is_empty(),
            }
            && match host {
                Some(value) => hosts.contains(value),
                None => hosts.is_empty(),
            }
            && valid_scope_time(from)
            && valid_scope_time(to)
            && from <= to
            && from >= scope_from.as_str()
            && to <= scope_to.as_str()
    }

    pub fn allows_source(&self, source: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote { sources, .. } => sources.contains(source),
        }
    }

    pub fn allows_account(&self, source: &str, account: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote {
                sources,
                accounts,
                hosts,
                ..
            } => sources.contains(source) && accounts.contains(account) && hosts.is_empty(),
        }
    }

    pub fn allows_host(&self, source: &str, host: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote {
                sources,
                accounts,
                hosts,
                ..
            } => sources.contains(source) && hosts.contains(host) && accounts.is_empty(),
        }
    }
}

fn parse_scope_set(value: &str) -> Result<BTreeSet<String>, DomainError> {
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }
    let values = value.split(',').collect::<Vec<_>>();
    if values.len() > 32 || values.iter().any(|item| !valid_scope_target(item)) {
        return Err(DomainError::InvalidScope);
    }
    let set = values
        .iter()
        .map(|item| (*item).to_owned())
        .collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        return Err(DomainError::InvalidScope);
    }
    Ok(set)
}

pub(crate) fn valid_scope_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/".contains(&byte))
}

pub(crate) fn valid_scope_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
        && {
            let number = |range: std::ops::Range<usize>| {
                value.get(range).and_then(|part| part.parse::<u32>().ok())
            };
            let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
                number(0..4),
                number(5..7),
                number(8..10),
                number(11..13),
                number(14..16),
                number(17..19),
            ) else {
                return false;
            };
            let leap =
                year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
            let max_day = match month {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                _ => 0,
            };
            year > 0 && (1..=max_day).contains(&day) && hour < 24 && minute < 60 && second < 60
        }
}

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
