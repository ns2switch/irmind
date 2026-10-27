use crate::{BTreeMap, BTreeSet, DomainError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseScope {
    LocalOnly,
    Remote {
        version: u8,
        sources: BTreeSet<String>,
        accounts: BTreeSet<String>,
        projects: BTreeSet<String>,
        hosts: BTreeSet<String>,
        from: String,
        to: String,
    },
}

impl CaseScope {
    /// Format: v1;sources=source1,source2;accounts=id1;hosts=host1;from=...Z;to=...Z.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let version = if value.starts_with("v2;") { 2 } else { 1 };
        let Some(rest) = value.strip_prefix(if version == 2 { "v2;" } else { "v1;" }) else {
            return Ok(Self::LocalOnly);
        };
        let parts = rest.split(';').collect::<Vec<_>>();
        if parts.len() != if version == 2 { 6 } else { 5 } {
            return Err(DomainError::InvalidScope);
        }
        let fields = parts
            .iter()
            .map(|part| part.split_once('=').ok_or(DomainError::InvalidScope))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if fields.len() != parts.len()
            || fields.keys().any(|key| {
                !matches!(
                    *key,
                    "sources" | "accounts" | "projects" | "hosts" | "from" | "to"
                )
            })
            || (version == 1 && fields.contains_key("projects"))
            || (version == 2 && !fields.contains_key("projects"))
        {
            return Err(DomainError::InvalidScope);
        }
        let sources = parse_scope_set(fields.get("sources").ok_or(DomainError::InvalidScope)?)?;
        let accounts = parse_scope_set(fields.get("accounts").ok_or(DomainError::InvalidScope)?)?;
        let projects = parse_scope_set(fields.get("projects").copied().unwrap_or(""))?;
        let hosts = parse_scope_set(fields.get("hosts").ok_or(DomainError::InvalidScope)?)?;
        let from = *fields.get("from").ok_or(DomainError::InvalidScope)?;
        let to = *fields.get("to").ok_or(DomainError::InvalidScope)?;
        if sources.is_empty()
            || (accounts.is_empty() && projects.is_empty() && hosts.is_empty())
            || !valid_scope_time(from)
            || !valid_scope_time(to)
            || from > to
        {
            return Err(DomainError::InvalidScope);
        }
        Ok(Self::Remote {
            version,
            sources,
            accounts,
            projects,
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
            version,
            sources,
            accounts,
            projects,
            hosts,
            from: scope_from,
            to: scope_to,
        } = self
        else {
            return false;
        };
        (account.is_some() || host.is_some())
            && sources.contains(source)
            && match account {
                Some(value) => {
                    accounts.contains(value)
                        && (*version == 2 || (projects.is_empty() && hosts.is_empty()))
                }
                None => *version == 2 || (accounts.is_empty() && projects.is_empty()),
            }
            && match host {
                Some(value) => {
                    hosts.contains(value)
                        && (*version == 2 || (accounts.is_empty() && projects.is_empty()))
                }
                None => *version == 2 || hosts.is_empty(),
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

    pub fn contains_project(&self, source: &str, project: &str, from: &str, to: &str) -> bool {
        let Self::Remote {
            version,
            sources,
            accounts,
            projects,
            hosts,
            from: scope_from,
            to: scope_to,
        } = self
        else {
            return false;
        };
        sources.contains(source)
            && (*version == 2 || (accounts.is_empty() && hosts.is_empty()))
            && projects.contains(project)
            && valid_scope_time(from)
            && valid_scope_time(to)
            && from <= to
            && from >= scope_from.as_str()
            && to <= scope_to.as_str()
    }

    pub fn allows_project(&self, source: &str, project: &str) -> bool {
        matches!(self, Self::Remote { version, sources, accounts, projects, hosts, .. }
            if sources.contains(source) && (*version == 2 || (accounts.is_empty() && hosts.is_empty())) && projects.contains(project))
    }

    pub fn allows_account(&self, source: &str, account: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote {
                version,
                sources,
                accounts,
                projects,
                hosts,
                ..
            } => {
                sources.contains(source)
                    && accounts.contains(account)
                    && (*version == 2 || (projects.is_empty() && hosts.is_empty()))
            }
        }
    }

    pub fn allows_host(&self, source: &str, host: &str) -> bool {
        match self {
            Self::LocalOnly => false,
            Self::Remote {
                version,
                sources,
                accounts,
                projects,
                hosts,
                ..
            } => {
                sources.contains(source)
                    && hosts.contains(host)
                    && (*version == 2 || (accounts.is_empty() && projects.is_empty()))
            }
        }
    }

    pub fn extend_target(&self, field: &str, value: &str) -> Result<Self, DomainError> {
        if !valid_scope_target(value) {
            return Err(DomainError::InvalidScope);
        }
        let Self::Remote {
            version: _,
            sources,
            accounts,
            projects,
            hosts,
            from,
            to,
        } = self
        else {
            return Err(DomainError::InvalidScope);
        };
        let mut expanded = Self::Remote {
            version: 2,
            sources: sources.clone(),
            accounts: accounts.clone(),
            projects: projects.clone(),
            hosts: hosts.clone(),
            from: from.clone(),
            to: to.clone(),
        };
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            ..
        } = &mut expanded
        else {
            return Err(DomainError::InvalidScope);
        };
        match field {
            "source" => {
                sources.insert(value.to_owned());
            }
            "account" => {
                accounts.insert(value.to_owned());
            }
            "project" => {
                projects.insert(value.to_owned());
            }
            "host" => {
                hosts.insert(value.to_owned());
            }
            _ => return Err(DomainError::InvalidScope),
        }
        Self::parse(&expanded.to_v2_string()?)
    }

    pub fn expand_window(&self, from: &str, to: &str) -> Result<Self, DomainError> {
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            from: old_from,
            to: old_to,
            ..
        } = self
        else {
            return Err(DomainError::InvalidScope);
        };
        if !valid_scope_time(from)
            || !valid_scope_time(to)
            || from > old_from
            || to < old_to
            || from > to
        {
            return Err(DomainError::InvalidScope);
        }
        Self::parse(&format!(
            "v2;sources={};accounts={};projects={};hosts={};from={from};to={to}",
            join_scope_set(sources),
            join_scope_set(accounts),
            join_scope_set(projects),
            join_scope_set(hosts)
        ))
    }

    pub fn to_v2_string(&self) -> Result<String, DomainError> {
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            from,
            to,
            ..
        } = self
        else {
            return Err(DomainError::InvalidScope);
        };
        Ok(format!(
            "v2;sources={};accounts={};projects={};hosts={};from={from};to={to}",
            join_scope_set(sources),
            join_scope_set(accounts),
            join_scope_set(projects),
            join_scope_set(hosts)
        ))
    }
}

fn join_scope_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(",")
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
