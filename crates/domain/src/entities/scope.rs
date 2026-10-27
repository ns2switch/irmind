use crate::{BTreeMap, BTreeSet, DomainError, UtcTimestamp};

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
            || !valid_window(from, to)
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
            && window_within(from, to, scope_from, scope_to)
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
            && window_within(from, to, scope_from, scope_to)
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
        if !window_within(old_from, old_to, from, to) {
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

    /// Whether every remote target and instant in this case is allowed by the policy ceiling.
    pub fn is_within(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (Self::LocalOnly, _) => true,
            (
                Self::Remote {
                    sources,
                    accounts,
                    projects,
                    hosts,
                    from,
                    to,
                    ..
                },
                Self::Remote {
                    sources: allowed_sources,
                    accounts: allowed_accounts,
                    projects: allowed_projects,
                    hosts: allowed_hosts,
                    from: allowed_from,
                    to: allowed_to,
                    ..
                },
            ) => {
                sources.is_subset(allowed_sources)
                    && accounts.is_subset(allowed_accounts)
                    && projects.is_subset(allowed_projects)
                    && hosts.is_subset(allowed_hosts)
                    && window_within(from, to, allowed_from, allowed_to)
            }
            _ => false,
        }
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
    UtcTimestamp::parse(value).is_ok()
}

fn valid_window(from: &str, to: &str) -> bool {
    UtcTimestamp::parse(from)
        .ok()
        .zip(UtcTimestamp::parse(to).ok())
        .is_some_and(|(from, to)| from <= to)
}

fn window_within(from: &str, to: &str, allowed_from: &str, allowed_to: &str) -> bool {
    let (Ok(from), Ok(to), Ok(allowed_from), Ok(allowed_to)) = (
        UtcTimestamp::parse(from),
        UtcTimestamp::parse(to),
        UtcTimestamp::parse(allowed_from),
        UtcTimestamp::parse(allowed_to),
    ) else {
        return false;
    };
    from <= to && from >= allowed_from && to <= allowed_to
}
