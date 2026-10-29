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
        objects: BTreeSet<String>,
        from: String,
        to: String,
    },
}

impl CaseScope {
    /// Format: v1;sources=source1,source2;accounts=id1;hosts=host1;from=...Z;to=...Z.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let version = if value.starts_with("v3;") {
            3
        } else if value.starts_with("v2;") {
            2
        } else {
            1
        };
        let Some(rest) = value.strip_prefix(match version {
            3 => "v3;",
            2 => "v2;",
            _ => "v1;",
        }) else {
            return Ok(Self::LocalOnly);
        };
        let parts = rest.split(';').collect::<Vec<_>>();
        if parts.len()
            != match version {
                3 => 7,
                2 => 6,
                _ => 5,
            }
        {
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
                    "sources" | "accounts" | "projects" | "hosts" | "objects" | "from" | "to"
                )
            })
            || (version == 1 && fields.contains_key("projects"))
            || (version >= 2 && !fields.contains_key("projects"))
            || (version < 3 && fields.contains_key("objects"))
            || (version == 3 && !fields.contains_key("objects"))
        {
            return Err(DomainError::InvalidScope);
        }
        let sources = parse_scope_set(fields.get("sources").ok_or(DomainError::InvalidScope)?)?;
        let accounts = parse_scope_set(fields.get("accounts").ok_or(DomainError::InvalidScope)?)?;
        let projects = parse_scope_set(fields.get("projects").copied().unwrap_or(""))?;
        let hosts = parse_scope_set(fields.get("hosts").ok_or(DomainError::InvalidScope)?)?;
        let objects = parse_object_set(fields.get("objects").copied().unwrap_or(""))?;
        let from = *fields.get("from").ok_or(DomainError::InvalidScope)?;
        let to = *fields.get("to").ok_or(DomainError::InvalidScope)?;
        if sources.is_empty()
            || (accounts.is_empty()
                && projects.is_empty()
                && hosts.is_empty()
                && objects.is_empty())
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
            objects,
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
            objects: _,
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
                        && (*version >= 2 || (projects.is_empty() && hosts.is_empty()))
                }
                None => *version >= 2 || (accounts.is_empty() && projects.is_empty()),
            }
            && match host {
                Some(value) => {
                    hosts.contains(value)
                        && (*version >= 2 || (accounts.is_empty() && projects.is_empty()))
                }
                None => *version >= 2 || hosts.is_empty(),
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
            objects: _,
            from: scope_from,
            to: scope_to,
        } = self
        else {
            return false;
        };
        sources.contains(source)
            && (*version >= 2 || (accounts.is_empty() && hosts.is_empty()))
            && projects.contains(project)
            && window_within(from, to, scope_from, scope_to)
    }

    pub fn allows_project(&self, source: &str, project: &str) -> bool {
        matches!(self, Self::Remote { version, sources, accounts, projects, hosts, .. }
            if sources.contains(source) && (*version >= 2 || (accounts.is_empty() && hosts.is_empty())) && projects.contains(project))
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
                    && (*version >= 2 || (projects.is_empty() && hosts.is_empty()))
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
                    && (*version >= 2 || (accounts.is_empty() && projects.is_empty()))
            }
        }
    }

    pub fn extend_target(&self, field: &str, value: &str) -> Result<Self, DomainError> {
        if !(valid_scope_target(value) || field == "object" && valid_object_scope(value)) {
            return Err(DomainError::InvalidScope);
        }
        let Self::Remote {
            version,
            sources,
            accounts,
            projects,
            hosts,
            objects,
            from,
            to,
        } = self
        else {
            return Err(DomainError::InvalidScope);
        };
        let mut expanded = Self::Remote {
            version: if field == "object" || *version == 3 {
                3
            } else {
                2
            },
            sources: sources.clone(),
            accounts: accounts.clone(),
            projects: projects.clone(),
            hosts: hosts.clone(),
            objects: objects.clone(),
            from: from.clone(),
            to: to.clone(),
        };
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            objects,
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
            "object" => {
                objects.insert(value.to_owned());
            }
            _ => return Err(DomainError::InvalidScope),
        }
        Self::parse(&expanded.to_current_string()?)
    }

    pub fn expand_window(&self, from: &str, to: &str) -> Result<Self, DomainError> {
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            objects,
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
        let expanded = format!(
            "v{};sources={};accounts={};projects={};hosts={};{}from={from};to={to}",
            if objects.is_empty() { 2 } else { 3 },
            join_scope_set(sources),
            join_scope_set(accounts),
            join_scope_set(projects),
            join_scope_set(hosts),
            if objects.is_empty() {
                String::new()
            } else {
                format!("objects={};", join_scope_set(objects))
            }
        );
        Self::parse(&expanded)
    }

    pub fn to_v2_string(&self) -> Result<String, DomainError> {
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            objects,
            from,
            to,
            ..
        } = self
        else {
            return Err(DomainError::InvalidScope);
        };
        if !objects.is_empty() {
            return Err(DomainError::InvalidScope);
        }
        Ok(format!(
            "v2;sources={};accounts={};projects={};hosts={};from={from};to={to}",
            join_scope_set(sources),
            join_scope_set(accounts),
            join_scope_set(projects),
            join_scope_set(hosts)
        ))
    }

    pub fn to_v3_string(&self) -> Result<String, DomainError> {
        let Self::Remote {
            sources,
            accounts,
            projects,
            hosts,
            objects,
            from,
            to,
            ..
        } = self
        else {
            return Err(DomainError::InvalidScope);
        };
        Ok(format!(
            "v3;sources={};accounts={};projects={};hosts={};objects={};from={from};to={to}",
            join_scope_set(sources),
            join_scope_set(accounts),
            join_scope_set(projects),
            join_scope_set(hosts),
            join_scope_set(objects)
        ))
    }

    pub fn to_current_string(&self) -> Result<String, DomainError> {
        match self {
            Self::Remote { objects, .. } if !objects.is_empty() => self.to_v3_string(),
            _ => self.to_v2_string(),
        }
    }

    pub fn allows_object(&self, source: &str, uri: &str, from: &str, to: &str) -> bool {
        let Self::Remote {
            sources,
            objects,
            from: scope_from,
            to: scope_to,
            ..
        } = self
        else {
            return false;
        };
        sources.contains(source)
            && valid_object_scope(uri)
            && objects.iter().any(|allowed| object_within(uri, allowed))
            && window_within(from, to, scope_from, scope_to)
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
                    objects,
                    from,
                    to,
                    ..
                },
                Self::Remote {
                    sources: allowed_sources,
                    accounts: allowed_accounts,
                    projects: allowed_projects,
                    hosts: allowed_hosts,
                    objects: allowed_objects,
                    from: allowed_from,
                    to: allowed_to,
                    ..
                },
            ) => {
                sources.is_subset(allowed_sources)
                    && accounts.is_subset(allowed_accounts)
                    && projects.is_subset(allowed_projects)
                    && hosts.is_subset(allowed_hosts)
                    && objects.iter().all(|object| {
                        allowed_objects
                            .iter()
                            .any(|allowed| object_within(object, allowed))
                    })
                    && window_within(from, to, allowed_from, allowed_to)
            }
            _ => false,
        }
    }
}

fn object_within(candidate: &str, allowed: &str) -> bool {
    candidate == allowed
        || candidate
            .strip_prefix(allowed)
            .is_some_and(|rest| allowed.ends_with('/') || rest.starts_with('/'))
}

fn parse_object_set(value: &str) -> Result<BTreeSet<String>, DomainError> {
    if value.is_empty() {
        return Ok(BTreeSet::new());
    }
    let values = value.split(',').collect::<Vec<_>>();
    if values.len() > 32 || values.iter().any(|item| !valid_object_scope(item)) {
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

pub(crate) fn valid_object_scope(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "s3" | "gs" | "az") || value.len() > 900 || !value.is_ascii() {
        return false;
    }
    let Some((container, prefix)) = rest.split_once('/') else {
        return false;
    };
    valid_scope_target(container)
        && !container.contains(':')
        && !prefix.is_empty()
        && !prefix.starts_with('/')
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte))
        && prefix
            .split('/')
            .all(|part| part != "." && part != ".." && part.len() <= 255)
        && !prefix.contains("//")
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
