use crate::{BTreeMap, CaseScope, DomainError, IndexedInstant, IndexedTime};

/// A bounded, optional partition and timestamp filter for local graph queries.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GraphQueryFilter {
    from: Option<(String, IndexedInstant)>,
    to: Option<(String, IndexedInstant)>,
    account: Option<String>,
    project: Option<String>,
    region: Option<String>,
}

impl GraphQueryFilter {
    pub fn parse(
        from: Option<&str>,
        to: Option<&str>,
        account: Option<&str>,
        project: Option<&str>,
        region: Option<&str>,
    ) -> Result<Self, DomainError> {
        if from.is_some() != to.is_some() || account.is_some() && project.is_some() {
            return Err(DomainError::InvalidScope);
        }
        let from = from.map(parse_boundary).transpose()?;
        let to = to.map(parse_boundary).transpose()?;
        if from
            .as_ref()
            .zip(to.as_ref())
            .is_some_and(|(a, b)| a.1 > b.1)
            || [account, project, region]
                .into_iter()
                .flatten()
                .any(|value| !valid_partition_value(value))
        {
            return Err(DomainError::InvalidScope);
        }
        Ok(Self {
            from,
            to,
            account: account.map(str::to_owned),
            project: project.map(str::to_owned),
            region: region.map(str::to_owned),
        })
    }

    pub fn from_args(args: &BTreeMap<String, String>) -> Result<Self, DomainError> {
        Self::parse(
            args.get("from").map(String::as_str),
            args.get("to").map(String::as_str),
            args.get("account").map(String::as_str),
            args.get("project").map(String::as_str),
            args.get("region").map(String::as_str),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.from.is_none()
            && self.account.is_none()
            && self.project.is_none()
            && self.region.is_none()
    }

    pub fn time_range(&self) -> Option<(&str, &str)> {
        self.from
            .as_ref()
            .zip(self.to.as_ref())
            .map(|(from, to)| (from.0.as_str(), to.0.as_str()))
    }

    pub fn account_or_project(&self) -> Option<&str> {
        self.account.as_deref().or(self.project.as_deref())
    }

    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    pub fn within_scope(&self, scope: &CaseScope) -> bool {
        let CaseScope::Remote {
            accounts,
            projects,
            from,
            to,
            ..
        } = scope
        else {
            return true;
        };
        self.account
            .as_ref()
            .is_none_or(|account| accounts.contains(account))
            && self
                .project
                .as_ref()
                .is_none_or(|project| projects.contains(project))
            && self.time_range().is_none_or(|(start, end)| {
                parse_boundary(from)
                    .ok()
                    .zip(parse_boundary(to).ok())
                    .zip(parse_boundary(start).ok())
                    .zip(parse_boundary(end).ok())
                    .is_some_and(|(((scope_start, scope_end), start), end)| {
                        start.1 >= scope_start.1 && end.1 <= scope_end.1
                    })
            })
    }
}

fn parse_boundary(raw: &str) -> Result<(String, IndexedInstant), DomainError> {
    if !raw.ends_with('Z') {
        return Err(DomainError::InvalidScope);
    }
    let time = IndexedTime::from_rfc3339(raw, false).map_err(|_| DomainError::InvalidScope)?;
    Ok((raw.into(), time.instant()))
}

fn valid_partition_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        Case, CaseId, CaseScope, Decision, ExecutionMode, PolicyRules, ProposedCall, Severity,
        Tool, evaluate, evaluate_with_rules,
    };

    #[test]
    fn rejects_invalid_or_ambiguous_filters() {
        assert!(
            GraphQueryFilter::parse(Some("2026-10-28T00:00:00Z"), None, None, None, None).is_err()
        );
        assert!(GraphQueryFilter::parse(None, None, Some("123"), Some("project"), None).is_err());
        assert!(GraphQueryFilter::parse(None, None, None, None, Some("../region")).is_err());
        assert!(
            GraphQueryFilter::parse(
                Some("2026-10-29T00:00:00Z"),
                Some("2026-10-28T00:00:00Z"),
                None,
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn fractional_boundaries_use_instants_and_keep_the_organization_ceiling() {
        let filter = GraphQueryFilter::parse(
            Some("2026-11-01T00:00:00.000001100Z"),
            Some("2026-11-01T00:00:00.000001900Z"),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(filter.within_scope(&CaseScope::parse("v2;sources=local;accounts=111111111111;projects=;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T00:00:01Z").unwrap()));
        assert!(!filter.within_scope(&CaseScope::parse("v2;sources=local;accounts=111111111111;projects=;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T00:00:00Z").unwrap()));
        assert!(
            GraphQueryFilter::parse(
                Some("2026-11-01T00:00:00.9Z"),
                Some("2026-11-01T00:00:00.10Z"),
                None,
                None,
                None
            )
            .is_err()
        );
        assert!(
            GraphQueryFilter::parse(
                Some("2026-11-01T00:00:00.1234567891Z"),
                Some("2026-11-01T00:00:01Z"),
                None,
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn policy_denies_a_graph_filter_outside_case_scope() {
        let case = Case {
            id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            title: "synthetic".into(),
            severity: Severity::Medium,
            scope: "v2;sources=local;accounts=111111111111;projects=;hosts=;from=2026-10-28T00:00:00Z;to=2026-10-29T00:00:00Z".into(),
            sealed: false,
        };
        let mut args = BTreeMap::from([
            ("kind".into(), "ip".into()),
            ("value".into(), "203.0.113.8".into()),
            ("account".into(), "222222222222".into()),
        ]);
        assert!(matches!(
            evaluate(
                &case,
                ProposedCall {
                    tool: Tool::Neighbors,
                    args: args.clone()
                },
                1,
                ExecutionMode::Attended,
                0
            ),
            Decision::Deny("graph filter outside case scope")
        ));
        args.insert("account".into(), "111111111111".into());
        assert!(matches!(
            evaluate(
                &case,
                ProposedCall {
                    tool: Tool::Neighbors,
                    args
                },
                1,
                ExecutionMode::Attended,
                0
            ),
            Decision::Allow(_)
        ));
    }

    #[test]
    fn organization_ceiling_denies_a_filter_allowed_by_the_case() {
        let case = Case {
            id: CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap(),
            title: "synthetic".into(),
            severity: Severity::Medium,
            scope: "v2;sources=local;accounts=111111111111,222222222222;projects=;hosts=;from=2026-10-28T00:00:00Z;to=2026-10-29T00:00:00Z".into(),
            sealed: false,
        };
        let rules = PolicyRules {
            scope: Some(CaseScope::parse("v2;sources=local;accounts=111111111111;projects=;hosts=;from=2026-10-28T00:00:00Z;to=2026-10-29T00:00:00Z").unwrap()),
            ..PolicyRules::default()
        };
        let proposal = ProposedCall {
            tool: Tool::TextSearch,
            args: BTreeMap::from([
                ("query".into(), "AssumeRole".into()),
                ("account".into(), "222222222222".into()),
            ]),
        };
        assert!(matches!(
            evaluate_with_rules(&case, proposal, 1, ExecutionMode::Attended, 0, &rules),
            Decision::Deny("outside organization policy scope")
        ));
    }
}
