use super::GraphQueryFilter;
use crate::DomainError;
use std::collections::BTreeMap;

impl GraphQueryFilter {
    pub const ARGUMENTS: &'static [&'static str] = &[
        "from",
        "to",
        "account",
        "project",
        "region",
        "host",
        "cluster",
        "event_category",
        "event_type",
        "event_outcome",
        "entity_role",
    ];
    pub fn from_args(args: &BTreeMap<String, String>) -> Result<Self, DomainError> {
        use crate::{EntityRole, EventCategory, EventOutcome, EventType};
        let mut filter = Self::parse_with_host(
            args.get("from").map(String::as_str),
            args.get("to").map(String::as_str),
            args.get("account").map(String::as_str),
            args.get("project").map(String::as_str),
            args.get("region").map(String::as_str),
            args.get("host").map(String::as_str),
        )?;
        if let Some(cluster) = args.get("cluster") {
            filter = filter.with_cluster(cluster)?;
        }
        filter.common = crate::CommonEventFilter {
            category: args
                .get("event_category")
                .map(|v| EventCategory::parse(v))
                .transpose()
                .map_err(|_| DomainError::InvalidScope)?,
            event_type: args
                .get("event_type")
                .map(|v| EventType::parse(v))
                .transpose()
                .map_err(|_| DomainError::InvalidScope)?,
            outcome: args
                .get("event_outcome")
                .map(|v| EventOutcome::parse(v))
                .transpose()
                .map_err(|_| DomainError::InvalidScope)?,
            role: args
                .get("entity_role")
                .map(|v| EntityRole::parse(v))
                .transpose()
                .map_err(|_| DomainError::InvalidScope)?,
        };
        Ok(filter)
    }
    pub const fn common(&self) -> crate::CommonEventFilter {
        self.common
    }
    #[must_use]
    pub const fn with_common(mut self, common: crate::CommonEventFilter) -> Self {
        self.common = common;
        self
    }

    pub const fn coverage_notice(&self) -> Option<&'static str> {
        if self.common.is_empty() {
            None
        } else {
            Some(
                "Schema coverage: only explicit common classifications and roles match; legacy or unmapped activity may be omitted. No match does not prove absence.",
            )
        }
    }
}
