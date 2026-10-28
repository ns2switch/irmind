use crate::UtcTimestamp;
use std::collections::BTreeMap;

/// A provider-neutral search over one approved field and a bounded aggregation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiemField {
    EventName,
    User,
    SourceIp,
    Host,
}

impl SiemField {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "event_name" => Some(Self::EventName),
            "user" => Some(Self::User),
            "source_ip" => Some(Self::SourceIp),
            "host" => Some(Self::Host),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiemOperator {
    Equals,
    NotEquals,
    Prefix,
}

impl SiemOperator {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "eq" => Some(Self::Equals),
            "not_eq" => Some(Self::NotEquals),
            "prefix" => Some(Self::Prefix),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiemAggregation {
    Events,
    CountBy,
    Top,
    Distinct,
}

impl SiemAggregation {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "events" => Some(Self::Events),
            "count_by" => Some(Self::CountBy),
            "top" => Some(Self::Top),
            "distinct" => Some(Self::Distinct),
            _ => None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SiemQuery {
    field: SiemField,
    operator: SiemOperator,
    value: String,
    from: UtcTimestamp,
    to: UtcTimestamp,
    aggregation: SiemAggregation,
    group_by: Option<SiemField>,
    limit: u8,
}

impl std::fmt::Debug for SiemQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiemQuery")
            .field("field", &self.field)
            .field("operator", &self.operator)
            .field("value", &"<redacted>")
            .field("aggregation", &self.aggregation)
            .finish_non_exhaustive()
    }
}

impl SiemQuery {
    /// Reject unknown semantics and SPL control characters before a connector sees them.
    pub fn parse(args: &BTreeMap<String, String>) -> Option<Self> {
        let field = SiemField::parse(args.get("field")?)?;
        let operator = SiemOperator::parse(args.get("operator")?)?;
        let from = UtcTimestamp::parse(args.get("from")?).ok()?;
        let to = UtcTimestamp::parse(args.get("to")?).ok()?;
        if !(1..=86_400).contains(&(to.unix_seconds() - from.unix_seconds())) {
            return None;
        }
        let value = args.get("value")?;
        if value.trim().is_empty()
            || value.trim() != value
            || value.len() > 128
            || value.chars().any(|ch| {
                ch.is_control()
                    || (ch.is_whitespace() && ch != ' ')
                    || matches!(
                        ch,
                        '*' | '`' | '|' | '$' | '\u{200b}' | '\u{202a}'..='\u{202e}'
                    )
            })
        {
            return None;
        }
        let aggregation = args
            .get("aggregation")
            .map_or(Some(SiemAggregation::Events), |value| {
                SiemAggregation::parse(value)
            })?;
        let group_by = match args.get("group_by") {
            Some(value) => Some(SiemField::parse(value)?),
            None => None,
        };
        if (aggregation == SiemAggregation::Events) != group_by.is_none() {
            return None;
        }
        let limit = args
            .get("limit")
            .map_or(Some(20), |value| value.parse::<u8>().ok())?;
        if !(1..=20).contains(&limit) {
            return None;
        }
        Some(Self {
            field,
            operator,
            value: value.clone(),
            from,
            to,
            aggregation,
            group_by,
            limit,
        })
    }

    pub fn field(&self) -> SiemField {
        self.field
    }

    pub fn operator(&self) -> SiemOperator {
        self.operator
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn from(&self) -> &UtcTimestamp {
        &self.from
    }

    pub fn to(&self) -> &UtcTimestamp {
        &self.to
    }

    pub fn aggregation(&self) -> SiemAggregation {
        self.aggregation
    }

    pub fn group_by(&self) -> Option<SiemField> {
        self.group_by
    }

    pub fn limit(&self) -> u8 {
        self.limit
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("field".into(), "event_name".into()),
            ("operator".into(), "eq".into()),
            ("value".into(), "AssumeRole".into()),
        ])
    }

    #[test]
    fn fields_operators_and_aggregations_are_bounded() {
        let mut input = args();
        let parsed = SiemQuery::parse(&input).unwrap();
        assert_eq!(parsed.field(), SiemField::EventName);
        assert_eq!(parsed.operator(), SiemOperator::Equals);
        assert_eq!(parsed.aggregation(), SiemAggregation::Events);
        assert_eq!(parsed.limit(), 20);
        assert_eq!(
            parsed.to().unix_seconds() - parsed.from().unix_seconds(),
            3600
        );
        assert!(!format!("{parsed:?}").contains("AssumeRole"));
        input.insert("field".into(), "_raw".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("field".into(), "host".into());
        input.insert("operator".into(), "regex".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("operator".into(), "prefix".into());
        input.insert("aggregation".into(), "top".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("group_by".into(), "source_ip".into());
        assert_eq!(
            SiemQuery::parse(&input).unwrap().aggregation(),
            SiemAggregation::Top
        );
        input.insert("limit".into(), "21".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("limit".into(), "5".into());
        input.insert("aggregation".into(), "collect".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("aggregation".into(), "count_by".into());
        input.insert("group_by".into(), "_raw".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("aggregation".into(), "events".into());
        input.insert("group_by".into(), "host".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("aggregation".into(), "count_by".into());
        input.insert("group_by".into(), "host".into());
        input.insert("to".into(), "2026-10-24T12:00:01Z".into());
        assert!(SiemQuery::parse(&input).is_none());
        input.insert("to".into(), "2026-10-23T11:59:59Z".into());
        assert!(SiemQuery::parse(&input).is_none());
    }

    #[test]
    fn spl_control_characters_and_legacy_query_are_rejected() {
        let mut input = args();
        for value in [
            "x | collect y",
            "x*",
            "`macro`",
            "$dashboard_token$",
            "line\nnew",
            "line\u{2028}new",
            "line\u{200b}new",
            " ",
        ] {
            input.insert("value".into(), value.into());
            assert!(SiemQuery::parse(&input).is_none(), "{value:?}");
        }
        input.remove("value");
        input.insert("query".into(), "AssumeRole".into());
        assert!(SiemQuery::parse(&input).is_none());
    }
}
