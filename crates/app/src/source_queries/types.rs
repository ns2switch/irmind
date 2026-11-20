use super::{
    QUERY_CASE_MAX_BYTES, QUERY_CASE_MAX_ROWS, QUERY_DEFAULT_INTERVAL_SECONDS, QUERY_MAX_BYTES,
    QUERY_MAX_INTERVAL_SECONDS, QUERY_MAX_ROWS, SourceQueryError, canonical::checked_value,
    canonical_query_json,
};
use irmind_domain::{
    CommonField, CommonFieldType, EventCategory, EventOutcome, EventType, IndexedTime,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}
pub(crate) fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
pub(crate) fn digest(value: &str) -> bool {
    irmind_domain::EvidenceHash::parse(value).is_ok()
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct QueryTime(String);
impl TryFrom<String> for QueryTime {
    type Error = SourceQueryError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !value.ends_with('Z') || !(20..=30).contains(&value.len()) {
            return Err(SourceQueryError::Invalid);
        }
        IndexedTime::from_rfc3339(&value, false).map_err(|_| SourceQueryError::Invalid)?;
        let base = &value[..19];
        let fraction = if value.len() == 20 {
            ""
        } else {
            if value.as_bytes()[19] != b'.' {
                return Err(SourceQueryError::Invalid);
            }
            &value[20..value.len() - 1]
        };
        if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SourceQueryError::Invalid);
        }
        Ok(Self(format!("{base}.{fraction:0<9}Z")))
    }
}
impl From<QueryTime> for String {
    fn from(value: QueryTime) -> Self {
        value.0
    }
}
impl QueryTime {
    pub fn parse(value: &str) -> Result<Self, SourceQueryError> {
        value.to_owned().try_into()
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn nanos(&self) -> Result<i128, SourceQueryError> {
        let t = IndexedTime::from_rfc3339(&self.0, false)
            .map_err(|_| SourceQueryError::Invalid)?
            .instant();
        Ok(i128::from(t.unix_micros()) * 1000 + i128::from(t.submicro_nanos()))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryOperator {
    Eq,
    In,
    Range,
    Prefix,
    Missing,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryPredicate {
    pub field: String,
    pub op: QueryOperator,
    pub value: Value,
}
fn field_type(field: &str) -> Result<CommonFieldType, SourceQueryError> {
    match field {
        "@timestamp" => Ok(CommonFieldType::Time),
        "event.category" | "event.type" | "event.outcome" | "event.action" => {
            Ok(CommonFieldType::Text)
        }
        _ => CommonField::parse(field)
            .map(CommonField::value_type)
            .map_err(|_| SourceQueryError::Unsupported),
    }
}
fn scalar(field: &str, value: &Value) -> Result<(), SourceQueryError> {
    let valid = match field_type(field)? {
        CommonFieldType::Boolean => value.is_boolean(),
        CommonFieldType::Port => value.as_u64().is_some_and(|n| u16::try_from(n).is_ok()),
        CommonFieldType::Pid => value.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
        CommonFieldType::Unsigned => value.is_u64(),
        CommonFieldType::HttpStatus => value.as_u64().is_some_and(|n| (100..=599).contains(&n)),
        CommonFieldType::Time => value.as_str().is_some_and(|s| QueryTime::parse(s).is_ok()),
        CommonFieldType::Ip => value
            .as_str()
            .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok()),
        CommonFieldType::Text | CommonFieldType::LongText => {
            value.as_str().is_some_and(|s| text(s, 256))
        }
        CommonFieldType::Md5 | CommonFieldType::Sha1 | CommonFieldType::Sha256 => {
            value.as_str().is_some_and(|s| {
                s.len()
                    == match field_type(field) {
                        Ok(CommonFieldType::Md5) => 32,
                        Ok(CommonFieldType::Sha1) => 40,
                        _ => 64,
                    }
                    && s.bytes().all(|b| b.is_ascii_hexdigit())
            })
        }
        CommonFieldType::Direction => value.as_str().is_some_and(|s| {
            matches!(
                s,
                "ingress" | "egress" | "inbound" | "outbound" | "internal" | "external" | "unknown"
            )
        }),
        _ => false,
    };
    if !valid {
        return Err(SourceQueryError::Invalid);
    }
    let enum_valid = match field {
        "event.category" => value
            .as_str()
            .is_some_and(|s| EventCategory::parse(s).is_ok()),
        "event.type" => value.as_str().is_some_and(|s| EventType::parse(s).is_ok()),
        "event.outcome" => value
            .as_str()
            .is_some_and(|s| EventOutcome::parse(s).is_ok()),
        _ => true,
    };
    if enum_valid {
        Ok(())
    } else {
        Err(SourceQueryError::Invalid)
    }
}
impl QueryPredicate {
    fn validate(&self) -> Result<(), SourceQueryError> {
        field_type(&self.field)?;
        match self.op {
            QueryOperator::Missing if self.value.is_null() => Ok(()),
            QueryOperator::Eq => scalar(&self.field, &self.value),
            QueryOperator::Prefix
                if matches!(
                    field_type(&self.field)?,
                    CommonFieldType::Text | CommonFieldType::LongText
                ) =>
            {
                scalar(&self.field, &self.value)
            }
            QueryOperator::In => {
                let a = self.value.as_array().ok_or(SourceQueryError::Invalid)?;
                if a.is_empty() || a.len() > 32 {
                    return Err(SourceQueryError::Limit);
                }
                let mut seen = std::collections::BTreeSet::new();
                for v in a {
                    scalar(&self.field, v)?;
                    if !seen.insert(canonical_query_json(v)?) {
                        return Err(SourceQueryError::Invalid);
                    }
                }
                Ok(())
            }
            QueryOperator::Range => {
                let a = self.value.as_array().ok_or(SourceQueryError::Invalid)?;
                if a.len() != 2 {
                    return Err(SourceQueryError::Invalid);
                }
                scalar(&self.field, &a[0])?;
                scalar(&self.field, &a[1])?;
                let ordered = if field_type(&self.field)? == CommonFieldType::Time {
                    QueryTime::parse(a[0].as_str().ok_or(SourceQueryError::Invalid)?)?.nanos()?
                        <= QueryTime::parse(a[1].as_str().ok_or(SourceQueryError::Invalid)?)?
                            .nanos()?
                } else {
                    a[0].as_u64()
                        .zip(a[1].as_u64())
                        .is_some_and(|(a, b)| a <= b)
                };
                if ordered {
                    Ok(())
                } else {
                    Err(SourceQueryError::Invalid)
                }
            }
            _ => Err(SourceQueryError::Invalid),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryResultKind {
    Events,
    Count,
    CountBy,
    Top,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "QueryWire")]
pub struct SourceQueryV1 {
    version: u8,
    source: String,
    dataset: String,
    from: QueryTime,
    to: QueryTime,
    filters: Vec<QueryPredicate>,
    fields: Vec<String>,
    result: QueryResultKind,
    limit: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryWire {
    version: u8,
    source: String,
    dataset: String,
    from: QueryTime,
    to: QueryTime,
    filters: Vec<QueryPredicate>,
    fields: Vec<String>,
    result: QueryResultKind,
    limit: u64,
}
impl TryFrom<QueryWire> for SourceQueryV1 {
    type Error = SourceQueryError;
    fn try_from(mut w: QueryWire) -> Result<Self, Self::Error> {
        if w.version != 1 || !id(&w.source) || !id(&w.dataset) {
            return Err(SourceQueryError::Invalid);
        }
        if w.filters.len() > 16 || w.fields.len() > 32 || w.limit == 0 || w.limit > QUERY_MAX_ROWS {
            return Err(SourceQueryError::Limit);
        }
        let interval = w.to.nanos()? - w.from.nanos()?;
        if interval <= 0 || interval > i128::from(QUERY_MAX_INTERVAL_SECONDS) * 1_000_000_000 {
            return Err(SourceQueryError::Limit);
        }
        for f in &w.filters {
            f.validate()?;
        }
        let mut keyed = w
            .filters
            .into_iter()
            .map(|f| Ok((canonical_query_json(&f)?, f)))
            .collect::<Result<Vec<_>, SourceQueryError>>()?;
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        if keyed.windows(2).any(|p| p[0].0 == p[1].0) {
            return Err(SourceQueryError::Invalid);
        }
        w.filters = keyed.into_iter().map(|(_, f)| f).collect();
        for f in &w.fields {
            field_type(f)?;
        }
        w.fields.sort();
        if w.fields.windows(2).any(|p| p[0] == p[1]) {
            return Err(SourceQueryError::Invalid);
        }
        if matches!(w.result, QueryResultKind::CountBy | QueryResultKind::Top)
            && (w.fields.is_empty() || w.fields.len() > 2)
        {
            return Err(SourceQueryError::Invalid);
        }
        if w.result == QueryResultKind::Events && w.fields.is_empty() {
            return Err(SourceQueryError::Invalid);
        }
        Ok(Self {
            version: w.version,
            source: w.source,
            dataset: w.dataset,
            from: w.from,
            to: w.to,
            filters: w.filters,
            fields: w.fields,
            result: w.result,
            limit: w.limit,
        })
    }
}
impl SourceQueryV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        checked_value(bytes)?;
        serde_json::from_slice(bytes).map_err(|_| SourceQueryError::Invalid)
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn dataset(&self) -> &str {
        &self.dataset
    }
    pub fn from(&self) -> &QueryTime {
        &self.from
    }
    pub fn to(&self) -> &QueryTime {
        &self.to
    }
    pub fn filters(&self) -> &[QueryPredicate] {
        &self.filters
    }
    pub fn fields(&self) -> &[String] {
        &self.fields
    }
    pub const fn result(&self) -> QueryResultKind {
        self.result
    }
    pub const fn limit(&self) -> u64 {
        self.limit
    }
    pub fn interval_within(&self, seconds: u64) -> Result<bool, SourceQueryError> {
        Ok(self.to.nanos()? - self.from.nanos()? <= i128::from(seconds) * 1_000_000_000)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryAllocationV1 {
    pub enabled: bool,
    pub analytics_allowed: bool,
    pub scan_bytes: Option<u64>,
    pub retained_rows: u64,
    pub retained_bytes: u64,
}
impl SourceQueryAllocationV1 {
    pub fn validate(self) -> Result<(), SourceQueryError> {
        if self.retained_rows > QUERY_CASE_MAX_ROWS
            || self.retained_bytes > QUERY_CASE_MAX_BYTES
            || self.scan_bytes == Some(0)
        {
            return Err(SourceQueryError::Limit);
        }
        if !self.enabled
            && (self.analytics_allowed
                || self.scan_bytes.is_some()
                || self.retained_rows != 0
                || self.retained_bytes != 0)
        {
            return Err(SourceQueryError::Invalid);
        }
        if self.enabled
            && (self.retained_rows == 0
                || self.retained_bytes == 0
                || (!self.analytics_allowed && self.scan_bytes.is_none()))
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(())
    }
    pub fn within(self, ceiling: Self) -> bool {
        self.validate().is_ok()
            && ceiling.validate().is_ok()
            && (!self.enabled || ceiling.enabled)
            && (!self.analytics_allowed || ceiling.analytics_allowed)
            && self.retained_rows <= ceiling.retained_rows
            && self.retained_bytes <= ceiling.retained_bytes
            && self
                .scan_bytes
                .is_none_or(|n| ceiling.scan_bytes.is_some_and(|m| n <= m))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceQueryLimits {
    pub interval_seconds: u64,
    pub rows: u64,
    pub retained_bytes: u64,
    pub scan_bytes: Option<u64>,
    pub deadline_seconds: u64,
    pub queries_per_minute: u64,
    pub concurrency: u64,
}
impl Default for SourceQueryLimits {
    fn default() -> Self {
        Self {
            interval_seconds: QUERY_DEFAULT_INTERVAL_SECONDS,
            rows: QUERY_MAX_ROWS,
            retained_bytes: QUERY_MAX_BYTES,
            scan_bytes: None,
            deadline_seconds: 180,
            queries_per_minute: 6,
            concurrency: 1,
        }
    }
}
impl SourceQueryLimits {
    pub fn validate(&self) -> Result<(), SourceQueryError> {
        if self.interval_seconds == 0
            || self.interval_seconds > QUERY_MAX_INTERVAL_SECONDS
            || self.rows == 0
            || self.rows > QUERY_MAX_ROWS
            || self.retained_bytes == 0
            || self.retained_bytes > QUERY_MAX_BYTES
            || self.deadline_seconds == 0
            || self.deadline_seconds > 600
            || self.queries_per_minute == 0
            || self.queries_per_minute > 60
            || self.concurrency == 0
            || self.concurrency > 16
            || self.scan_bytes == Some(0)
        {
            Err(SourceQueryError::Limit)
        } else {
            Ok(())
        }
    }
}
