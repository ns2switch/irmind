use super::{END_OF_EVENT_SECONDS, MAX_GROUP_BYTES, MAX_GROUP_RECORDS, MAX_GROUPS, fields::Line};
use crate::AppError;
use irmind_app::source_mapping::SourceValue;
use irmind_domain::{IndexedInstant, IndexedTime, SourceMemberV1, TimePrecision};
use std::collections::BTreeMap;
type Key = (String, i64, u32, u64);
pub(crate) struct DecodedAudit {
    pub fields: SourceValue,
    pub timestamp: IndexedTime,
    pub partial: bool,
    pub members: Vec<SourceMemberV1>,
}
#[derive(Default)]
pub(crate) struct Groups {
    groups: BTreeMap<Key, Group>,
}
struct Group {
    fields: Vec<SourceValue>,
    members: Vec<SourceMemberV1>,
    bytes: usize,
    precision: TimePrecision,
    nodes: usize,
    invalid: bool,
}
impl Groups {
    pub(crate) fn push(
        &mut self,
        raw: &str,
        index: u64,
        offset: u64,
    ) -> Result<Vec<DecodedAudit>, AppError> {
        let row = Line::parse_strict(raw)?;
        let key = (
            row.field("node").unwrap_or_default().into(),
            row.seconds,
            row.nanos,
            row.serial,
        );
        if raw.len() > MAX_GROUP_BYTES
            || self.groups.get(&key).is_some_and(|g| {
                g.fields.len() >= MAX_GROUP_RECORDS
                    || g.bytes + raw.len() > MAX_GROUP_BYTES
                    || g.nodes + row.fields.len() * 2 + 1 > irmind_domain::SOURCE_MAX_NODES - 16
            })
        {
            return Err(invalid());
        }
        let expired = self
            .groups
            .keys()
            .filter(|k| row.seconds.saturating_sub(k.1) > END_OF_EVENT_SECONDS)
            .cloned()
            .collect::<Vec<_>>();
        let mut ready = Vec::new();
        for key in expired {
            if let Some(group) = self.groups.remove(&key) {
                ready.push(finish(&key, group, true)?);
            }
        }
        if !self.groups.contains_key(&key)
            && self.groups.len() >= MAX_GROUPS
            && let Some((key, group)) = self.groups.pop_first()
        {
            ready.push(finish(&key, group, true)?);
        }
        let fields = SourceValue::object(
            row.fields
                .iter()
                .map(|(name, value)| ((*name).into(), source_value(&row, name, value)))
                .collect(),
        )
        .map_err(|_| invalid())?;
        let group = self.groups.entry(key.clone()).or_insert_with(|| Group {
            fields: vec![],
            members: vec![],
            bytes: 0,
            precision: precision(&row),
            nodes: 0,
            invalid: false,
        });
        if precision(&row).code() < group.precision.code() {
            group.precision = precision(&row);
        }
        group.nodes += row.fields.len() * 2 + 1;
        group.bytes += raw.len();
        group.fields.push(fields);
        group.members.push(member(index, offset));
        if row.field("type") == Some("EOE")
            && let Some(group) = self.groups.remove(&key)
        {
            ready.push(finish(&key, group, false)?);
        }
        Ok(ready)
    }
    pub(crate) fn invalidate_open(&mut self) {
        for group in self.groups.values_mut() {
            group.invalid = true;
        }
    }
    pub(crate) fn finish(&mut self) -> Result<Vec<DecodedAudit>, AppError> {
        std::mem::take(&mut self.groups)
            .into_iter()
            .map(|(k, g)| finish(&k, g, true))
            .collect()
    }
}
fn finish(key: &Key, group: Group, partial: bool) -> Result<DecodedAudit, AppError> {
    let micros = key
        .1
        .checked_mul(1_000_000)
        .and_then(|s| s.checked_add(i64::from(key.2 / 1000)))
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::new(
        IndexedInstant::new(micros, u16::try_from(key.2 % 1000).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        group.precision,
        false,
    )
    .map_err(|_| invalid())?;
    let fields = object(vec![
        ("node", text(&key.0)),
        ("serial", text(&key.3.to_string())),
        ("records", SourceValue::Array(group.fields)),
    ])?;
    Ok(DecodedAudit {
        fields,
        timestamp,
        partial: partial || group.invalid,
        members: group.members,
    })
}

fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
fn text(value: &str) -> SourceValue {
    SourceValue::Text(value.into())
}
fn object(values: Vec<(&str, SourceValue)>) -> Result<SourceValue, AppError> {
    SourceValue::object(values.into_iter().map(|(k, v)| (k.into(), v)).collect())
        .map_err(|_| invalid())
}
fn member(index: u64, offset: u64) -> SourceMemberV1 {
    SourceMemberV1 {
        ordinal: index,
        offset: Some(offset),
    }
}

fn precision(row: &Line<'_>) -> TimePrecision {
    let digits = row
        .field("msg")
        .and_then(|s| s.split_once(':'))
        .map(|(s, _)| s)
        .and_then(|s| s.split_once('.'))
        .map_or(0, |(_, f)| f.len());
    match digits {
        0 => TimePrecision::Second,
        1..=3 => TimePrecision::Millisecond,
        4..=6 => TimePrecision::Microsecond,
        _ => TimePrecision::Nanosecond,
    }
}

fn source_value(row: &Line<'_>, name: &str, value: &str) -> SourceValue {
    let argument = name.strip_prefix('a').is_some_and(|n| {
        n.as_bytes().first().is_some_and(u8::is_ascii_digit)
            && n.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'[' | b']'))
    });
    if (argument || matches!(name, "exe" | "comm" | "cwd" | "name"))
        && !row.is_quoted(name)
        && let Some(bytes) = super::encoding::hex(value, 8192)
    {
        return match String::from_utf8(bytes) {
            Ok(text) => SourceValue::Text(text),
            Err(e) => SourceValue::Bytes(e.into_bytes()),
        };
    }
    text(value)
}
