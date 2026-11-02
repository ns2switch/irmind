use crate::{AppError, DeclarativeParser, error};
use chrono::{
    DateTime, Datelike as _, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone as _, Utc,
};
use irmind_app::GraphRecord;
use serde::Serialize;
use serde_json::value::RawValue;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Original<'a> {
    Json(&'a RawValue),
    Text(&'a str),
}

#[derive(Serialize)]
struct Normalized<'a> {
    at: &'a str,
    account_id: Option<&'a str>,
    #[serde(flatten)]
    fields: &'a BTreeMap<String, String>,
    original: Original<'a>,
}

impl DeclarativeParser {
    pub(crate) fn map_record(
        &self,
        index: usize,
        extracted: &BTreeMap<String, String>,
        original: Original<'_>,
    ) -> Result<GraphRecord, AppError> {
        let mut fields = BTreeMap::new();
        for (field, path) in &self.definition.mapping {
            if let Some(value) = extracted.get(path) {
                if value.len() > 4096 {
                    return Err(error("mapped value exceeds 4096 bytes"));
                }
                fields.insert(field.clone(), value.clone());
            }
        }
        let at = timestamp(
            fields
                .get("time")
                .ok_or_else(|| error("mapped time is missing"))?,
            &self.definition.timestamp,
        )?;
        let event = fields
            .get("action")
            .filter(|value| !value.is_empty())
            .map_or("record", String::as_str)
            .to_owned();
        let entities = entities(&fields)?;
        let text = serde_json::to_string(&Normalized {
            at: &at,
            account_id: fields.get("account").map(String::as_str),
            fields: &fields,
            original,
        })
        .map_err(|_| error("cannot normalize declarative record"))?;
        Ok(GraphRecord {
            index,
            at,
            event,
            text,
            entities,
            relations: Vec::new(),
        })
    }
}

fn entities(fields: &BTreeMap<String, String>) -> Result<Vec<(String, String)>, AppError> {
    let mut entities = Vec::new();
    for (field, kind) in [
        ("host", "host"),
        ("user", "user"),
        ("process", "process"),
        ("command_line", "command_line"),
        ("source_ip", "ip"),
        ("destination_ip", "ip"),
        ("source_port", "port"),
        ("destination_port", "port"),
        ("account", "account"),
    ] {
        if let Some(value) = fields.get(field).filter(|value| !value.is_empty()) {
            if kind == "ip" && value.parse::<IpAddr>().is_err() {
                return Err(error("mapped IP address is invalid"));
            }
            if kind == "port" && value.parse::<u16>().is_err() {
                return Err(error("mapped network port is invalid"));
            }
            entities.push((kind.to_owned(), value.clone()));
        }
    }
    entities.sort();
    entities.dedup();
    Ok(entities)
}

pub(crate) fn timezone(value: &str) -> Result<FixedOffset, AppError> {
    if matches!(value, "UTC" | "Z") {
        return FixedOffset::east_opt(0).ok_or_else(|| error("invalid default timezone"));
    }
    let bytes = value.as_bytes();
    if bytes.len() != 6
        || !matches!(bytes[0], b'+' | b'-')
        || bytes[3] != b':'
        || ![bytes[1], bytes[2], bytes[4], bytes[5]]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(error("default timezone requires UTC or a numeric offset"));
    }
    let hours = i32::from(bytes[1] - b'0') * 10 + i32::from(bytes[2] - b'0');
    let minutes = i32::from(bytes[4] - b'0') * 10 + i32::from(bytes[5] - b'0');
    if hours > 23 || minutes > 59 {
        return Err(error("default timezone offset is out of range"));
    }
    let seconds = (hours * 3600 + minutes * 60) * if bytes[0] == b'-' { -1 } else { 1 };
    FixedOffset::east_opt(seconds).ok_or_else(|| error("default timezone offset is out of range"))
}

fn timestamp(value: &str, context: &crate::config::Timestamp) -> Result<String, AppError> {
    let instant = match context.format.as_str() {
        "rfc3339" => DateTime::parse_from_rfc3339(value)
            .map_err(|_| error("invalid RFC 3339 event time"))?
            .with_timezone(&Utc),
        "unix" => unix_time(value)?,
        format => {
            if let Ok(at) = DateTime::parse_from_str(value, format) {
                at.with_timezone(&Utc)
            } else {
                let at = NaiveDateTime::parse_from_str(value, format)
                    .map_err(|_| error("event time does not match its declared format"))?;
                timezone(&context.default_timezone)?
                    .from_local_datetime(&at)
                    .single()
                    .ok_or_else(|| error("invalid event time or offset"))?
                    .with_timezone(&Utc)
            }
        }
    };
    if !(1..=9999).contains(&instant.year()) {
        return Err(error("event year is out of range"));
    }
    if instant.timestamp_subsec_nanos() >= 1_000_000_000 {
        return Err(error("leap-second event time is unsupported"));
    }
    Ok(instant.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn unix_time(value: &str) -> Result<DateTime<Utc>, AppError> {
    let negative = value.starts_with('-');
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (seconds, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if (unsigned.contains('.') && fraction.is_empty())
        || seconds.is_empty()
        || !seconds.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(error("invalid exact Unix timestamp"));
    }
    let seconds = seconds
        .parse::<i64>()
        .map_err(|_| error("Unix timestamp exceeds range"))?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u32>()
            .map_err(|_| error("invalid Unix fraction"))?
            * 10u32.pow(
                u32::try_from(9 - fraction.len()).map_err(|_| error("invalid Unix fraction"))?,
            )
    };
    let (seconds, nanos) = if negative && nanos != 0 {
        (
            seconds
                .checked_neg()
                .and_then(|s| s.checked_sub(1))
                .ok_or_else(|| error("Unix timestamp exceeds range"))?,
            1_000_000_000 - nanos,
        )
    } else {
        (if negative { -seconds } else { seconds }, nanos)
    };
    DateTime::from_timestamp(seconds, nanos).ok_or_else(|| error("Unix timestamp exceeds range"))
}
