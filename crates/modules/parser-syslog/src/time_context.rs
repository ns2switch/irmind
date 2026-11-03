use super::{AppError, LegacyTimestamp, SyslogParser};
use chrono::{Datelike, FixedOffset};
use irmind_app::{ParserTimeBasis, ParserTimeContext, ParserTimeRequirement};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct StoredRow<'a> {
    #[serde(borrow)]
    raw: Cow<'a, str>,
    #[serde(borrow)]
    timestamp: Option<Cow<'a, str>>,
}

pub(super) fn requirement(
    parser: &SyslogParser,
    source: &str,
    sample: &[u8],
) -> Result<Option<ParserTimeRequirement>, AppError> {
    let sample = &sample[..sample.len().min(65_536)];
    let expanded;
    let bytes = if sample.starts_with(&[0x1f, 0x8b]) {
        expanded = super::gzip::sample(sample);
        expanded.as_slice()
    } else {
        sample
    };
    let line = bytes
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    let Ok(text) = std::str::from_utf8(line) else {
        return Ok(None);
    };
    let stored = if text.starts_with('{') {
        serde_json::from_str::<StoredRow<'_>>(text).ok()
    } else {
        None
    };
    let raw = stored
        .as_ref()
        .map_or(text, |row| row.raw.as_ref())
        .trim_end_matches('\r');
    let Some(score) = super::record::detect(raw) else {
        return Ok(None);
    };
    let context = parser.legacy.unwrap_or(LegacyTimestamp::new(2000, 0)?);
    let Ok(row) = super::record::parse(raw, Some(context), 0) else {
        return Ok(None);
    };
    let hosts = row
        .entities
        .into_iter()
        .filter(|(kind, _)| kind == "host")
        .take(1)
        .map(|(_, host)| {
            let location =
                ParserLocation::new(source, "parser-syslog", 0).map_err(|_| super::invalid())?;
            Ok(Tainted::from_external(
                host,
                Provenance::new(irmind_app::sha256(sample), Some(0), SourceKind::File),
            )
            .with_parser_location(location))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let observed = observed_time(parser, score, raw, stored.as_ref())?;
    Ok(Some(ParserTimeRequirement {
        required: score == 90,
        hosts,
        observed,
    }))
}

pub(super) fn month(line: &str) -> Option<u8> {
    let rest = line.strip_prefix('<')?.split_once('>')?.1;
    [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|name| rest.get(..3) == Some(*name))
    .and_then(|index| u8::try_from(index + 1).ok())
}

fn observed_time(
    parser: &SyslogParser,
    score: u8,
    raw: &str,
    stored: Option<&StoredRow<'_>>,
) -> Result<Option<ParserTimeContext>, AppError> {
    let observed = if score == 95 {
        raw.split_ascii_whitespace()
            .nth(1)
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .and_then(|at| {
                ParserTimeContext::new(
                    u16::try_from(at.year()).ok()?,
                    i16::try_from(at.offset().local_minus_utc() / 60).ok()?,
                    true,
                    ParserTimeBasis::ConfirmedSuggestion,
                )
                .ok()
            })
    } else if let Some(legacy) = parser.legacy {
        let year = stored
            .and_then(|row| row.timestamp.as_deref())
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .and_then(|at| {
                FixedOffset::east_opt(legacy.offset_minutes() * 60)
                    .map(|offset| at.with_timezone(&offset).year())
            })
            .unwrap_or(legacy.year());
        Some(ParserTimeContext::new(
            u16::try_from(year).map_err(|_| super::invalid())?,
            i16::try_from(legacy.offset_minutes()).map_err(|_| super::invalid())?,
            true,
            ParserTimeBasis::ConfirmedSuggestion,
        )?)
    } else {
        None
    };
    Ok(observed)
}
