use super::{AppError, LegacyTimestamp, SyslogParser};
use irmind_app::{ParserTimeContext, ParserTimeRequirement};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct StoredRow<'a> {
    #[serde(borrow)]
    raw: Cow<'a, str>,
    #[serde(borrow, rename = "timestamp")]
    _timestamp: Option<Cow<'a, str>>,
}

pub(super) fn requirement(
    _parser: &SyslogParser,
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
    // A leap-year calendar checks framing only; it never supplies an inferred year.
    let (_, rest) = super::record::priority(raw)?;
    let header = if let Some(body) = rest.strip_prefix("1 ") {
        super::record::modern(body)
    } else {
        super::record::classic(rest, LegacyTimestamp::new(2000, 0)?)
    };
    let Ok((_, host, _, _, _, _, _)) = header else {
        return Ok(None);
    };
    let hosts = if host == "-" || host.is_empty() {
        Vec::new()
    } else {
        let location =
            ParserLocation::new(source, "parser-syslog", 0).map_err(|_| super::invalid())?;
        vec![
            Tainted::from_external(
                host.to_owned(),
                Provenance::new(irmind_app::sha256(sample), Some(0), SourceKind::File),
            )
            .with_parser_location(location),
        ]
    };
    let observed = if score == 95 {
        raw.split_ascii_whitespace()
            .nth(1)
            .and_then(ParserTimeContext::from_timestamp_hint)
    } else {
        None
    };
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
