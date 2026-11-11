use super::{AppError, LinuxParser, ParserTimeContext, ParserTimeRequirement, bad};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Clone, Copy)]
pub(super) struct Calendar {
    context: ParserTimeContext,
    sequence: irmind_app::ParserCalendar,
}
impl Calendar {
    pub(super) fn new(context: ParserTimeContext) -> Self {
        Self {
            context,
            sequence: irmind_app::ParserCalendar::new(context),
        }
    }
    pub(super) fn candidate(self, raw: &str) -> Result<(Self, DateTime<Utc>), AppError> {
        let month = month(raw).ok_or_else(invalid)?;
        let mut next = self;
        next.sequence = self.sequence.candidate(month)?;
        let naive = NaiveDateTime::parse_from_str(
            &format!("{} {raw}", next.sequence.year()),
            "%Y %b %e %H:%M:%S",
        )
        .map_err(|_| invalid())?;
        let at = FixedOffset::east_opt(i32::from(self.context.offset_minutes()) * 60)
            .ok_or_else(invalid)?
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(invalid)?
            .with_timezone(&Utc);
        Ok((next, at))
    }
}
pub(super) fn month(raw: &str) -> Option<u8> {
    [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|month| raw.get(..3) == Some(*month))
    .and_then(|index| u8::try_from(index + 1).ok())
}
#[derive(Deserialize)]
struct Stored<'a> {
    #[serde(borrow)]
    raw: Cow<'a, str>,
    #[serde(borrow, rename = "timestamp")]
    _timestamp: Option<Cow<'a, str>>,
}

pub(super) fn requirement(
    _parser: &LinuxParser,
    source: &str,
    sample: &[u8],
) -> Result<Option<ParserTimeRequirement>, AppError> {
    let sample = &sample[..sample.len().min(65_536)];
    let line = sample
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let Ok(text) = std::str::from_utf8(line) else {
        return Ok(None);
    };
    let stored = if text.starts_with('{') {
        serde_json::from_str::<Stored<'_>>(text).ok()
    } else {
        None
    };
    let raw = stored
        .as_ref()
        .map_or(text, |row| row.raw.as_ref())
        .trim_end_matches('\r');
    if let Some(header) = super::auth::header(raw) {
        let observed = if header.classic {
            None
        } else {
            ParserTimeContext::from_timestamp_hint(header.time)
        };
        let location = ParserLocation::new(source, "parser-linux", 0).map_err(|_| invalid())?;
        return Ok(Some(ParserTimeRequirement {
            required: header.classic,
            observed,
            hosts: vec![
                Tainted::from_external(
                    header.host.to_owned(),
                    Provenance::new(irmind_app::sha256(sample), Some(0), SourceKind::File),
                )
                .with_parser_location(location),
            ],
        }));
    }
    irmind_app::json_time_requirement(
        source,
        sample,
        &irmind_app::ParserTimeFields {
            parser_id: "parser-linux",
            hosts: &["/host", "/event/host"],
            timestamps: &["/timestamp", "/event/timestamp"],
        },
    )
}
fn invalid() -> AppError {
    bad("invalid Linux source calendar or backward month outside the confirmed year-rollover rule")
}
