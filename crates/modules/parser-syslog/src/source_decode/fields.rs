use super::{AppError, SourceMetadata, VERSION, invalid};
use irmind_app::{
    ParserCalendar,
    source_mapping::{
        SourceDiscriminator, SourceFormatV1, SourceValue, framed::DecodedSourceFrame,
    },
};
use irmind_domain::{IndexedTime, SourceNumber};
use std::collections::BTreeMap;
pub(super) fn decode(
    line: &str,
    metadata: SourceMetadata<'_>,
    calendar: &mut Option<ParserCalendar>,
    compressed: bool,
) -> Result<DecodedSourceFrame, AppError> {
    let (priority, rest) = crate::record::priority(line)?;
    let modern = rest.starts_with("1 ");
    let (header, next) = if let Some(body) = rest.strip_prefix("1 ") {
        (crate::record::modern(body)?, None)
    } else {
        classic(line, rest, metadata, *calendar)?
    };
    let (resolved, host, app, pid, msgid, data, message) = header;
    let raw_time = if modern {
        rest.strip_prefix("1 ")
            .and_then(|s| s.split(' ').next())
            .ok_or_else(invalid)?
    } else {
        rest.get(..15).ok_or_else(invalid)?
    };
    let timestamp = if resolved.is_empty() {
        None
    } else {
        Some(
            IndexedTime::from_rfc3339(if modern { raw_time } else { &resolved }, !modern)
                .map_err(|_| invalid())?,
        )
    };
    let text = |v: &str| SourceValue::Text(v.into());
    let mut fields = vec![
        (
            "pri".into(),
            SourceValue::Number(
                SourceNumber::try_new(&priority.to_string()).map_err(|_| invalid())?,
            ),
        ),
        ("timestamp".into(), text(raw_time)),
        ("hostname".into(), text(host)),
        ("app-name".into(), text(app)),
        ("message".into(), text(message)),
        ("raw".into(), text(line)),
    ];
    if modern {
        fields.extend([
            (
                "version".into(),
                SourceValue::Number(SourceNumber::try_new("1").map_err(|_| invalid())?),
            ),
            ("procid".into(), text(pid.unwrap_or("-"))),
            ("msgid".into(), text(msgid.unwrap_or("-"))),
            ("structured-data".into(), text(data.unwrap_or("-"))),
        ]);
    } else if let Some(pid) = pid {
        fields.push(("procid".into(), text(pid)));
    }
    let format = SourceFormatV1::try_new(
        if compressed { "syslog-gzip" } else { "syslog" },
        VERSION,
        BTreeMap::from([(
            SourceDiscriminator::Dataset,
            if modern { "rfc5424" } else { "rfc3164" }.into(),
        )]),
    )
    .map_err(|_| invalid())?;
    let fields = SourceValue::object(fields).map_err(|_| invalid())?;
    if let Some(next) = next {
        *calendar = Some(next);
    }
    Ok(DecodedSourceFrame {
        fields,
        timestamp,
        format,
    })
}
fn classic<'a>(
    line: &str,
    rest: &'a str,
    metadata: SourceMetadata<'_>,
    calendar: Option<ParserCalendar>,
) -> Result<(crate::record::Header<'a>, Option<ParserCalendar>), AppError> {
    let current = calendar.ok_or_else(|| {
        let requirement = crate::time_context::requirement(
            &crate::SyslogParser::default(),
            metadata.source.reference(),
            line.as_bytes(),
        );
        match requirement {
            Ok(Some(requirement)) => AppError::ParserTimeContextRequired {
                source_name: metadata.source.reference().into(),
                requirement,
                suggestions: vec![],
            },
            _ => invalid(),
        }
    })?;
    let next = current.candidate(crate::time_context::month(line).ok_or_else(invalid)?)?;
    let context = metadata.time_context.ok_or_else(invalid)?;
    let header = crate::record::classic(
        rest,
        crate::LegacyTimestamp::new(i32::from(next.year()), i32::from(context.offset_minutes()))?,
    )?;
    Ok((header, Some(next)))
}
