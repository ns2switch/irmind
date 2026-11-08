use irmind_app::{
    GraphRecord,
    source_mapping::{MappingError, SourceRecordV1, SourceValue},
};
use irmind_domain::{IndexedInstant, IndexedTime, TimePrecision};
use serde::Serialize;

/// Historical field order is explicit, independent of `serde_json`'s map features.
#[derive(Serialize)]
struct Record<'a> {
    timestamp: String,
    timestamp_inferred: bool,
    host: Option<&'a str>,
    user: Option<&'a str>,
    authentication_method: Option<&'a str>,
    url: Option<&'a str>,
    http_method: Option<&'a str>,
    target_user: Option<&'a str>,
    auid: Option<&'a str>,
    process: Option<&'a str>,
    pid: Option<&'a str>,
    command_line: Option<&'a str>,
    socket_ip: Option<&'a str>,
    socket_port: Option<&'a str>,
    source_ip: Option<&'a str>,
    source_port: Option<&'a str>,
    destination_ip: Option<&'a str>,
    destination_port: Option<&'a str>,
    cwd: Option<&'a str>,
    path: Option<&'a str>,
    action: &'a str,
    outcome: &'a str,
    partial: bool,
    raw: &'a str,
}
pub(super) fn project(source: &SourceRecordV1) -> Result<GraphRecord, MappingError> {
    let time = source.timestamp().ok_or(MappingError::InvalidOutput)?;
    let fields = source.fields();
    let text = |key| fields.field(key).and_then(SourceValue::as_text);
    let record = Record {
        timestamp: timestamp(time),
        timestamp_inferred: false,
        host: text("_HOSTNAME"),
        user: text("_UID"),
        auid: text("_AUDIT_LOGINUID"),
        process: text("_EXE")
            .or_else(|| text("_COMM"))
            .or_else(|| text("SYSLOG_IDENTIFIER")),
        pid: text("_PID"),
        command_line: text("_CMDLINE"),
        authentication_method: None,
        url: None,
        http_method: None,
        target_user: None,
        socket_ip: None,
        socket_port: None,
        source_ip: None,
        source_port: None,
        destination_ip: None,
        destination_port: None,
        cwd: None,
        path: None,
        action: "journal_entry",
        outcome: "unknown",
        partial: source.annotations().partial(),
        raw: source
            .annotations()
            .raw()
            .ok_or(MappingError::InvalidOutput)?,
    };
    let mut entities = [
        ("host", record.host),
        ("user", record.user),
        ("user", record.auid),
        ("process", record.process),
        ("pid", record.pid),
        ("command_line", record.command_line),
    ]
    .into_iter()
    .filter_map(|(kind, value)| {
        value
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .map(|v| (kind.into(), v.into()))
    })
    .collect::<Vec<(String, String)>>();
    entities.sort();
    entities.dedup();
    let instant = IndexedInstant::new(
        time.instant().unix_micros().div_euclid(1_000_000) * 1_000_000,
        0,
    )
    .map_err(|_| MappingError::InvalidOutput)?;
    let at = IndexedTime::new(instant, TimePrecision::Second, false)
        .map_err(|_| MappingError::InvalidOutput)?
        .to_rfc3339();
    Ok(GraphRecord {
        index: usize::try_from(source.origin().record())
            .map_err(|_| MappingError::InvalidOutput)?,
        at,
        event: "journal_entry".into(),
        text: serde_json::to_string(&record).map_err(|_| MappingError::InvalidOutput)?,
        entities,
        relations: Vec::new(),
    })
}
fn timestamp(time: IndexedTime) -> String {
    let mut text = time.to_rfc3339();
    if time.instant().unix_micros().rem_euclid(1000) == 0 && text.ends_with("000Z") {
        text.truncate(text.len() - 4);
        if text.ends_with(".000") {
            text.truncate(text.len() - 4);
        }
        text.push('Z');
    }
    text
}
