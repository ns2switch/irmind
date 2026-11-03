use super::{AppError, GraphRecord, bad, record::Record};
use chrono::DateTime;
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "__REALTIME_TIMESTAMP")]
    realtime: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_HOSTNAME")]
    host: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_UID")]
    user: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_AUDIT_LOGINUID")]
    auid: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_PID")]
    pid: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_EXE")]
    executable: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_COMM")]
    process: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_CMDLINE")]
    command: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "SYSLOG_IDENTIFIER")]
    identifier: Option<Cow<'a, str>>,
    #[serde(rename = "MESSAGE")]
    message: Option<serde::de::IgnoredAny>,
}
pub(super) fn detect(line: &str) -> bool {
    if !super::bounds::json_shape(line.as_bytes()) {
        return false;
    }
    let Ok(row) = serde_json::from_str::<Row<'_>>(line) else {
        return false;
    };
    row.realtime.is_some() && (row.host.is_some() || row.message.is_some())
}
pub(super) fn parse(line: &str, index: usize) -> Result<GraphRecord, AppError> {
    if !super::bounds::json_shape(line.as_bytes()) {
        return Err(invalid());
    }
    let row: Row<'_> = serde_json::from_str(line).map_err(|_| invalid())?;
    let micros = row
        .realtime
        .as_deref()
        .ok_or_else(invalid)?
        .parse::<i64>()
        .map_err(|_| invalid())?;
    let at = DateTime::from_timestamp_micros(micros).ok_or_else(invalid)?;
    let mut record = Record::new(at, "journal_entry", line);
    record.host = row.host.as_deref();
    record.user = row.user.as_deref();
    record.auid = row.auid.as_deref();
    record.pid = row.pid.as_deref();
    record.process = row
        .executable
        .as_deref()
        .or(row.process.as_deref())
        .or(row.identifier.as_deref());
    record.command_line = row.command.as_deref();
    // raw contains the exact __REALTIME_TIMESTAMP and every unmapped field.
    record.graph(index)
}
fn invalid() -> AppError {
    bad("invalid bounded journald JSON record")
}
