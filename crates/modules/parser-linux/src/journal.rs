use serde::Deserialize;
use std::borrow::Cow;

#[derive(Deserialize)]
struct Row<'a> {
    #[serde(borrow, rename = "__REALTIME_TIMESTAMP")]
    realtime: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_HOSTNAME")]
    host: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_UID")]
    _user: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_AUDIT_LOGINUID")]
    _auid: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_PID")]
    _pid: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_EXE")]
    _executable: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_COMM")]
    _process: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "_CMDLINE")]
    _command: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "SYSLOG_IDENTIFIER")]
    _identifier: Option<Cow<'a, str>>,
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
