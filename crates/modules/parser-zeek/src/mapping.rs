use serde::Deserialize;

// Borrowed columns retain the detector's input-type checks. Underscored
// columns are validated by deserialization and never normalized here.
#[derive(Deserialize)]
struct JsonRow<'a> {
    #[serde(borrow)]
    ts: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow)]
    uid: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "id.orig_h")]
    orig_h: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "id.resp_h")]
    _resp_h: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "id.orig_p")]
    _orig_p: Option<serde_json::Number>,
    #[serde(rename = "id.resp_p")]
    _resp_p: Option<serde_json::Number>,
    #[serde(rename = "query", borrow)]
    _query: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "host", borrow)]
    _host: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "method", borrow)]
    _method: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "sensor_host", borrow)]
    _sensor_host: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "uri", borrow)]
    _uri: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "server_name", borrow)]
    _server_name: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    fuid: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "filename", borrow)]
    _filename: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    fingerprint: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    note: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "name", borrow)]
    _name: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "user_agent", borrow)]
    _user_agent: Option<std::borrow::Cow<'a, str>>,
}

pub(super) fn detect_json(sample: &[u8]) -> Option<u8> {
    let first = sample
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())?;
    let row: JsonRow<'_> = serde_json::from_slice(first).ok()?;
    row.ts.as_ref()?;
    if row.uid.is_some() && row.orig_h.is_some() {
        Some(95)
    } else if row.fingerprint.is_some() || row.fuid.is_some() || row.note.is_some() {
        Some(80)
    } else {
        None
    }
}
