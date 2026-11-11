use serde::Deserialize;

// Borrowed columns retain the detector's input-type checks. Underscored
// columns are validated by deserialization and never normalized here.
#[derive(Deserialize)]
struct EveRow<'a> {
    #[serde(borrow)]
    timestamp: Option<std::borrow::Cow<'a, str>>,
    flow_id: Option<u64>,
    #[serde(borrow)]
    event_type: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "src_ip", borrow)]
    _src_ip: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "src_port")]
    _src_port: Option<u16>,
    #[serde(rename = "dest_ip", borrow)]
    _dest_ip: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "dest_port")]
    _dest_port: Option<u16>,
    #[serde(rename = "host", borrow)]
    _host: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "alert", borrow)]
    _alert: Option<Alert<'a>>,
    #[serde(rename = "dns", borrow)]
    _dns: Option<Dns<'a>>,
    #[serde(rename = "http", borrow)]
    _http: Option<Http<'a>>,
    #[serde(rename = "tls", borrow)]
    _tls: Option<Tls<'a>>,
    #[serde(rename = "fileinfo", borrow)]
    _fileinfo: Option<FileInfo<'a>>,
    #[serde(rename = "anomaly", borrow)]
    _anomaly: Option<Anomaly<'a>>,
}

#[derive(Deserialize)]
struct Alert<'a> {
    #[serde(rename = "signature", borrow)]
    _signature: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "category", borrow)]
    _category: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "action", borrow)]
    _action: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "signature_id")]
    _signature_id: Option<u64>,
}

#[derive(Deserialize)]
struct Dns<'a> {
    #[serde(rename = "rrname", borrow)]
    _rrname: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Http<'a> {
    #[serde(rename = "hostname", borrow)]
    _hostname: Option<std::borrow::Cow<'a, str>>,
    #[serde(rename = "url", borrow)]
    _url: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "http_method")]
    _method: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "http_user_agent")]
    _user_agent: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Tls<'a> {
    #[serde(rename = "sni", borrow)]
    _sni: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct FileInfo<'a> {
    #[serde(rename = "filename", borrow)]
    _filename: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Anomaly<'a> {
    #[serde(rename = "event", borrow)]
    _event: Option<std::borrow::Cow<'a, str>>,
}

pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let first = sample
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())?;
    let row: EveRow<'_> = serde_json::from_slice(first).ok()?;
    row.timestamp?;
    row.flow_id?;
    supported_type(row.event_type.as_deref()?).then_some(95)
}

fn supported_type(kind: &str) -> bool {
    matches!(
        kind,
        "alert" | "flow" | "dns" | "http" | "tls" | "fileinfo" | "anomaly"
    )
}
