use irmind_app::{AppError, GraphRecord, GraphRelation};
use serde::Deserialize;

#[derive(Deserialize)]
struct EveRow<'a> {
    #[serde(borrow)]
    timestamp: Option<std::borrow::Cow<'a, str>>,
    flow_id: Option<u64>,
    #[serde(borrow)]
    event_type: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    src_ip: Option<std::borrow::Cow<'a, str>>,
    src_port: Option<u16>,
    #[serde(borrow)]
    dest_ip: Option<std::borrow::Cow<'a, str>>,
    dest_port: Option<u16>,
    #[serde(borrow)]
    host: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    alert: Option<Alert<'a>>,
    #[serde(borrow)]
    dns: Option<Dns<'a>>,
    #[serde(borrow)]
    http: Option<Http<'a>>,
    #[serde(borrow)]
    tls: Option<Tls<'a>>,
    #[serde(borrow)]
    fileinfo: Option<FileInfo<'a>>,
    #[serde(borrow)]
    anomaly: Option<Anomaly<'a>>,
}

#[derive(Deserialize)]
struct Alert<'a> {
    #[serde(borrow)]
    signature: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    category: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    action: Option<std::borrow::Cow<'a, str>>,
    signature_id: Option<u64>,
}

#[derive(Deserialize)]
struct Dns<'a> {
    #[serde(borrow)]
    rrname: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Http<'a> {
    #[serde(borrow)]
    hostname: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow)]
    url: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "http_method")]
    method: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, rename = "http_user_agent")]
    user_agent: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Tls<'a> {
    #[serde(borrow)]
    sni: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct FileInfo<'a> {
    #[serde(borrow)]
    filename: Option<std::borrow::Cow<'a, str>>,
}

#[derive(Deserialize)]
struct Anomaly<'a> {
    #[serde(borrow)]
    event: Option<std::borrow::Cow<'a, str>>,
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

pub(super) fn parse(line: &[u8], index: usize) -> Result<GraphRecord, AppError> {
    let row: EveRow<'_> = serde_json::from_slice(line).map_err(|_| bad())?;
    let event_type = row
        .event_type
        .as_deref()
        .filter(|kind| supported_type(kind))
        .ok_or_else(bad)?;
    let timestamp = row.timestamp.as_deref().ok_or_else(bad)?;
    let at = parse_time(timestamp)?;
    let text = std::str::from_utf8(line)
        .map_err(|_| bad())?
        .trim_end()
        .to_owned();
    let (entities, relations) = graph_fields(&row);
    Ok(GraphRecord {
        index,
        at,
        event: format!("suricata_{event_type}"),
        text,
        entities,
        relations,
    })
}

fn supported_type(kind: &str) -> bool {
    matches!(
        kind,
        "alert" | "flow" | "dns" | "http" | "tls" | "fileinfo" | "anomaly"
    )
}

fn parse_time(raw: &str) -> Result<String, AppError> {
    if raw.len() > 64 || !raw.is_ascii() {
        return Err(bad());
    }
    let mut normalized = raw.to_owned();
    if let Some(zone) = raw.get(raw.len().saturating_sub(5)..)
        && zone.len() == 5
        && zone.starts_with(['+', '-'])
        && zone.as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        normalized.insert(normalized.len() - 2, ':');
    }
    irmind_app::indexed_rfc3339(&normalized, false, false)
        .map(irmind_app::IndexedTime::to_rfc3339)
        .map_err(|_| bad())
}

fn graph_fields(row: &EveRow<'_>) -> (Vec<(String, String)>, Vec<GraphRelation>) {
    let mut entities = Vec::new();
    let flow = row.flow_id.map(|id| id.to_string());
    let src_port = row.src_port.map(|port| port.to_string());
    let dst_port = row.dest_port.map(|port| port.to_string());
    let signature_id = row
        .alert
        .as_ref()
        .and_then(|alert| alert.signature_id)
        .map(|id| id.to_string());
    for (kind, value) in [
        ("flow", flow.as_deref()),
        ("ip", row.src_ip.as_deref()),
        ("ip", row.dest_ip.as_deref()),
        ("port", src_port.as_deref()),
        ("port", dst_port.as_deref()),
        ("host", row.host.as_deref()),
        (
            "finding",
            row.alert
                .as_ref()
                .and_then(|alert| alert.signature.as_deref()),
        ),
        (
            "category",
            row.alert
                .as_ref()
                .and_then(|alert| alert.category.as_deref()),
        ),
        (
            "action",
            row.alert.as_ref().and_then(|alert| alert.action.as_deref()),
        ),
        ("rule_id", signature_id.as_deref()),
        (
            "domain",
            row.dns.as_ref().and_then(|dns| dns.rrname.as_deref()),
        ),
        (
            "domain",
            row.http.as_ref().and_then(|http| http.hostname.as_deref()),
        ),
        (
            "url",
            row.http.as_ref().and_then(|http| http.url.as_deref()),
        ),
        (
            "method",
            row.http.as_ref().and_then(|http| http.method.as_deref()),
        ),
        (
            "user_agent",
            row.http
                .as_ref()
                .and_then(|http| http.user_agent.as_deref()),
        ),
        (
            "domain",
            row.tls.as_ref().and_then(|tls| tls.sni.as_deref()),
        ),
        (
            "file",
            row.fileinfo
                .as_ref()
                .and_then(|file| file.filename.as_deref()),
        ),
        (
            "finding",
            row.anomaly
                .as_ref()
                .and_then(|anomaly| anomaly.event.as_deref()),
        ),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty() && value.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    entities.sort();
    entities.dedup();
    let mut relations = Vec::new();
    if let Some(flow) = flow.as_deref() {
        add_relation(
            &mut relations,
            flow,
            "ip",
            row.src_ip.as_deref(),
            "source_ip",
        );
        add_relation(
            &mut relations,
            flow,
            "ip",
            row.dest_ip.as_deref(),
            "destination_ip",
        );
        add_relation(
            &mut relations,
            flow,
            "finding",
            row.alert
                .as_ref()
                .and_then(|alert| alert.signature.as_deref()),
            "triggered",
        );
        add_relation(
            &mut relations,
            flow,
            "domain",
            row.dns.as_ref().and_then(|dns| dns.rrname.as_deref()),
            "queried",
        );
        add_relation(
            &mut relations,
            flow,
            "domain",
            row.tls.as_ref().and_then(|tls| tls.sni.as_deref()),
            "connected_to",
        );
    }
    (entities, relations)
}

fn add_relation(
    relations: &mut Vec<GraphRelation>,
    flow: &str,
    to_kind: &str,
    to_value: Option<&str>,
    relation: &str,
) {
    if let Some(value) = to_value.filter(|value| !value.is_empty() && value.len() <= 4096) {
        relations.push(GraphRelation {
            from_kind: "flow".into(),
            from_value: flow.into(),
            relation: relation.into(),
            to_kind: to_kind.into(),
            to_value: value.into(),
        });
    }
}

fn bad() -> AppError {
    AppError::Policy("invalid Suricata EVE record".into())
}
