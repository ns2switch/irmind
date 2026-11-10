//! Preserve network search identities and correlation relations without classifying telemetry.
use irmind_app::{
    GraphRecord, GraphRelation,
    source_mapping::{
        MappingError, SourceDiscriminator, SourceRecordV1, SourceValue, json::render_source_fields,
    },
};
type Alias = (&'static str, &'static str);
const ZEEK: &[Alias] = &[
    ("uid", "uid"),
    ("ip", "id.orig_h"),
    ("ip", "id.resp_h"),
    ("port", "id.orig_p"),
    ("port", "id.resp_p"),
    ("domain", "query"),
    ("host", "sensor_host"),
    ("domain", "server_name"),
    ("file", "filename"),
    ("fuid", "fuid"),
    ("certificate", "fingerprint"),
    ("finding", "note"),
    ("finding", "name"),
    ("user_agent", "user_agent"),
];
const SURICATA: &[Alias] = &[
    ("flow", "flow_id"),
    ("ip", "src_ip"),
    ("ip", "dest_ip"),
    ("port", "src_port"),
    ("port", "dest_port"),
    ("host", "host"),
    ("rule_id", "alert.signature_id"),
    ("finding", "alert.signature"),
    ("category", "alert.category"),
    ("action", "alert.action"),
    ("domain", "dns.rrname"),
    ("domain", "http.hostname"),
    ("url", "http.url"),
    ("method", "http.http_method"),
    ("user_agent", "http.http_user_agent"),
    ("domain", "tls.sni"),
    ("file", "fileinfo.filename"),
    ("finding", "anomaly.event"),
];
struct View<'a> {
    fields: &'a SourceValue,
    zeek: bool,
    tsv: bool,
}
impl<'a> View<'a> {
    fn new(source: &'a SourceRecordV1, zeek: bool) -> Result<Self, MappingError> {
        let tsv = zeek && source.format().id() == "zeek-tsv";
        let fields = if tsv {
            source.fields().field("columns").ok_or_else(invalid)?
        } else {
            source.fields()
        };
        Ok(Self { fields, zeek, tsv })
    }
    fn get(&self, path: &str) -> Option<&'a str> {
        let value = if self.zeek {
            self.fields.field(path)
        } else {
            path.split('.').try_fold(self.fields, |v, key| v.field(key))
        }?;
        let text = match value {
            SourceValue::Text(t) => t.as_str(),
            SourceValue::Number(n) => n.as_str(),
            _ => return None,
        };
        (!text.is_empty() && text.len() <= 4096 && (!self.tsv || !matches!(text, "-" | "(empty)")))
            .then_some(text)
    }
}
pub(super) fn project<'a>(
    parser: &str,
    source: &'a SourceRecordV1,
) -> Result<(GraphRecord, &'a str), MappingError> {
    let zeek = parser == "parser-zeek";
    let view = View::new(source, zeek)?;
    let aliases = if zeek { ZEEK } else { SURICATA };
    let mut entities = aliases
        .iter()
        .filter_map(|(kind, path)| view.get(path).map(|v| ((*kind).into(), v.into())))
        .collect::<Vec<_>>();
    if zeek
        && view.get("query").is_none()
        && !view.tsv
        && let Some(v) = view.get("host")
    {
        entities.push(("domain".into(), v.into()));
    }
    entities.sort();
    entities.dedup();
    let host = view
        .get(if zeek { "sensor_host" } else { "host" })
        .unwrap_or("");
    let event = if zeek {
        format!("zeek_{}", zeek_kind(source, &view))
    } else {
        format!("suricata_{}", view.get("event_type").ok_or_else(invalid)?)
    };
    let record = GraphRecord {
        index: usize::try_from(source.origin().record()).map_err(|_| invalid())?,
        at: source
            .timestamp()
            .map(irmind_app::IndexedTime::to_rfc3339)
            .unwrap_or_default(),
        event,
        text: render_source_fields(source.fields()).map_err(|_| invalid())?,
        entities,
        relations: relations(&view),
    };
    Ok((record, host))
}
fn zeek_kind<'a>(source: &'a SourceRecordV1, view: &View<'_>) -> &'a str {
    if let Some(kind) = source
        .format()
        .discriminators()
        .get(&SourceDiscriminator::Dataset)
    {
        return kind;
    }
    for (field, kind) in [
        ("query", "dns"),
        ("method", "http"),
        ("uri", "http"),
        ("server_name", "ssl"),
        ("fuid", "files"),
        ("fingerprint", "x509"),
        ("note", "notice"),
        ("name", "weird"),
    ] {
        if view.get(field).is_some() {
            return kind;
        }
    }
    "conn"
}
fn relations(view: &View<'_>) -> Vec<GraphRelation> {
    let (kind, key, aliases) = if view.zeek {
        (
            "uid",
            "uid",
            &[
                ("ip", "id.orig_h", "originated_from"),
                ("ip", "id.resp_h", "responded_at"),
                ("domain", "query", "queried"),
                ("domain", "server_name", "connected_to"),
                ("fuid", "fuid", "transferred"),
            ][..],
        )
    } else {
        (
            "flow",
            "flow_id",
            &[
                ("ip", "src_ip", "source_ip"),
                ("ip", "dest_ip", "destination_ip"),
                ("finding", "alert.signature", "triggered"),
                ("domain", "dns.rrname", "queried"),
                ("domain", "tls.sni", "connected_to"),
            ][..],
        )
    };
    let Some(from) = view.get(key) else {
        return Vec::new();
    };
    let mut out = aliases
        .iter()
        .filter_map(|(to_kind, path, relation)| {
            view.get(path).map(|value| GraphRelation {
                from_kind: kind.into(),
                from_value: from.into(),
                relation: (*relation).into(),
                to_kind: (*to_kind).into(),
                to_value: value.into(),
            })
        })
        .collect::<Vec<_>>();
    if view.zeek
        && !view.tsv
        && view.get("query").is_none()
        && let Some(value) = view.get("host")
    {
        out.push(GraphRelation {
            from_kind: kind.into(),
            from_value: from.into(),
            relation: "queried".into(),
            to_kind: "domain".into(),
            to_value: value.into(),
        });
    }
    out
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
