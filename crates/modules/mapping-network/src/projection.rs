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
pub(super) struct View<'a> {
    fields: &'a SourceValue,
    zeek: bool,
    tsv: bool,
}
impl<'a> View<'a> {
    pub(super) fn new(source: &'a SourceRecordV1, zeek: bool) -> Result<Self, MappingError> {
        let tsv = zeek && source.format().id() == "zeek-tsv";
        let fields = if tsv {
            source.fields().field("columns").ok_or_else(invalid)?
        } else {
            source.fields()
        };
        Ok(Self { fields, zeek, tsv })
    }
    pub(super) fn is_tsv(&self) -> bool {
        self.tsv
    }
    pub(super) fn raw(&self, path: &str) -> Option<&'a SourceValue> {
        if self.zeek {
            self.fields.field(path)
        } else {
            path.split('.').try_fold(self.fields, |v, key| v.field(key))
        }
    }
    pub(super) fn get(&self, path: &str) -> Option<&'a str> {
        let value = self.raw(path)?;
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
pub(super) fn zeek_kind<'a>(source: &'a SourceRecordV1, view: &View<'a>) -> &'a str {
    let declared = source
        .format()
        .discriminators()
        .get(&SourceDiscriminator::Dataset)
        .map(String::as_str)
        .or_else(|| view.get("_path"));
    if let Some(kind) = declared {
        return if matches!(
            kind,
            "conn" | "dns" | "http" | "ssl" | "files" | "x509" | "notice" | "weird"
        ) {
            kind
        } else {
            "unknown"
        };
    }
    let candidates = [
        (
            "dns",
            ["query", "qtype_name", "rcode", "rcode_name"]
                .iter()
                .any(|f| view.get(f).is_some()),
        ),
        (
            "http",
            ["method", "uri", "status_code"]
                .iter()
                .any(|f| view.get(f).is_some()),
        ),
        (
            "ssl",
            view.get("server_name").is_some()
                || view.get("cipher").is_some()
                || view.raw("established").is_some(),
        ),
        ("files", view.get("fuid").is_some()),
        ("x509", view.get("fingerprint").is_some()),
        ("notice", view.get("note").is_some()),
        ("weird", view.get("name").is_some()),
    ];
    let mut selected = candidates.into_iter().filter(|(_, present)| *present);
    match (selected.next(), selected.next()) {
        (Some((kind, _)), None) => kind,
        (None, None) if view.get("id.orig_h").is_some() || view.get("id.resp_h").is_some() => {
            "conn"
        }
        _ => "unknown",
    }
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
