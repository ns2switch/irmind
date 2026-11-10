use irmind_app::{
    GraphRecord,
    source_mapping::{MappingError, SourceRecordV1, SourceValue, json::render_source_fields},
};
use irmind_domain::SourceNumber;
pub(super) fn project(source: &SourceRecordV1) -> Result<GraphRecord, MappingError> {
    let fields = source.fields();
    let text = |key| fields.field(key).and_then(SourceValue::as_text);
    let priority = match fields.field("pri") {
        Some(SourceValue::Number(n)) => n
            .as_str()
            .parse::<u8>()
            .ok()
            .filter(|v| *v <= 191)
            .ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    let mut projection = match fields {
        SourceValue::Object(values) => values.clone(),
        _ => return Err(invalid()),
    };
    let at = source
        .timestamp()
        .map(irmind_app::IndexedTime::to_rfc3339)
        .unwrap_or_default();
    projection.insert("timestamp".into(), SourceValue::Text(at.clone()));
    projection.insert(
        "timestamp_inferred".into(),
        SourceValue::Boolean(
            source
                .timestamp()
                .is_some_and(irmind_app::IndexedTime::inferred),
        ),
    );
    for (target, key) in [
        ("host", "hostname"),
        ("process", "app-name"),
        ("pid", "procid"),
        ("message_id", "msgid"),
        ("structured_data", "structured-data"),
    ] {
        projection.insert(
            target.into(),
            fields.field(key).cloned().unwrap_or(SourceValue::Null),
        );
    }
    projection.insert(
        "facility".into(),
        SourceValue::Number(
            SourceNumber::try_new(&(priority / 8).to_string()).map_err(|_| invalid())?,
        ),
    );
    projection.insert(
        "severity".into(),
        SourceValue::Number(
            SourceNumber::try_new(&(priority % 8).to_string()).map_err(|_| invalid())?,
        ),
    );
    let mut entities = [
        ("host", text("hostname")),
        ("process", text("app-name")),
        ("pid", text("procid")),
    ]
    .into_iter()
    .filter_map(|(kind, value)| {
        value
            .filter(|v| *v != "-" && !v.is_empty() && v.len() <= 4096)
            .map(|v| (kind.into(), v.into()))
    })
    .collect::<Vec<_>>();
    entities.sort();
    entities.dedup();
    let event = text("app-name").filter(|v| *v != "-").unwrap_or("syslog");
    Ok(GraphRecord {
        index: usize::try_from(source.origin().record()).map_err(|_| invalid())?,
        at,
        event: event.into(),
        text: render_source_fields(&SourceValue::Object(projection)).map_err(|_| invalid())?,
        entities,
        relations: Vec::new(),
    })
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
