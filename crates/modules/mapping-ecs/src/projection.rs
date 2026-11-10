use super::view::View;
use irmind_app::{
    GraphRecord,
    source_mapping::{MappingError, SourceRecordV1, SourceValue, json::render_source_fields},
};
use std::collections::BTreeMap;
pub(super) fn project(
    source: &SourceRecordV1,
    view: &View<'_>,
) -> Result<GraphRecord, MappingError> {
    let instant = source.timestamp().ok_or_else(invalid)?.to_rfc3339();
    let at = format!("{}Z", instant.get(..19).ok_or_else(invalid)?);
    let event = view
        .text("event.action")?
        .or_else(|| match view.get("event.category") {
            Ok(Some(SourceValue::Array(values))) => values.first().and_then(SourceValue::as_text),
            _ => None,
        })
        .unwrap_or("record");
    let mut fields = BTreeMap::from([
        ("at".into(), SourceValue::Text(at.clone())),
        ("action".into(), SourceValue::Text(event.into())),
        ("attributes".into(), source.fields().clone()),
    ]);
    for (target, key) in [
        ("result", "event.outcome"),
        ("host", "host.name"),
        ("user", "user.name"),
        ("process", "process.name"),
        ("command_line", "process.command_line"),
        ("source_ip", "source.ip"),
        ("source_port", "source.port"),
        ("destination_ip", "destination.ip"),
        ("destination_port", "destination.port"),
        ("file", "file.path"),
        ("url", "url.full"),
    ] {
        fields.insert(
            target.into(),
            view.get(key)?.cloned().unwrap_or(SourceValue::Null),
        );
    }
    let mut entities = Vec::new();
    for (kind, key) in [
        ("host", "host.name"),
        ("user", "user.name"),
        ("process", "process.name"),
        ("command_line", "process.command_line"),
        ("ip", "source.ip"),
        ("ip", "destination.ip"),
        ("port", "source.port"),
        ("port", "destination.port"),
        ("file", "file.path"),
        ("url", "url.full"),
    ] {
        let value = match view.get(key)? {
            Some(SourceValue::Text(text)) => Some(text.clone()),
            Some(SourceValue::Number(number)) => Some(number.as_str().into()),
            _ => None,
        };
        if let Some(value) = value.filter(|value| !value.is_empty() && value.len() <= 4096) {
            entities.push((kind.into(), value));
        }
    }
    entities.sort();
    entities.dedup();
    Ok(GraphRecord {
        index: usize::try_from(source.origin().record()).map_err(|_| invalid())?,
        at,
        event: event.into(),
        text: render_source_fields(&SourceValue::Object(fields)).map_err(|_| invalid())?,
        entities,
        relations: Vec::new(),
    })
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
