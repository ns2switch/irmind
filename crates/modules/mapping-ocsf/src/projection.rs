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
    let time = source
        .timestamp()
        .ok_or(MappingError::UnsupportedSourceValue)?
        .to_rfc3339();
    let at = format!(
        "{}Z",
        time.get(..19).ok_or(MappingError::UnsupportedSourceValue)?
    );
    let action = view
        .text("activity_name")?
        .or(view.text("api.operation")?)
        .unwrap_or("OCSF event");
    let mut fields = BTreeMap::from([
        ("at".into(), SourceValue::Text(at.clone())),
        ("action".into(), SourceValue::Text(action.into())),
        ("attributes".into(), source.fields().clone()),
    ]);
    for (target, path) in [
        ("result", "status"),
        ("host", "device.hostname"),
        ("user", "actor.user.name"),
        ("process", "process.name"),
        ("command_line", "process.cmd_line"),
        ("source_ip", "src_endpoint.ip"),
        ("source_port", "src_endpoint.port"),
        ("destination_ip", "dst_endpoint.ip"),
        ("destination_port", "dst_endpoint.port"),
        ("account_id", "cloud.account.uid"),
        ("provider", "cloud.provider"),
        ("region", "cloud.region"),
    ] {
        fields.insert(
            target.into(),
            view.get(path).cloned().unwrap_or(SourceValue::Null),
        );
    }
    let entities = entities(view);
    Ok(GraphRecord {
        index: usize::try_from(source.origin().record())
            .map_err(|_| MappingError::UnsupportedSourceValue)?,
        at,
        event: action.into(),
        text: render_source_fields(&SourceValue::Object(fields))
            .map_err(|_| MappingError::UnsupportedSourceValue)?,
        entities,
        relations: Vec::new(),
    })
}

fn entities(view: &View<'_>) -> Vec<(String, String)> {
    let mut entities = Vec::new();
    for (kind, path) in [
        ("host", "device.hostname"),
        ("user", "actor.user.name"),
        ("user", "user.name"),
        ("process", "process.name"),
        ("command_line", "process.cmd_line"),
        ("ip", "src_endpoint.ip"),
        ("ip", "dst_endpoint.ip"),
        ("port", "src_endpoint.port"),
        ("port", "dst_endpoint.port"),
        ("file", "file.path"),
        ("finding", "finding_info.title"),
        ("account", "cloud.account.uid"),
    ] {
        let value = match view.get(path) {
            Some(SourceValue::Text(s)) => Some(s.as_str()),
            Some(SourceValue::Number(n)) => Some(n.as_str()),
            _ => None,
        };
        if let Some(value) = value.filter(|s| !s.is_empty() && s.len() <= 4096) {
            entities.push((kind.into(), value.into()));
        }
    }
    // OCSF resource names retain the legacy searchable projection without assigning a role.
    if let Some(SourceValue::Array(resources)) = view.get("resources")
        && let Some(name) = resources
            .first()
            .and_then(|v| v.field("name"))
            .and_then(SourceValue::as_text)
            .filter(|s| !s.is_empty() && s.len() <= 4096)
    {
        entities.push(("resource".into(), name.into()));
    }
    entities.sort();
    entities.dedup();
    entities
}
