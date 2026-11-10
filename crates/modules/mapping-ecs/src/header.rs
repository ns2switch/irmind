use super::view::View;
use irmind_app::source_mapping::{MappingDiagnostic, MappingError, SourceValue};
use irmind_domain::{
    CategorySet, EventCategory, EventHeaderV1, EventKind, EventOutcome, EventType, EventTypeSet,
};
fn labels<T>(
    view: &View<'_>,
    path: &str,
    parse: fn(&str) -> Result<T, irmind_domain::EventSchemaError>,
    unsupported: &mut bool,
) -> Result<Vec<T>, MappingError> {
    if let Some(SourceValue::Text(value)) = view.get(path)? {
        return Ok(if let Ok(label) = parse(value) {
            vec![label]
        } else {
            *unsupported = true;
            Vec::new()
        });
    }
    let values = match view.get(path)? {
        None | Some(SourceValue::Null) => return Ok(Vec::new()),
        Some(SourceValue::Array(values)) if values.len() <= 32 => values,
        _ => {
            *unsupported = true;
            return Ok(Vec::new());
        }
    };
    let mut result = Vec::new();
    for value in values {
        match value.as_text().and_then(|text| parse(text).ok()) {
            Some(label) => result.push(label),
            None => *unsupported = true,
        }
    }
    Ok(result)
}
pub(super) fn project(
    view: &View<'_>,
) -> Result<(EventHeaderV1, Vec<MappingDiagnostic>), MappingError> {
    let mut unsupported = false;
    let categories = CategorySet::new(labels(
        view,
        "event.category",
        EventCategory::parse,
        &mut unsupported,
    )?);
    let types = EventTypeSet::new(labels(
        view,
        "event.type",
        EventType::parse,
        &mut unsupported,
    )?);
    let outcome = match view.text("event.outcome")? {
        None => EventOutcome::Unknown,
        Some(value) => EventOutcome::parse(value).unwrap_or_else(|_| {
            unsupported = true;
            EventOutcome::Unknown
        }),
    };
    let kind = match view.text("event.kind")? {
        None => EventKind::Event,
        Some(value) => EventKind::parse(value).unwrap_or_else(|_| {
            unsupported = true;
            EventKind::Event
        }),
    };
    let mut header = EventHeaderV1::new(categories, types, outcome, kind);
    if let Some(value) = view.text("event.action")? {
        header = header.with_action(value).map_err(invalid)?;
    }
    if let Some(value) = view.text("event.code")? {
        header = header.with_code(value).map_err(invalid)?;
    }
    if let Some(value) = view.text("event.id")? {
        header = header.with_id(value).map_err(invalid)?;
    }
    if let Some(value) = view.text("event.dataset")? {
        header = header.with_dataset(value).map_err(invalid)?;
    }
    Ok((
        header,
        if unsupported {
            vec![MappingDiagnostic::UnsupportedValue]
        } else {
            Vec::new()
        },
    ))
}
fn invalid(_: irmind_domain::EventSchemaError) -> MappingError {
    MappingError::UnsupportedSourceValue
}
