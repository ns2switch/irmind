use super::view::View;
use irmind_app::source_mapping::{MappingDiagnostic, MappingError};
use irmind_domain::{
    CategorySet, EventCategory as C, EventHeaderV1, EventKind, EventOutcome as O, EventType as T,
    EventTypeSet,
};
pub(super) fn project(
    view: &View<'_>,
) -> Result<(EventHeaderV1, Vec<MappingDiagnostic>), MappingError> {
    let class = view
        .uint("class_uid")?
        .ok_or(MappingError::UnsupportedSourceValue)?;
    let category = view
        .uint("category_uid")?
        .ok_or(MappingError::UnsupportedSourceValue)?;
    let known = match class {
        1001 => Some((1, C::File)),
        1007 => Some((1, C::Process)),
        2004 => Some((2, C::IntrusionDetection)),
        3002 => Some((3, C::Authentication)),
        4001 => Some((4, C::Network)),
        6003 => Some((6, C::Api)),
        _ => None,
    };
    let supported = view.text("metadata.version")? == Some("1.4.0")
        && known.is_some_and(|(expected, _)| expected == category);
    let mut diagnostics = Vec::new();
    let (categories, types, outcome) = if supported {
        (
            CategorySet::new(known.into_iter().map(|(_, c)| c)),
            EventTypeSet::new(types(class, view.uint("activity_id")?)),
            outcome(view, &mut diagnostics)?,
        )
    } else {
        diagnostics.extend([
            MappingDiagnostic::UnsupportedValue,
            MappingDiagnostic::Unclassified,
        ]);
        (CategorySet::new([]), EventTypeSet::new([]), O::Unknown)
    };
    let kind = if supported
        && class == 2004
        && matches!(
            view.get("is_alert"),
            Some(irmind_app::source_mapping::SourceValue::Boolean(true))
        ) {
        EventKind::Alert
    } else {
        EventKind::Event
    };
    let mut header = EventHeaderV1::new(categories, types, outcome, kind);
    if let Some(action) = view.text("activity_name")?.or(view.text("api.operation")?) {
        header = header
            .with_action(action)
            .map_err(|_| MappingError::UnsupportedSourceValue)?;
    }
    header = header
        .with_code(&class.to_string())
        .map_err(|_| MappingError::UnsupportedSourceValue)?;
    Ok((header, diagnostics))
}
fn outcome(view: &View<'_>, diagnostics: &mut Vec<MappingDiagnostic>) -> Result<O, MappingError> {
    let from_id = match view.uint("status_id")? {
        Some(1) => Some(O::Success),
        Some(2) => Some(O::Failure),
        Some(0 | 99) => Some(O::Unknown),
        None => None,
        Some(_) => {
            diagnostics.push(MappingDiagnostic::UnsupportedValue);
            Some(O::Unknown)
        }
    };
    let from_text = match view.text("status")? {
        Some("Success") => Some(O::Success),
        Some("Failure") => Some(O::Failure),
        Some("Unknown" | "Other") => Some(O::Unknown),
        None => None,
        Some(_) => {
            diagnostics.push(MappingDiagnostic::UnsupportedValue);
            Some(O::Unknown)
        }
    };
    if matches!((from_id,from_text),(Some(a),Some(b)) if a!=b) {
        diagnostics.push(MappingDiagnostic::UnsupportedValue);
        return Ok(O::Unknown);
    }
    Ok(from_id.or(from_text).unwrap_or(O::Unknown))
}
fn types(class: u32, activity: Option<u32>) -> Vec<T> {
    match (class, activity) {
        (3002 | 1007, Some(1)) => vec![T::Start],
        (3002 | 1007, Some(2)) => vec![T::End],
        (1007, Some(3)) | (1001 | 6003, Some(2)) | (1001, Some(8 | 9 | 14)) => vec![T::Access],
        (1007, Some(4 | 5)) | (1001 | 6003, Some(3)) | (1001, Some(5..=7 | 10 | 11)) => {
            vec![T::Change]
        }
        (1001 | 6003, Some(1)) => vec![T::Creation],
        (1001 | 6003, Some(4)) => vec![T::Deletion],
        (4001, Some(1)) => vec![T::Connection, T::Start],
        (4001, Some(2 | 3)) => vec![T::Connection, T::End],
        (4001, Some(4)) => vec![T::Connection, T::Error],
        (4001, Some(5)) => vec![T::Connection, T::Denied],
        (4001, Some(6 | 7)) => vec![T::Connection],
        (2004, _) => vec![T::Info],
        _ => Vec::new(),
    }
}
