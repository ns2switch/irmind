use crate::{AppError, IndexedTime};

/// A module declares whether its documented naive form is UTC. Input stays bounded.
pub fn indexed_rfc3339(
    raw: &str,
    inferred: bool,
    assume_utc: bool,
) -> Result<IndexedTime, AppError> {
    if raw.len() > 64 || !raw.is_ascii() {
        return Err(AppError::Fixed(
            crate::FixedAppError::PolicyInvalidIndexedTimestamp,
        ));
    }
    let mut value = raw.trim().to_owned();
    if value.as_bytes().get(10) == Some(&b' ') {
        value.replace_range(10..11, "T");
    }
    if let Some(prefix) = value.strip_suffix(" UTC") {
        value = format!("{prefix}Z");
    }
    if let Some((clock, zone)) = value.rsplit_once(' ')
        && (zone.starts_with('+') || zone.starts_with('-'))
    {
        value = format!("{clock}{zone}");
    }
    if assume_utc
        && !value.ends_with('Z')
        && !value
            .get(19..)
            .is_some_and(|tail| tail.contains(['+', '-']))
    {
        value.push('Z');
    }
    IndexedTime::from_rfc3339(&value, inferred)
        .map_err(|_| AppError::Fixed(crate::FixedAppError::PolicyInvalidIndexedTimestamp))
}
