use crate::{AppError, ParserTimeContext};
use irmind_domain::IndexedTime;
/// Original datetime text with a confirmed offset only when the source omits one.
pub fn source_datetime(
    raw: &str,
    context: Option<&ParserTimeContext>,
) -> Result<IndexedTime, AppError> {
    if raw.len() > 128 {
        return Err(super::invalid());
    }
    if let Ok(value) = IndexedTime::from_rfc3339(raw, false) {
        return Ok(value);
    }
    let normalized = if raw.as_bytes().get(10) == Some(&b' ') {
        format!(
            "{}T{}",
            &raw[..10],
            raw[11..].replace(" +", "+").replace(" -", "-")
        )
    } else {
        raw.to_owned()
    };
    if let Ok(value) = IndexedTime::from_rfc3339(&normalized, false) {
        return Ok(value);
    }
    let offset = context.ok_or_else(super::invalid)?.offset_minutes();
    let normalized = format!(
        "{normalized}{}{:02}:{:02}",
        if offset < 0 { '-' } else { '+' },
        offset.abs() / 60,
        offset.abs() % 60
    );
    IndexedTime::from_rfc3339(&normalized, true).map_err(|_| super::invalid())
}
