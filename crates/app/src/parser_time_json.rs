use crate::{AppError, ParserTimeContext, ParserTimeRequirement, Provenance, SourceKind, Tainted};
use irmind_domain::ParserLocation;
use serde_json::Value;

pub struct ParserTimeFields {
    pub parser_id: &'static str,
    pub hosts: &'static [&'static str],
    pub timestamps: &'static [&'static str],
}

/// Bounded metadata only; this never changes an adapter's normalized output.
pub fn json_time_requirement(
    source: &str,
    sample: &[u8],
    fields: &ParserTimeFields,
) -> Result<Option<ParserTimeRequirement>, AppError> {
    let sample = &sample[..sample.len().min(65_536)];
    let first = sample
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let Ok(mut value) = serde_json::from_slice::<Value>(first) else {
        return Ok(None);
    };
    value.sort_all_objects();
    let mut budget = 512;
    let Some((host, context)) = find_time(&value, fields, 0, &mut budget) else {
        return Ok(None);
    };
    let provenance = Provenance::new(crate::sha256(sample), Some(0), SourceKind::File)
        .with_parser_location(
            ParserLocation::new(source, fields.parser_id, 0)
                .map_err(|_| AppError::Policy("invalid parser metadata source".into()))?,
        );
    Ok(Some(ParserTimeRequirement {
        required: false,
        hosts: vec![Tainted::from_external(host, provenance)],
        observed: Some(context),
    }))
}

fn find_time(
    value: &Value,
    fields: &ParserTimeFields,
    depth: usize,
    budget: &mut usize,
) -> Option<(String, ParserTimeContext)> {
    if depth >= 32 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let host = fields.hosts.iter().find_map(|path| {
        value
            .pointer(path)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 255)
    });
    let context = fields.timestamps.iter().find_map(|path| {
        value
            .pointer(path)
            .and_then(Value::as_str)
            .and_then(ParserTimeContext::from_timestamp_hint)
    });
    if let (Some(host), Some(context)) = (host, context) {
        return Some((host.into(), context));
    }
    match value {
        Value::Object(object) => object
            .values()
            .find_map(|child| find_time(child, fields, depth + 1, budget)),
        Value::Array(array) => array
            .iter()
            .find_map(|child| find_time(child, fields, depth + 1, budget)),
        _ => None,
    }
}
