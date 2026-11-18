use super::{QUERY_MAX_RECORD_BYTES, SourceQueryError};
use serde::Serialize;
use serde_json::Value;

pub(crate) fn checked_value(bytes: &[u8]) -> Result<Value, SourceQueryError> {
    crate::source_mapping::json::decode_json_value(
        bytes,
        crate::source_mapping::json::SourceJsonLimits {
            bytes: QUERY_MAX_RECORD_BYTES,
            nodes: 4096,
            fields: 4096,
            depth: 32,
        },
    )
    .map_err(|_| SourceQueryError::Invalid)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| SourceQueryError::Invalid)?;
    unsigned_only(&value)?;
    Ok(value)
}
fn unsigned_only(value: &Value) -> Result<(), SourceQueryError> {
    match value {
        Value::Number(n) if !n.is_u64() => Err(SourceQueryError::Invalid),
        Value::Array(a) => a.iter().try_for_each(unsigned_only),
        Value::Object(m) => m.values().try_for_each(unsigned_only),
        _ => Ok(()),
    }
}
/// Explicit key ordering, independent of serde_json/preserve_order.
pub fn canonical_query_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SourceQueryError> {
    let value = serde_json::to_value(value).map_err(|_| SourceQueryError::Invalid)?;
    unsigned_only(&value)?;
    let mut out = Vec::new();
    write(&value, &mut out)?;
    if out.len() > QUERY_MAX_RECORD_BYTES {
        return Err(SourceQueryError::Limit);
    }
    // Apply depth/node/duplicate controls to producers too.
    crate::source_mapping::json::validate_json_value(
        &out,
        crate::source_mapping::json::SourceJsonLimits {
            bytes: QUERY_MAX_RECORD_BYTES,
            nodes: 4096,
            fields: 4096,
            depth: 32,
        },
    )
    .map_err(|_| SourceQueryError::Limit)?;
    Ok(out)
}
fn write(value: &Value, out: &mut Vec<u8>) -> Result<(), SourceQueryError> {
    match value {
        Value::Object(m) => {
            out.push(b'{');
            let mut keys = m.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (i, key) in keys.into_iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).map_err(|_| SourceQueryError::Invalid)?;
                out.push(b':');
                write(&m[key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                write(v, out)?;
            }
            out.push(b']');
        }
        _ => serde_json::to_writer(out, value).map_err(|_| SourceQueryError::Invalid)?,
    }
    Ok(())
}
pub fn query_content_id<T: Serialize>(domain: &str, value: &T) -> Result<String, SourceQueryError> {
    if !domain.starts_with("irmind-")
        || domain.len() > 96
        || !domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(SourceQueryError::Invalid);
    }
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend(canonical_query_json(value)?);
    Ok(crate::hex(&crate::sha256(&preimage)))
}
