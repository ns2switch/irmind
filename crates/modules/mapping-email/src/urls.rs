//! Pure URI interpretation of bounded decoded source-byte spans; never follows links.
use irmind_mapping_contracts::source_mapping::{MappingError, SourceValue};
fn bad() -> MappingError {
    MappingError::UnsupportedSourceValue
}
pub(super) fn extract(fields: &SourceValue) -> Result<Vec<String>, MappingError> {
    let Some(raw) = fields
        .field("body_bytes_hex")
        .and_then(SourceValue::as_text)
    else {
        return Ok(Vec::new());
    };
    let mut bytes = unhex(raw, 256 * 1024)?;
    let primary = bytes.len();
    if let Some(after) = fields
        .field("following_bytes_hex")
        .and_then(SourceValue::as_text)
    {
        bytes.extend(unhex(after, 4096)?);
    }
    scan(&bytes, primary)
}
fn scan(bytes: &[u8], primary: usize) -> Result<Vec<String>, MappingError> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < primary {
        if bytes[index..]
            .get(..8)
            .is_some_and(|v| v.eq_ignore_ascii_case(b"https://"))
            || bytes[index..]
                .get(..7)
                .is_some_and(|v| v.eq_ignore_ascii_case(b"http://"))
        {
            let length = bytes[index..]
                .iter()
                .position(|b| b.is_ascii_whitespace() || matches!(*b, b'<' | b'>' | b'\"' | b'\''))
                .unwrap_or(bytes.len() - index);
            if length > 4096 || output.len() >= 127 {
                return Err(bad());
            }
            let url = std::str::from_utf8(&bytes[index..index + length]).map_err(|_| bad())?;
            output.push(url.into());
            index += length.max(1);
        } else {
            index += 1;
        }
    }
    Ok(output)
}
fn unhex(text: &str, max: usize) -> Result<Vec<u8>, MappingError> {
    if text.len() > max * 2 || !text.len().is_multiple_of(2) {
        return Err(bad());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(nibble(pair[0])? * 16 + nibble(pair[1])?))
        .collect()
}
fn nibble(value: u8) -> Result<u8, MappingError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(bad()),
    }
}
