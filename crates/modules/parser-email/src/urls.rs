//! Literal URL extraction. No HTML interpretation, entity decoding or network.
use crate::{limit, number};
use irmind_app::{AppError, CancellationToken, source_mapping::SourceValue};
pub(super) fn extract(
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<Vec<(usize, SourceValue)>, AppError> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if index.is_multiple_of(8192) && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if bytes[index..]
            .get(..8)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"https://"))
            || bytes[index..]
                .get(..7)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"http://"))
        {
            let length = bytes[index..]
                .iter()
                .position(|b| b.is_ascii_whitespace() || matches!(*b, b'<' | b'>' | b'\"' | b'\''))
                .unwrap_or(bytes.len() - index);
            if length > 4096 || output.len() >= 128 {
                return Err(limit());
            }
            let fields = match std::str::from_utf8(&bytes[index..index + length]) {
                Ok(url) => vec![("url".into(), SourceValue::Text(url.into()))],
                Err(_) => vec![
                    (
                        "url_bytes_hex".into(),
                        SourceValue::Text(irmind_app::hex(&bytes[index..index + length])),
                    ),
                    (
                        "coverage".into(),
                        SourceValue::Text("non-UTF8 literal URL; original bytes retained".into()),
                    ),
                ],
            };
            let mut fields = fields;
            fields.push(("decoded_body_offset".into(), number(index)?));
            output.push((index, SourceValue::object(fields).map_err(|_| limit())?));
            index += length.max(1);
        } else {
            index += 1;
        }
    }
    Ok(output)
}
