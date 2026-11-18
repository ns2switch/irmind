//! Bodies remain untrusted. HTML is indexed as literal source, never rendered.
use crate::{decode::PendingFrame, headers::Headers, invalid, limit, number};
use irmind_app::{AppError, CancellationToken, source_mapping::SourceValue};
use std::{borrow::Cow, collections::BTreeMap};
pub(super) fn leaf(
    bytes: &[u8],
    headers: &Headers,
    start: usize,
    part: usize,
    cancel: &CancellationToken,
) -> Result<Vec<PendingFrame>, AppError> {
    let raw = &bytes[headers.body..];
    let decoded = transport(raw, &headers.encoding)?;
    let exact = matches!(decoded, Cow::Borrowed(_));
    let mut output = Vec::new();
    let attachment =
        headers.attachment || headers.filename.is_some() || !headers.media.starts_with("text/");
    if attachment {
        let mut fields = BTreeMap::from([
            (
                "declared_type".into(),
                SourceValue::Text(headers.media.clone()),
            ),
            ("size".into(), number(decoded.len())?),
            (
                "sha256".into(),
                SourceValue::Text(irmind_app::hex(&irmind_app::sha256(&decoded))),
            ),
        ]);
        if let Some(name) = &headers.filename {
            fields.insert("filename".into(), SourceValue::Text(name.clone()));
        }
        output.push(PendingFrame {
            kind: "attachment",
            fields,
            offset: Some(start),
            part,
        });
        return Ok(output);
    }
    for (offset, value) in crate::urls::extract(&decoded, cancel)? {
        let SourceValue::Object(fields) = value else {
            return Err(invalid());
        };
        output.push(PendingFrame {
            kind: "url",
            fields,
            offset: exact.then_some(start + headers.body + offset),
            part,
        });
    }
    if matches!(headers.media.as_str(), "text/plain" | "text/html") {
        output.extend(text_frames(&decoded, headers, start, part, exact, cancel)?);
    }
    Ok(output)
}
fn text_frames(
    decoded: &[u8],
    headers: &Headers,
    start: usize,
    part: usize,
    exact: bool,
    cancel: &CancellationToken,
) -> Result<Vec<PendingFrame>, AppError> {
    let mut output = Vec::new();
    let textual = matches!(headers.charset.as_str(), "us-ascii" | "utf-8" | "utf8");
    let valid_utf8 = std::str::from_utf8(decoded).ok();
    let mut offset = 0;
    while offset < decoded.len() {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut end = (offset + 256 * 1024).min(decoded.len());
        if let Some(text) = valid_utf8 {
            while !text.is_char_boundary(end) {
                end -= 1;
            }
        }
        let chunk = &decoded[offset..end];
        let mut fields = BTreeMap::from([
            (
                "body_bytes_hex".into(),
                SourceValue::Text(irmind_app::hex(chunk)),
            ),
            ("decoded_body_offset".into(), number(offset)?),
            ("charset".into(), SourceValue::Text(headers.charset.clone())),
        ]);
        if textual {
            fields.insert(
                if headers.media == "text/html" {
                    "html_source"
                } else {
                    "text"
                }
                .into(),
                SourceValue::Text(String::from_utf8_lossy(chunk).into_owned()),
            );
            fields.insert(
                "utf8_valid".into(),
                SourceValue::Boolean(valid_utf8.is_some()),
            );
        } else {
            fields.insert(
                "coverage".into(),
                SourceValue::Text("unsupported charset; original bytes retained".into()),
            );
        }
        output.push(PendingFrame {
            kind: "text",
            fields,
            offset: exact.then_some(start + headers.body + offset),
            part,
        });
        offset = end;
    }
    Ok(output)
}

fn transport<'a>(bytes: &'a [u8], encoding: &str) -> Result<Cow<'a, [u8]>, AppError> {
    match encoding {
        "" | "7bit" | "8bit" | "binary" => Ok(Cow::Borrowed(bytes)),
        "base64" => {
            let clean: Vec<_> = bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            let data = clean.iter().position(|b| *b == b'=').unwrap_or(clean.len());
            if !clean.len().is_multiple_of(4)
                || clean.len() - data > 2
                || !clean[data..].iter().all(|b| *b == b'=')
                || !clean[..data]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
            {
                return Err(invalid());
            }
            mail_parser::decoders::base64::base64_decode(&clean)
                .map(Cow::Owned)
                .ok_or_else(invalid)
        }
        "quoted-printable" => {
            mail_parser::decoders::quoted_printable::quoted_printable_decode(bytes)
                .map(Cow::Owned)
                .ok_or_else(invalid)
        }
        _ => Err(invalid()),
    }
    .and_then(|value| {
        if value.len() > 32 * 1024 * 1024 {
            Err(limit())
        } else {
            Ok(value)
        }
    })
}
