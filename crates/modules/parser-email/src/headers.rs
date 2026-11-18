//! The library sees a bounded header block, never an unbounded MIME message.
use crate::{invalid, limit, number};
use irmind_app::{AppError, source_mapping::SourceValue};
use irmind_domain::IndexedTime;
use mail_parser::{HeaderValue, MessageParser};
use std::collections::BTreeMap;
mod values;
pub(super) struct Headers {
    pub fields: BTreeMap<String, SourceValue>,
    pub body: usize,
    pub count: usize,
    pub time: Option<IndexedTime>,
    pub media: String,
    pub boundary: Option<String>,
    pub filename: Option<String>,
    pub encoding: String,
    pub charset: String,
    pub attachment: bool,
}
pub(super) fn parse(bytes: &[u8], allow_empty: bool) -> Result<Headers, AppError> {
    let (body, count, raw, offsets) = block(bytes)?;
    let mut out = Headers {
        fields: BTreeMap::new(),
        body,
        count,
        time: None,
        media: "text/plain".into(),
        boundary: None,
        filename: None,
        encoding: "7bit".into(),
        charset: "us-ascii".into(),
        attachment: false,
    };
    out.fields.insert("headers".into(), SourceValue::Array(raw));
    out.fields
        .insert("header_offsets".into(), SourceValue::Array(offsets));
    out.fields.insert(
        "headers_raw_hex".into(),
        SourceValue::Text(irmind_app::hex(&bytes[..body])),
    );
    if count == 0 {
        return if allow_empty { Ok(out) } else { Err(invalid()) };
    }
    let parsed = MessageParser::default()
        .parse_headers(&bytes[..body])
        .ok_or_else(invalid)?;
    let headers = &parsed.parts.first().ok_or_else(invalid)?.headers;
    let mut decoded: BTreeMap<String, Vec<SourceValue>> = BTreeMap::new();
    for header in headers {
        let name = header.name.as_str().to_ascii_lowercase();
        let raw = bytes
            .get(header.offset_start as usize..header.offset_end as usize)
            .ok_or_else(invalid)?;
        if matches!(
            name.as_str(),
            "content-type" | "content-disposition" | "content-transfer-encoding"
        ) && decoded.contains_key(&name)
        {
            return Err(invalid());
        }
        update(&mut out, &name, &header.value, raw);
        decoded
            .entry(name)
            .or_default()
            .push(values::value(&header.value, raw)?);
    }
    if decoded.get("date").is_some_and(|values| values.len() != 1) {
        out.time = None;
    }
    out.fields.insert(
        "decoded_headers".into(),
        SourceValue::object(
            decoded
                .into_iter()
                .map(|(key, values)| (key, SourceValue::Array(values)))
                .collect(),
        )
        .map_err(|_| limit())?,
    );
    Ok(out)
}
fn update(out: &mut Headers, name: &str, value: &HeaderValue<'_>, raw: &[u8]) {
    match name {
        "date" => {
            if let Some(date) = value.as_datetime().filter(|d| d.is_valid()) {
                let text = String::from_utf8_lossy(raw);
                let zone = text.split_ascii_whitespace().last().unwrap_or_default();
                let known = matches!(zone, "GMT" | "UT")
                    || (zone.len() == 5
                        && matches!(zone.as_bytes()[0], b'+' | b'-')
                        && zone.as_bytes()[1..].iter().all(u8::is_ascii_digit));
                if known {
                    out.time = IndexedTime::from_rfc3339(&date.to_rfc3339(), false).ok();
                }
            }
        }
        "content-type" => {
            if let Some(kind) = value.as_content_type() {
                out.media = format!(
                    "{}/{}",
                    kind.c_type.to_ascii_lowercase(),
                    kind.c_subtype
                        .as_deref()
                        .unwrap_or("plain")
                        .to_ascii_lowercase()
                );
                out.boundary = kind.attribute("boundary").map(str::to_owned);
                out.filename = kind.attribute("name").map(str::to_owned);
                out.charset = kind
                    .attribute("charset")
                    .unwrap_or("us-ascii")
                    .to_ascii_lowercase();
            }
        }
        "content-disposition" => {
            if let Some(kind) = value.as_content_type() {
                out.attachment = kind.is_attachment();
                if let Some(name) = kind.attribute("filename") {
                    out.filename = Some(name.into());
                }
            }
        }
        "content-transfer-encoding" => {
            out.encoding = String::from_utf8_lossy(raw).trim().to_ascii_lowercase();
        }
        _ => {}
    }
}
fn block(bytes: &[u8]) -> Result<(usize, usize, Vec<SourceValue>, Vec<SourceValue>), AppError> {
    let mut used = 0;
    let mut raw: Vec<SourceValue> = Vec::new();
    let mut offsets = Vec::new();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        let text = line.strip_suffix(b"\n").unwrap_or(line);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        if used + line.len() > 65536 {
            return Err(limit());
        }
        if text.is_empty() {
            return Ok((used + line.len(), raw.len(), raw, offsets));
        }
        if matches!(text.first(), Some(b' ' | b'\t')) {
            let Some(SourceValue::Text(previous)) = raw.last_mut() else {
                return Err(invalid());
            };
            previous.push_str(&String::from_utf8_lossy(line));
        } else {
            let colon = text.iter().position(|b| *b == b':').ok_or_else(invalid)?;
            if colon == 0
                || !text[..colon]
                    .iter()
                    .all(|b| (33..=126).contains(b) && *b != b':')
            {
                return Err(invalid());
            }
            if raw.len() >= 1024 {
                return Err(limit());
            }
            raw.push(SourceValue::Text(
                String::from_utf8_lossy(line).into_owned(),
            ));
            offsets.push(number(used)?);
        }
        used += line.len();
    }
    Ok((used, raw.len(), raw, offsets))
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let headers = parse(sample, false).ok()?;
    let values = headers.fields.get("decoded_headers")?;
    let count = ["from", "date", "message-id", "received", "subject", "to"]
        .iter()
        .filter(|key| values.field(key).is_some())
        .count();
    if count < 3 || values.field("from").is_none() {
        return None;
    }
    Some(
        if values.field("message-id").is_some() || values.field("received").is_some() {
            98
        } else {
            70
        },
    )
}
