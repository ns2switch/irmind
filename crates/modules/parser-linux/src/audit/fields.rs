use super::super::{AppError, bad};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};
type Values<'a> = BTreeMap<&'a str, &'a str>;
type Tokens<'a> = (Values<'a>, BTreeSet<&'a str>);

pub(super) struct Line<'a> {
    pub(super) fields: Values<'a>,
    quoted: BTreeSet<&'a str>,
    pub(super) seconds: i64,
    pub(super) nanos: u32,
    pub(super) serial: u64,
}
impl<'a> Line<'a> {
    pub(super) fn parse(raw: &'a str) -> Result<Self, AppError> {
        Self::parse_impl(raw, false)
    }
    pub(super) fn parse_strict(raw: &'a str) -> Result<Self, AppError> {
        Self::parse_impl(raw, true)
    }
    fn parse_impl(raw: &'a str, strict: bool) -> Result<Self, AppError> {
        let (fields, quoted) = if strict {
            tokenize_impl(raw, true)?
        } else {
            tokenize(raw)?
        };
        let stamp = fields
            .get("msg")
            .and_then(|value| value.strip_prefix("audit("))
            .and_then(|value| value.strip_suffix("):"))
            .ok_or_else(invalid)?;
        let (time, serial) = stamp.split_once(':').ok_or_else(invalid)?;
        let (seconds, fraction) = time.split_once('.').unwrap_or((time, ""));
        if fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        let nanos = if fraction.is_empty() {
            0
        } else {
            fraction.parse::<u32>().map_err(|_| invalid())?
                * 10u32.pow(u32::try_from(9 - fraction.len()).map_err(|_| invalid())?)
        };
        let result = Self {
            seconds: seconds.parse().map_err(|_| invalid())?,
            nanos,
            serial: serial.parse().map_err(|_| invalid())?,
            fields,
            quoted,
        };
        let at =
            chrono::DateTime::from_timestamp(result.seconds, result.nanos).ok_or_else(invalid)?;
        if result.seconds < 0
            || irmind_domain::UtcTimestamp::parse(&at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .is_err()
        {
            return Err(invalid());
        }
        if result.field("node").is_some_and(|node| node.len() > 255)
            || !result.fields.contains_key("type")
            || chrono::DateTime::from_timestamp(result.seconds, result.nanos).is_none()
        {
            return Err(invalid());
        }
        Ok(result)
    }
    pub(super) fn is_quoted(&self, name: &str) -> bool {
        self.quoted.contains(name)
    }
    pub(super) fn decoded(&self, name: &str) -> Option<Cow<'a, str>> {
        self.field(name)
            .map(|value| super::encoding::text(value, self.quoted.contains(name)))
    }
    pub(super) fn field(&self, key: &str) -> Option<&'a str> {
        self.fields.get(key).copied()
    }
}
pub(super) fn tokenize(text: &str) -> Result<Tokens<'_>, AppError> {
    tokenize_impl(text, false)
}
fn tokenize_impl(mut text: &str, strict: bool) -> Result<Tokens<'_>, AppError> {
    let mut fields = BTreeMap::new();
    let mut quoted_keys = BTreeSet::new();
    let mut count = 0;
    while !text.trim_start().is_empty() {
        text = text.trim_start();
        let key_end = text.find(['=', ' ', '\t']).unwrap_or(text.len());
        if text.as_bytes().get(key_end) != Some(&b'=') {
            let end = text.find(char::is_whitespace).unwrap_or(text.len());
            text = &text[end..];
            continue;
        }
        let key = &text[..key_end];
        text = &text[key_end + 1..];
        count += 1;
        if count > 1024
            || key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
            })
        {
            return Err(invalid());
        }
        let is_quoted = text.starts_with(['\'', '"']);
        let (value, tail) = if text.starts_with(['\'', '"']) {
            quoted(text)?
        } else {
            let end = text.find(char::is_whitespace).unwrap_or(text.len());
            (&text[..end], &text[end..])
        };
        if strict && fields.contains_key(key) {
            return Err(invalid());
        }
        if !fields.contains_key(key) {
            fields.insert(key, value);
            if is_quoted {
                quoted_keys.insert(key);
            }
        }
        if !tail.is_empty() && !tail.starts_with(char::is_whitespace) {
            return Err(invalid());
        }
        text = tail;
    }
    Ok((fields, quoted_keys))
}
fn quoted(text: &str) -> Result<(&str, &str), AppError> {
    let delimiter = *text.as_bytes().first().ok_or_else(invalid)?;
    let mut escaped = false;
    for (index, byte) in text.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == delimiter {
            return Ok((&text[1..index], &text[index + 1..]));
        }
    }
    Err(invalid())
}
fn invalid() -> AppError {
    bad("invalid bounded auditd record")
}
