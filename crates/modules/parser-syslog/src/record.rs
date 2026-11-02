use super::{AppError, GraphRecord, LegacyTimestamp, timestamp};
use serde::Serialize;

#[derive(Serialize)]
struct Row<'a> {
    timestamp: String,
    timestamp_inferred: bool,
    host: &'a str,
    process: &'a str,
    pid: Option<&'a str>,
    facility: u8,
    severity: u8,
    message_id: Option<&'a str>,
    structured_data: Option<&'a str>,
    message: &'a str,
    raw: &'a str,
}

type Header<'a> = (
    String,
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
    &'a str,
);

pub(super) fn detect(line: &str) -> Option<u8> {
    let (_, rest) = priority(line).ok()?;
    if let Some(body) = rest.strip_prefix("1 ") {
        let raw = body.split(' ').next()?;
        (raw == "-" || timestamp::explicit(raw).is_ok()).then_some(95)
    } else {
        let time = rest.get(..15)?;
        LegacyTimestamp::new(2000, 0).ok()?.parse(time).ok()?;
        (rest.as_bytes().get(15) == Some(&b' ')).then_some(90)
    }
}

pub(super) fn parse(
    line: &str,
    legacy: Option<LegacyTimestamp>,
    index: usize,
) -> Result<GraphRecord, AppError> {
    let (pri, rest) = priority(line)?;
    let inferred = !rest.starts_with("1 ");
    let (at, host, app, pid, message_id, structured_data, message) =
        if let Some(body) = rest.strip_prefix("1 ") {
            modern(body)?
        } else {
            classic(rest, legacy.ok_or_else(super::invalid)?)?
        };
    let mut entities = Vec::new();
    for (kind, value) in [
        ("host", host),
        ("process", app),
        ("pid", pid.unwrap_or("-")),
    ] {
        if value != "-" && !value.is_empty() {
            entities.push((kind.into(), value.into()));
        }
    }
    entities.sort();
    let row = Row {
        timestamp: at.clone(),
        timestamp_inferred: inferred,
        host,
        process: app,
        pid,
        facility: pri / 8,
        severity: pri % 8,
        message_id,
        structured_data,
        message,
        raw: line,
    };
    let indexed = if at.is_empty() {
        String::new()
    } else {
        chrono::DateTime::parse_from_rfc3339(&at)
            .map_err(|_| invalid())?
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    Ok(GraphRecord {
        index,
        at: indexed,
        event: if app == "-" { "syslog" } else { app }.into(),
        text: serde_json::to_string(&row).map_err(|_| invalid())?,
        entities,
        relations: Vec::new(),
    })
}

fn priority(line: &str) -> Result<(u8, &str), AppError> {
    let (pri, rest) = line
        .strip_prefix('<')
        .and_then(|text| text.split_once('>'))
        .ok_or_else(invalid)?;
    if pri.is_empty() || pri.len() > 3 || !pri.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let pri = pri
        .parse::<u8>()
        .ok()
        .filter(|value| *value <= 191)
        .ok_or_else(invalid)?;
    Ok((pri, rest))
}

fn modern(body: &str) -> Result<Header<'_>, AppError> {
    let mut parts = body.splitn(6, ' ');
    let time = field(&mut parts, 64)?;
    let host = field(&mut parts, 255)?;
    let app = field(&mut parts, 48)?;
    let pid = field(&mut parts, 128)?;
    let message_id = field(&mut parts, 32)?;
    let rest = parts.next().ok_or_else(invalid)?;
    let (data, message) = if rest == "-" {
        (None, "")
    } else if let Some(message) = rest.strip_prefix("- ") {
        (None, message)
    } else {
        let end = structured_end(rest)?;
        let after = &rest[end..];
        if !after.is_empty() && !after.starts_with(' ') {
            return Err(invalid());
        }
        (Some(&rest[..end]), after.strip_prefix(' ').unwrap_or(after))
    };
    let time = if time == "-" {
        String::new()
    } else {
        timestamp::explicit(time)?
    };
    Ok((
        time,
        host,
        app,
        (pid != "-").then_some(pid),
        (message_id != "-").then_some(message_id),
        data,
        message,
    ))
}

fn classic(body: &str, context: LegacyTimestamp) -> Result<Header<'_>, AppError> {
    let time = context.parse(body.get(..15).ok_or_else(invalid)?)?;
    let rest = body
        .get(16..)
        .filter(|_| body.as_bytes().get(15) == Some(&b' '))
        .ok_or_else(invalid)?;
    let (host, rest) = rest.split_once(' ').ok_or_else(invalid)?;
    if host.is_empty() || host.len() > 255 {
        return Err(invalid());
    }
    let (tag, message) = rest.split_once(':').ok_or_else(invalid)?;
    if tag.is_empty() || tag.len() > 128 {
        return Err(invalid());
    }
    let (app, pid) = if let Some((app, pid)) = tag.split_once('[') {
        (app, Some(pid.strip_suffix(']').ok_or_else(invalid)?))
    } else {
        (tag, None)
    };
    Ok((
        time,
        host,
        app,
        pid,
        None,
        None,
        message.strip_prefix(' ').unwrap_or(message),
    ))
}

fn field<'a>(parts: &mut impl Iterator<Item = &'a str>, max: usize) -> Result<&'a str, AppError> {
    parts
        .next()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= max
                && value.bytes().all(|byte| (33..=126).contains(&byte))
        })
        .ok_or_else(invalid)
}

fn structured_end(text: &str) -> Result<usize, AppError> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut elements = 0;
    while bytes.get(index) == Some(&b'[') {
        elements += 1;
        if elements > 1024 {
            return Err(invalid());
        }
        index += 1;
        let mut quoted = false;
        loop {
            match bytes.get(index) {
                Some(b'\\') if quoted => {
                    if !matches!(bytes.get(index + 1), Some(b'\\' | b'"' | b']')) {
                        return Err(invalid());
                    }
                    index += 2;
                }
                Some(b'"') => {
                    quoted = !quoted;
                    index += 1;
                }
                Some(b']') if !quoted => {
                    index += 1;
                    break;
                }
                Some(b'[' | 0..=31 | 127) | None => return Err(invalid()),
                Some(_) => index += 1,
            }
        }
    }
    if index == 0 {
        return Err(invalid());
    }
    Ok(index)
}

fn invalid() -> AppError {
    AppError::Policy("invalid syslog record".into())
}
