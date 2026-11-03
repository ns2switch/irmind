use super::{AppError, GraphRecord, bad, record::Record};
use chrono::{DateTime, Utc};

struct Access<'a> {
    ip: &'a str,
    user: &'a str,
    time: &'a str,
    request: &'a str,
    status: &'a str,
}
pub(super) fn detect(line: &str) -> bool {
    fields(line).is_ok()
}
pub(super) fn parse(line: &str, index: usize) -> Result<GraphRecord, AppError> {
    let row = fields(line)?;
    let at = DateTime::parse_from_str(row.time, "%d/%b/%Y:%H:%M:%S %z")
        .map_err(|_| invalid())?
        .with_timezone(&Utc);
    let mut record = Record::new(at, "http_access", line);
    record.source_ip = Some(row.ip);
    record.user = (row.user != "-").then_some(row.user);
    record.http_method = row.request.split_ascii_whitespace().next();
    record.url = row.request.split_ascii_whitespace().nth(1);
    record.outcome = if row.status.starts_with(['4', '5']) {
        "failure"
    } else {
        "success"
    };
    record.graph(index)
}
fn fields(line: &str) -> Result<Access<'_>, AppError> {
    let mut parts = line.splitn(4, ' ');
    let ip = parts.next().ok_or_else(invalid)?;
    ip.parse::<std::net::IpAddr>().map_err(|_| invalid())?;
    let _ident = parts.next().ok_or_else(invalid)?;
    let user = parts.next().ok_or_else(invalid)?;
    let rest = parts.next().ok_or_else(invalid)?;
    let (time, rest) = rest
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .ok_or_else(invalid)?;
    DateTime::parse_from_str(time, "%d/%b/%Y:%H:%M:%S %z").map_err(|_| invalid())?;
    let (request, rest) = quoted(rest)?;
    let mut fields = rest.trim_start().splitn(3, ' ');
    let status = fields.next().ok_or_else(invalid)?;
    if status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
        || !('1'..='5').contains(&status.chars().next().ok_or_else(invalid)?)
    {
        return Err(invalid());
    }
    let bytes = fields.next().ok_or_else(invalid)?;
    if bytes != "-" && bytes.parse::<u64>().is_err() {
        return Err(invalid());
    }
    if let Some(tail) = fields.next() {
        let (_, tail) = quoted(tail)?;
        let (_, tail) = quoted(tail.trim_start())?;
        if !tail.trim().is_empty() {
            return Err(invalid());
        }
    }
    Ok(Access {
        ip,
        user,
        time,
        request,
        status,
    })
}
fn quoted(text: &str) -> Result<(&str, &str), AppError> {
    let text = text.strip_prefix('"').ok_or_else(invalid)?;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Ok((&text[..index], &text[index + 1..]));
        }
    }
    Err(invalid())
}
fn invalid() -> AppError {
    bad("invalid combined/common HTTP access record")
}
