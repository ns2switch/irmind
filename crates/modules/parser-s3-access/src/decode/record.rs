use super::invalid;
use irmind_app::{
    AppError,
    source_mapping::{
        SourceFormatV1, SourceNumber, SourceValue,
        framed::{DecodedSourceFrame, access_log_fields, request_line, request_path},
    },
};
use irmind_domain::IndexedTime;
use std::collections::BTreeMap;

const FIELDS: &[&str] = &[
    "bucket_owner",
    "bucket",
    "time",
    "remote_ip",
    "requester",
    "request_id",
    "operation",
    "key",
    "request_uri",
    "http_status",
    "error_code",
    "bytes_sent",
    "object_size",
    "total_time",
    "turn_around_time",
    "referer",
    "user_agent",
    "version_id",
    "host_id",
    "signature_version",
    "cipher_suite",
    "authentication_type",
    "host_header",
    "tls_version",
    "access_point_arn",
    "acl_required",
    "source_region",
];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub(super) fn prepare(bytes: &[u8]) -> Result<DecodedSourceFrame, AppError> {
    let raw = std::str::from_utf8(bytes.trim_ascii()).map_err(|_| invalid())?;
    let row = layout(raw).ok_or_else(invalid)?;
    let indexed_time = timestamp(row[2]).ok_or_else(invalid)?;
    let mut fields = Vec::new();
    for (&name, &value) in FIELDS.iter().zip(&row) {
        let raw = match name {
            "http_status" | "bytes_sent" | "object_size" | "total_time" | "turn_around_time"
                if value != "-" =>
            {
                let number = value.parse::<u64>().map_err(|_| invalid())?;
                SourceValue::Number(
                    SourceNumber::try_new(&number.to_string()).map_err(|_| invalid())?,
                )
            }
            _ => text(value),
        };
        fields.push((name.into(), raw));
    }
    if let Some((method, target, version)) = request_line(row[8]) {
        let (path, query) = request_path(target);
        fields.extend([
            ("request_method".into(), text(method)),
            ("request_target".into(), text(target)),
            ("request_path".into(), text(path)),
        ]);
        if let Some(query) = query {
            fields.push(("request_query".into(), text(query)));
        }
        if let Some(version) = version {
            fields.push(("request_http_version".into(), text(version)));
        }
    }
    if row.len() > FIELDS.len() {
        fields.push((
            "trailing_fields".into(),
            SourceValue::Array(
                row[FIELDS.len()..]
                    .iter()
                    .map(|field| text(field))
                    .collect(),
            ),
        ));
    }
    Ok(DecodedSourceFrame {
        fields: SourceValue::object(fields).map_err(|_| invalid())?,
        timestamp: Some(indexed_time),
        format: SourceFormatV1::try_new("aws-s3-access", super::super::VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}

fn text(value: &str) -> SourceValue {
    SourceValue::Text(value.to_owned())
}

fn decimal_or_missing(value: &str) -> bool {
    value == "-" || (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_row(row: &[&str]) -> bool {
    row.len() >= 17
        && row.len() <= 64
        && row[0].len() == 64
        && row[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        && !row[1].is_empty()
        && row[1].len() <= 255
        && (row[3] == "-" || row[3].parse::<std::net::IpAddr>().is_ok())
        && (1..=128).contains(&row[6].len())
        && row[6]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        && row[9].len() <= 3
        && decimal_or_missing(row[9])
        && row[11..=14].iter().all(|value| decimal_or_missing(value))
}

fn layout(raw: &str) -> Option<Vec<&str>> {
    if let Some(row) = access_log_fields(raw, Some(2))
        && valid_row(&row)
    {
        return Some(row);
    }

    // S3 can include unescaped quotation marks in Request-URI. The status,
    // byte counts and timings after it provide an independent boundary.
    // Accept a unique complete parse and bound the candidate count.
    let (before, request) = raw.split_once(" \"")?;
    let prefix = access_log_fields(before, Some(2))?;
    if prefix.len() != 8 || request.len() > 65_536 {
        return None;
    }
    let mut result = None;
    for (candidate, (end, _)) in request.match_indices('"').enumerate() {
        if candidate == 32 {
            return None;
        }
        let suffix = &request[end + 1..];
        if !suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_whitespace)
        {
            continue;
        }
        let Some(suffix) = access_log_fields(suffix, None) else {
            continue;
        };
        let mut row = prefix.clone();
        row.push(&request[..end]);
        row.extend(suffix);
        if valid_row(&row) {
            if result.is_some() {
                return None;
            }
            result = Some(row);
        }
    }
    result
}

fn timestamp(raw: &str) -> Option<IndexedTime> {
    let (date, zone) = raw.split_once(' ')?;
    let (day, date) = date.split_once('/')?;
    let (month, date) = date.split_once('/')?;
    let (year, clock) = date.split_once(':')?;
    let month = MONTHS.iter().position(|value| *value == month)? + 1;
    if day.len() != 2
        || year.len() != 4
        || zone.len() != 5
        || !matches!(zone.as_bytes()[0], b'+' | b'-')
        || !zone.as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    IndexedTime::from_rfc3339(
        &format!(
            "{year}-{month:02}-{day}T{clock}{}:{}",
            &zone[..3],
            &zone[3..]
        ),
        false,
    )
    .ok()
}
