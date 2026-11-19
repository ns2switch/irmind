use super::invalid;
use irmind_app::{
    AppError,
    source_mapping::{
        SourceDiscriminator, SourceFormatV1, SourceNumber, SourceValue,
        framed::{DecodedSourceFrame, access_log_fields, request_line, request_path},
    },
};
use irmind_domain::IndexedTime;
use std::collections::BTreeMap;

const CLASSIC: &[&str] = &[
    "time",
    "elb",
    "client:port",
    "backend:port",
    "request_processing_time",
    "backend_processing_time",
    "response_processing_time",
    "elb_status_code",
    "backend_status_code",
    "received_bytes",
    "sent_bytes",
    "request",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
];
const APPLICATION: &[&str] = &[
    "type",
    "time",
    "elb",
    "client:port",
    "target:port",
    "request_processing_time",
    "target_processing_time",
    "response_processing_time",
    "elb_status_code",
    "target_status_code",
    "received_bytes",
    "sent_bytes",
    "request",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
    "target_group_arn",
    "trace_id",
    "domain_name",
    "chosen_cert_arn",
    "matched_rule_priority",
    "request_creation_time",
    "actions_executed",
    "redirect_url",
    "error_reason",
    "target:port_list",
    "target_status_code_list",
    "classification",
    "classification_reason",
    "conn_trace_id",
    "transformed_host",
    "transformed_uri",
    "request_transform_status",
    "ip_address",
];

fn number(raw: &str) -> Result<SourceValue, AppError> {
    if raw != "-" && raw.bytes().all(|byte| byte.is_ascii_digit()) {
        let value = raw.parse::<u64>().map_err(|_| invalid())?;
        Ok(SourceValue::Number(
            SourceNumber::try_new(&value.to_string()).map_err(|_| invalid())?,
        ))
    } else {
        Ok(text(raw))
    }
}

fn text(raw: &str) -> SourceValue {
    SourceValue::Text(raw.to_owned())
}

fn endpoint(raw: &str) -> Option<(&str, &str)> {
    let (address, port) = raw.rsplit_once(':')?;
    let address = address
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(address);
    address.parse::<std::net::IpAddr>().ok()?;
    port.parse::<u16>().ok()?;
    Some((address, port))
}

fn fields(row: &[&str], names: &[&str]) -> Result<Vec<(String, SourceValue)>, AppError> {
    let mut fields = Vec::new();
    for (name, value) in names.iter().zip(row) {
        let projected = match *name {
            "elb_status_code" | "received_bytes" | "sent_bytes" => number(value)?,
            _ => text(value),
        };
        fields.push(((*name).into(), projected));
        if let Some((address, port)) = match *name {
            "client:port" | "target:port" | "backend:port" => endpoint(value),
            _ => None,
        } {
            let key = if *name == "client:port" {
                "client"
            } else {
                "backend"
            };
            fields.push((format!("{key}_ip"), text(address)));
            fields.push((format!("{key}_port"), number(port)?));
        }
        if *name == "request"
            && let Some((method, target, version)) = request_line(value)
        {
            let (path, query) = request_path(target);
            fields.extend([
                ("request_method".into(), text(method)),
                ("request_target".into(), text(target)),
                ("request_path".into(), text(path)),
            ]);
            if let Some(version) = version {
                fields.push(("request_http_version".into(), text(version)));
            }
            if let Some(query) = query {
                fields.push(("request_query".into(), text(query)));
            }
        }
    }
    if row.len() > names.len() {
        fields.push((
            "trailing_fields".into(),
            SourceValue::Array(row[names.len()..].iter().map(|part| text(part)).collect()),
        ));
    }
    Ok(fields)
}

pub(super) fn prepare(bytes: &[u8]) -> Result<DecodedSourceFrame, AppError> {
    let raw = std::str::from_utf8(bytes.trim_ascii()).map_err(|_| invalid())?;
    let row = access_log_fields(raw, None).ok_or_else(invalid)?;
    let (layout, names, start) = if row.get(2).is_some_and(|name| name.starts_with("app/")) {
        ("application", APPLICATION, 1)
    } else {
        ("classic", CLASSIC, 0)
    };
    if row.len() < names.len().min(15 + start)
        || endpoint(row[start + 2]).is_none()
        || !(row[start + 3] == "-" || endpoint(row[start + 3]).is_some())
        || !row[start + 4..=start + 6]
            .iter()
            .all(|value| latency(value))
        || !row[start + 7..=start + 10]
            .iter()
            .all(|value| decimal_or_missing(value))
    {
        return Err(invalid());
    }
    let timestamp = IndexedTime::from_rfc3339(row[start], false).map_err(|_| invalid())?;
    let format = SourceFormatV1::try_new(
        "aws-elb-access",
        super::super::VERSION,
        BTreeMap::from([(SourceDiscriminator::Dataset, layout.into())]),
    )
    .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields: SourceValue::object(fields(&row, names)?).map_err(|_| invalid())?,
        timestamp: Some(timestamp),
        format,
    })
}

fn decimal_or_missing(value: &str) -> bool {
    value == "-" || (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn latency(value: &str) -> bool {
    value == "-"
        || value.len() <= 32
            && value
                .parse::<f64>()
                .is_ok_and(|seconds| seconds.is_finite() && seconds >= -1.0)
}
