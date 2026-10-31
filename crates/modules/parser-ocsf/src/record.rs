use chrono::{DateTime, Utc};
use irmind_app::{AppError, GraphRecord};
use irmind_domain::UtcTimestamp;
use serde_json::{Value, json};

const MAX_FIELDS: usize = 1024;
const MAX_DEPTH: usize = 64;

pub(super) fn parse(index: usize, value: &Value) -> Result<GraphRecord, AppError> {
    validate_shape(value)?;
    let class = value
        .get("class_uid")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let category = value
        .get("category_uid")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let _version = field(value, "/metadata/version").ok_or_else(invalid)?;
    let (expected_category, class_name) = match class {
        1001 => (1, "File Activity"),
        1007 => (1, "Process Activity"),
        2004 => (2, "Detection Finding"),
        3002 => (3, "Authentication"),
        4001 => (4, "Network Activity"),
        6003 => (6, "API Activity"),
        _ => (category, "OCSF event"),
    };
    if category != expected_category {
        return Err(invalid());
    }
    let at = timestamp(value)?;
    let action = field(value, "/activity_name")
        .or_else(|| field(value, "/api/operation"))
        .unwrap_or(class_name);
    let event = format!("{class_name}: {action}");
    let mut entities = entities(value);
    entities.sort();
    entities.dedup();
    let normalized = json!({
        "at": at, "action": action, "result": field(value, "/status"),
        "host": field(value, "/device/hostname"),
        "user": field(value, "/actor/user/name").or_else(|| field(value, "/user/name")),
        "process": field(value, "/process/name"),
        "command_line": field(value, "/process/cmd_line"),
        "source_ip": field(value, "/src_endpoint/ip"),
        "source_port": value.pointer("/src_endpoint/port"),
        "destination_ip": field(value, "/dst_endpoint/ip"),
        "destination_port": value.pointer("/dst_endpoint/port"),
        "account_id": field(value, "/cloud/account/uid"),
        "provider": field(value, "/cloud/provider"),
        "region": field(value, "/cloud/region"),
        "attributes": value,
    });
    Ok(GraphRecord {
        index,
        at,
        event,
        text: normalized.to_string(),
        entities,
        relations: Vec::new(),
    })
}

fn entities(value: &Value) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (kind, path) in [
        ("host", "/device/hostname"),
        ("user", "/actor/user/name"),
        ("user", "/user/name"),
        ("process", "/process/name"),
        ("command_line", "/process/cmd_line"),
        ("ip", "/src_endpoint/ip"),
        ("ip", "/dst_endpoint/ip"),
        ("port", "/src_endpoint/port"),
        ("port", "/dst_endpoint/port"),
        ("file", "/file/path"),
        ("resource", "/resources/0/name"),
        ("finding", "/finding_info/title"),
        ("account", "/cloud/account/uid"),
    ] {
        let value = value.pointer(path).and_then(scalar);
        if let Some(value) = value.filter(|item| !item.is_empty() && item.len() <= 4096) {
            result.push((kind.into(), value));
        }
    }
    result
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn field<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    value.pointer(path).and_then(Value::as_str)
}

fn timestamp(value: &Value) -> Result<String, AppError> {
    let normalized = if let Some(raw) = field(value, "/time_dt") {
        DateTime::parse_from_rfc3339(raw)
            .map_err(|_| invalid())?
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    } else {
        let millis = value
            .get("time")
            .and_then(Value::as_i64)
            .ok_or_else(invalid)?;
        DateTime::<Utc>::from_timestamp_millis(millis)
            .ok_or_else(invalid)?
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    UtcTimestamp::parse(&normalized).map_err(|_| invalid())?;
    Ok(normalized)
}

fn validate_shape(value: &Value) -> Result<(), AppError> {
    fn walk(value: &Value, depth: usize, fields: &mut usize) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        match value {
            Value::Object(object) => {
                *fields = fields.saturating_add(object.len());
                *fields <= MAX_FIELDS && object.values().all(|item| walk(item, depth + 1, fields))
            }
            Value::Array(array) => array.iter().all(|item| walk(item, depth + 1, fields)),
            _ => true,
        }
    }
    if walk(value, 0, &mut 0) {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn invalid() -> AppError {
    AppError::Policy("invalid or unsupported OCSF record".into())
}
