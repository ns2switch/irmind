//! The public `HuntEval` normalized JSON schema is parsed as untrusted evidence.
//! Hidden answers are never accepted as input to this parser.

use irmind_app::{AppError, GraphRelation, hex};
use irmind_domain::UtcTimestamp;
use serde_json::Value;
use std::net::IpAddr;

pub(super) struct Extracted {
    pub entities: Vec<(String, String)>,
    pub relations: Vec<GraphRelation>,
}

pub(super) fn is_normalized(value: &Value) -> bool {
    value.get("event_id").is_some()
        && (value.get("account_id").is_some() || value.get("principal").is_some())
}

pub(super) fn extract(value: &Value, source_hash: [u8; 32]) -> Result<Extracted, AppError> {
    let event_id = field(value, "event_id", 128)?;
    let timestamp = field(value, "event_time", 32)?;
    UtcTimestamp::parse(timestamp).map_err(|_| invalid())?;
    let _event_name = field(value, "event_name", 256)?;
    let account = field(value, "account_id", 128)?;
    let principal = field(value, "principal", 512)?;
    let resource = field(value, "resource", 512)?;
    let ip = field(value, "source_ip", 64)?;
    ip.parse::<IpAddr>().map_err(|_| invalid())?;
    let agent = field(value, "user_agent", 512)?;
    let provider = value
        .get("provider")
        .and_then(Value::as_str)
        .or_else(|| principal.starts_with("arn:aws:").then_some("aws"))
        .ok_or_else(invalid)?;
    if !matches!(provider, "aws" | "azure" | "gcp")
        || !event_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid());
    }
    let event_ref = format!("{}:{event_id}", hex(&source_hash));
    let fields = [
        ("principal", principal),
        ("account", account),
        ("resource", resource),
        ("ip", ip),
        ("user_agent", agent),
    ];
    let mut entities = vec![("event_id".into(), event_ref.clone())];
    let mut relations = Vec::with_capacity(fields.len());
    for (kind, value) in fields {
        entities.push((kind.into(), value.into()));
        relations.push(GraphRelation {
            from_kind: "event_id".into(),
            from_value: event_ref.clone(),
            relation: "observed".into(),
            to_kind: kind.into(),
            to_value: value.into(),
        });
    }
    Ok(Extracted {
        entities,
        relations,
    })
}

fn field<'a>(value: &'a Value, name: &str, max: usize) -> Result<&'a str, AppError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= max)
        .ok_or_else(invalid)
}

fn invalid() -> AppError {
    AppError::Policy("invalid HuntEval normalized event".into())
}
