#![forbid(unsafe_code)]

use irmind_app::{
    AppError, EventParser, GraphRecord, GraphRelation,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    sha256,
};
use irmind_domain::{Provenance, SourceKind, Tainted, classify_field};
use serde_json::Value;

mod stream;

pub struct JsonParser;

static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-json",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

impl Module for JsonParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(self)
    }
}

impl EventParser for JsonParser {
    fn version(&self) -> &'static str {
        "json-cloudtrail-v5"
    }
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &irmind_app::CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::JSONInputExceeds50MB,
            )));
        }
        let first = bytes.iter().copied().find(|b| !b.is_ascii_whitespace());
        if !matches!(first, Some(b'{' | b'[')) {
            return Ok(0);
        }
        stream::parse_each(source, bytes, cancel, emit)
    }
}

fn parse_record(
    source: &str,
    evidence_hash: [u8; 32],
    index: usize,
    value: &Value,
) -> Result<Tainted<GraphRecord>, AppError> {
    let at = value
        .get("eventTime")
        .or_else(|| value.get("timestamp"))
        .or_else(|| value.get("time"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let event = value
        .get("eventName")
        .or_else(|| value.get("eventType"))
        .or_else(|| value.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("record")
        .to_owned();
    let mut entities = Vec::new();
    collect(value, &mut entities, 0);
    let relations = cloudtrail_relations(value, &mut entities);
    entities.sort();
    entities.dedup();
    Ok(Tainted::from_external(
        GraphRecord {
            index,
            at,
            event,
            text: serde_json::to_string(value)
                .map_err(|e| AppError::Storage(format!("serialize JSON record: {e}")))?,
            entities,
            relations,
        },
        Provenance::new(
            evidence_hash,
            Some(index as u64),
            if source.starts_with("siem_")
                || source.starts_with("cloud_")
                || source.starts_with("edr_")
            {
                SourceKind::ToolResult
            } else {
                SourceKind::File
            },
        ),
    ))
}

fn normalize_record(value: Value) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    let Some(result) = object.remove("result") else {
        return Value::Object(object);
    };
    let Value::Object(mut result) = result else {
        object.insert("result".into(), result);
        return Value::Object(object);
    };
    if let Some(raw) = result.get("_raw").and_then(Value::as_str)
        && let Ok(Value::Object(raw)) = serde_json::from_str::<Value>(raw)
    {
        return Value::Object(raw);
    }
    Value::Object(std::mem::take(&mut result))
}

fn cloudtrail_relations(value: &Value, entities: &mut Vec<(String, String)>) -> Vec<GraphRelation> {
    let event = value.get("eventName").and_then(Value::as_str);
    let actor = value.pointer("/userIdentity/arn").and_then(Value::as_str);
    let mut relations = Vec::new();
    if let (Some(_), Some(actor)) = (event, actor) {
        actor_relations(value, event, actor, entities, &mut relations);
    }
    if event == Some("CreateAccessKey")
        && let (Some(user), Some(key)) = (
            value
                .pointer("/requestParameters/userName")
                .and_then(Value::as_str),
            value
                .pointer("/responseElements/accessKey/accessKeyId")
                .and_then(Value::as_str),
        )
        && valid_access_key(key)
    {
        add_relation(
            entities,
            &mut relations,
            ("user", user),
            "created_access_key",
            ("key", key),
        );
    }
    relations.sort();
    relations.dedup();
    relations
}

fn actor_relations(
    value: &Value,
    event: Option<&str>,
    actor: &str,
    entities: &mut Vec<(String, String)>,
    relations: &mut Vec<GraphRelation>,
) {
    let actor_kind = if actor.contains(":role/") {
        "role"
    } else {
        "identity"
    };
    if let Some(ip) = value.get("sourceIPAddress").and_then(Value::as_str)
        && ip.parse::<std::net::IpAddr>().is_ok()
    {
        add_relation(
            entities,
            relations,
            (actor_kind, actor),
            "observed_from_ip",
            ("ip", ip),
        );
    }
    if let Some(issuer) = value
        .pointer("/userIdentity/sessionContext/sessionIssuer/arn")
        .and_then(Value::as_str)
    {
        add_relation(
            entities,
            relations,
            ("role", issuer),
            "issued_session",
            (actor_kind, actor),
        );
    }
    if let Some(key) = value
        .pointer("/userIdentity/accessKeyId")
        .and_then(Value::as_str)
        && valid_access_key(key)
    {
        add_relation(
            entities,
            relations,
            (actor_kind, actor),
            "used_access_key",
            ("key", key),
        );
    }
    if event == Some("AssumeRole")
        && let Some(target) = value
            .pointer("/requestParameters/roleArn")
            .and_then(Value::as_str)
        && target.contains(":role/")
    {
        add_relation(
            entities,
            relations,
            (actor_kind, actor),
            "assumed_role",
            ("role", target),
        );
    }
}

fn valid_access_key(value: &str) -> bool {
    (16..=128).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn add_relation(
    entities: &mut Vec<(String, String)>,
    relations: &mut Vec<GraphRelation>,
    from: (&str, &str),
    relation: &str,
    to: (&str, &str),
) {
    if from.1.is_empty() || to.1.is_empty() || from.1.len() > 512 || to.1.len() > 512 || from == to
    {
        return;
    }
    entities.push((from.0.into(), from.1.into()));
    entities.push((to.0.into(), to.1.into()));
    relations.push(GraphRelation {
        from_kind: from.0.into(),
        from_value: from.1.into(),
        relation: relation.into(),
        to_kind: to.0.into(),
        to_value: to.1.into(),
    });
}

fn collect(value: &Value, entities: &mut Vec<(String, String)>, depth: usize) {
    if depth > 8 || entities.len() >= 32 {
        return;
    }
    if let Value::Object(object) = value {
        for (key, child) in object {
            if let Some(text) = child.as_str() {
                if let Some(kind) = classify_field(key, text) {
                    entities.push((kind.to_owned(), text.to_owned()));
                }
            } else if child.is_object() || child.is_array() {
                collect(child, entities, depth + 1);
            }
            if entities.len() >= 32 {
                break;
            }
        }
    } else if let Value::Array(items) = value {
        for item in items.iter().take(100) {
            collect(item, entities, depth + 1);
            if entities.len() >= 32 {
                break;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::wildcard_imports)]
mod tests;
