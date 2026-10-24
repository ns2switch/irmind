#![forbid(unsafe_code)]

use irmind_app::{
    AppError, EventParser, GraphRecord, GraphRelation,
    modules::{Module, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{Tainted, classify_field};
use serde_json::Value;

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

    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
        registry.add_parser(self)
    }
}

impl EventParser for JsonParser {
    fn version(&self) -> &'static str {
        "json-cloudtrail-v4"
    }
    fn parse(&self, source: &str, bytes: &[u8]) -> Result<Vec<Tainted<GraphRecord>>, AppError> {
        let first = bytes.iter().copied().find(|b| !b.is_ascii_whitespace());
        if !matches!(first, Some(b'{' | b'[')) {
            return Ok(Vec::new());
        }
        let values = match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Array(items)) => items,
            Ok(Value::Object(mut object)) => {
                if let Some(Value::Array(items)) = object.remove("Records") {
                    items
                } else if let Some(Value::Array(items)) = object.remove("events") {
                    items
                } else {
                    vec![Value::Object(object)]
                }
            }
            Ok(_) => Vec::new(),
            Err(_) => {
                let mut items = Vec::new();
                for line in bytes.split(|byte| *byte == b'\n') {
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    let item = serde_json::from_slice(line)
                        .map_err(|e| AppError::Storage(format!("invalid JSON record: {e}")))?;
                    items.push(normalize_record(item));
                    if items.len() > 100_000 {
                        return Err(AppError::Policy("too many JSON records".into()));
                    }
                }
                items
            }
        };
        if values.len() > 100_000 {
            return Err(AppError::Policy("too many JSON records".into()));
        }
        let mut records = Vec::with_capacity(values.len());
        for (index, value) in values.into_iter().map(normalize_record).enumerate() {
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
            collect(&value, &mut entities, 0);
            let relations = cloudtrail_relations(&value, &mut entities);
            entities.sort();
            entities.dedup();
            records.push(Tainted::from_external(
                GraphRecord {
                    index,
                    at,
                    event,
                    text: serde_json::to_string(&value)
                        .map_err(|e| AppError::Storage(format!("serialize JSON record: {e}")))?,
                    entities,
                    relations,
                },
                source,
            ));
        }
        Ok(records)
    }
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
                &mut relations,
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
                &mut relations,
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
                &mut relations,
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
                &mut relations,
                (actor_kind, actor),
                "assumed_role",
                ("role", target),
            );
        }
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn indexes_cloudtrail_record() {
        let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","sourceIPAddress":"203.0.113.8","userIdentity":{"arn":"arn:aws:iam::123456789012:role/Admin"}}]}"#;
        let records = JsonParser.parse("cloudtrail.json", bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert!(
            records[0]
                .value()
                .entities
                .contains(&("ip".into(), "203.0.113.8".into()))
        );
        assert!(
            records[0]
                .value()
                .entities
                .contains(&("role".into(), "arn:aws:iam::123456789012:role/Admin".into()))
        );
        assert!(records[0].value().text.contains("AssumeRole"));
    }

    #[test]
    fn extracts_assume_role_relation_from_cloudtrail_fields() {
        let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/Admin"}}]}"#;
        let records = JsonParser.parse("cloudtrail.json", bytes).unwrap();
        assert_eq!(records[0].value().relations.len(), 1);
        assert_eq!(records[0].value().relations[0].relation, "assumed_role");
        assert_eq!(records[0].value().relations[0].from_kind, "identity");
        assert_eq!(records[0].value().relations[0].to_kind, "role");
    }

    #[test]
    fn links_cloudtrail_origin_session_and_access_keys() {
        let bytes = br#"{"Records":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"GetObject","sourceIPAddress":"198.51.100.9","userIdentity":{"arn":"arn:aws:sts::123456789012:assumed-role/Analyst/session","accessKeyId":"ASIAABCDEFGHIJKLMNOP","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::123456789012:role/Analyst"}}}},{"eventTime":"2026-10-23T12:01:00Z","eventName":"CreateAccessKey","requestParameters":{"userName":"alice"},"responseElements":{"accessKey":{"accessKeyId":"AKIAABCDEFGHIJKLMNOP"}}}]}"#;
        let records = JsonParser.parse("cloudtrail.json", bytes).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].value().relations.len(), 3);
        assert!(
            records[0]
                .value()
                .relations
                .iter()
                .any(|relation| relation.relation == "observed_from_ip"
                    && relation.to_value == "198.51.100.9")
        );
        assert!(
            records[0]
                .value()
                .relations
                .iter()
                .any(|relation| relation.relation == "issued_session"
                    && relation.from_kind == "role")
        );
        assert!(records[0].value().relations.iter().any(|relation| relation.relation == "used_access_key" && relation.to_kind == "key"));
        assert_eq!(
            records[1].value().relations[0].relation,
            "created_access_key"
        );
    }

    #[test]
    fn remote_envelopes_become_separate_timeline_records() {
        let cloud = br#"{"events":[{"eventTime":"2026-10-23T12:00:00Z","eventName":"AssumeRole"},{"eventTime":"2026-10-23T13:00:00Z","eventName":"GetObject"}]}"#;
        let records = JsonParser.parse("cloud_audit_events:aws", cloud).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].value().event, "GetObject");
        let splunk = br#"{"result":{"_raw":"{\"eventTime\":\"2026-10-23T12:00:00Z\",\"eventName\":\"AssumeRole\"}"}}"#;
        let records = JsonParser.parse("siem_search:splunk", splunk).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value().event, "AssumeRole");
    }
}
