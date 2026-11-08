use super::view::LegacyView;
use irmind_app::{GraphRelation, source_mapping::SourceValue as Value};

pub(super) fn cloudtrail_relations(
    value: &Value,
    entities: &mut Vec<(String, String)>,
) -> Vec<GraphRelation> {
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
