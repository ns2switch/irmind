#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::common_event::*;
use serde_json::{Value, json};

fn descriptor(
    kind: &str,
    value: &str,
    role: EntityRole,
    field: CommonField,
    scope: &EntityIdentityScope,
) -> Value {
    json!({"kind":kind,"value":value,"role":role.code(),"field":field.code(),"scope":encode_identity_scope(scope).unwrap()})
}
fn legacy_descriptor(kind: &str, value: &str) -> Value {
    json!({"kind":kind,"value":value,"role":0,"field":0,"scope":"legacy-unspecified"})
}
fn wire(value: &Value) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn sparse_and_complete_legacy_peers_are_equivalent() {
    let pairs = json!([
        ["ip", "203.0.113.77"],
        ["user", "alice"],
        ["process", "42"],
        ["user", "alice"]
    ]);
    let complete = json!([
        legacy_descriptor("ip", "203.0.113.77"),
        legacy_descriptor("user", "alice"),
        legacy_descriptor("process", "42")
    ]);
    let sparse = decode(&wire(&pairs), Some("[]")).unwrap();
    assert_eq!(
        sparse,
        decode(&wire(&pairs), Some(&wire(&complete))).unwrap()
    );
    assert_eq!(sparse, decode(&wire(&pairs), None).unwrap());
    assert_eq!(sparse.len(), 3);
}

fn typed_observations() -> Vec<Value> {
    let text = |s| EventText::identifier(s).unwrap();
    vec![
        descriptor(
            "ip",
            "203.0.113.77",
            EntityRole::Source,
            CommonField::SourceIp,
            &EntityIdentityScope::Global,
        ),
        descriptor(
            "ip",
            "203.0.113.77",
            EntityRole::Destination,
            CommonField::DestinationIp,
            &EntityIdentityScope::Global,
        ),
        descriptor(
            "user",
            "alice",
            EntityRole::Actor,
            CommonField::UserName,
            &EntityIdentityScope::Account(text("account-a")),
        ),
        descriptor(
            "user",
            "bob",
            EntityRole::Target,
            CommonField::UserTargetName,
            &EntityIdentityScope::Account(text("account-b")),
        ),
        descriptor(
            "process",
            "42",
            EntityRole::Subject,
            CommonField::ProcessPid,
            &EntityIdentityScope::ProcessLifetime {
                host: text("host-a"),
                lifetime: text("lifetime-a"),
            },
        ),
        descriptor(
            "process",
            "42",
            EntityRole::Subject,
            CommonField::ProcessPid,
            &EntityIdentityScope::ProcessLifetime {
                host: text("host-a"),
                lifetime: text("lifetime-b"),
            },
        ),
    ]
}

#[test]
fn sparse_mixed_peers_keep_roles_namespaces_and_pid_lifetimes() {
    let pairs = json!([
        ["ip", "203.0.113.77"],
        ["user", "alice"],
        ["user", "bob"],
        ["process", "42"],
        ["user", "collector"],
        ["account", "999"]
    ]);
    let typed = typed_observations();
    let mut complete = typed.clone();
    complete.extend([
        legacy_descriptor("user", "collector"),
        legacy_descriptor("account", "999"),
    ]);
    let before = decode(&wire(&pairs), Some(&wire(&json!(complete)))).unwrap();
    let after = decode(&wire(&pairs), Some(&wire(&json!(typed)))).unwrap();
    assert_eq!(before, after);
    assert_eq!(after.len(), 7);
    assert_eq!(after.iter().filter(|n| n.kind == "ip").count(), 1);
    let processes = after
        .iter()
        .filter(|n| n.kind == "process")
        .collect::<Vec<_>>();
    assert_eq!(processes.len(), 2);
    assert!(
        processes
            .iter()
            .all(|n| n.scope.contains("process_lifetime"))
    );
}

#[test]
fn invalid_descriptors_never_fall_back_to_legacy_pairs() {
    let pairs = r#"[["ip","203.0.113.77"]]"#;
    let valid = typed_observations().remove(0);
    for (field, invalid) in [
        ("role", json!(99)),
        ("field", json!(0)),
        ("scope", json!("not a scope")),
        ("kind", json!("user")),
    ] {
        let mut broken = valid.clone();
        broken[field] = invalid;
        assert!(decode(pairs, Some(&wire(&json!([valid.clone(), broken])))).is_err());
    }
    assert!(decode(pairs, Some("not JSON")).is_err());
    assert!(decode("not JSON", Some(&wire(&json!([valid])))).is_err());
}
