#![allow(clippy::unwrap_used)]
use super::*;
mod batch;
mod queries;
fn assign(a: &mut Allocator, host: &str) -> ArtifactPartitionV2 {
    a.assign("2026-11-01", PartitionProfile::EndpointHost, ["", "", host])
        .unwrap()
}
#[test]
fn cardinality_and_recovery_come_only_from_signed_assignments() {
    let mut a = Allocator::from_signed(
        &[],
        PartitionLimits {
            host: 2,
            ..PartitionLimits::default()
        },
    )
    .unwrap();
    let first = assign(&mut a, "HOST-A");
    assert_eq!(first.scopes[0].value, Value::Ordinary("host-a".into()));
    assert_eq!(assign(&mut a, "host-a"), first);
    assign(&mut a, "host-b");
    assert_eq!(
        assign(&mut a, "host-c").scopes[0].value,
        Value::Overflow(Reason::Cardinality)
    );
    let mut recovered = Allocator::from_signed(
        &[],
        PartitionLimits {
            host: 2,
            ..PartitionLimits::default()
        },
    )
    .unwrap();
    recovered.observe(&first).unwrap();
    assert_eq!(
        assign(&mut recovered, "host-c").scopes[0].value,
        Value::Ordinary("host-c".into())
    );
    assert_eq!(
        assign(&mut recovered, "host-b").scopes[0].value,
        Value::Overflow(Reason::Cardinality)
    );
}
#[test]
fn invalid_values_use_typed_overflow_and_paths_never_contain_raw_values() {
    let mut a = Allocator::from_signed(&[], PartitionLimits::default()).unwrap();
    for raw in ["../host", "host/a", "host\u{200b}a", "host\n"] {
        let partition = assign(&mut a, raw);
        assert_eq!(
            partition.scopes[0].value,
            Value::Overflow(Reason::UnrepresentableValue)
        );
        assert!(!partition.path_prefix().unwrap().contains(raw));
    }
    let ordinary = assign(&mut a, "overflow-cardinality-cap64");
    assert!(matches!(ordinary.scopes[0].value, Value::Ordinary(_)));
    assert!(
        !ordinary
            .path_prefix()
            .unwrap()
            .contains("overflow-cardinality-cap64")
    );
}
#[test]
fn tuple_overflow_does_not_consume_an_ordinary_value() {
    let mut a = Allocator::from_signed(&[], PartitionLimits::default()).unwrap();
    a.tuples.insert(
        "2026-11-01".into(),
        (0..4096).map(|i| format!("tuple-{i}")).collect(),
    );
    let overflow = assign(&mut a, "host-a");
    assert!(overflow.all_scope_overflow);
    assert_eq!(
        overflow.scopes[0].value,
        Value::Overflow(Reason::TupleBudget)
    );
    assert!(a.keys.is_empty());
    a.tuples.clear();
    assert!(matches!(
        assign(&mut a, "host-a").scopes[0].value,
        Value::Ordinary(_)
    ));
}
#[test]
fn signed_caps_are_authoritative_and_cannot_be_exceeded() {
    let mut a = Allocator::from_signed(&[], PartitionLimits::default()).unwrap();
    for i in 0..64 {
        assert!(matches!(
            assign(&mut a, &format!("host-{i}")).scopes[0].value,
            Value::Ordinary(_)
        ));
    }
    assert_eq!(
        assign(&mut a, "host-64").scopes[0].value,
        Value::Overflow(Reason::Cardinality)
    );
    assert!(
        staging::check_space(100, 101)
            .unwrap_err()
            .to_string()
            .contains("space")
    );
    assert!(staging::check_space(101, 101).is_ok());
    assert!(
        PartitionLimits {
            host: 1025,
            ..PartitionLimits::default()
        }
        .validate()
        .is_err()
    );
}
