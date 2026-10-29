use super::case;
use crate::*;

const FROM: &str = "2026-10-23T10:00:00Z";
const TO: &str = "2026-10-23T11:00:00Z";

fn object_call(tool: Tool, path: &str) -> ProposedCall {
    let mut args = BTreeMap::from([
        ("source".into(), "storage".into()),
        ("scheme".into(), "s3".into()),
        ("container".into(), "audit-bucket".into()),
        ("from".into(), FROM.into()),
        ("to".into(), TO.into()),
    ]);
    if tool == Tool::ObjectList {
        args.insert("prefix".into(), path.into());
        args.insert("limit".into(), "20".into());
    } else {
        args.insert("key".into(), path.into());
        args.insert("version".into(), "version-1".into());
        args.insert("max_bytes".into(), "1048576".into());
    }
    ProposedCall { tool, args }
}

fn scoped_case() -> Case {
    let mut scoped = case();
    scoped.scope = format!(
        "v3;sources=storage;accounts=;projects=;hosts=;objects=s3://audit-bucket/AWSLogs/123/CloudTrail/;from={FROM};to={TO}"
    );
    scoped
}

#[test]
fn version_three_object_prefix_is_bounded_and_legacy_is_unchanged() {
    let scoped = scoped_case();
    let scope = CaseScope::parse(&scoped.scope).unwrap();
    assert_eq!(scope.to_v3_string().unwrap(), scoped.scope);
    assert!(scope.allows_object(
        "storage",
        "s3://audit-bucket/AWSLogs/123/CloudTrail/a.json",
        FROM,
        TO
    ));
    assert!(!scope.allows_object(
        "storage",
        "s3://audit-bucket/AWSLogs/123/CloudTrailExtra/a.json",
        FROM,
        TO
    ));
    assert!(!scope.allows_object(
        "storage",
        "s3://audit-bucket/AWSLogs/123/CloudTrail/../secret",
        FROM,
        TO
    ));
    assert!(CaseScope::parse("v2;sources=s;accounts=a;projects=;hosts=;from=2026-10-23T10:00:00Z;to=2026-10-23T11:00:00Z").unwrap().to_v2_string().is_ok());
}

#[test]
fn object_calls_outside_case_and_policy_scope_are_denied() {
    let scoped = scoped_case();
    for tool in [Tool::ObjectList, Tool::ObjectRead] {
        assert!(matches!(
            evaluate(
                &scoped,
                object_call(tool.clone(), "AWSLogs/123/CloudTrail/"),
                1,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
        let outside = object_call(tool, "AWSLogs/other/");
        assert!(matches!(
            evaluate(&scoped, outside, 1, ExecutionMode::Attended, 1_700_000_000),
            Decision::Deny(_)
        ));
    }
    let ceiling = CaseScope::parse(&format!("v3;sources=storage;accounts=;projects=;hosts=;objects=s3://audit-bucket/AWSLogs/123/CloudTrail/restricted/;from={FROM};to={TO}")).unwrap();
    let rules = PolicyRules {
        scope: Some(ceiling),
        ..PolicyRules::default()
    };
    assert!(matches!(
        evaluate_with_rules(
            &scoped,
            object_call(Tool::ObjectRead, "AWSLogs/123/CloudTrail/a.json"),
            1,
            ExecutionMode::Attended,
            1_700_000_000,
            &rules
        ),
        Decision::Deny(_)
    ));
    assert!(
        !CaseScope::parse(&scoped.scope)
            .unwrap()
            .is_within(rules.scope.as_ref().unwrap())
    );
}

#[test]
fn object_paths_and_arguments_fail_closed() {
    let scoped = scoped_case();
    for path in [
        "AWSLogs/../secret",
        "AWSLogs//secret",
        "AWSLogs/secret?token=1",
        "AWSLogs/secret#part",
        "AWSLogs/\u{1b}[31m",
        "AWSLogs/%2e%2e/secret",
    ] {
        assert!(matches!(
            evaluate(
                &scoped,
                object_call(Tool::ObjectRead, path),
                1,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::Deny(_)
        ));
    }
    let mut request = object_call(Tool::ObjectRead, "AWSLogs/123/CloudTrail/a.json");
    request.args.insert("unknown".into(), "x".into());
    assert!(matches!(
        evaluate(&scoped, request, 1, ExecutionMode::Attended, 1_700_000_000),
        Decision::Deny(_)
    ));
}

#[test]
#[allow(clippy::panic)]
fn large_transfer_requires_signed_approval_and_policy_limit_is_absolute() {
    let scoped = scoped_case();
    let rules = PolicyRules {
        max_object_read_bytes: 1_048_576,
        object_transfer_approval_bytes: 1_024,
        ..PolicyRules::default()
    };
    let call = object_call(Tool::ObjectRead, "AWSLogs/123/CloudTrail/a.json");
    let Decision::NeedsApproval(pending) = evaluate_with_rules(
        &scoped,
        call.clone(),
        3,
        ExecutionMode::Attended,
        1_700_000_000,
        &rules,
    ) else {
        panic!("large read must require approval")
    };
    assert!(
        PendingApproval::recover_with_rules(
            &scoped,
            ExecutionMode::Attended,
            &pending.challenge(),
            1_700_000_000,
            &rules
        )
        .is_ok()
    );
    let mut oversized = call;
    oversized.args.insert("max_bytes".into(), "1048577".into());
    assert!(matches!(
        evaluate_with_rules(
            &scoped,
            oversized,
            4,
            ExecutionMode::Attended,
            1_700_000_000,
            &rules
        ),
        Decision::Deny(_)
    ));
}
