use super::case;
use crate::*;

fn cloud<'a>(project: &'a str, from: &'a str) -> [(&'static str, &'a str); 5] {
    [
        ("source", "cloud"),
        ("project", project),
        ("from", from),
        ("to", "2026-10-23T13:00:00Z"),
        ("event_name", "AssumeRole"),
    ]
}

#[test]
fn version_two_scope_checks_accounts_projects_hosts_and_time() {
    let scope = CaseScope::parse("v2;sources=cloud,edr,siem;accounts=account-a;projects=project-a;hosts=host-a;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z").unwrap();
    assert!(scope.contains(
        "siem",
        Some("account-a"),
        None,
        "2026-10-23T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(scope.contains_project(
        "cloud",
        "project-a",
        "2026-10-23T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(scope.allows_host("edr", "host-a"));
    assert!(!scope.contains_project(
        "cloud",
        "project-b",
        "2026-10-23T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(!scope.contains_project(
        "cloud",
        "project-a",
        "2026-10-22T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(!scope.allows_host("edr", "host-b"));
    let expanded = scope.extend_target("project", "project-b").unwrap();
    assert!(expanded.allows_project("cloud", "project-b"));
    assert!(
        expanded
            .expand_window("2026-10-22T00:00:00Z", "2026-10-24T00:00:00Z")
            .is_ok()
    );
    assert!(
        expanded
            .expand_window("2026-10-24T00:00:00Z", "2026-10-25T00:00:00Z")
            .is_err()
    );
}

#[test]
fn siem_alert_is_bounded_by_case_and_organization_scope() {
    let mut scoped = case();
    scoped.scope = "v2;sources=siem;accounts=account-a,account-b;projects=;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let rules = PolicyRules {
        scope: Some(CaseScope::parse("v2;sources=siem;accounts=account-a;projects=;hosts=;from=2026-10-23T10:00:00Z;to=2026-10-23T20:00:00Z").unwrap()),
        ..PolicyRules::default()
    };
    let alert = |account: &str, from: &str, id: &str| ProposedCall {
        tool: Tool::SiemGetAlert,
        args: [
            ("source", "siem"),
            ("account", account),
            ("from", from),
            ("to", "2026-10-23T13:00:00Z"),
            ("alert_id", id),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect(),
    };
    assert!(matches!(
        evaluate_with_rules(
            &scoped,
            alert("account-a", "2026-10-23T12:00:00Z", "alert-1"),
            1,
            ExecutionMode::Attended,
            1_700_000_000,
            &rules,
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate_with_rules(
            &scoped,
            alert("account-b", "2026-10-23T12:00:00Z", "alert-1"),
            1,
            ExecutionMode::Attended,
            1_700_000_000,
            &rules,
        ),
        Decision::Deny(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            alert("account-a", "2026-10-24T12:00:00Z", "alert-1"),
            1,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            alert("account-a", "2026-10-23T12:00:00Z", "x\"|collect"),
            1,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::Deny(_)
    ));
}

#[test]
#[allow(clippy::too_many_lines, clippy::panic)]
fn toml_policy_scope_is_a_hard_ceiling_even_for_pending_approvals() {
    let mut scoped = case();
    scoped.scope = "v2;sources=cloud,edr,siem;accounts=account-a,account-b;projects=project-a,project-b;hosts=host-a,host-b;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let rules = PolicyRules {
        scope: Some(CaseScope::parse("v2;sources=cloud,edr,siem;accounts=account-a;projects=project-a;hosts=host-a;from=2026-10-23T10:00:00Z;to=2026-10-23T20:00:00Z").unwrap()),
        ..PolicyRules::default()
    };
    let check = |tool: Tool, args: &[(&str, &str)]| {
        evaluate_tainted_with_rules(
            &scoped,
            Tainted::from_external(
                ProposedCall {
                    tool,
                    args: args
                        .iter()
                        .map(|(key, value)| ((*key).into(), (*value).into()))
                        .collect(),
                },
                Provenance::new([0; 32], None, SourceKind::ModelProposal),
            ),
            1,
            ExecutionMode::Attended,
            false,
            1_700_000_000,
            &rules,
        )
    };
    assert!(matches!(
        check(
            Tool::CloudAuditEvents,
            &cloud("project-a", "2026-10-23T12:00:00Z")
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        check(
            Tool::CloudAuditEvents,
            &cloud("project-b", "2026-10-23T12:00:00Z")
        ),
        Decision::Deny(_)
    ));
    let Decision::NeedsApproval(pending) = evaluate(
        &scoped,
        ProposedCall {
            tool: Tool::CloudAuditEvents,
            args: cloud("project-c", "2026-10-23T12:00:00Z")
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        },
        1,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("case scope must require approval");
    };
    assert!(
        PendingApproval::recover_with_rules(
            &scoped,
            ExecutionMode::Attended,
            &pending.challenge(),
            1_700_000_000,
            &rules
        )
        .is_err()
    );
    assert!(matches!(
        check(
            Tool::CloudAuditEvents,
            &cloud("project-a", "2026-10-23T09:00:00Z")
        ),
        Decision::Deny(_)
    ));
    assert!(matches!(
        check(Tool::EdrHostInfo, &[("source", "edr"), ("host", "host-b")]),
        Decision::Deny(_)
    ));
    assert!(matches!(
        check(
            Tool::SiemSearch,
            &[
                ("source", "siem"),
                ("account", "account-b"),
                ("from", "2026-10-23T12:00:00Z"),
                ("to", "2026-10-23T13:00:00Z"),
                ("field", "event_name"),
                ("operator", "eq"),
                ("value", "AssumeRole")
            ]
        ),
        Decision::Deny(_)
    ));
    let case_scope = CaseScope::parse(&scoped.scope).unwrap();
    assert!(!case_scope.is_within(rules.scope.as_ref().unwrap()));
}
