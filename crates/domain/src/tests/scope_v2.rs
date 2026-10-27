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
fn toml_policy_scope_tightens_case_scope_to_pending_approval() {
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
        Decision::NeedsApproval(_)
    ));
    if let Decision::NeedsApproval(pending) = check(
        Tool::CloudAuditEvents,
        &cloud("project-b", "2026-10-23T12:00:00Z"),
    ) {
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
    }
    assert!(matches!(
        check(
            Tool::CloudAuditEvents,
            &cloud("project-a", "2026-10-23T09:00:00Z")
        ),
        Decision::NeedsApproval(_)
    ));
    assert!(matches!(
        check(Tool::EdrHostInfo, &[("source", "edr"), ("host", "host-b")]),
        Decision::NeedsApproval(_)
    ));
    assert!(matches!(
        check(
            Tool::SiemSearch,
            &[
                ("source", "siem"),
                ("account", "account-b"),
                ("from", "2026-10-23T12:00:00Z"),
                ("to", "2026-10-23T13:00:00Z"),
                ("query", "AssumeRole")
            ]
        ),
        Decision::NeedsApproval(_)
    ));
}
