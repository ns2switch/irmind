use super::case;
use crate::*;

#[test]
fn debug_of_tainted_and_proposed_values_is_redacted() {
    let tainted = Tainted::from_external(
        "SECRET-from-log".to_owned(),
        Provenance::new([0; 32], Some(3), SourceKind::File),
    );
    assert!(!format!("{tainted:?}").contains("SECRET"));
    let proposal = ProposedCall {
        tool: Tool::ThreatIntelExternal,
        args: BTreeMap::from([("ioc".into(), "SECRET-from-log".into())]),
    };
    assert!(!format!("{proposal:?}").contains("SECRET"));
}

#[test]
fn unknown_arguments_fail_closed() {
    let proposal = ProposedCall {
        tool: Tool::EvidenceSearch,
        args: BTreeMap::from([
            ("query".into(), "test".into()),
            ("send_to".into(), "outside".into()),
        ]),
    };
    assert!(matches!(
        evaluate(&case(), proposal, 1, ExecutionMode::Attended, 1_700_000_000),
        Decision::Deny(_)
    ));
}

#[test]
#[allow(clippy::panic)]
fn spl_commands_are_denied_and_unparseable_queries_need_exact_approval() {
    let mut scoped = case();
    scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let proposal = |query: &str| ProposedCall {
        tool: Tool::SiemSearch,
        args: BTreeMap::from([
            ("source".into(), "splunk-prod".into()),
            ("account".into(), "123".into()),
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("query".into(), query.into()),
        ]),
    };
    for command in [
        "outputlookup",
        "outputcsv",
        "collect",
        "sendemail",
        "sendalert",
        "script",
        "run",
        "rest",
        "map",
        "delete",
        "tscollect",
        "meventcollect",
    ] {
        assert_eq!(
            classify_spl_query(&format!("event | {command} target")),
            SplQueryClass::Forbidden
        );
        assert!(matches!(
            evaluate(
                &scoped,
                proposal(&format!("event | {command} target")),
                1,
                ExecutionMode::Attended,
                1_700_000_000
            ),
            Decision::Deny(_)
        ));
    }
    let exact = "event | stats count";
    let Decision::NeedsApproval(pending) = evaluate(
        &scoped,
        proposal(exact),
        2,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("expected approval")
    };
    assert_eq!(
        pending.proposal().args.get("query").map(String::as_str),
        Some(exact)
    );
    assert!(matches!(
        evaluate(
            &scoped,
            proposal("AssumeRole"),
            3,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
}

#[test]
fn external_lookup_requires_approval() {
    let proposal = ProposedCall {
        tool: Tool::ThreatIntelExternal,
        args: BTreeMap::from([("ioc".into(), "example.com".into())]),
    };
    assert!(matches!(
        evaluate(&case(), proposal, 1, ExecutionMode::Attended, 1_700_000_000),
        Decision::NeedsApproval(_)
    ));
}

#[test]
#[allow(clippy::panic)]
fn approval_signature_binds_case_arguments_sequence_and_expiry() {
    struct ExactChallenge(Vec<u8>);
    impl AnalystApprovalVerifier for ExactChallenge {
        fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
            message == self.0 && signature == self.0
        }
    }
    let proposal = |ioc: &str| ProposedCall {
        tool: Tool::ThreatIntelExternal,
        args: BTreeMap::from([("ioc".into(), ioc.into())]),
    };
    let Decision::NeedsApproval(first) = evaluate(
        &case(),
        proposal("example.com"),
        7,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval")
    };
    let signed = first.challenge();
    let verifier = ExactChallenge(signed.clone());
    assert!(first.resolve(&signed, &verifier, 1_700_000_000).is_ok());

    let mut other_case = case();
    other_case.id = CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap();
    let Decision::NeedsApproval(other) = evaluate(
        &other_case,
        proposal("example.com"),
        7,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval")
    };
    assert!(other.resolve(&signed, &verifier, 1_700_000_000).is_err());
    let Decision::NeedsApproval(other_args) = evaluate(
        &case(),
        proposal("other.example"),
        7,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval")
    };
    assert!(
        other_args
            .resolve(&signed, &verifier, 1_700_000_000)
            .is_err()
    );
    let Decision::NeedsApproval(other_seq) = evaluate(
        &case(),
        proposal("example.com"),
        8,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval")
    };
    assert!(
        other_seq
            .resolve(&signed, &verifier, 1_700_000_000)
            .is_err()
    );
    let before =
        PendingApproval::recover(&case(), ExecutionMode::Attended, &signed, 1_700_000_000).unwrap();
    assert!(before.resolve(&signed, &verifier, 1_700_000_299).is_ok());
    let after =
        PendingApproval::recover(&case(), ExecutionMode::Attended, &signed, 1_700_000_000).unwrap();
    assert!(after.resolve(&signed, &verifier, 1_700_000_301).is_err());
    assert!(!signed.starts_with(b"irmind-audit-v2\0"));
    assert!(!signed.starts_with(b"irmind-seal-v1\0"));
}

#[test]
fn policy_limits_cannot_enable_a_denied_tool_or_exceed_quota() {
    let rules = PolicyRules {
        denied_tools: vec![Tool::ThreatIntelExternal],
        max_tool_calls_per_case: 2,
        max_model_result_bytes: 100,
        max_model_tokens_per_case: 200,
    };
    assert!(rules.validate().is_ok());
    assert!(rules.permits(&Tool::ThreatIntelExternal, 0).is_err());
    assert!(rules.permits(&Tool::EvidenceSearch, 1).is_ok());
    assert!(rules.permits(&Tool::EvidenceSearch, 2).is_err());
    assert!(matches!(
        evaluate(
            &case(),
            ProposedCall {
                tool: Tool::ThreatIntelExternal,
                args: BTreeMap::from([("ioc".into(), "example.com".into())]),
            },
            1,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
fn remote_scope_requires_explicit_source_target_and_bounded_window() {
    let scope = CaseScope::parse("v1;sources=siem-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z").unwrap();
    assert!(scope.contains(
        "siem-prod",
        Some("123"),
        None,
        "2026-10-23T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(!scope.contains(
        "siem-other",
        Some("123"),
        None,
        "2026-10-23T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(!scope.contains(
        "siem-prod",
        Some("456"),
        None,
        "2026-10-23T12:00:00Z",
        "2026-10-23T13:00:00Z"
    ));
    assert!(CaseScope::parse("analyst note").unwrap() == CaseScope::LocalOnly);
    assert!(
        CaseScope::parse(
            "v1;sources=a;accounts=b;hosts=;from=2026-02-30T00:00:00Z;to=2026-03-01T00:00:00Z"
        )
        .is_err()
    );
}

#[test]
fn siem_read_is_allowed_only_inside_explicit_scope() {
    let mut scoped = case();
    scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let call = |source: &str| ProposedCall {
        tool: Tool::SiemSearch,
        args: BTreeMap::from([
            ("source".into(), source.into()),
            ("account".into(), "123".into()),
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("query".into(), "AssumeRole".into()),
        ]),
    };
    assert!(matches!(
        evaluate(
            &scoped,
            call("splunk-prod"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            call("splunk-other"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
    assert!(matches!(
        evaluate(
            &case(),
            call("splunk-prod"),
            1,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
    scoped.scope = "v1;sources=splunk-prod;accounts=;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    assert!(matches!(
        evaluate(
            &scoped,
            call("splunk-prod"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
    scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    assert!(matches!(
        evaluate(
            &scoped,
            call("splunk-prod"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}
