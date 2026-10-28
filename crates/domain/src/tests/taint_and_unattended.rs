use super::case;
use crate::*;

#[test]
fn cloud_audit_read_requires_account_source_and_window_scope() {
    let mut scoped = case();
    scoped.scope = "v1;sources=aws-prod;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let call = |account: &str| ProposedCall {
        tool: Tool::CloudAuditEvents,
        args: BTreeMap::from([
            ("source".into(), "aws-prod".into()),
            ("account".into(), account.into()),
            ("from".into(), "2026-10-23T12:00:00Z".into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
            ("event_name".into(), "AssumeRole".into()),
        ]),
    };
    assert!(matches!(
        evaluate(
            &scoped,
            call("123456789012"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            call("999999999999"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
fn cloud_identity_read_is_scoped_to_account_and_source() {
    let mut scoped = case();
    scoped.scope = "v1;sources=aws-prod;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let call = |account: &str| ProposedCall {
        tool: Tool::CloudIdentity,
        args: BTreeMap::from([
            ("source".into(), "aws-prod".into()),
            ("account".into(), account.into()),
            ("kind".into(), "role".into()),
            ("name".into(), "Admin".into()),
        ]),
    };
    assert!(matches!(
        evaluate(
            &scoped,
            call("123456789012"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            call("999999999999"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
fn internal_intel_is_read_only_for_a_scoped_source() {
    let mut scoped = case();
    scoped.scope = "v1;sources=misp-internal;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let proposal = ProposedCall {
        tool: Tool::ThreatIntelInternal,
        args: BTreeMap::from([
            ("source".into(), "misp-internal".into()),
            ("ioc".into(), "example.com".into()),
        ]),
    };
    assert!(matches!(
        evaluate(
            &scoped,
            proposal.clone(),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(
            &case(),
            proposal,
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
fn unattended_read_is_allowed_but_external_lookup_is_pending() {
    let read = ProposedCall {
        tool: Tool::EvidenceSearch,
        args: BTreeMap::from([("query".into(), "alice".into())]),
    };
    assert!(matches!(
        evaluate(&case(), read, 1, ExecutionMode::Unattended, 1_700_000_000),
        Decision::Allow(_)
    ));
    let external = ProposedCall {
        tool: Tool::ThreatIntelExternal,
        args: BTreeMap::from([("ioc".into(), "example.com".into())]),
    };
    assert!(matches!(
        evaluate(
            &case(),
            external,
            2,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn graph_queries_are_local_reads_with_bounded_arguments() {
    let args = BTreeMap::from([
        ("kind".into(), "ip".into()),
        ("value".into(), "203.0.113.8".into()),
        ("limit".into(), "20".into()),
    ]);
    assert!(matches!(
        evaluate(
            &case(),
            ProposedCall {
                tool: Tool::Neighbors,
                args: args.clone(),
            },
            2,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    let mut invalid = args;
    invalid.insert("limit".into(), "1000".into());
    assert!(matches!(
        evaluate(
            &case(),
            ProposedCall {
                tool: Tool::Neighbors,
                args: invalid,
            },
            3,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::Deny(_)
    ));
    for proposal in [
        ProposedCall {
            tool: Tool::GraphPath,
            args: BTreeMap::from([
                ("from_kind".into(), "ip".into()),
                ("from_value".into(), "203.0.113.8".into()),
                ("to_kind".into(), "user".into()),
                ("to_value".into(), "alice".into()),
            ]),
        },
        ProposedCall {
            tool: Tool::TextSearch,
            args: BTreeMap::from([
                ("query".into(), "AssumeRole".into()),
                ("limit".into(), "20".into()),
            ]),
        },
        ProposedCall {
            tool: Tool::RawRecords,
            args: BTreeMap::from([
                ("hash".into(), "a".repeat(64)),
                ("index".into(), "0".into()),
            ]),
        },
    ] {
        assert!(matches!(
            evaluate(
                &case(),
                proposal,
                4,
                ExecutionMode::Unattended,
                1_700_000_000
            ),
            Decision::Allow(_)
        ));
    }
    assert!(matches!(
        evaluate(
            &case(),
            ProposedCall {
                tool: Tool::RawRecords,
                args: BTreeMap::from([
                    ("hash".into(), "a".repeat(64)),
                    ("index".into(), "100000".into())
                ]),
            },
            5,
            ExecutionMode::Attended,
            1_700_000_000
        ),
        Decision::Deny(_)
    ));
}

#[test]
fn unattended_edr_reads_require_scoped_host_and_window() {
    let mut scoped = case();
    scoped.scope = "v1;sources=edr-prod;accounts=;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let info = |host: &str| ProposedCall {
        tool: Tool::EdrHostInfo,
        args: BTreeMap::from([
            ("source".into(), "edr-prod".into()),
            ("host".into(), host.into()),
        ]),
    };
    assert!(matches!(
        evaluate(
            &scoped,
            info("host-1"),
            1,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            info("host-2"),
            2,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
    let detection = |from: &str| ProposedCall {
        tool: Tool::EdrDetections,
        args: BTreeMap::from([
            ("source".into(), "edr-prod".into()),
            ("host".into(), "host-1".into()),
            ("from".into(), from.into()),
            ("to".into(), "2026-10-23T13:00:00Z".into()),
        ]),
    };
    assert!(matches!(
        evaluate(
            &scoped,
            detection("2026-10-23T12:00:00Z"),
            3,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate(
            &scoped,
            detection("2026-10-22T12:00:00Z"),
            4,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
    scoped.scope = "v1;sources=edr-prod;accounts=123;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    assert!(matches!(
        evaluate(
            &scoped,
            info("host-1"),
            5,
            ExecutionMode::Unattended,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
fn tainted_external_value_requires_approval() {
    let proposal = Tainted::from_external(
        ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.com".into())]),
        },
        Provenance::new([7; 32], Some(3), SourceKind::ToolResult),
    );
    assert_eq!(proposal.provenance().record_index(), Some(3));
    assert!(matches!(
        evaluate_tainted(
            &case(),
            proposal,
            1,
            ExecutionMode::Attended,
            false,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}

#[test]
fn detection_does_not_expand_read_scope() {
    let mut scoped = case();
    scoped.scope = "v1;sources=splunk-prod;accounts=123;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z".into();
    let proposal = |account: &str| {
        Tainted::from_external(
            ProposedCall {
                tool: Tool::SiemSearch,
                args: BTreeMap::from([
                    ("source".into(), "splunk-prod".into()),
                    ("account".into(), account.into()),
                    ("from".into(), "2026-10-23T12:00:00Z".into()),
                    ("to".into(), "2026-10-23T13:00:00Z".into()),
                    ("field".into(), "event_name".into()),
                    ("operator".into(), "eq".into()),
                    ("value".into(), "AssumeRole".into()),
                ]),
            },
            Provenance::new([8; 32], Some(4), SourceKind::ToolResult),
        )
    };
    assert!(matches!(
        evaluate_tainted(
            &scoped,
            proposal("123"),
            1,
            ExecutionMode::Attended,
            true,
            1_700_000_000
        ),
        Decision::Allow(_)
    ));
    assert!(matches!(
        evaluate_tainted(
            &scoped,
            proposal("999"),
            2,
            ExecutionMode::Attended,
            true,
            1_700_000_000
        ),
        Decision::NeedsApproval(_)
    ));
}
