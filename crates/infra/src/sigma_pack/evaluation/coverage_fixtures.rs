use super::*;
use crate::sigma_pack::field_table::ReviewedSigmaFieldTable;
use irmind_app::v10_proofs::SigmaFieldTableV1;
use irmind_domain::{
    BoundedObservations, CategorySet, EventCategory, EventContextV1, EventHeaderV1, EventKind,
    EventOrigin, EventOutcome, EventText, EventType, EventTypeSet, EvidenceHash,
};

pub(super) fn parse_table(toml: &str) -> ReviewedSigmaFieldTable {
    // Fixture runs do not authenticate manifests. The production table is
    // resolved against the complete native implementation identities.
    ReviewedSigmaFieldTable::parse(&SigmaFieldTableV1 {
        id: "synthetic-sigma-bindings".into(),
        version: "v1".into(),
        toml: toml.replace("mapping_version = \"@", "mapping_version = \"synthetic-"),
    })
    .unwrap()
}

pub(super) fn evaluate(
    variant: &SigmaSourceVariant,
    taxonomy: &str,
    selection: &str,
    row: &CommonEventV1,
    original: Option<&str>,
) -> (usize, Option<SigmaCoverageV1>) {
    let raw = format!(
        "title: Synthetic binding exercise\nlogsource: {taxonomy}\ndetection: {{selection: {selection}, condition: selection}}\n"
    );
    let key = SigmaRuleKeyV1 {
        id: "synthetic-binding".into(),
        sha256: irmind_app::sha256(raw.as_bytes()),
    };
    let programs = SigmaVariantPrograms::compile(variant, [(key, raw.as_bytes())]).unwrap();
    let mut hits = 0;
    assert!(
        programs
            .start(100_000)
            .row(row, original, &CancellationToken::new(), |_| {
                hits += 1;
                Ok(())
            })
            .unwrap()
    );
    (hits, programs.skipped().first().map(|(_, status)| *status))
}

pub(super) fn synthetic_row(
    variant: &SigmaSourceVariant,
    header: EventHeaderV1,
    fields: impl IntoIterator<Item = (CommonField, CommonValue)>,
) -> CommonEventV1 {
    let mut context = EventContextV1::default();
    for (field, value) in fields {
        context.try_insert(field, value).unwrap();
    }
    CommonEventV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([19; 32]),
            3,
            Some(271),
            &variant.parser_id,
            &variant.parser_version,
        )
        .unwrap(),
        None,
        header,
        context,
        BoundedObservations::default(),
    )
    .unwrap()
}

fn linux_variant<'a>(
    table: &'a ReviewedSigmaFieldTable,
    service: &str,
    category: &str,
) -> &'a SigmaSourceVariant {
    table
        .variants
        .iter()
        .find(|variant| {
            variant.service.as_deref() == Some(service)
                && variant.category.as_deref() == Some(category)
        })
        .unwrap()
}

#[test]
fn sigma_linux_authentication_uses_the_sshd_outcome_and_verb() {
    let reviewed = parse_table(include_str!("../linux-v1.toml"));
    let sshd = linux_variant(&reviewed, "sshd", "authentication");
    let taxonomy = "{product: linux, service: sshd}";
    for (outcome, verb, expected) in [
        (EventOutcome::Failure, "Failed", 1),
        (EventOutcome::Success, "Accepted", 0),
    ] {
        let row = synthetic_row(
            sshd,
            EventHeaderV1::new(
                CategorySet::new([EventCategory::Authentication]),
                EventTypeSet::new([EventType::Start]),
                outcome,
                EventKind::Event,
            )
            .with_action("sshd")
            .unwrap(),
            [(
                CommonField::SourceIp,
                CommonValue::Ip("203.0.113.77".parse().unwrap()),
            )],
        );
        let original = format!(r#"{{"sshd":{{"user":"analyst","verb":"{verb}"}}}}"#);
        assert_eq!(
            evaluate(
                sshd,
                taxonomy,
                "{'SourceIP|cidr': 203.0.113.0/24, Outcome: failure, Verb: Failed}",
                &row,
                Some(&original)
            ),
            (expected, None)
        );
    }
}

#[test]
fn sigma_linux_auditd_process_selects_exactly_exec_events() {
    let reviewed = parse_table(include_str!("../linux-v1.toml"));
    let auditd = linux_variant(&reviewed, "auditd", "process_creation");
    for (category, expected) in [(EventCategory::Process, 1), (EventCategory::Api, 0)] {
        let row = synthetic_row(
            auditd,
            EventHeaderV1::new(
                CategorySet::new([category]),
                EventTypeSet::new([EventType::Start]),
                EventOutcome::Success,
                EventKind::Event,
            )
            .with_action("59")
            .unwrap(),
            [(
                CommonField::ProcessExecutable,
                CommonValue::Text(EventText::new("/usr/bin/synthetic").unwrap()),
            )],
        );
        assert_eq!(
            evaluate(
                auditd,
                "{product: linux, service: auditd, category: process_creation}",
                "{Image: /usr/bin/synthetic, Syscall: '59', Serial: '155'}",
                &row,
                Some(r#"{"serial":"155","node":"synthetic-endpoint"}"#)
            ),
            (expected, None)
        );
    }
}

#[test]
fn sigma_linux_ecs_requires_linux_platform_and_a_supported_service() {
    let reviewed = parse_table(include_str!("../linux-v1.toml"));
    let ecs = linux_variant(&reviewed, "ecs", "process_creation");
    for (os, expected) in [("linux", 1), ("windows", 0)] {
        let row = synthetic_row(
            ecs,
            EventHeaderV1::new(
                CategorySet::new([EventCategory::Process]),
                EventTypeSet::new([EventType::Start]),
                EventOutcome::Unknown,
                EventKind::Event,
            ),
            [
                (
                    CommonField::HostOsType,
                    CommonValue::Text(EventText::new(os).unwrap()),
                ),
                (
                    CommonField::ProcessExecutable,
                    CommonValue::Text(EventText::new("/usr/bin/synthetic").unwrap()),
                ),
            ],
        );
        assert_eq!(
            evaluate(
                ecs,
                "{product: linux, service: ecs, category: process_creation}",
                "{Image: /usr/bin/synthetic}",
                &row,
                None
            ),
            (expected, None)
        );
        assert_eq!(
            evaluate(
                ecs,
                "{product: linux, service: unreviewed}",
                "{Image: /usr/bin/synthetic}",
                &row,
                None
            ),
            (0, Some(SigmaCoverageV1::UnsupportedLogsource))
        );
    }
}
