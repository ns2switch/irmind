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

#[test]
fn sigma_cloudtrail_operation_and_principal_require_the_aws_cloudtrail_source() {
    let table = parse_table(include_str!("../cloudtrail-v1.toml"));
    let variant = &table.variants[0];
    for (action, principal, expected) in [
        ("DeleteTrail", "synthetic/operator", 1),
        ("DeleteTrail", "synthetic/auditor", 0),
        ("StartLogging", "synthetic/operator", 0),
    ] {
        let row = synthetic_row(
            variant,
            EventHeaderV1::default().with_action(action).unwrap(),
            [],
        );
        let raw = format!(
            r#"{{"eventName":"{action}","eventSource":"cloudtrail.amazonaws.com","userIdentity":{{"principalId":"{principal}"}},"sourceIPAddress":"203.0.113.77"}}"#
        );
        let selection = "{eventName: DeleteTrail, eventSource: cloudtrail.amazonaws.com, userIdentity.principalId: synthetic/operator, sourceIPAddress: 203.0.113.77}";
        assert_eq!(
            evaluate(
                variant,
                "{product: aws, service: cloudtrail}",
                selection,
                &row,
                Some(&raw)
            ),
            (expected, None)
        );
        assert_eq!(
            evaluate(
                variant,
                "{product: aws, service: guardduty}",
                selection,
                &row,
                Some(&raw)
            ),
            (0, Some(SigmaCoverageV1::UnsupportedLogsource))
        );
    }
}

const NETWORK_EXAMPLES: [(&str, &str, CommonField, &str); 6] = [
    (
        "zeek",
        "dns",
        CommonField::DnsQuestionName,
        "{query: probe.example.test, 'id.orig_h|cidr': 203.0.113.0/24}",
    ),
    (
        "zeek",
        "http",
        CommonField::UrlDomain,
        "{host: probe.example.test, 'id.orig_h|cidr': 203.0.113.0/24}",
    ),
    (
        "zeek",
        "conn",
        CommonField::NetworkTransport,
        "{proto: tcp, 'id.orig_h|cidr': 203.0.113.0/24}",
    ),
    (
        "suricata",
        "dns",
        CommonField::DnsQuestionName,
        "{dns.rrname: probe.example.test, 'src_ip|cidr': 203.0.113.0/24}",
    ),
    (
        "suricata",
        "http",
        CommonField::UrlDomain,
        "{http.hostname: probe.example.test, 'src_ip|cidr': 203.0.113.0/24}",
    ),
    (
        "suricata",
        "flow",
        CommonField::NetworkTransport,
        "{Protocol: tcp, 'src_ip|cidr': 203.0.113.0/24}",
    ),
];

#[test]
fn sigma_network_separates_event_classes_and_source_destination_roles() {
    let reviewed = parse_table(include_str!("../network-v1.toml"));
    for (product, service, field, condition) in NETWORK_EXAMPLES {
        let variant = reviewed
            .variants
            .iter()
            .find(|binding| {
                binding.product.as_deref() == Some(product)
                    && binding.service.as_deref() == Some(service)
            })
            .unwrap();
        let taxonomy = format!("{{product: {product}, service: {service}}}");
        for (action, source, dest, expected) in [
            (service, "203.0.113.77", "192.0.2.5", 1),
            (service, "192.0.2.5", "203.0.113.77", 0),
            ("unreviewed", "203.0.113.77", "192.0.2.5", 0),
        ] {
            let value = if field == CommonField::NetworkTransport {
                "tcp"
            } else {
                "probe.example.test"
            };
            let row = synthetic_row(
                variant,
                EventHeaderV1::default().with_action(action).unwrap(),
                [
                    (field, CommonValue::Text(EventText::new(value).unwrap())),
                    (
                        CommonField::SourceIp,
                        CommonValue::Ip(source.parse().unwrap()),
                    ),
                    (
                        CommonField::DestinationIp,
                        CommonValue::Ip(dest.parse().unwrap()),
                    ),
                ],
            );
            assert_eq!(
                evaluate(variant, &taxonomy, condition, &row, None),
                (expected, None)
            );
            assert_eq!(
                evaluate(
                    variant,
                    &format!("{{product: {product}, service: unreviewed}}"),
                    condition,
                    &row,
                    None
                ),
                (0, Some(SigmaCoverageV1::UnsupportedLogsource))
            );
        }
    }
}

const ENTRA: &str =
    include_str!("../../../../testkit/fixtures/parser-entra/source/signin-table.ndjson");
const AUDIT: &str =
    include_str!("../../../../testkit/fixtures/parser-entra/source/audit-resource.ndjson");
const M365: &str = include_str!("../../../../testkit/fixtures/parser-m365/source/events.ndjson");
const OKTA: &str = include_str!("../../../../testkit/fixtures/parser-okta/source/events.ndjson");
const GCP: &str = include_str!("../../../../testkit/fixtures/parser-gcp-audit/source/event.ndjson");
const IDENTITY_EXAMPLES: [(&str, &str, &str, &str, EventCategory); 5] = [
    (
        "entra-signin-table",
        ENTRA,
        "{ResultType: '50076', UserPrincipalName: analyst@example.invalid}",
        "{ResultType: '0'}",
        EventCategory::Authentication,
    ),
    (
        "entra-audit-resource",
        AUDIT,
        "{OperationName: Add service principal credentials, Result: success}",
        "{Result: failure}",
        EventCategory::Iam,
    ),
    (
        "m365-audit",
        M365,
        "{Operation: UserLoginFailed, ClientIP: 203.0.113.77}",
        "{Operation: UserLoggedIn}",
        EventCategory::Authentication,
    ),
    (
        "okta-system-log",
        OKTA,
        "{eventType: user.session.start, actor.alternateId: alice@example.invalid}",
        "{actor.alternateId: bob@example.invalid}",
        EventCategory::Authentication,
    ),
    (
        "gcp-audit",
        GCP,
        "{protoPayload.methodName: google.iam.admin.v1.CreateServiceAccountKey}",
        "{protoPayload.methodName: google.iam.admin.v1.DeleteServiceAccountKey}",
        EventCategory::Iam,
    ),
];

#[test]
fn sigma_cloud_identity_uses_exact_source_fields_and_keeps_missing_status_absent() {
    use SigmaCoverageV1::UnsupportedLogsource;
    let reviewed = parse_table(include_str!("../cloud-identity-v1.toml"));
    for (dataset, fixture, positive, negative, category) in IDENTITY_EXAMPLES {
        let variant = reviewed
            .variants
            .iter()
            .find(|entry| entry.dataset.as_deref() == Some(dataset))
            .unwrap();
        let product = variant.product.as_deref().unwrap();
        let service = variant.service.as_deref().unwrap();
        let condition = format!("{{product: {product}, service: {service}}}");
        let row = synthetic_row(
            variant,
            EventHeaderV1::new(
                CategorySet::new([category]),
                EventTypeSet::default(),
                EventOutcome::Unknown,
                EventKind::Event,
            ),
            [],
        );
        let raw = fixture.lines().next();
        assert_eq!(
            evaluate(variant, &condition, positive, &row, raw),
            (1, None),
            "{dataset}"
        );
        assert_eq!(
            evaluate(variant, &condition, negative, &row, raw),
            (0, None),
            "{dataset}"
        );
        assert_eq!(
            evaluate(
                variant,
                &format!("{{product: {product}, service: unreviewed}}"),
                positive,
                &row,
                raw
            ),
            (0, Some(UnsupportedLogsource)),
            "{dataset}"
        );
        if product == "gcp" {
            let mut value: Value = serde_json::from_str(raw.unwrap()).unwrap();
            value["protoPayload"]
                .as_object_mut()
                .unwrap()
                .remove("status");
            let raw = value.to_string();
            assert_eq!(
                evaluate(
                    variant,
                    &condition,
                    "{'protoPayload.status.code|exists': false}",
                    &row,
                    Some(&raw)
                ),
                (1, None)
            );
            assert_eq!(
                evaluate(
                    variant,
                    &condition,
                    "{protoPayload.status.code: 0}",
                    &row,
                    Some(&raw)
                ),
                (0, None)
            );
        }
    }
}

#[test]
fn sigma_kubernetes_requires_the_exact_resource_and_does_not_scalarize_source_ips() {
    let reviewed = parse_table(include_str!("../cloud-identity-v1.toml"));
    let taxonomy = "{product: kubernetes, service: audit}";
    for variant in reviewed
        .variants
        .iter()
        .filter(|variant| variant.product.as_deref() == Some("kubernetes"))
    {
        let header = EventHeaderV1::new(
            CategorySet::new([EventCategory::Api]),
            EventTypeSet::default(),
            EventOutcome::Success,
            EventKind::Event,
        )
        .with_action("get")
        .unwrap();
        let row = synthetic_row(
            variant,
            header,
            [
                (
                    CommonField::OrchestratorResourceType,
                    CommonValue::Text(EventText::new("secrets").unwrap()),
                ),
                (
                    CommonField::OrchestratorNamespace,
                    CommonValue::Text(EventText::new("synthetic-ns").unwrap()),
                ),
            ],
        );
        assert_eq!(
            evaluate(
                variant,
                taxonomy,
                "{objectRef.resource: secrets, objectRef.namespace: synthetic-ns}",
                &row,
                None
            ),
            (1, None)
        );
        assert_eq!(
            evaluate(variant, taxonomy, "{objectRef.resource: pods}", &row, None),
            (0, None)
        );
        assert_eq!(
            evaluate(
                variant,
                taxonomy,
                "{'sourceIPs|cidr': 203.0.113.0/24}",
                &row,
                None
            ),
            (0, Some(SigmaCoverageV1::UnsupportedField))
        );
        assert_eq!(
            evaluate(
                variant,
                "{product: kubernetes, service: unreviewed}",
                "{objectRef.resource: secrets}",
                &row,
                None
            ),
            (0, Some(SigmaCoverageV1::UnsupportedLogsource))
        );
    }
}
