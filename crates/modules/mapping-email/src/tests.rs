use super::*;
#[test]
fn email_mapping_contract_preserves_roles_and_unknown_outcome() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-email/source/multipart.eml");
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_email::EmailSourceDecoder),
        Arc::new(EmailMapping::new().unwrap()),
        "synthetic.eml",
        bytes,
        9,
    )
    .unwrap();
}

#[test]
fn claimed_sender_recipient_and_ip_have_roles_without_authentication_inference() {
    use irmind_app::{
        CancellationToken, SourceDecoder,
        source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
    };
    use irmind_domain::{EntityIdentityScope, EntityRole, EventOutcome};
    let bytes = include_bytes!("../../../testkit/fixtures/parser-email/source/multipart.eml");
    let source = SourceReferenceV1::file("synthetic.eml").unwrap();
    let cancel = CancellationToken::new();
    let mapper = EmailMapping::new().unwrap();
    let mut outputs = Vec::new();
    irmind_mod_parser_email::EmailSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_slice(),
            },
            &mut |r| {
                r.inspect(|source| outputs.push(mapper.map(source).unwrap()));
                Ok(())
            },
        )
        .unwrap();
    let root = &outputs[0].record().common;
    for (role, value) in [
        (EntityRole::Actor, "sender@example.invalid"),
        (EntityRole::Target, "analyst@example.invalid"),
        (EntityRole::Source, "203.0.113.77"),
    ] {
        assert!(
            root.observations()
                .values()
                .iter()
                .any(|o| o.role() == role && o.entity().value() == value)
        );
    }
    assert!(
        outputs
            .iter()
            .all(|o| o.record().common.event().outcome() == EventOutcome::Unknown)
    );
    assert!(
        outputs
            .iter()
            .flat_map(|o| o.record().common.observations().values())
            .all(|o| !matches!(
                o.entity().scope(),
                EntityIdentityScope::ProcessLifetime { .. }
            ))
    );
    assert!(outputs.iter().any(|o| {
        o.record()
            .indexed
            .record
            .entities
            .iter()
            .any(|(k, v)| k == "url" && v.contains("portal.example.invalid"))
    }));
}
