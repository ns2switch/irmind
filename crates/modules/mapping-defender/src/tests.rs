use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
fn mapped(bytes: &[u8]) -> Vec<MappingOutput> {
    let source = SourceReferenceV1::file("synthetic.data").unwrap();
    let cancel = CancellationToken::new();
    let mapper = DefenderMapping::new().unwrap();
    let mut output = Vec::new();
    irmind_mod_parser_defender::DefenderSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |record| {
                record.inspect(|r| output.push(mapper.map(r).unwrap()));
                Ok(())
            },
        )
        .unwrap();
    output
}
#[test]
fn finite_tables_and_mapping_contract_cover_json_csv_and_streaming() {
    for (name, bytes) in [
        (
            "events.ndjson",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/events.ndjson")
                .as_slice(),
        ),
        (
            "api.json",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/api.json").as_slice(),
        ),
        (
            "stream.json",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/stream.json")
                .as_slice(),
        ),
        (
            "hunting.csv",
            include_bytes!("../../../testkit/fixtures/parser-defender/source/hunting.csv")
                .as_slice(),
        ),
    ] {
        irmind_testkit::run_source_mapping_contract(
            Arc::new(irmind_mod_parser_defender::DefenderSourceDecoder),
            Arc::new(DefenderMapping::new().unwrap()),
            name,
            bytes,
            9,
        )
        .unwrap();
        let output = mapped(bytes);
        assert!(output.iter().all(|o| o.diagnostics().is_empty()));
        assert_eq!(
            output[4].record().common.event().outcome(),
            irmind_domain::EventOutcome::Failure
        );
        assert_eq!(
            output[7].record().common.event().kind(),
            irmind_domain::EventKind::Alert
        );
        assert_eq!(
            output[8].record().common.event().kind(),
            irmind_domain::EventKind::Alert
        );
        assert!(
            output
                .iter()
                .flat_map(|r| r.record().common.observations().values())
                .all(|o| !matches!(
                    o.entity().scope(),
                    irmind_domain::EntityIdentityScope::ProcessLifetime { .. }
                ))
        );
    }
}
#[test]
fn actor_target_and_pid_roles_are_record_scoped_without_lifetime_inference() {
    let output = mapped(include_bytes!(
        "../../../testkit/fixtures/parser-defender/source/events.ndjson"
    ));
    let observations = output[0].record().common.observations().values();
    for (value, role) in [
        ("actor", irmind_domain::EntityRole::Actor),
        ("target", irmind_domain::EntityRole::Target),
        ("200", irmind_domain::EntityRole::Subject),
        ("100", irmind_domain::EntityRole::Parent),
    ] {
        assert!(
            observations
                .iter()
                .any(|o| o.entity().value() == value && o.role() == role)
        );
    }
    assert_eq!(output[0].partition().host(), "synthetic-device-a");
}
