use super::*;
use irmind_app::CancellationToken;
use irmind_domain::{CommonField, EntityIdentityScope, EntityRole, EventOutcome};
use std::sync::Arc;
const FIXTURE: &[u8] = include_bytes!("../../../testkit/fixtures/parser-fdr/source/events.ndjson");
fn mapped(bytes: &[u8]) -> Vec<MappingOutput> {
    let mapper = FdrMapping::new().unwrap();
    let mut output = Vec::new();
    irmind_testkit::decode_source(
        &irmind_mod_parser_fdr::FdrSourceDecoder,
        "synthetic.ndjson",
        &mut std::io::Cursor::new(bytes),
        irmind_app::sha256(bytes),
        &CancellationToken::new(),
        None,
        &mut |r| {
            r.inspect(|s| output.push(mapper.map(s).unwrap()));
            Ok(())
        },
    )
    .unwrap();
    output
}
#[test]
fn mapping_contract_and_finite_categories_preserve_unknown_originals() {
    let mapper = FdrMapping::new().unwrap();
    irmind_testkit::run_source_mapping_contract(
        Arc::new(irmind_mod_parser_fdr::FdrSourceDecoder),
        Arc::new(mapper),
        "synthetic.ndjson",
        FIXTURE,
        11,
    )
    .unwrap();
    let output = mapped(FIXTURE);
    assert!(
        output[..10].iter().all(|o| o.diagnostics().is_empty()),
        "{:?}",
        output
            .iter()
            .map(MappingOutput::diagnostics)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        output[6].record().common.event().outcome(),
        EventOutcome::Success
    );
    assert_eq!(
        output[7].record().common.event().outcome(),
        EventOutcome::Failure
    );
    assert!(
        output[10]
            .record()
            .common
            .event()
            .categories()
            .iter()
            .next()
            .is_none()
    );
    assert!(
        output[10]
            .record()
            .indexed
            .record
            .text
            .contains("FutureUnknownEvent")
    );
}
#[test]
fn provider_ids_correlate_inside_tenant_and_host_but_pids_remain_record_scoped() {
    let output = mapped(FIXTURE);
    let process = |index: usize, field| {
        output[index]
            .record()
            .common
            .observations()
            .values()
            .iter()
            .find(|o| o.field() == field)
            .unwrap()
            .entity()
    };
    assert_eq!(
        process(0, CommonField::ProcessEntityId),
        process(2, CommonField::ProcessEntityId)
    );
    assert_ne!(
        process(0, CommonField::ProcessPid),
        process(1, CommonField::ProcessPid)
    );
    assert!(matches!(
        process(0, CommonField::ProcessPid).scope(),
        EntityIdentityScope::SourceRecord { .. }
    ));
    assert!(
        output
            .iter()
            .flat_map(|o| o.record().common.observations().values())
            .all(|o| !matches!(
                o.entity().scope(),
                EntityIdentityScope::ProcessLifetime { .. }
            ))
    );
    let text = std::str::from_utf8(FIXTURE).unwrap();
    let other = mapped(
        text.replace(
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
        )
        .as_bytes(),
    );
    let entity = other[0]
        .record()
        .common
        .observations()
        .values()
        .iter()
        .find(|o| o.field() == CommonField::ProcessEntityId)
        .unwrap()
        .entity();
    assert_ne!(process(0, CommonField::ProcessEntityId), entity);
    assert_eq!(
        output[0].partition().host(),
        "00000000000000000000000000000100"
    );
}
#[test]
fn identical_ip_values_keep_source_and_destination_roles_and_invalid_ids_have_no_fallback() {
    let row = std::str::from_utf8(FIXTURE)
        .unwrap()
        .lines()
        .nth(2)
        .unwrap();
    let output = mapped(row.replace("192.0.2.10", "203.0.113.77").as_bytes());
    let obs = output[0].record().common.observations().values();
    for role in [EntityRole::Source, EntityRole::Destination] {
        assert!(
            obs.iter()
                .any(|o| o.entity().value() == "203.0.113.77" && o.role() == role)
        );
    }
    for bad in ["0", "-1", "18446744073709551616", "1e3"] {
        let output = mapped(row.replace("4294967338", bad).as_bytes());
        assert!(!output[0].diagnostics().is_empty());
        assert!(output[0].record().common.observations().values().is_empty());
        assert_eq!(
            output[0].partition().host(),
            "00000000000000000000000000000100"
        );
    }
}
