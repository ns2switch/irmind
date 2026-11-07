use super::*;

#[test]
fn typed_common_payload_and_new_envelopes_are_feature_independent() {
    let wire = include_str!("../../../app/src/common_event/goldens/network-v1.json").trim();
    let event = irmind_app::decode_common_event(wire).unwrap();
    assert_eq!(irmind_app::encode_common_event(&event).unwrap(), wire);
    for wire in [
        include_str!("../../../domain/tests/fixtures/common-artifact-events-v2.hex"),
        include_str!("../../../domain/tests/fixtures/common-artifact-entities-v2.hex"),
        include_str!("../../../domain/tests/fixtures/common-artifact-coobservations-v2.hex"),
    ] {
        assert_eq!(
            irmind_domain::ParquetArtifactV2::decode(wire.trim())
                .unwrap()
                .encode()
                .unwrap(),
            wire.trim()
        );
    }
}

#[test]
fn every_existing_parser_keeps_a_valid_unclassified_bridge() {
    for (_, parser, fixture) in parsers() {
        let count = normalized_rows(
            parser.as_ref(),
            "fixture.json",
            fixture,
            &CancellationToken::new(),
        )
        .len();
        irmind_testkit::run_common_event_contract(parser.as_ref(), "fixture.json", fixture, count)
            .unwrap();
    }
}
