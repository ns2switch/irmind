use super::*;
use irmind_app::{
    CancellationToken, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::{CommonField, EntityRole, EventCategory, EventKind, EventOutcome};
struct Fixture {
    parser: &'static str,
    name: &'static str,
    bytes: &'static [u8],
    decoder: Arc<dyn SourceDecoder>,
}
fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            parser: "parser-zeek",
            name: "conn.log",
            bytes: include_bytes!("../../../testkit/fixtures/parser-zeek/source/events.log"),
            decoder: Arc::new(irmind_mod_parser_zeek::ZeekSourceDecoder),
        },
        Fixture {
            parser: "parser-suricata",
            name: "eve.jsonl",
            bytes: include_bytes!("../../../testkit/fixtures/parser-suricata/source/eve.jsonl"),
            decoder: Arc::new(irmind_mod_parser_suricata::SuricataSourceDecoder),
        },
    ]
}
fn decoded(fixture: &Fixture, bytes: &[u8]) -> (irmind_app::ParseReport, Vec<SourceRecordV1>) {
    let mut rows = Vec::new();
    let reference = SourceReferenceV1::file(fixture.name).unwrap();
    let cancel = CancellationToken::new();
    let report = fixture
        .decoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |row| {
                row.inspect(|r| rows.push(r.clone()));
                Ok(())
            },
        )
        .unwrap();
    (report, rows)
}
#[test]
fn every_decoder_and_extraction_module_passes_the_shared_contract() {
    for f in fixtures() {
        irmind_testkit::run_source_mapping_contract(
            f.decoder.clone(),
            Arc::new(NetworkMapping::new(f.parser).unwrap()),
            f.name,
            f.bytes,
            2,
        )
        .unwrap();
    }
}
#[test]
fn original_aliases_events_time_and_relations_survive_with_typed_network_roles() {
    for f in fixtures() {
        let (report, sources) = decoded(&f, f.bytes);
        assert_eq!((report.accepted, report.rejected), (2, 0));
        let mapper = NetworkMapping::new(f.parser).unwrap();
        for source in &sources {
            let out = mapper.map(source).unwrap();
            let graph = &out.record().indexed;
            assert!(!graph.record.entities.is_empty(), "{}", f.parser);
            assert!(!graph.record.event.is_empty(), "{}", f.parser);
            assert_eq!(graph.time, source.timestamp(), "{}", f.parser);
            assert_eq!(graph.source_offset, source.origin().offset());
            assert!(
                out.record()
                    .common
                    .event()
                    .categories()
                    .contains(EventCategory::Network)
            );
            assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
            assert!(
                out.record()
                    .common
                    .observations()
                    .values()
                    .iter()
                    .any(|o| o.role() == EntityRole::Source)
            );
            assert!(
                out.record()
                    .common
                    .observations()
                    .values()
                    .iter()
                    .any(|o| o.role() == EntityRole::Destination)
            );
            assert_eq!(
                source.origin().source(),
                &EvidenceHash::from_bytes(irmind_app::sha256(f.bytes))
            );
            assert!(source.origin().offset().is_some());
        }
    }
}
#[test]
fn bad_ndjson_rows_are_counted_without_losing_original_offsets() {
    for f in fixtures().into_iter().filter(|f| f.name.ends_with("jsonl")) {
        let bytes = [b"{broken}\n".as_slice(), f.bytes].concat();
        let (report, rows) = decoded(&f, &bytes);
        assert_eq!((report.accepted, report.rejected), (2, 1));
        assert_eq!(rows[0].origin().offset(), Some(9));
        assert_eq!(rows[0].annotations().members()[0].ordinal, 1);
    }
}
#[test]
fn zeek_json_preserves_decimal_microseconds_and_explicit_endpoint_roles() {
    let bytes = include_bytes!("../../../testkit/fixtures/parser-zeek/source/dns.jsonl");
    let f = Fixture {
        parser: "parser-zeek",
        name: "dns.jsonl",
        bytes,
        decoder: Arc::new(irmind_mod_parser_zeek::ZeekSourceDecoder),
    };
    let (report, rows) = decoded(&f, bytes);
    assert_eq!((report.accepted, report.rejected), (1, 0));
    assert_eq!(
        rows[0].timestamp().unwrap().instant().unix_micros(),
        1_790_000_000_123_458
    );
    assert!(
        matches!(rows[0].fields().field("ts"),Some(irmind_domain::SourceValue::Number(n)) if n.as_str()=="1790000000.123458")
    );
    let mapper = NetworkMapping::new("parser-zeek").unwrap();
    let out = mapper.map(&rows[0]).unwrap();
    assert_eq!(out.record().indexed.record.event, "zeek_dns");
    assert!(
        out.record()
            .indexed
            .record
            .entities
            .contains(&("domain".into(), "synthetic.example.test".into()))
    );
    assert!(
        out.record()
            .common
            .observations()
            .values()
            .iter()
            .any(|o| o.field() == CommonField::DnsQuestionName)
    );
}
#[test]
fn tsv_columns_and_declared_types_are_original_not_reconstructed_from_normalized_text() {
    let f = fixtures().remove(0);
    let (_, rows) = decoded(&f, f.bytes);
    assert_eq!(
        rows[0]
            .fields()
            .field("columns")
            .unwrap()
            .field("ts")
            .unwrap()
            .as_text(),
        Some("1790000000.123456")
    );
    assert_eq!(
        rows[0]
            .fields()
            .field("types")
            .unwrap()
            .field("ts")
            .unwrap()
            .as_text(),
        Some("time")
    );
    assert_eq!(
        rows[0].timestamp().unwrap().instant().unix_micros(),
        1_790_000_000_123_456
    );
    assert!(rows[1].origin().offset().unwrap() > rows[0].origin().offset().unwrap());
}

mod protocols;
