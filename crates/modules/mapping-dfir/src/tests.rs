use super::*;
use irmind_app::{
    CancellationToken, LogParser, SourceDecoder,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1},
};
use irmind_domain::EventOutcome;
struct Fixture {
    parser: &'static str,
    name: &'static str,
    bytes: &'static [u8],
    decoder: Arc<dyn SourceDecoder>,
    legacy: Arc<dyn LogParser>,
}
fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            parser: "parser-velociraptor",
            name: "events.jsonl",
            bytes: include_bytes!(
                "../../../testkit/fixtures/parser-velociraptor/source/events.jsonl"
            ),
            decoder: Arc::new(irmind_mod_parser_velociraptor::VelociraptorSourceDecoder),
            legacy: Arc::new(irmind_mod_parser_velociraptor::VelociraptorParser),
        },
        Fixture {
            parser: "parser-hayabusa",
            name: "events.jsonl",
            bytes: include_bytes!("../../../testkit/fixtures/parser-hayabusa/source/events.jsonl"),
            decoder: Arc::new(irmind_mod_parser_hayabusa::HayabusaSourceDecoder),
            legacy: Arc::new(irmind_mod_parser_hayabusa::HayabusaParser),
        },
        Fixture {
            parser: "parser-chainsaw",
            name: "events.jsonl",
            bytes: include_bytes!("../../../testkit/fixtures/parser-chainsaw/source/events.jsonl"),
            decoder: Arc::new(irmind_mod_parser_chainsaw::ChainsawSourceDecoder),
            legacy: Arc::new(irmind_mod_parser_chainsaw::ChainsawParser),
        },
        Fixture {
            parser: "parser-plaso",
            name: "events.jsonl",
            bytes: include_bytes!("../../../testkit/fixtures/parser-plaso/source/events.jsonl"),
            decoder: Arc::new(irmind_mod_parser_plaso::PlasoSourceDecoder),
            legacy: Arc::new(irmind_mod_parser_plaso::PlasoParser),
        },
        Fixture {
            parser: "parser-eztools",
            name: "events.csv",
            bytes: include_bytes!("../../../testkit/fixtures/parser-eztools/source/events.csv"),
            decoder: Arc::new(irmind_mod_parser_eztools::EztoolsSourceDecoder),
            legacy: Arc::new(irmind_mod_parser_eztools::EztoolsParser),
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
            Arc::new(DfirExtractionMapping::new(f.parser).unwrap()),
            f.name,
            f.bytes,
            2,
        )
        .unwrap();
    }
}
#[test]
fn original_aliases_events_time_and_relations_survive_without_classifying() {
    for f in fixtures() {
        let mut legacy = Vec::new();
        f.legacy
            .parse_indexed_reader_report(
                f.name,
                &mut std::io::Cursor::new(f.bytes),
                irmind_app::sha256(f.bytes),
                &CancellationToken::new(),
                &mut |row| {
                    row.inspect(|r| legacy.push(r.clone()));
                    Ok(())
                },
            )
            .unwrap();
        let (report, sources) = decoded(&f, f.bytes);
        assert_eq!((report.accepted, report.rejected), (2, 0));
        let mapper = DfirExtractionMapping::new(f.parser).unwrap();
        for (source, old) in sources.iter().zip(legacy) {
            let out = mapper.map(source).unwrap();
            let graph = &out.record().indexed;
            assert_eq!(graph.record.entities, old.record.entities, "{}", f.parser);
            assert_eq!(graph.record.event, old.record.event, "{}", f.parser);
            assert_eq!(graph.record.relations, old.record.relations, "{}", f.parser);
            assert_eq!(graph.time, old.time, "{}", f.parser);
            assert_eq!(out.record().common.event().categories().bits(), 0);
            assert_eq!(out.record().common.event().outcome(), EventOutcome::Unknown);
            assert!(out.record().common.observations().values().is_empty());
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
fn original_custom_fields_and_numeric_types_do_not_come_from_normalized_text() {
    let f = fixtures().remove(0);
    let raw = std::str::from_utf8(f.bytes)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let bytes = raw.replacen(
        '{',
        "{\"original_only\":{\"n\":1.2300,\"events\":[1,2]},",
        1,
    );
    let (_, rows) = decoded(&f, bytes.as_bytes());
    let fields = rows[0].fields().field("original_only").unwrap();
    assert!(
        matches!(fields.field("n"),Some(irmind_domain::SourceValue::Number(n)) if n.as_str()=="1.2300")
    );
    assert!(fields.field("events").is_some());
    assert!(rows[0].fields().field("attributes").is_none());
}
