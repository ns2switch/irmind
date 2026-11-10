use super::*;
use irmind_app::{
    CancellationToken, DefinitionCompiler,
    source_mapping::{SourceInput, SourceMetadata, SourceReferenceV1, SourceValue},
};
use std::io::Cursor;
const CASES: [(&str, &[u8]); 3] = [
    (
        include_str!("../../../../../docs/examples/parsers/access-csv.toml"),
        include_bytes!("../../../../testkit/fixtures/parser-declarative/source/access.csv"),
    ),
    (
        include_str!("../../../../../docs/examples/parsers/nested-ndjson.toml"),
        include_bytes!("../../../../testkit/fixtures/parser-declarative/source/events.ndjson"),
    ),
    (
        include_str!("../../../../../docs/examples/parsers/auth-regex.toml"),
        include_bytes!("../../../../testkit/fixtures/parser-declarative/source/auth.log"),
    ),
];
fn decode(
    pipeline: &CompiledDefinition,
    bytes: &[u8],
) -> (
    irmind_app::ParseReport,
    Vec<irmind_app::source_mapping::SourceRecordV1>,
) {
    let cancel = CancellationToken::new();
    let source = SourceReferenceV1::file("synthetic.log").unwrap();
    let mut rows = Vec::new();
    let report = pipeline
        .decoder()
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cancel: &cancel,
                },
                reader: &mut Cursor::new(bytes),
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
fn all_formats_preserve_extraction_with_independent_original_source_fields() {
    for (definition, bytes) in CASES {
        let pipeline = crate::DeclarativeCompiler.compile(definition).unwrap();
        let (report, rows) = decode(&pipeline, bytes);
        let mut historical = Vec::new();
        let old = crate::DeclarativeParser::from_toml(definition)
            .unwrap()
            .parse_source(
                "synthetic.log",
                &mut Cursor::new(bytes),
                irmind_app::sha256(bytes),
                &CancellationToken::new(),
                &mut |row| {
                    row.inspect(|r| historical.push(r.clone()));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            (report.accepted, report.rejected),
            (old.accepted, old.rejected)
        );
        assert!(!rows.is_empty());
        for (source, expected) in rows.iter().zip(historical) {
            let output = pipeline.extraction_mapper().map(source).unwrap();
            assert_eq!(output.record().indexed.record, expected);
            assert_eq!(output.record().common.event().categories().bits(), 0);
            assert_eq!(
                source.origin().parser(),
                pipeline.selector().identity().name
            );
            assert!(source.origin().offset().is_some());
            assert_eq!(source.source(), "synthetic.log");
            assert!(source.fields().field("original").is_none());
        }
        irmind_testkit::run_source_mapping_contract(
            pipeline.decoder().clone(),
            pipeline.extraction_mapper().clone(),
            "synthetic.log",
            bytes,
            report.accepted,
        )
        .unwrap();
    }
}
#[test]
fn json_keeps_types_unmapped_fields_and_all_regex_captures() {
    let definition = CASES[1].0;
    let bytes = br#"{"custom_event":{"time":"2026-11-01T00:00:00.123456789Z","host":"test","action":"login","counter":42,"ok":true},"unmapped":[false,null]}"#;
    let pipeline = compile(definition).unwrap();
    let (_, rows) = decode(&pipeline, bytes);
    assert_eq!(rows.len(), 1);
    let fields = rows[0].fields().field("custom_event").unwrap();
    assert!(matches!(
        fields.field("counter"),
        Some(SourceValue::Number(_))
    ));
    assert!(matches!(
        fields.field("ok"),
        Some(SourceValue::Boolean(true))
    ));
    assert!(matches!(
        rows[0].fields().field("unmapped"),
        Some(SourceValue::Array(_))
    ));
}
#[test]
fn compiler_rejects_definition_or_decoder_mismatch_before_registration() {
    let first = compile(CASES[0].0).unwrap();
    let other = compile(CASES[1].0).unwrap();
    assert!(
        CompiledDefinition::try_new(
            first.selector().clone(),
            other.decoder().clone(),
            first.extraction_mapper().clone(),
            CASES[0].0
        )
        .is_err()
    );
    assert!(
        CompiledDefinition::try_new(
            first.selector().clone(),
            first.decoder().clone(),
            other.extraction_mapper().clone(),
            CASES[0].0
        )
        .is_err()
    );
    assert!(
        CompiledDefinition::try_new(
            first.selector().clone(),
            first.decoder().clone(),
            first.extraction_mapper().clone(),
            &(CASES[0].0.to_owned() + "\n")
        )
        .is_err()
    );
}
#[test]
fn bad_records_are_bounded_and_callbacks_and_cancellation_propagate() {
    let definition = CASES[1].0;
    let pipeline = compile(definition).unwrap();
    let mut bytes = b"not json\n".to_vec();
    bytes.extend_from_slice(CASES[1].1);
    let (report, rows) = decode(&pipeline, &bytes);
    assert_eq!(report.rejected, 1);
    assert!(!rows.is_empty());
    let cancel = CancellationToken::new();
    let source = SourceReferenceV1::file("synthetic.log").unwrap();
    let input = || SourceMetadata {
        source: &source,
        evidence_hash: [8; 32],
        time_context: None,
        cancel: &cancel,
    };
    assert!(matches!(
        pipeline.decoder().decode_reader(
            SourceInput {
                metadata: input(),
                reader: &mut Cursor::new(CASES[1].1)
            },
            &mut |_| Err(AppError::Cancelled)
        ),
        Err(AppError::Cancelled)
    ));
    cancel.cancel();
    let mut emitted = false;
    assert!(matches!(
        pipeline.decoder().decode_reader(
            SourceInput {
                metadata: input(),
                reader: &mut Cursor::new(CASES[1].1)
            },
            &mut |_| {
                emitted = true;
                Ok(())
            }
        ),
        Err(AppError::Cancelled)
    ));
    assert!(!emitted);
}

#[test]
fn extraction_descriptor_has_a_fixed_golden_digest() {
    let hash = "00".repeat(32);
    let build = b"irmind-native-mapping-build-v1\0synthetic";
    let descriptor = irmind_app::definition_mapping_descriptor(&hash, build).unwrap();
    assert_eq!(
        irmind_app::hex(&irmind_app::sha256(&descriptor)),
        "f814f4693f4113ed0aea47871fc0fd5b4c3493de399f4190aff6fbc600f36d02"
    );
    let pipeline = compile(CASES[0].0).unwrap();
    let expected = irmind_app::definition_mapping_descriptor(
        pipeline.definition_hash(),
        include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin")),
    )
    .unwrap();
    assert!(
        matches!(pipeline.extraction_mapper().manifest().provenance(), irmind_app::source_mapping::MappingProvenance::NativeBuild { manifest } if *manifest == expected)
    );
    assert!(irmind_app::definition_mapping_descriptor(&hash, b"unknown-build").is_err());
}
