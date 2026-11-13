use super::*;
use irmind_app::{
    DefinitionCompiler, SourceDecoder,
    source_mapping::{DecodeBudget, DecodeInput, SourceInput, SourceMetadata, SourceReferenceV1},
};
use std::num::NonZeroUsize;

#[test]
fn native_source_bytes_and_provenance_are_independent_of_worker_count() {
    let available = std::thread::available_parallelism().unwrap().get();
    for (name, decoder, bytes) in fixtures() {
        let mut expected = None;
        for workers in [1, 2, 4, available] {
            let actual = decode_digest(decoder.as_ref(), bytes, workers);
            assert!(actual.accepted > 0, "{name}");
            if let Some(expected) = &expected {
                assert_eq!(&actual, expected, "{name}: {workers} workers");
            } else {
                expected = Some(actual);
            }
        }
    }
}

#[test]
fn parallel_csv_windows_preserve_multiline_record_boundaries_and_byte_offsets() {
    let mut bytes = b"RunTime,ExecutableName,SourceFilename,PathValidated\r\n".to_vec();
    let mut expected = Vec::new();
    for ordinal in 0..1025 {
        expected.push((ordinal, Some(bytes.len() as u64)));
        bytes.extend_from_slice(
            format!("2026-10-23T12:04:00Z,cmd.exe,\"C:/Synthetic/{ordinal}\nfile.pf\",true\r\n")
                .as_bytes(),
        );
    }
    let mut digest = None;
    let available = std::thread::available_parallelism().unwrap().get();
    for workers in [1, 2, 4, available] {
        let actual = decode_digest(
            &irmind_mod_parser_eztools::EztoolsSourceDecoder,
            &bytes,
            workers,
        );
        assert_eq!(actual.accepted, 1025);
        assert_eq!(actual.positions, expected);
        assert_eq!(*digest.get_or_insert(actual.hash), actual.hash);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DecodedDigest {
    accepted: usize,
    hash: [u8; 32],
    positions: Vec<(u64, Option<u64>)>,
}

fn decode_digest(decoder: &dyn SourceDecoder, bytes: &[u8], workers: usize) -> DecodedDigest {
    let source = SourceReferenceV1::file("synthetic.log").unwrap();
    let cancel = CancellationToken::new();
    let hash = sha256(bytes);
    let mut canonical = Vec::new();
    let mut positions = Vec::new();
    let report = decoder
        .decode_with_budget(
            DecodeInput::Reader(SourceInput {
                metadata: SourceMetadata {
                    source: &source,
                    evidence_hash: hash,
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            }),
            DecodeBudget::new(NonZeroUsize::new(workers).unwrap(), 8 * 1024 * 1024),
            &mut |row| {
                assert_eq!(row.provenance().evidence_hash(), &hash);
                row.inspect(|record| {
                    positions.push((record.origin().record(), record.origin().offset()));
                    let mut encoded = Vec::new();
                    record.feed_canonical(&mut |bytes| encoded.extend_from_slice(bytes));
                    canonical.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
                    canonical.extend_from_slice(&encoded);
                });
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.rejected, 0, "{}", decoder.identity().name);
    DecodedDigest {
        accepted: report.accepted,
        hash: sha256(&canonical),
        positions,
    }
}

fn fixtures() -> Vec<(&'static str, Arc<dyn SourceDecoder>, &'static [u8])> {
    let mut fixtures = super::dfir_source_goldens::fixtures();
    fixtures.extend([
        (
            "json",
            Arc::new(irmind_mod_parser_json::JsonSourceDecoder) as Arc<dyn SourceDecoder>,
            include_bytes!("../../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json")
                as &'static [u8],
        ),
        (
            "ecs",
            Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-ecs/source/events.ndjson"),
        ),
        (
            "ocsf",
            Arc::new(irmind_mod_parser_ocsf::OcsfSourceDecoder),
            include_bytes!("../../../testkit/fixtures/parser-ocsf/source/events.ndjson"),
        ),
        (
            "declarative",
            irmind_mod_parser_declarative::DeclarativeCompiler
                .compile(include_str!(
                    "../../../../docs/examples/parsers/nested-ndjson.toml"
                ))
                .unwrap()
                .decoder()
                .clone(),
            include_bytes!("../../../testkit/fixtures/parser-declarative/source/events.ndjson"),
        ),
    ]);
    #[cfg(feature = "parser-linux")]
    fixtures.push((
        "journald",
        Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder),
        include_bytes!("../../../testkit/fixtures/parser-linux/source/journal.jsonl"),
    ));
    #[cfg(feature = "parser-syslog")]
    fixtures.push((
        "syslog",
        Arc::new(irmind_mod_parser_syslog::SyslogSourceDecoder),
        b"<34>1 2026-11-01T00:02:03.123456700Z lab app 42 X - synthetic\n",
    ));
    #[cfg(feature = "parser-zeek")]
    fixtures.push((
        "zeek",
        Arc::new(irmind_mod_parser_zeek::ZeekSourceDecoder),
        include_bytes!("../../../testkit/fixtures/parser-zeek/source/dns.jsonl"),
    ));
    #[cfg(feature = "parser-suricata")]
    fixtures.push((
        "suricata",
        Arc::new(irmind_mod_parser_suricata::SuricataSourceDecoder),
        include_bytes!("../../../testkit/fixtures/parser-suricata/source/eve.jsonl"),
    ));
    fixtures
}
