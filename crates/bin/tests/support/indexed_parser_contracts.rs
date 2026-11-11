use super::*;
use irmind_app::IndexedTime;
use irmind_domain::TimePrecision;

fn indexed(parser: &dyn SourceDecoder, mut bytes: &[u8]) -> Vec<irmind_domain::SourceRecordV1> {
    let mut output = Vec::new();
    let digest = sha256(bytes);
    let report = irmind_testkit::decode_source(
        parser,
        "synthetic",
        &mut bytes,
        digest,
        &CancellationToken::new(),
        None,
        &mut |row| {
            assert_eq!(row.provenance().evidence_hash(), &digest);
            row.inspect(|record| output.push(record.clone()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        report.rejected,
        0,
        "{}: {:?}",
        parser.identity().name,
        report.samples
    );
    assert!(!output.is_empty());
    output
}
#[test]
fn native_precision_preserves_zero_fraction_digits_instead_of_guessing() {
    for (name, parser, bytes) in decoders() {
        if !matches!(
            name,
            "json" | "ecs" | "ocsf" | "velociraptor" | "chainsaw" | "plaso"
        ) {
            continue;
        }
        let raw = std::str::from_utf8(bytes).unwrap();
        let changed = raw
            .replace("2026-10-23T12:00:00Z", "2026-10-23T12:00:00.000000100Z")
            .replace("2026-01-02T03:04:05Z", "2026-01-02T03:04:05.000000Z")
            .replace("2026-10-23T12:01:00Z", "2026-10-23T12:01:00.000000Z");
        let rows = indexed(parser.as_ref(), changed.as_bytes());
        let time = rows[0].timestamp().unwrap();
        match name {
            "ocsf" => assert_eq!(time.precision(), TimePrecision::Millisecond),
            "plaso" | "ecs" | "chainsaw" => {
                assert_eq!(time.precision(), TimePrecision::Microsecond);
            }
            "velociraptor" => {
                assert_eq!(time.precision(), TimePrecision::Nanosecond);
                assert_eq!(time.instant().submicro_nanos(), 100);
            }
            _ => {}
        }
    }
}
#[cfg(all(feature = "parser-linux", feature = "parser-syslog"))]
#[test]
fn linux_and_syslog_recover_precision_from_original_records() {
    let linux = irmind_mod_parser_linux::LinuxSourceDecoder;
    let journal = indexed(
        &linux,
        include_bytes!("../../../testkit/fixtures/parser-linux/source/journal.jsonl"),
    );
    assert_eq!(
        journal[0].timestamp().unwrap().instant().unix_micros(),
        1_793_494_800_123_456
    );
    assert_eq!(
        journal[0].timestamp().unwrap().precision(),
        TimePrecision::Microsecond
    );
    let audit = indexed(
        &linux,
        include_bytes!("../../../testkit/fixtures/parser-linux/source/audit.log"),
    );
    assert_eq!(
        audit[0].timestamp().unwrap().instant().unix_micros(),
        1_793_494_800_123_456
    );
    let syslog = irmind_mod_parser_syslog::SyslogSourceDecoder;
    let rows = indexed(
        &syslog,
        b"<34>1 2026-11-01T00:02:03.123456700Z lab app 42 X - synthetic\n",
    );
    let time = rows[0].timestamp().unwrap();
    assert_eq!(
        time,
        IndexedTime::from_rfc3339("2026-11-01T00:02:03.123456700Z", false).unwrap()
    );
}

#[test]
fn all_decoder_canonical_bytes_are_independent_of_worker_count() {
    use irmind_app::source_mapping::{
        DecodeBudget, DecodeInput, SourceInput, SourceMetadata, SourceReferenceV1,
    };
    use std::num::NonZeroUsize;
    let available = std::thread::available_parallelism().unwrap().get();
    for (name, decoder, bytes) in decoders() {
        let source = SourceReferenceV1::file("synthetic.log").unwrap();
        let cancel = CancellationToken::new();
        let mut expected = None;
        for workers in [1, 2, 4, available] {
            let mut canonical = Vec::new();
            let report = decoder
                .decode_with_budget(
                    DecodeInput::Reader(SourceInput {
                        metadata: SourceMetadata {
                            source: &source,
                            evidence_hash: sha256(bytes),
                            time_context: None,
                            cancel: &cancel,
                        },
                        reader: &mut std::io::Cursor::new(bytes),
                    }),
                    DecodeBudget::new(NonZeroUsize::new(workers).unwrap(), 8 * 1024 * 1024),
                    &mut |row| {
                        row.inspect(|record| {
                            let mut encoded = Vec::new();
                            record.feed_canonical(&mut |bytes| encoded.extend_from_slice(bytes));
                            canonical.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
                            canonical.extend_from_slice(&encoded);
                        });
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(report.rejected, 0, "{name}");
            let digest = (report.accepted, sha256(&canonical));
            if let Some(expected) = &expected {
                assert_eq!(&digest, expected, "{name}: {workers} workers");
            } else {
                expected = Some(digest);
            }
        }
    }
}
