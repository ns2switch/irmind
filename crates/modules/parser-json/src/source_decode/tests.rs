use super::*;
use irmind_app::{CancellationToken, source_mapping::SourceMetadata};

fn decode(bytes: &[u8]) -> (ParseReport, Vec<Tainted<SourceRecordV1>>) {
    let cancel = CancellationToken::new();
    let mut output = Vec::new();
    let report = JsonSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &irmind_domain::SourceReferenceV1::file("synthetic.json").unwrap(),
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |record| {
                output.push(record);
                Ok(())
            },
        )
        .unwrap();
    (report, output)
}

#[test]
fn source_decoder_preserves_fields_without_normalization_or_entity_interpretation() {
    let input = br#"{"result":{"_raw":"synthetic original string"},"source.ip":"203.0.113.1","source":{"ip":"203.0.113.2"},"count":9007199254740993,"eventTime":"2026-11-08T00:00:00.123456789Z"}"#;
    let (report, decoded) = decode(input);
    assert_eq!((report.accepted, report.rejected), (1, 0));
    decoded[0].inspect(|record| {
        assert_eq!(
            record
                .fields()
                .field("result")
                .unwrap()
                .field("_raw")
                .unwrap()
                .as_text(),
            Some("synthetic original string")
        );
        assert_eq!(record.timestamp().unwrap().instant().submicro_nanos(), 789);
        assert_eq!(record.origin().offset(), Some(0));
        assert!(record.fields().field("event.outcome").is_none());
        let SourceValue::Number(number) = record.fields().field("count").unwrap() else {
            return;
        };
        assert_eq!(number.as_str(), "9007199254740993");
    });
}

#[test]
fn gzip_members_preserve_cloudtrail_records_and_the_compressed_original_hash() {
    use irmind_app::LogParser as _;
    use std::io::Write as _;

    let parts: [&[u8]; 3] = [
        br#"{"Records":[{"eventVersion":"1.08","eventTime":"2026-11-08T00:"#,
        br#"00:00Z","eventName":"ConsoleLogin"},"#,
        br#"{"eventVersion":"1.08","eventTime":"2026-11-08T00:00:01Z","eventName":"PutObject"}]}"#,
    ];
    let mut compressed = Vec::new();
    for part in parts {
        let mut gzip = flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::fast());
        gzip.write_all(part).unwrap();
        gzip.finish().unwrap();
    }
    let parser = crate::JsonParser;
    assert!(
        parser
            .detect("misleading.jsonl", &compressed)
            .unwrap()
            .is_high()
    );
    let (report, records) = decode(&compressed);
    let (plain_report, plain) = decode(&parts.concat());
    assert_eq!((report.accepted, report.rejected), (2, 0));
    assert_eq!(plain_report.accepted, report.accepted);
    for (index, (record, original)) in records.iter().zip(&plain).enumerate() {
        record.inspect(|record| {
            original.inspect(|original| {
                assert_eq!(record.fields(), original.fields());
                assert_eq!(record.timestamp(), original.timestamp());
                assert_eq!(record.origin().record(), index as u64);
                assert_eq!(record.origin().offset(), None);
                assert_eq!(
                    record.origin().source(),
                    &EvidenceHash::from_bytes(irmind_app::sha256(&compressed))
                );
                assert!(original.origin().offset().is_some());
            });
        });
    }
}

#[test]
fn source_decoder_streams_a_large_single_line_array_without_losing_its_prefix() {
    let row = format!(
        "{{\"eventTime\":\"2026-11-08T00:00:00Z\",\"original\":\"{}\"}}",
        "x".repeat(1000)
    );
    let input = format!(
        "{{\"metadata\":\"synthetic\",\"Records\":[{}],\"after\":true}}",
        vec![row; 6000].join(",")
    );
    assert!(input.len() > 4 * 1024 * 1024);
    let (report, records) = decode(input.as_bytes());
    assert_eq!((report.accepted, report.rejected), (6000, 0));
    for (index, record) in records.iter().enumerate() {
        record.inspect(|r| assert_eq!(r.origin().record(), index as u64));
    }
}

#[test]
fn duplicate_keys_are_rejected_and_following_records_remain_visible() {
    let (report, records) = decode(b"{\"x\":1,\"x\":2}\n{\"original\":\"kept\"}\n");
    assert_eq!((report.accepted, report.rejected, records.len()), (1, 1, 1));
    assert!(!report.samples.is_empty());
    let (_, records) = decode(b"{\"Records\":[]}\n{\"Records\":[]}\n{\"x\":true}");
    assert_eq!(records.len(), 1);
}

#[test]
fn source_decoder_propagates_cancellation_and_callback_failures() {
    let bytes = b"{\"original\":true}";
    for cancelled in [true, false] {
        let cancel = CancellationToken::new();
        if cancelled {
            cancel.cancel();
        }
        let result = JsonSourceDecoder.decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &irmind_domain::SourceReferenceV1::file("synthetic.json").unwrap(),
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |_| Err(AppError::Cancelled),
        );
        assert!(matches!(result, Err(AppError::Cancelled)));
    }
}

#[test]
fn source_container_metadata_is_validated_on_both_sides_of_the_record_array() {
    let (report, _) = decode(
        b"{\n \"metadata\": true,\n \"Records\": [{\"kept\":true}] \n,\n \"after\": [1,2]\n}",
    );
    assert_eq!(report.accepted, 1);
    for bytes in [
        br#"{"metadata":invalid,"Records":[{"kept":true}]}"#.as_slice(),
        br#"{"Records":[{"kept":true}],"metadata":{"duplicate":1,"duplicate":2}}"#,
    ] {
        let cancel = CancellationToken::new();
        let result = JsonSourceDecoder.decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &irmind_domain::SourceReferenceV1::file("synthetic.json").unwrap(),
                    evidence_hash: irmind_app::sha256(bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut std::io::Cursor::new(bytes),
            },
            &mut |_| Ok(()),
        );
        assert!(result.is_err());
    }
}

#[test]
fn logical_ndjson_rejects_an_oversized_line_and_retains_the_following_offset() {
    let row = b"{\"eventTime\":\"2026-11-08T00:00:00Z\",\"original\":true}";
    let mut bytes = row.to_vec();
    bytes.resize(5 * 1024 * 1024, b' ');
    bytes.extend_from_slice(row);
    bytes.push(b'\n');
    let offset = bytes.len() as u64;
    bytes.extend_from_slice(row);
    bytes.push(b'\n');
    let cancel = CancellationToken::new();
    let reference =
        irmind_domain::SourceReferenceV1::file("s3://synthetic/logs/events.ndjson").unwrap();
    let mut output = Vec::new();
    let report = JsonSourceDecoder
        .decode_reader(
            SourceInput {
                metadata: SourceMetadata {
                    source: &reference,
                    evidence_hash: irmind_app::sha256(&bytes),
                    time_context: None,
                    cluster_context: None,
                    cancel: &cancel,
                },
                reader: &mut bytes.as_slice(),
            },
            &mut |record| {
                output.push(record);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((report.accepted, report.rejected, output.len()), (1, 1, 1));
    assert_eq!(report.samples.len(), 1);
    assert!(report.samples[0].len() <= 256);
    output[0].inspect(|record| assert_eq!(record.origin().offset(), Some(offset)));
}

#[test]
fn logical_ndjson_keeps_canonical_records_and_rejections_at_every_worker_count() {
    let mut input = b"\nnot-json\r\n".to_vec();
    for index in 0..80 {
        input.extend_from_slice(
            format!("{{\"eventTime\":\"2026-11-08T00:00:00Z\",\"value\":{index}}}\r\n").as_bytes(),
        );
    }
    input.extend_from_slice(b"{\"eventTime\":\"invalid\"}\n[{\"value\":81},{\"value\":82}]\n");
    let cancel = CancellationToken::new();
    let source = irmind_domain::SourceReferenceV1::file("s3://synthetic/events.ndjson").unwrap();
    let mut expected = None;
    for workers in [1, 2, 4, 7] {
        let mut records = Vec::new();
        let report = JsonSourceDecoder
            .decode_with_budget(
                DecodeInput::Reader(SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: irmind_app::sha256(&input),
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut input.as_slice(),
                }),
                DecodeBudget::new(
                    std::num::NonZeroUsize::new(workers).unwrap(),
                    8 * 1024 * 1024,
                ),
                &mut |record| {
                    let mut bytes = Vec::<u8>::new();
                    record.inspect(|record| record.feed_canonical(&mut |part| bytes.extend(part)));
                    records.push(bytes);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (82, 2));
        let actual = (records, report.samples);
        if let Some(expected) = &expected {
            assert_eq!(&actual, expected);
        } else {
            expected = Some(actual);
        }
    }
}
