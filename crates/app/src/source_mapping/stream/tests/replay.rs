use super::*;
use irmind_domain::{ParserSelectionMode, SourceManifestV1, SourceManifestV2};

fn input_set(rows: &[Tainted<SourceRecordV1>]) -> irmind_domain::SourceRecordSetV1 {
    let reference = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut acc = accumulator(&reference, &cancel, &catalog);
    let mut spool = Cursor::new(Vec::new());
    for row in rows {
        acc.accept(row, &mut spool).unwrap();
    }
    let decoded = acc.finish(&mut spool, &report(rows.len())).unwrap();
    decoded
        .bind_manifest(&SourceManifestV2 {
            source: SourceManifestV1 {
                source: "logs/record.json".into(),
                size: 100,
                modified_unix_seconds: None,
                version: None,
                provider_checksum: None,
                sha256: EvidenceHash::from_bytes([7; 32]),
                copied: false,
            },
            parser_id: "parser-json".into(),
            parser_version: "json-source-v1".into(),
            confidence: 90,
            selection: ParserSelectionMode::Automatic,
            timestamp_context: None,
            cluster_context: None,
            rejected_records: 0,
            rejected_sample: vec![],
        })
        .unwrap()
}
fn metadata<'a>(
    reference: &'a SourceReferenceV1,
    cancel: &'a CancellationToken,
) -> SourceMetadata<'a> {
    SourceMetadata {
        source: reference,
        evidence_hash: [7; 32],
        time_context: None,
        cluster_context: None,
        cancel,
    }
}
#[test]
fn replay_matches_the_existing_signed_commitment_without_a_mapping_or_spool() {
    let rows = [record(0, 0), record(1, 20)];
    let set = input_set(&rows);
    assert_eq!(
        set.records_commitment().as_str(),
        "3b638075f7dbb44fb45bea6ecd6fe8ee0b0c21628eca1e9bd9f9e462baf12a4a"
    );
    let cancel = CancellationToken::new();
    let mut replay =
        SourceRecordReplay::new(&set, metadata(set.reference(), &cancel), 100, 1).unwrap();
    for row in &rows {
        replay.accept(row).unwrap();
    }
    assert_eq!(replay.finish(&report(2)).unwrap(), rows[1]);
}
#[test]
fn the_full_set_is_checked_even_when_the_requested_record_is_unchanged() {
    let rows = [record(0, 0), record(1, 20)];
    let set = input_set(&rows);
    let cancel = CancellationToken::new();
    for changed in 0..4 {
        let mut replay =
            SourceRecordReplay::new(&set, metadata(set.reference(), &cancel), 100, 0).unwrap();
        replay.accept(&rows[0]).unwrap();
        if changed != 0 {
            replay
                .accept(&record(1, if changed == 1 { 21 } else { 20 }))
                .unwrap();
        }
        let mut summary = report(if changed == 0 { 1 } else { 2 });
        if changed == 2 {
            summary.rejected = 1;
        }
        if changed == 3 {
            summary.accepted = 1;
        }
        assert!(replay.finish(&summary).is_err());
    }
}
#[test]
fn replay_rejects_duplicate_order_provenance_and_frozen_context_changes() {
    let rows = [record(0, 0), record(1, 20)];
    let set = input_set(&rows);
    let cancel = CancellationToken::new();
    let mut replay =
        SourceRecordReplay::new(&set, metadata(set.reference(), &cancel), 100, 1).unwrap();
    replay.accept(&rows[0]).unwrap();
    assert!(replay.accept(&rows[0]).is_err());
    assert!(replay.accept(&rows[1]).is_err());
    assert!(replay.finish(&report(2)).is_err());
    let mut wrong = metadata(set.reference(), &cancel);
    wrong.evidence_hash = [8; 32];
    assert!(SourceRecordReplay::new(&set, wrong, 100, 0).is_err());
    let time =
        crate::ParserTimeContext::new(2026, 0, true, crate::ParserTimeBasis::Analyst).unwrap();
    let mut wrong = metadata(set.reference(), &cancel);
    wrong.time_context = Some(&time);
    assert!(SourceRecordReplay::new(&set, wrong, 100, 0).is_err());
    assert!(
        SourceRecordReplay::new(&set, metadata(set.reference(), &cancel), 100, 100_000).is_err()
    );
}
#[test]
fn selected_records_are_not_released_after_cancellation_or_if_the_pointer_is_missing() {
    let rows = [record(0, 0), record(1, 20)];
    let set = input_set(&rows);
    let cancel = CancellationToken::new();
    let mut replay =
        SourceRecordReplay::new(&set, metadata(set.reference(), &cancel), 100, 2).unwrap();
    for row in &rows {
        replay.accept(row).unwrap();
    }
    assert!(replay.finish(&report(2)).is_err());
    let mut replay =
        SourceRecordReplay::new(&set, metadata(set.reference(), &cancel), 100, 0).unwrap();
    for row in &rows {
        replay.accept(row).unwrap();
    }
    cancel.cancel();
    assert!(matches!(
        replay.finish(&report(2)),
        Err(AppError::Cancelled)
    ));
}
