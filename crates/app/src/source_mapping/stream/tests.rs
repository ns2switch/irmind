use super::*;
use crate::source_mapping::{
    DecodeAnnotationsV1, SourceDecoder, SourceFormatV1, SourceInput, SourceNumber,
    SourceReferenceV1, SourceValue,
};
use crate::{CancellationToken, ParserIdentity};
use irmind_domain::{EventOrigin, ParserLocation, Provenance, SourceKind};
use std::{collections::BTreeMap, io::Cursor, sync::Arc};

struct Decoder;
impl SourceDecoder for Decoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-json",
            version: "json-source-v1",
        }
    }
    fn decode_reader(
        &self,
        _: SourceInput<'_>,
        _: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        Err(AppError::Cancelled)
    }
}
fn record(n: u64, offset: u64) -> Tainted<SourceRecordV1> {
    let source = SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([7; 32]),
            n,
            Some(offset),
            "parser-json",
            "json-source-v1",
        )
        .unwrap(),
        "logs/record.json",
        None,
        SourceFormatV1::try_new("json", "source-json-v1", BTreeMap::new()).unwrap(),
        SourceValue::object(vec![
            ("a".into(), SourceValue::Text("1".into())),
            (
                "n".into(),
                SourceValue::Number(SourceNumber::try_new("9007199254740993").unwrap()),
            ),
        ])
        .unwrap(),
        DecodeAnnotationsV1::default(),
    )
    .unwrap();
    let provenance = Provenance::new([7; 32], Some(n), SourceKind::File).with_parser_location(
        ParserLocation::new("logs/record.json", "parser-json", offset).unwrap(),
    );
    Tainted::from_external(source, provenance)
}
fn accumulator<'a>(
    source: &'a SourceReferenceV1,
    cancel: &'a CancellationToken,
    catalog: &'a MappingCatalog,
) -> SourceRecordAccumulator<'a> {
    SourceRecordAccumulator::new(
        SourceMetadata {
            source,
            evidence_hash: [7; 32],
            time_context: None,
            cancel,
        },
        Decoder.identity(),
        100,
        catalog,
    )
    .unwrap()
}
fn report(n: usize) -> ParseReport {
    ParseReport {
        accepted: n,
        rejected: 0,
        samples: vec![],
    }
}

#[test]
fn source_commitment_has_independent_bytes_and_only_hash_tuples_are_spooled() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut acc = accumulator(&source, &cancel, &catalog);
    let mut spool = Cursor::new(Vec::new());
    for (n, offset) in [(0, 0), (1, 20)] {
        let input = record(n, offset);
        let output = acc.accept(&input, &mut spool).unwrap();
        assert!(output.identity.is_none());
        assert_eq!(output.output.provenance(), input.provenance());
    }
    assert_eq!(spool.get_ref().len(), 98);
    assert!(
        !spool
            .get_ref()
            .windows(16)
            .any(|v| v == b"9007199254740993")
    );
    let decoded = acc.finish(&mut spool, &report(2)).unwrap();
    assert_eq!(
        decoded.commitment().as_str(),
        "3b638075f7dbb44fb45bea6ecd6fe8ee0b0c21628eca1e9bd9f9e462baf12a4a"
    );
    assert_eq!(decoded.records(), 2);
    assert_eq!(decoded.routes()[0].counts().unclassified(), 2);
}

#[test]
fn altered_or_extended_spool_and_inconsistent_report_are_rejected() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    for mode in 0..3 {
        let mut acc = accumulator(&source, &cancel, &catalog);
        let mut spool = Cursor::new(Vec::new());
        acc.accept(&record(0, 0), &mut spool).unwrap();
        match mode {
            0 => spool.get_mut()[20] ^= 1,
            1 => spool.get_mut().push(0),
            _ => {}
        }
        assert!(
            acc.finish(&mut spool, &report(if mode == 2 { 2 } else { 1 }))
                .is_err()
        );
    }
}

#[test]
fn provenance_offsets_ordinals_and_cancellation_fail_closed() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut acc = accumulator(&source, &cancel, &catalog);
    let mut spool = Cursor::new(Vec::new());
    let input = record(0, 0);
    let mut changed = None;
    input.inspect(|value| {
        changed = Some(Tainted::from_external(
            value.clone(),
            Provenance::new([8; 32], Some(0), SourceKind::File),
        ));
    });
    assert!(acc.accept(&changed.unwrap(), &mut spool).is_err());
    assert!(acc.accept(&record(0, 100), &mut spool).is_err());
    assert!(spool.get_ref().is_empty());
    acc.accept(&input, &mut spool).unwrap();
    assert!(acc.accept(&input, &mut spool).is_err());
    cancel.cancel();
    assert!(matches!(
        acc.accept(&record(1, 20), &mut spool),
        Err(AppError::Cancelled)
    ));
    assert!(matches!(
        acc.finish(&mut spool, &report(1)),
        Err(AppError::Cancelled)
    ));
}

#[test]
fn final_manifest_must_match_the_exact_source_size_and_rejection_report() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut acc = accumulator(&source, &cancel, &catalog);
    let mut spool = Cursor::new(Vec::new());
    acc.accept(&record(0, 0), &mut spool).unwrap();
    let mut report = report(1);
    report.rejected = 1;
    report.samples = vec!["synthetic rejected record".into()];
    let decoded = acc.finish(&mut spool, &report).unwrap();
    let manifest = irmind_domain::SourceManifestV2 {
        source: irmind_domain::SourceManifestV1 {
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
        selection: irmind_domain::ParserSelectionMode::Automatic,
        timestamp_context: Some("normalized-utc".into()),
        rejected_records: 1,
        rejected_sample: report.samples.clone(),
    };
    let input = decoded.bind_manifest(&manifest).unwrap();
    input.validate_manifest(&manifest).unwrap();
    let mut changed = manifest.clone();
    changed.source.size += 1;
    assert!(decoded.bind_manifest(&changed).is_err());
    let mut changed = manifest.clone();
    changed.rejected_sample.clear();
    assert!(decoded.bind_manifest(&changed).is_err());
    let mut changed = manifest;
    changed.rejected_records = 0;
    assert!(decoded.bind_manifest(&changed).is_err());
}

#[test]
fn confirmed_time_inputs_survive_the_decoder_selection_and_input_commitment() {
    use crate::{LogParser, ParserTimeBasis, ParserTimeContext};
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let time = ParserTimeContext::new(2026, -210, true, ParserTimeBasis::Command).unwrap();
    let selected = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap()
        .with_time_context(&time)
        .unwrap();
    assert_eq!(
        super::super::decode_source_time_context(selected.timestamp_context()).unwrap(),
        Some(time)
    );
    let metadata = SourceMetadata {
        source: &source,
        evidence_hash: [7; 32],
        time_context: Some(&time),
        cancel: &cancel,
    };
    let mut acc =
        SourceRecordAccumulator::new(metadata, Decoder.identity(), 100, &catalog).unwrap();
    let mut spool = Cursor::new(Vec::new());
    acc.accept(&record(0, 0), &mut spool).unwrap();
    let decoded = acc.finish(&mut spool, &report(1)).unwrap();
    let mut manifest = irmind_domain::SourceManifestV2 {
        source: irmind_domain::SourceManifestV1 {
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
        selection: irmind_domain::ParserSelectionMode::Forced,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: vec![],
    };
    assert!(decoded.bind_manifest(&manifest).is_err());
    manifest.timestamp_context = selected.timestamp_context().map(str::to_owned);
    let set = decoded.bind_manifest(&manifest).unwrap();
    assert_eq!(
        super::super::parser_time_context(set.time_context().unwrap()).unwrap(),
        time
    );
}

#[test]
fn prepared_outputs_bind_only_after_complete_source_manifest_and_row_accounting() {
    use crate::source_mapping::{MappedArtifactProjection, PreparedMappingSource};
    use irmind_domain::{
        ARTIFACT_V2_MAX_DATE_TUPLES, ARTIFACT_V2_PARTITION_POLICY, ARTIFACT_V2_SCOPE_KEYS,
        ARTIFACT_V2_STABLE_ORDER, ARTIFACT_V2_TIME_SEMANTICS, ArtifactPartitionV2,
        ArtifactSchemaV2, COMMON_EVENT_BUILDER, ParquetArtifactV2,
    };
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut acc = accumulator(&source, &cancel, &catalog);
    let mut spool = Cursor::new(Vec::new());
    acc.accept(&record(0, 0), &mut spool).unwrap();
    acc.accept(&record(1, 20), &mut spool).unwrap();
    let decoded = acc.finish(&mut spool, &report(2)).unwrap();
    let manifest = irmind_domain::SourceManifestV2 {
        source: irmind_domain::SourceManifestV1 {
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
        selection: irmind_domain::ParserSelectionMode::Automatic,
        timestamp_context: Some("normalized-utc".into()),
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let core = ParquetArtifactV2 {
        path: "date=unknown/part.parquet".into(),
        size: 123,
        sha256: EvidenceHash::from_bytes([8; 32]),
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        schema: ArtifactSchemaV2::CommonEvents,
        partition: ArtifactPartitionV2 {
            date: "unknown".into(),
            key_set: ARTIFACT_V2_SCOPE_KEYS.into(),
            policy: ARTIFACT_V2_PARTITION_POLICY.into(),
            tuple_cap: ARTIFACT_V2_MAX_DATE_TUPLES,
            all_scope_overflow: false,
            scopes: vec![],
        },
        source_hashes: vec![EvidenceHash::from_bytes([7; 32])],
        time_semantics: ARTIFACT_V2_TIME_SEMANTICS.into(),
        stable_order: ARTIFACT_V2_STABLE_ORDER.into(),
        builder_version: COMMON_EVENT_BUILDER.into(),
        superseded_hashes: vec![],
    };
    let prepare = |rows| {
        PreparedMappingSource::try_new(
            decoded.clone(),
            catalog.snapshots().unwrap(),
            vec![MappedArtifactProjection::try_new(core.clone(), None, rows).unwrap()],
        )
        .unwrap()
    };
    let prepared = prepare(2);
    let catalog_id = prepared.catalog_commitment().unwrap();
    let bound = prepared.bind(&manifest).unwrap();
    assert_eq!(bound.profile().catalog_identity(), catalog_id);
    bound
        .receipt()
        .verify(bound.profile(), bound.artifacts())
        .unwrap();
    assert_eq!(bound.artifacts()[0].pipeline().rows(), 2);
    assert!(prepare(1).bind(&manifest).is_err());
    let mut bad = manifest;
    bad.source.size += 1;
    assert!(prepare(2).bind(&bad).is_err());
}
