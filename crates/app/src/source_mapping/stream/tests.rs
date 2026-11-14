mod replay;
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
    record_with_offset(n, Some(offset))
}
fn record_with_offset(n: u64, offset: Option<u64>) -> Tainted<SourceRecordV1> {
    let source = SourceRecordV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([7; 32]),
            n,
            offset,
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
    let provenance = Provenance::new([7; 32], Some(n), SourceKind::File);
    let provenance = if let Some(offset) = offset {
        provenance.with_parser_location(
            ParserLocation::new("logs/record.json", "parser-json", offset).unwrap(),
        )
    } else {
        provenance
    };
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
            cluster_context: None,
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
        cluster_context: None,
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
        cluster_context: None,
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
        cluster_context: None,
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
        cluster_context: None,
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

#[test]
fn buffered_commitment_rejects_changes_on_both_sides_of_the_read_boundary() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    for position in [None, Some(65_535), Some(65_536), Some(65_537)] {
        let mut acc = accumulator(&source, &cancel, &catalog);
        let mut spool = Cursor::new(Vec::new());
        for n in 0..2048 {
            acc.accept(&record(n, 0), &mut spool).unwrap();
        }
        if let Some(position) = position {
            spool.get_mut()[position] ^= 1;
        }
        let result = acc.finish(&mut spool, &report(2048));
        assert_eq!(result.is_ok(), position.is_none());
    }
}

mod offsets;

#[test]
fn prepared_records_preserve_canonical_tuples_and_commitments() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut sequential = accumulator(&source, &cancel, &catalog);
    let mut parallel = accumulator(&source, &cancel, &catalog);
    let mut a = Cursor::new(Vec::new());
    let mut b = Cursor::new(Vec::new());
    let preparer = parallel.preparer();
    // Preparation may complete backwards; only ordered commit mutates accounting.
    let later = preparer.prepare(record(1, 20)).unwrap();
    let first = preparer.prepare(record(0, 0)).unwrap();
    for (n, offset) in [(0, 0), (1, 20)] {
        sequential.accept(&record(n, offset), &mut a).unwrap();
    }
    parallel.accept_prepared(first, &mut b).unwrap();
    parallel.accept_prepared(later, &mut b).unwrap();
    assert_eq!(a.get_ref(), b.get_ref());
    let a = sequential.finish(&mut a, &report(2)).unwrap();
    let b = parallel.finish(&mut b, &report(2)).unwrap();
    assert_eq!(a.commitment(), b.commitment());
    assert_eq!(a.records(), b.records());
    assert_eq!(a.routes(), b.routes());
}

#[test]
fn prepared_records_remain_bound_to_catalog_source_order_and_cancellation() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let other = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut acc = accumulator(&source, &cancel, &catalog);
    let other_acc = accumulator(&source, &cancel, &other);
    let mut spool = Cursor::new(Vec::new());
    let foreign = other_acc.preparer().prepare(record(0, 0)).unwrap();
    assert!(acc.accept_prepared(foreign, &mut spool).is_err());
    assert!(spool.get_ref().is_empty());
    assert!(acc.preparer().prepare(record(0, 100)).is_err());
    let preparer = acc.preparer();
    let first = preparer.prepare(record(0, 0)).unwrap();
    let repeated = preparer.prepare(record(0, 0)).unwrap();
    let next = preparer.prepare(record(1, 20)).unwrap();
    acc.accept_prepared(first, &mut spool).unwrap();
    assert!(acc.accept_prepared(repeated, &mut spool).is_err());
    cancel.cancel();
    assert!(matches!(
        acc.accept_prepared(next, &mut spool),
        Err(AppError::Cancelled)
    ));
    assert_eq!(spool.get_ref().len(), 49);
}

#[test]
fn acquisition_cluster_must_match_every_record_and_the_signed_manifest() {
    use irmind_domain::{
        ClusterContextBasis, ClusterIdentity, ClusterProvider, SourceClusterBinding,
        SourceClusterContext,
    };
    let cluster = ClusterIdentity::try_new(ClusterProvider::Kubernetes, "urn:k8s:lab-a").unwrap();
    let context = SourceClusterContext::try_new(vec![
        SourceClusterBinding::try_new(cluster.clone(), ClusterContextBasis::Analyst, None).unwrap(),
    ])
    .unwrap();
    let reference = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let metadata = SourceMetadata {
        source: &reference,
        evidence_hash: [7; 32],
        time_context: None,
        cluster_context: Some(&context),
        cancel: &cancel,
    };
    let mut acc =
        SourceRecordAccumulator::new(metadata, Decoder.identity(), 100, &catalog).unwrap();
    let mut spool = Cursor::new(Vec::new());
    assert!(acc.accept(&record(0, 0), &mut spool).is_err());
    let wrong = ClusterIdentity::try_new(ClusterProvider::Kubernetes, "urn:k8s:lab-b").unwrap();
    assert!(
        acc.accept(
            &record(0, 0).with_cluster_identity(wrong).unwrap(),
            &mut spool
        )
        .is_err()
    );
    let tagged = record(0, 0).with_cluster_identity(cluster).unwrap();
    assert!(
        accumulator(&reference, &cancel, &catalog)
            .accept(&tagged, &mut spool)
            .is_err()
    );
    acc.accept(&tagged, &mut spool).unwrap();
    let commitment = acc.finish(&mut spool, &report(1)).unwrap();
    let mut manifest = irmind_domain::SourceManifestV2 {
        source: irmind_domain::SourceManifestV1 {
            source: reference.reference().into(),
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
        selection: irmind_domain::ParserSelectionMode::Analyst,
        timestamp_context: None,
        cluster_context: Some(context),
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let set = commitment.bind_manifest(&manifest).unwrap();
    assert_eq!(set.cluster_context(), manifest.cluster_context.as_ref());
    manifest.cluster_context = None;
    assert!(commitment.bind_manifest(&manifest).is_err());
}
