#![allow(clippy::unwrap_used)]
use super::*;
use crate::SignedEntry;
use irmind_domain::{
    Actor, ArtifactPipelineV1, MappingBindingV1, MappingCountsV1, MappingInputRefV1,
    MappingProfileV1, MappingRouteV1, MappingRunV1, ParquetArtifactV3, ParserSelectionMode,
    SourceFormatIdentityV1, SourceRecordSetV1, SourceReferenceV1,
};

fn entry(seq: u64, kind: AuditEventKind, payload: String) -> SignedEntry {
    SignedEntry {
        seq,
        case_id: "11111111-1111-1111-1111-111111111111".into(),
        at: 0,
        actor: Actor::Analyst,
        origin: "system".into(),
        kind,
        payload,
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: Vec::new(),
    }
}

fn mapped_entries() -> (Vec<SignedEntry>, ParquetArtifactV3) {
    let template = ParquetArtifactV3::decode(
        include_str!("../../../../domain/src/custody_manifest/mapping/goldens/mapped-v3.hex")
            .trim(),
    )
    .unwrap();
    let source = SourceManifestV2 {
        source: SourceManifestV1 {
            source: "synthetic.json".into(),
            size: 1,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: template.core().source_hashes[0].clone(),
            copied: false,
        },
        parser_id: template.core().parser_id.clone(),
        parser_version: template.core().parser_version.clone(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: Vec::new(),
    };
    let input = SourceRecordSetV1::from_manifest(
        &source,
        SourceReferenceV1::file("synthetic.json").unwrap(),
        vec![SourceFormatIdentityV1::try_new("json", "source-json-v1").unwrap()],
        1,
        EvidenceHash::from_bytes([3; 32]),
    )
    .unwrap();
    let profile =
        MappingProfileV1::try_new(vec![MappingInputRefV1::from_set(&input).unwrap()], vec![])
            .unwrap();
    let binding = MappingBindingV1::new(
        MappingInputRefV1::from_set(&input).unwrap(),
        profile.identity().unwrap(),
        profile.catalog_identity(),
        input.decoder().clone(),
        None,
    );
    let artifact = ParquetArtifactV3::try_new(
        template.core().clone(),
        ArtifactPipelineV1::mapped(vec![binding], 1).unwrap(),
    )
    .unwrap();
    let run = MappingRunV1::between(
        &profile,
        vec![
            MappingRouteV1::try_new(
                source.source.sha256.clone(),
                None,
                MappingCountsV1::try_new(1, 1, 0, 0).unwrap(),
            )
            .unwrap(),
        ],
        std::slice::from_ref(&artifact),
    )
    .unwrap();
    let entries = [
        (AuditEventKind::SourceManifestV2, source.encode().unwrap()),
        (AuditEventKind::SourceRecordSetV1, input.encode().unwrap()),
        (AuditEventKind::MappingProfileV1, profile.encode().unwrap()),
        (
            AuditEventKind::ParquetArtifactV3,
            artifact.encode().unwrap(),
        ),
        (AuditEventKind::MappingRunV1, run.encode().unwrap()),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (kind, payload))| entry(index as u64 + 1, kind, payload))
    .collect();
    (entries, artifact)
}

#[test]
fn mapped_manifest_requires_exact_signed_parser_selection_and_receipt() {
    let (mut entries, _) = mapped_entries();
    assert!(read_manifest_index(&entries).is_ok());
    assert!(read_manifest_index(&entries[..entries.len() - 1]).is_err());
    let mut source = SourceManifestV2::decode(&entries[0].payload).unwrap();
    source.parser_id = "parser-evil".into();
    entries[0].payload = source.encode().unwrap();
    assert!(matches!(
        read_manifest_index(&entries),
        Err(AppError::InvalidChain(_))
    ));
}

#[test]
fn mapped_artifact_rejects_a_changed_decoder_and_partial_replacement() {
    let (mut entries, artifact) = mapped_entries();
    let mut core = artifact.core().clone();
    core.superseded_hashes = vec![EvidenceHash::from_bytes([9; 32])];
    assert!(ParquetArtifactV3::try_new(core, artifact.pipeline().clone()).is_err());
    let payload = artifact.encode().unwrap();
    let original = hex::encode(artifact.core().parser_id.as_bytes());
    let altered = hex::encode(b"parser-evil");
    assert_eq!(original.len(), altered.len());
    let altered_payload = payload.replacen(&original, &altered, 1);
    assert_ne!(payload, altered_payload);
    entries[3].payload = altered_payload;
    assert!(matches!(
        read_manifest_index(&entries),
        Err(AppError::InvalidChain(_))
    ));
}
