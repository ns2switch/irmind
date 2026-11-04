#![allow(clippy::unwrap_used)]
use super::*;
use crate::SignedEntry;
use irmind_domain::{ParquetArtifactV2, ParserSelectionMode};
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
#[test]
#[allow(clippy::too_many_lines)]
fn a_v2_envelope_requires_an_exact_signed_parser_binding_and_no_partial_replacement() {
    let mut artifact = ParquetArtifactV2::decode(
        include_str!("../../../../domain/tests/fixtures/parquet-artifact-v2.hex").trim(),
    )
    .unwrap();
    let source = SourceManifestV2 {
        source: SourceManifestV1 {
            source: "synthetic.json".into(),
            size: 1,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: artifact.source_hashes[0].clone(),
            copied: false,
        },
        parser_id: artifact.parser_id.clone(),
        parser_version: artifact.parser_version.clone(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: Some("normalized-utc".into()),
        rejected_records: 0,
        rejected_sample: Vec::new(),
    };
    let source_entry = entry(
        1,
        AuditEventKind::SourceManifestV2,
        source.encode().unwrap(),
    );
    let valid = [
        source_entry.clone(),
        entry(
            2,
            AuditEventKind::ParquetArtifactV2,
            artifact.encode().unwrap(),
        ),
    ];
    assert!(read_manifest_index(&valid).is_ok());
    let legacy = irmind_domain::ParquetArtifactV1 {
        path: "date=2026-11-04/account=unknown/region=unknown/legacy.parquet".into(),
        size: 1,
        sha256: EvidenceHash::parse(&"8".repeat(64)).unwrap(),
        parser_version: source.parser_version.clone(),
        schema_version: "irmind-events-v2".into(),
        partition_date: "2026-11-04".into(),
        partition_account: "unknown".into(),
        partition_region: "unknown".into(),
        source_hashes: artifact.source_hashes.clone(),
    };
    assert!(
        read_manifest_index(&[
            source_entry.clone(),
            entry(
                2,
                AuditEventKind::ParquetArtifactV1,
                legacy.encode().unwrap()
            ),
            valid[1].clone()
        ])
        .is_err()
    );
    artifact.parser_id = "parser-ecs".into();
    assert!(matches!(
        read_manifest_index(&[
            source_entry.clone(),
            entry(
                2,
                AuditEventKind::ParquetArtifactV2,
                artifact.encode().unwrap()
            )
        ]),
        Err(AppError::InvalidChain(0))
    ));
    artifact.parser_id.clone_from(&source.parser_id);
    artifact.superseded_hashes = vec![EvidenceHash::parse(&"9".repeat(64)).unwrap()];
    assert!(
        read_manifest_index(&[
            source_entry,
            entry(
                2,
                AuditEventKind::ParquetArtifactV2,
                artifact.encode().unwrap()
            )
        ])
        .is_err()
    );
}
