use super::*;
use irmind_domain::{
    Actor, AuditEventKind, EvidenceHash, ParquetArtifactV1, ParquetArtifactV2, ParserSelectionMode,
    SourceManifestV1, SourceManifestV2,
};
fn entry(kind: AuditEventKind, payload: String) -> SignedEntry {
    SignedEntry {
        seq: 1,
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
fn hash(digit: &str) -> EvidenceHash {
    EvidenceHash::parse(&digit.repeat(64)).unwrap()
}
fn source(name: &str, hash: EvidenceHash) -> SourceManifestV1 {
    SourceManifestV1 {
        source: name.into(),
        sha256: hash,
        size: 1,
        modified_unix_seconds: None,
        version: None,
        provider_checksum: None,
        copied: false,
    }
}
#[test]
fn mixed_seal_inventory_includes_both_generations_and_matches_golden_order() {
    let old = source("old.json", hash("1"));
    let artifact = ParquetArtifactV1 {
        path: "date=2026-11-04/account=unknown/region=unknown/old.parquet".into(),
        sha256: hash("2"),
        size: 1,
        parser_version: "json-stream-v2".into(),
        schema_version: "irmind-events-v2".into(),
        partition_date: "2026-11-04".into(),
        partition_account: "unknown".into(),
        partition_region: "unknown".into(),
        source_hashes: vec![old.sha256.clone()],
    };
    let new = ParquetArtifactV2::decode(
        include_str!("../../../domain/tests/fixtures/parquet-artifact-v2.hex").trim(),
    )
    .unwrap();
    let selected = SourceManifestV2 {
        source: source("new.json", new.source_hashes[0].clone()),
        parser_id: new.parser_id.clone(),
        parser_version: new.parser_version.clone(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: Vec::new(),
    };
    let entries = [
        entry(AuditEventKind::SourceManifestV1, old.encode().unwrap()),
        entry(
            AuditEventKind::ParquetArtifactV1,
            artifact.encode().unwrap(),
        ),
        entry(AuditEventKind::SourceManifestV2, selected.encode().unwrap()),
        entry(AuditEventKind::ParquetArtifactV2, new.encode().unwrap()),
    ];
    let golden = include_str!("../../tests/fixtures/mixed-seal-inventory.txt").trim();
    assert_eq!(
        seal_inventory(&entries, &["3".repeat(64)])
            .unwrap()
            .join(","),
        golden
    );
    assert_eq!(
        seal_inventory(&entries[..2], &["3".repeat(64)]).unwrap(),
        ["3".repeat(64)]
    );
}
