use super::*;
use crate::verify_seal_inventory_snapshot;
use irmind_domain::SealInventoryV2;

fn append(entries: &mut Vec<SignedEntry>, mut value: SignedEntry) {
    value.seq = entries.len() as u64 + 1;
    value.prev = entries.last().map_or([0; 32], |last| last.hash);
    value.hash = crate::sha256(&value.canonical());
    entries.push(value);
}
fn snapshot(count: usize) -> Vec<SignedEntry> {
    let mut artifact = ParquetArtifactV2::decode(
        include_str!("../../../../domain/tests/fixtures/parquet-artifact-v2.hex").trim(),
    )
    .unwrap();
    artifact.builder_version = "parquet-builder-v3".into();
    // This suite measures inventory cardinality, independently of partition
    // normalization, whose scoped golden and boundary suites run separately.
    artifact.partition.scopes.clear();
    let source = SourceManifestV2 {
        source: source("source.json", artifact.source_hashes[0].clone()),
        parser_id: artifact.parser_id.clone(),
        parser_version: artifact.parser_version.clone(),
        confidence: 90,
        selection: ParserSelectionMode::Automatic,
        timestamp_context: None,
        rejected_records: 0,
        rejected_sample: Vec::new(),
    };
    let mut entries = Vec::with_capacity(count + 1);
    append(
        &mut entries,
        entry(AuditEventKind::SourceManifestV2, source.encode().unwrap()),
    );
    let prefix = artifact.partition.path_prefix().unwrap();
    for n in 0..count {
        artifact.path = format!("{prefix}part-{n:08}.parquet");
        artifact.sha256 = EvidenceHash::parse(&format!("{n:064x}")).unwrap();
        append(
            &mut entries,
            entry(
                AuditEventKind::ParquetArtifactV2,
                artifact.encode().unwrap(),
            ),
        );
    }
    entries
}
fn exercise(count: usize) {
    let mut entries = snapshot(count);
    let payload = seal_inventory(&entries, &[]).unwrap().join(",");
    assert!(payload.len() < 1024);
    assert_eq!(
        SealInventoryV2::decode(&payload).unwrap().count,
        count as u64 + 1
    );
    verify_seal_inventory_snapshot(&entries, &[], &payload).unwrap();
    let mut counter = SealInventoryV2::decode(&payload).unwrap();
    counter.count += 1;
    assert!(verify_seal_inventory_snapshot(&entries, &[], &counter.encode().unwrap()).is_err());
    counter.count -= 1;
    counter.sha256 = EvidenceHash::from_bytes([0; 32]);
    assert!(verify_seal_inventory_snapshot(&entries, &[], &counter.encode().unwrap()).is_err());
    let mut added = entries.last().unwrap().clone();
    let mut artifact = ParquetArtifactV2::decode(&added.payload).unwrap();
    artifact.path = format!("{}extra.parquet", artifact.partition.path_prefix().unwrap());
    added.payload = artifact.encode().unwrap();
    append(&mut entries, added);
    assert!(verify_seal_inventory_snapshot(&entries, &[], &payload).is_err());
    entries.pop();
    let removed = entries.pop().unwrap();
    assert!(verify_seal_inventory_snapshot(&entries, &[], &payload).is_err());
    entries.push(removed);
    let middle = count / 2;
    entries.swap(middle, middle + 1);
    assert!(verify_seal_inventory_snapshot(&entries, &[], &payload).is_err());
    entries.swap(middle, middle + 1);
    let original = entries[middle].payload.clone();
    entries[middle].payload.push('0');
    assert!(verify_seal_inventory_snapshot(&entries, &[], &payload).is_err());
    entries[middle].payload = original;
    verify_seal_inventory_snapshot(&entries, &[], &payload).unwrap();
}
#[test]
fn inventory_checks_20000_metadata_artifacts_without_large_files() {
    exercise(20_000);
}
#[test]
fn inventory_checks_100000_metadata_artifacts_without_large_files() {
    exercise(100_000);
}
