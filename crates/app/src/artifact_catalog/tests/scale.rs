use super::*;
use crate::verify_seal_inventory_snapshot;
use irmind_domain::SealInventoryV2;

fn append(entries: &mut Vec<SignedEntry>, mut value: SignedEntry) {
    value.seq = entries.len() as u64 + 1;
    value.prev = entries.last().map_or([0; 32], |last| last.hash);
    value.hash = crate::sha256(&value.canonical());
    entries.push(value);
}
const ARTIFACTS_PER_GROUP: usize = 1_000;

fn snapshot(count: usize) -> Vec<SignedEntry> {
    let mut entries = Vec::new();
    for (group, start) in (0..count).step_by(ARTIFACTS_PER_GROUP).enumerate() {
        let records = (count - start).min(ARTIFACTS_PER_GROUP);
        let (batch, _) = super::mapped::mapped_history_for(group, records);
        for value in batch {
            append(&mut entries, value);
        }
    }
    entries
}
fn exercise(count: usize) {
    let mut entries = snapshot(count);
    let payload = seal_inventory(&entries, &[]).unwrap().join(",");
    assert!(payload.len() < 1024);
    assert_eq!(
        SealInventoryV2::decode(&payload).unwrap().count,
        (count + count.div_ceil(ARTIFACTS_PER_GROUP)) as u64
    );
    verify_seal_inventory_snapshot(&entries, &[], &payload).unwrap();
    let mut counter = SealInventoryV2::decode(&payload).unwrap();
    counter.count += 1;
    assert!(verify_seal_inventory_snapshot(&entries, &[], &counter.encode().unwrap()).is_err());
    counter.count -= 1;
    counter.sha256 = EvidenceHash::from_bytes([0; 32]);
    assert!(verify_seal_inventory_snapshot(&entries, &[], &counter.encode().unwrap()).is_err());
    let mut added = entries
        .iter()
        .rfind(|entry| entry.kind == AuditEventKind::ParquetArtifactV3)
        .unwrap()
        .clone();
    let artifact = irmind_domain::ParquetArtifactV3::decode(&added.payload).unwrap();
    let mut core = artifact.core().clone();
    core.path = format!("{}extra.parquet", core.partition.path_prefix().unwrap());
    added.payload = irmind_domain::ParquetArtifactV3::try_new(core, artifact.pipeline().clone())
        .unwrap()
        .encode()
        .unwrap();
    append(&mut entries, added);
    assert!(verify_seal_inventory_snapshot(&entries, &[], &payload).is_err());
    entries.pop();
    let position = entries
        .iter()
        .rposition(|entry| entry.kind == AuditEventKind::ParquetArtifactV3)
        .unwrap();
    let removed = entries.remove(position);
    assert!(verify_seal_inventory_snapshot(&entries, &[], &payload).is_err());
    entries.insert(position, removed);
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
