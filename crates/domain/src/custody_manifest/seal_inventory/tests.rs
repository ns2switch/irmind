use super::*;
use sha2::{Digest, Sha256};
fn digest(stream: &mut crate::ByteStream<'_>) -> [u8; 32] {
    let mut hash = Sha256::new();
    stream(&mut |bytes| hash.update(bytes));
    hash.finalize().into()
}
#[test]
fn inventory_has_independent_versioned_golden_and_rejects_wrong_order() {
    let a = "a".repeat(64);
    let entries = [
        (SealItemKind::Evidence, a.as_str(), a.as_bytes()),
        (
            SealItemKind::Source,
            "events.json",
            b"source-fixture".as_slice(),
        ),
        (
            SealItemKind::Artifact,
            "date=2026-11-04/part.parquet",
            b"artifact-fixture".as_slice(),
        ),
    ];
    let hashes =
        entries.map(|(kind, key, payload)| SealInventoryV2::item_hash(kind, key, payload, digest));
    let values = entries
        .iter()
        .zip(&hashes)
        .map(|((kind, key, _), hash)| (*kind, *key, hash));
    let root = SealInventoryV2::from_ordered(values, digest).unwrap();
    let golden = include_str!("../../../tests/fixtures/seal-inventory-v2.hex").trim();
    assert_eq!(root.encode().unwrap(), golden);
    assert_eq!(SealInventoryV2::decode(golden).unwrap(), root);
    assert!(SealInventoryV2::decode(&format!("{golden}00")).is_err());
    assert!(SealInventoryV2::decode(&golden.to_ascii_uppercase()).is_err());
    let reversed = entries
        .iter()
        .zip(&hashes)
        .rev()
        .map(|((kind, key, _), hash)| (*kind, *key, hash));
    assert!(SealInventoryV2::from_ordered(reversed, digest).is_err());
    let mut changed = root;
    changed.count = 0;
    assert!(changed.encode().is_err());
}
