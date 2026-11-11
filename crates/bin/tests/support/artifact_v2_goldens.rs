use irmind_app::{hex, sha256};

#[test]
fn v2_seal_inventory_golden_is_portable_with_either_json_map_implementation() {
    let golden = include_str!("../../../domain/tests/fixtures/seal-inventory-v2.hex").trim();
    let expected = include_str!("../../../domain/tests/fixtures/seal-inventory-v2.sha256").trim();
    let root = irmind_domain::SealInventoryV2::decode(golden).unwrap();
    assert_eq!(root.count, 3);
    assert_eq!(root.encode().unwrap(), golden);
    let bytes = golden
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(hex(&sha256(&bytes)), expected);
}
