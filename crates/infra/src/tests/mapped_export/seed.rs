//! Immutable current V7 wire goldens remain usable without a construction recipe.
use super::*;
fn verify_golden(bytes: &[u8], digest: &str, entries: usize) {
    assert_eq!(hex(&sha256(bytes)), digest);
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("golden.irmind");
    fs::write(&package, bytes).unwrap();
    let key = hex(&sha256(
        &SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
    ));
    let verified = LocalExportVerifier
        .verify_export_details(&package, Some(&key))
        .unwrap();
    assert_eq!(
        (
            verified.format_version,
            verified.entries,
            verified.source_manifests
        ),
        (7, entries, 1)
    );
    assert!(
        LocalExportVerifier
            .verify_export_details(&package, Some(&"0".repeat(64)))
            .is_err()
    );
    let mut changed = bytes.to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    fs::write(&package, changed).unwrap();
    assert!(verify_export(&package).is_err());
}
#[test]
fn synthetic_v7_package_golden_authenticates_without_any_keystore() {
    verify_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v7-mapped.irmind"),
        "1b01d95f59f055610c9fce87becdea460fa489f5f62e4c04445ad8facdb57efc",
        7,
    );
}
#[test]
fn synthetic_installed_v7_golden_authenticates_portable_global_authorization() {
    verify_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v7-installed.irmind"),
        "f4a92ac507e83897434a0a9ac365adf812e424afc2d95ebadeceee5cd62e41fa",
        8,
    );
}
