//! Immutable current V6 wire goldens remain usable without a construction recipe.
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
        (6, entries, 1)
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
fn synthetic_v6_package_golden_authenticates_without_any_keystore() {
    verify_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v6-mapped.irmind"),
        "f8dcfff30baece687942f1a38d1d30f21fd235b9718d83792361a7db79530d95",
        7,
    );
}
#[test]
fn synthetic_installed_v6_golden_authenticates_portable_global_authorization() {
    verify_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v6-installed.irmind"),
        "6991b04ecab077034cbf34980afb3e3fbe74157f18afa7854147f8a75847e40f",
        8,
    );
}
