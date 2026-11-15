//! Immutable current V8 wire goldens remain usable without a construction recipe.
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
        (8, entries, 1)
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
fn synthetic_v8_package_golden_authenticates_without_any_keystore() {
    verify_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v8-mapped.irmind"),
        "b803905c4850264edac3cf7571fde706f0ba26afa96c8023f91a944293c3985a",
        7,
    );
}
#[test]
fn synthetic_installed_v8_golden_authenticates_portable_global_authorization() {
    verify_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v8-installed.irmind"),
        "771f2482d755b97ab4f0abcd18a0d783dc747ee07e0f9f056aabccc81dbffbf9",
        8,
    );
}

#[test]
fn v8_requires_both_extension_counts_and_rejects_unreferenced_sections() {
    let valid = include_bytes!("../../../../../fuzz/seeds/export/valid-v8-mapped.irmind");
    assert_eq!(&valid[valid.len() - 16..], &[0; 16]);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("extensions.irmind");
    for missing in 1..=16 {
        fs::write(&path, &valid[..valid.len() - missing]).unwrap();
        assert!(
            verify_export(&path).is_err(),
            "missing {missing} tail bytes"
        );
    }
    for (offset, count) in [(16, 1u64), (8, 1), (16, u64::MAX), (8, u64::MAX)] {
        let mut changed = valid.to_vec();
        let start = changed.len() - offset;
        changed[start..start + 8].copy_from_slice(&count.to_be_bytes());
        fs::write(&path, changed).unwrap();
        let error = verify_export(&path).unwrap_err();
        // Both extensions are supported, but no signed record references one here.
        assert!(matches!(error, AppError::InvalidChain(0)));
    }
    let mut changed = valid.to_vec();
    changed.push(0);
    fs::write(&path, changed).unwrap();
    assert!(
        verify_export(&path)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes")
    );
}
