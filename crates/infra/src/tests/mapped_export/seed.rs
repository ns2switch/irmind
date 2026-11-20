//! Preserve historical V8 bytes and check that the current reader rejects them.
use super::*;
fn verify_retired_golden(bytes: &[u8], digest: &str) {
    assert_eq!(hex(&sha256(bytes)), digest);
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("golden.irmind");
    fs::write(&package, bytes).unwrap();
    assert!(matches!(
        verify_export(&package),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredExportFormat
        ))
    ));
}
#[test]
fn retired_mapped_v8_package_preserves_its_historical_digest() {
    verify_retired_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v8-mapped.irmind"),
        "b803905c4850264edac3cf7571fde706f0ba26afa96c8023f91a944293c3985a",
    );
}
#[test]
fn retired_installed_v8_package_preserves_its_historical_digest() {
    verify_retired_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v8-installed.irmind"),
        "771f2482d755b97ab4f0abcd18a0d783dc747ee07e0f9f056aabccc81dbffbf9",
    );
}

fn verify_v9_golden(bytes: &[u8], digest: &str, entries: usize) {
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
        (9, entries, 1)
    );
    assert!(
        LocalExportVerifier
            .verify_export_details(&package, Some(&"0".repeat(64)))
            .is_err()
    );
}

#[test]
fn synthetic_v9_package_authenticates_without_any_keystore() {
    verify_v9_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v9-mapped.irmind"),
        "b4f518d70206c8c00aac284aaa13098cc093708247b0b95504e40a02c771bc3d",
        7,
    );
}

#[test]
fn synthetic_installed_v9_retains_portable_mapping_authorization() {
    verify_v9_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v9-installed.irmind"),
        "6f8f8f01ad9223f353f52139164473b88cf9a1d8b28c301f61cb3f7175edb656",
        8,
    );
}

pub(super) fn verify_required_tail(valid: &[u8], root: &Path) {
    assert_eq!(&valid[valid.len() - 24..], &[0; 24]);
    let path = root.join("extensions.irmind");
    for missing in 1..=24 {
        fs::write(&path, &valid[..valid.len() - missing]).unwrap();
        assert!(
            verify_export(&path).is_err(),
            "missing {missing} tail bytes"
        );
    }
    for (offset, count) in [
        (24, 1u64),
        (16, 1),
        (8, 1),
        (24, u64::MAX),
        (16, u64::MAX),
        (8, u64::MAX),
    ] {
        let mut changed = valid.to_vec();
        let start = changed.len() - offset;
        changed[start..start + 8].copy_from_slice(&count.to_be_bytes());
        fs::write(&path, changed).unwrap();
        let error = verify_export(&path).unwrap_err();
        // This case has no references to catalog, branch, or capture frames.
        assert!(matches!(error, AppError::InvalidChain(0)));
    }
    let mut changed = valid.to_vec();
    changed.extend_from_slice(&0u64.to_be_bytes());
    fs::write(&path, changed).unwrap();
    assert!(
        verify_export(&path)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes")
    );
}
