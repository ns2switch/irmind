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

fn verify_v10_golden(bytes: &[u8], digest: &str, entries: usize) {
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
        (10, entries, 1)
    );
    assert!(
        LocalExportVerifier
            .verify_export_details(&package, Some(&"0".repeat(64)))
            .is_err()
    );
}

#[test]
fn retired_v9_packages_preserve_their_historical_digests() {
    verify_retired_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v9-mapped.irmind"),
        "b4f518d70206c8c00aac284aaa13098cc093708247b0b95504e40a02c771bc3d",
    );
    verify_retired_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v9-installed.irmind"),
        "6f8f8f01ad9223f353f52139164473b88cf9a1d8b28c301f61cb3f7175edb656",
    );
}

#[test]
fn synthetic_v10_package_authenticates_without_any_keystore() {
    verify_v10_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v10-mapped.irmind"),
        "e066b8539092394868477607bd97cd421d1051f4ffddcd004952d024f97806fd",
        7,
    );
}

#[test]
fn synthetic_installed_v10_retains_portable_mapping_authorization() {
    verify_v10_golden(
        include_bytes!("../../../../../fuzz/seeds/export/valid-v10-installed.irmind"),
        "1bbbcb484b9832932d8555e1569325e67623768412e8277cc2cedbd149072d8e",
        8,
    );
}

pub(super) fn verify_required_tail(valid: &[u8], root: &Path) {
    const COUNTS: usize = 5 * 8;
    assert_eq!(&valid[valid.len() - COUNTS..], &[0; COUNTS]);
    let path = root.join("extensions.irmind");
    for missing in 1..=COUNTS {
        fs::write(&path, &valid[..valid.len() - missing]).unwrap();
        assert!(
            verify_export(&path).is_err(),
            "missing {missing} tail bytes"
        );
    }
    for (offset, count) in (8..=COUNTS)
        .step_by(8)
        .flat_map(|offset| [(offset, 1u64), (offset, u64::MAX)])
    {
        let mut changed = valid.to_vec();
        let start = changed.len() - offset;
        changed[start..start + 8].copy_from_slice(&count.to_be_bytes());
        fs::write(&path, changed).unwrap();
        let error = verify_export(&path).unwrap_err();
        // This case has no references to catalog, branch, capture, Sigma, or report frames.
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
