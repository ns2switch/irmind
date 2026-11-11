//! Test the real first-read gate without creating a multi-terabyte file.
#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;

struct Unreadable;
impl Read for Unreadable {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("an oversized package must be rejected before its first read");
    }
}
#[test]
fn oversized_export_is_rejected_before_any_payload_read_on_every_platform() {
    for size in [MAX_PACKAGE_FILE_BYTES + 1, u64::MAX] {
        let error = read_package_magic(&mut Unreadable, size).unwrap_err();
        assert_eq!(
            error.to_string(),
            storage_reason("export package exceeds size limit").to_string()
        );
    }
    for size in [MAGIC_V6.len() as u64, MAX_PACKAGE_FILE_BYTES] {
        read_package_magic(&mut &MAGIC_V6[..], size).unwrap();
    }
    assert!(matches!(
        read_package_magic(&mut &b"bad"[..], 3),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredExportFormat
        ))
    ));
}
