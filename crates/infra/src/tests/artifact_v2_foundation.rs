use super::*;

#[test]
fn older_export_headers_fail_with_an_actionable_format_error() {
    let root = tempfile::tempdir().unwrap();
    for version in 1..=10 {
        let path = root.path().join(format!("synthetic-v{version}.irmind"));
        fs::write(&path, format!("IRMIND-EXPORT-V{version}\0")).unwrap();
        let error = verify_export(&path).unwrap_err();
        assert!(matches!(
            error,
            AppError::Fixed(irmind_app::FixedAppError::CaseFormat(
                irmind_app::case_format::CaseFormatError::Export(found)
            )) if found == version
        ));
        assert!(error.to_string().contains("verified originals"));
    }
}
