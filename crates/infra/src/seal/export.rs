use super::{AppError, CancellationToken, CaseExporter, CaseId, ExportVerifier, LocalStore, Path};

impl CaseExporter for LocalStore {
    fn export_case(
        &self,
        id: &CaseId,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        self.export_current(id, path, None, false, cancel)
    }
}

pub struct LocalExportVerifier;
impl ExportVerifier for LocalExportVerifier {
    fn verify_export(
        &self,
        path: &Path,
        expected_key: Option<&str>,
    ) -> Result<(String, usize), AppError> {
        verify_export_expected(path, expected_key)
    }
    fn verify_export_details(
        &self,
        path: &Path,
        expected_key: Option<&str>,
    ) -> Result<irmind_app::ExportVerification, AppError> {
        super::verify_current::verify_export_v6(path, expected_key)
    }
}

pub fn verify_export(path: &Path) -> Result<(String, usize), AppError> {
    verify_export_expected(path, None)
}
pub fn verify_export_expected(
    path: &Path,
    expected_key: Option<&str>,
) -> Result<(String, usize), AppError> {
    let verified = super::verify_current::verify_export_v6(path, expected_key)?;
    Ok((verified.analyst_key_fingerprint, verified.entries))
}
