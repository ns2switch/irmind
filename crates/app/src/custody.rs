use crate::{AppError, CancellationToken, CaseId, CaseSeal, Engine, SignedEntry};
use std::path::Path;

pub fn verify_export(
    verifier: &dyn crate::ExportVerifier,
    path: &Path,
    expected_key: Option<&str>,
) -> Result<(String, usize), AppError> {
    verifier.verify_export(path, expected_key)
}

pub fn export_case(
    engine: &Engine<'_>,
    exporter: &dyn crate::CaseExporter,
    id: &CaseId,
    path: &Path,
    cancel: &CancellationToken,
) -> Result<String, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let _case_lock = engine.repo.lock_case(id)?;
    engine.verify_unlocked_cancelable(id, cancel)?;
    if !engine.repo.get_case(id)?.sealed {
        return Err(AppError::Fixed(
            crate::FixedAppError::PolicySealTheCaseBeforeExport,
        ));
    }
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    exporter.export_case(id, path, cancel)
}

pub struct SealPreview {
    entry: SignedEntry,
    seal: CaseSeal,
}

impl SealPreview {
    pub fn case_id(&self) -> &str {
        &self.entry.case_id
    }
    pub fn entry_count(&self) -> u64 {
        self.entry.seq
    }
    pub fn final_hash(&self) -> [u8; 32] {
        self.entry.hash
    }
    pub fn analyst_key_fingerprint(&self) -> &str {
        &self.seal.analyst_key_fingerprint
    }
}

mod migration;
mod seal_verify;
