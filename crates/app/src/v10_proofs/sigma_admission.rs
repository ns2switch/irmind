//! Use the existing Analyst global audit log for Sigma admissions.
use super::{ADMISSION, SigmaPackAdmissionV1};
use crate::{Actor, AppError, Engine, GLOBAL_OPERATION_SCOPE, SignedOperation, Verifier};

pub fn sigma_pack_operation(
    entry: &SignedOperation,
) -> Result<Option<SigmaPackAdmissionV1>, AppError> {
    if !entry.operation.starts_with(&crate::hex(ADMISSION)) {
        return Ok(None);
    }
    if entry.case_id != GLOBAL_OPERATION_SCOPE || entry.actor != Actor::Analyst || entry.seq == 0 {
        return Err(AppError::InvalidChain(entry.seq));
    }
    SigmaPackAdmissionV1::decode(&entry.operation)
        .map(Some)
        .map_err(|_| AppError::InvalidChain(entry.seq))
}

pub fn verify_sigma_pack_operation(
    entry: &SignedOperation,
    verifier: &dyn Verifier,
) -> Result<SigmaPackAdmissionV1, AppError> {
    let invalid = || AppError::InvalidChain(entry.seq);
    let admission = sigma_pack_operation(entry)?.ok_or_else(invalid)?;
    if crate::sha256(&entry.canonical()) != entry.hash
        || verifier.trusted_public_key(&Actor::Analyst)? != entry.public_key
    {
        return Err(invalid());
    }
    verifier
        .verify(&entry.public_key, &entry.hash, &entry.sig)
        .map_err(|_| invalid())?;
    Ok(admission)
}

impl Engine<'_> {
    pub fn admit_sigma_pack<T>(
        &self,
        admission: &SigmaPackAdmissionV1,
        publish: impl FnOnce(&SignedOperation, &dyn Fn() -> Result<(), AppError>) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        self.require_attended_analyst("admit Sigma pack")?;
        let _lock = self.audit_log.lock_global_operations()?;
        if self.admitted_sigma_pack(admission.pack_manifest)?.is_some() {
            return Err(AppError::Policy(
                "This Sigma pack is already admitted".into(),
            ));
        }
        let payload = admission
            .encode()
            .map_err(|_| AppError::Policy("Invalid Sigma pack admission".into()))?;
        let entry = self.sign_global_operation_unlocked(payload)?;
        publish(&entry, &|| self.audit_log.append_global_operation(&entry))
    }

    pub fn admitted_sigma_pack(
        &self,
        manifest: [u8; 32],
    ) -> Result<Option<SignedOperation>, AppError> {
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        let mut selected = None;
        for entry in entries {
            if sigma_pack_operation(&entry)?.is_some_and(|proof| proof.pack_manifest == manifest)
                && selected.replace(entry).is_some()
            {
                return Err(AppError::InvalidChain(0));
            }
        }
        Ok(selected)
    }
}
