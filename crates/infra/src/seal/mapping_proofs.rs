//! V6 carries only global signatures referenced by mapping snapshots.
use super::{AppError, AuditLog, CancellationToken, CaseId, LocalStore, LocalVerifier};
use irmind_app::{
    SignedEntry, SignedOperation,
    source_mapping::{
        MappingManifest, mapping_installation_proofs, required_mapping_installations,
    },
};
use irmind_domain::EvidenceHash;
use std::{collections::BTreeMap, fs::File};

pub(super) fn collect(
    entry: &SignedEntry,
    required: &mut BTreeMap<EvidenceHash, MappingManifest>,
) -> Result<(), AppError> {
    for (key, manifest) in required_mapping_installations([(entry.kind, entry.payload.as_str())])? {
        if required.get(&key).is_some_and(|old| old != &manifest) {
            return Err(AppError::InvalidChain(entry.seq));
        }
        required.insert(key, manifest);
        if required.len() > 4096 {
            return Err(AppError::InvalidChain(entry.seq));
        }
    }
    Ok(())
}

pub(super) fn write(
    store: &LocalStore,
    case: &CaseId,
    analyst_key: &[u8],
    out: &mut File,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    use std::io::Write as _;
    let required = required_mapping_installations(
        store
            .entries(case)?
            .iter()
            .map(|e| (e.kind, e.payload.as_str())),
    )?;
    let verifier = LocalVerifier {
        trusted: BTreeMap::new(),
    };
    let proofs = mapping_installation_proofs(
        &required,
        &store.global_operations()?,
        &verifier,
        analyst_key,
    )?;
    out.write_all(&(proofs.len() as u64).to_be_bytes())
        .map_err(super::storage)?;
    for proof in proofs {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        super::export_v4::write_frame(out, &serde_json::to_vec(&proof).map_err(super::storage)?)?;
    }
    Ok(())
}

pub(super) fn read(
    input: &mut File,
    required: &BTreeMap<EvidenceHash, MappingManifest>,
    verifier: &dyn irmind_app::Verifier,
    analyst_key: &[u8],
) -> Result<(), AppError> {
    let count = super::frames::read_u64(input)?;
    if count != required.len() as u64 {
        return Err(AppError::InvalidChain(0));
    }
    let mut proofs = Vec::new();
    let mut previous = None;
    for _ in 0..count {
        let proof: SignedOperation =
            serde_json::from_slice(&super::frames::read_frame(input)?).map_err(super::storage)?;
        if previous.is_some_and(|old| old >= proof.hash) {
            return Err(AppError::InvalidChain(proof.seq));
        }
        previous = Some(proof.hash);
        proofs.push(proof);
    }
    mapping_installation_proofs(required, &proofs, verifier, analyst_key)?;
    Ok(())
}

impl LocalStore {
    pub(crate) fn verify_installed_mapping_metadata(
        &self,
        entries: &[SignedEntry],
    ) -> Result<(), AppError> {
        let required =
            required_mapping_installations(entries.iter().map(|e| (e.kind, e.payload.as_str())))?;
        if required.is_empty() {
            return Ok(());
        }
        let key = entries
            .first()
            .filter(|entry| entry.actor == irmind_domain::Actor::Analyst)
            .ok_or(AppError::InvalidChain(0))?;
        let verifier = LocalVerifier {
            trusted: BTreeMap::new(),
        };
        mapping_installation_proofs(
            &required,
            &self.global_operations()?,
            &verifier,
            &key.public_key,
        )?;
        Ok(())
    }
}
