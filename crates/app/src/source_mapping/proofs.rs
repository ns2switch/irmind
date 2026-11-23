//! Portable authorization material is separate from canonical mapping snapshots.
use super::{MappingError, MappingManifest, MappingProvenance, verify_mapping_installation};
use crate::{AppError, SignedOperation, Verifier};
use irmind_domain::{AuditEventKind, EvidenceHash, MappingProfileRecordV1};
use std::collections::{BTreeMap, BTreeSet};

pub fn required_mapping_installations<'a>(
    events: impl IntoIterator<Item = (AuditEventKind, &'a str)>,
) -> Result<BTreeMap<EvidenceHash, MappingManifest>, AppError> {
    let mut required = BTreeMap::new();
    for (kind, payload) in events {
        if kind != AuditEventKind::MappingProfileV1 {
            continue;
        }
        let MappingProfileRecordV1::Snapshot(snapshot) = MappingProfileRecordV1::decode(payload)
            .map_err(|_| AppError::from(MappingError::InvalidManifest))?
        else {
            continue;
        };
        let manifest = MappingManifest::from_snapshot(&snapshot).map_err(AppError::from)?;
        if let MappingProvenance::InstalledDefinition { operation, .. } = manifest.provenance() {
            if required
                .get(operation)
                .is_some_and(|prior| prior != &manifest)
            {
                return Err(AppError::from(MappingError::InvalidDefinition));
            }
            required.insert(operation.clone(), manifest);
        }
    }
    Ok(required)
}

/// Count distinct native build recipes in an authenticated snapshot.
pub(crate) fn native_mapping_build_counts(
    entries: &[crate::SignedEntry],
) -> Result<(usize, usize), AppError> {
    let (mut provisional, mut release) = (BTreeSet::new(), BTreeSet::new());
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::MappingProfileV1)
    {
        let MappingProfileRecordV1::Snapshot(snapshot) =
            MappingProfileRecordV1::decode(&entry.payload)
                .map_err(|_| MappingError::InvalidManifest)?
        else {
            continue;
        };
        let manifest = MappingManifest::from_snapshot(&snapshot)?;
        if let Some(is_provisional) = manifest.native_build_is_provisional() {
            let builds = if is_provisional {
                &mut provisional
            } else {
                &mut release
            };
            builds.insert(manifest.identity().implementation().clone());
        }
    }
    Ok((provisional.len(), release.len()))
}

/// Exactly one matching proof per referenced installation; unrelated global
/// operations are not exported and cannot substitute another analyst's signature.
pub fn mapping_installation_proofs(
    required: &BTreeMap<EvidenceHash, MappingManifest>,
    operations: &[SignedOperation],
    verifier: &dyn Verifier,
    analyst_key: &[u8],
) -> Result<Vec<SignedOperation>, AppError> {
    let mut selected = BTreeMap::new();
    for operation in operations {
        let hash = EvidenceHash::from_bytes(operation.hash);
        if let Some(manifest) = required.get(&hash) {
            verify_mapping_installation(manifest, operation, verifier, analyst_key)?;
            if selected.insert(hash, operation.clone()).is_some() {
                return Err(AppError::from(MappingError::InvalidDefinition));
            }
        }
    }
    if selected.len() != required.len() {
        return Err(AppError::from(MappingError::InvalidDefinition));
    }
    Ok(selected.into_values().collect())
}

impl crate::Engine<'_> {
    pub(crate) fn verify_mapping_events<'a>(
        &self,
        events: impl IntoIterator<Item = (AuditEventKind, &'a str)>,
    ) -> Result<(), AppError> {
        let required = required_mapping_installations(events)?;
        if required.is_empty() {
            return Ok(());
        }
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        mapping_installation_proofs(
            &required,
            &entries,
            self.verifier.as_ref(),
            &self.verifier.trusted_public_key(&crate::Actor::Analyst)?,
        )?;
        Ok(())
    }
}
