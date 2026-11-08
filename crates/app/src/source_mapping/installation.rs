//! Analyst-signed definition snapshots live in the existing global audit chain.
use super::{MappingCatalog, MappingError, MappingManifest, MappingProvenance};
use crate::{Actor, AppError, Engine, GLOBAL_OPERATION_SCOPE, SignedOperation, Verifier};
use irmind_domain::{EvidenceHash, MappingSnapshotV1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PREFIX: &str = "irmind-mapping-definition-v1:";
const MAX_OPERATION: usize = 768 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    version: u8,
    active: bool,
    previous: Option<String>,
    manifest: String,
}

#[derive(Clone)]
pub struct ApprovedMappingDefinition {
    manifest: MappingManifest,
    operation: SignedOperation,
    active: bool,
}
impl ApprovedMappingDefinition {
    pub const fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    pub const fn operation(&self) -> &SignedOperation {
        &self.operation
    }
    pub const fn active(&self) -> bool {
        self.active
    }
    pub fn installed_manifest(&self) -> Result<MappingManifest, MappingError> {
        let MappingProvenance::BundledDefinition {
            canonical,
            interpreter,
        } = self.manifest.provenance()
        else {
            return Err(MappingError::InvalidDefinition);
        };
        MappingManifest::try_new(
            self.manifest.identity().clone(),
            self.manifest.selectors().to_vec(),
            MappingProvenance::InstalledDefinition {
                canonical: canonical.clone(),
                interpreter: interpreter.clone(),
                operation: EvidenceHash::from_bytes(self.operation.hash),
            },
            self.manifest.compatibility_projection(),
        )
    }
}
impl std::fmt::Debug for ApprovedMappingDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedMappingDefinition")
            .field("identity", self.manifest.identity())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

pub(super) fn operation_definition(
    operation: &SignedOperation,
) -> Result<Option<ApprovedMappingDefinition>, MappingError> {
    let Some(payload) = operation.operation.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    if payload.len() > MAX_OPERATION {
        return Err(MappingError::InvalidDefinition);
    }
    let bytes = hex::decode(payload).map_err(|_| MappingError::InvalidDefinition)?;
    let change: Change =
        serde_json::from_slice(&bytes).map_err(|_| MappingError::InvalidDefinition)?;
    if change.version != 1
        || serde_json::to_vec(&change).map_err(|_| MappingError::InvalidDefinition)? != bytes
        || change
            .previous
            .as_deref()
            .is_some_and(|h| EvidenceHash::parse(h).is_err())
    {
        return Err(MappingError::InvalidDefinition);
    }
    let snapshot =
        MappingSnapshotV1::decode(&change.manifest).map_err(|_| MappingError::InvalidDefinition)?;
    let manifest = MappingManifest::from_snapshot(&snapshot)?;
    if !matches!(
        manifest.provenance(),
        MappingProvenance::BundledDefinition { .. }
    ) {
        return Err(MappingError::InvalidDefinition);
    }
    Ok(Some(ApprovedMappingDefinition {
        manifest,
        operation: operation.clone(),
        active: change.active,
    }))
}

/// Authentication checks metadata and signatures only; it never evaluates a definition.
pub fn verify_mapping_installation(
    manifest: &MappingManifest,
    proof: &SignedOperation,
    verifier: &dyn Verifier,
    analyst_key: &[u8],
) -> Result<(), AppError> {
    let MappingProvenance::InstalledDefinition { operation, .. } = manifest.provenance() else {
        return Ok(());
    };
    let bad = || MappingError::InvalidDefinition.into_app();
    if proof.case_id != GLOBAL_OPERATION_SCOPE
        || proof.actor != Actor::Analyst
        || proof.seq == 0
        || proof.public_key != analyst_key
        || proof.hash != crate::sha256(&proof.canonical())
        || operation != &EvidenceHash::from_bytes(proof.hash)
    {
        return Err(bad());
    }
    verifier
        .verify(&proof.public_key, &proof.hash, &proof.sig)
        .map_err(|_| bad())?;
    let approved = operation_definition(proof)
        .map_err(MappingError::into_app)?
        .ok_or_else(bad)?;
    if !approved.active
        || approved
            .installed_manifest()
            .map_err(MappingError::into_app)?
            != *manifest
    {
        return Err(bad());
    }
    Ok(())
}

impl Engine<'_> {
    pub fn approved_mapping_definitions(&self) -> Result<Vec<ApprovedMappingDefinition>, AppError> {
        let entries = self.audit_log.global_operations()?;
        self.verify_global_operation_entries(&entries)?;
        let mut latest = BTreeMap::<String, ApprovedMappingDefinition>::new();
        let mut versions = BTreeMap::new();
        for operation in entries {
            let Some(approved) =
                operation_definition(&operation).map_err(MappingError::into_app)?
            else {
                continue;
            };
            let payload = operation
                .operation
                .strip_prefix(PREFIX)
                .ok_or_else(|| MappingError::InvalidDefinition.into_app())?;
            let change: Change = serde_json::from_slice(
                &hex::decode(payload).map_err(|_| MappingError::InvalidDefinition.into_app())?,
            )
            .map_err(|_| MappingError::InvalidDefinition.into_app())?;
            let identity = approved.manifest.identity();
            let previous = latest
                .get(identity.id())
                .map(|p| crate::hex(&p.operation.hash));
            if change.previous != previous {
                return Err(MappingError::InvalidDefinition.into_app());
            }
            let key = (identity.id().to_owned(), identity.version().to_owned());
            if versions
                .insert(key, identity.implementation().clone())
                .is_some_and(|old| old != *identity.implementation())
            {
                return Err(MappingError::InvalidDefinition.into_app());
            }
            latest.insert(identity.id().into(), approved);
            if latest.len() > 256
                || versions.len() > 4096
                || latest.values().filter(|m| m.active).count() > 64
            {
                return Err(MappingError::InvalidDefinition.into_app());
            }
        }
        Ok(latest.into_values().collect())
    }
    /// Historical active authorizations remain available for exact case replay.
    /// New ingestions must use `approved_mapping_definitions`, the latest state.
    pub fn mapping_definition_history(&self) -> Result<Vec<ApprovedMappingDefinition>, AppError> {
        self.approved_mapping_definitions()?;
        self.audit_log
            .global_operations()?
            .iter()
            .filter_map(|operation| match operation_definition(operation) {
                Ok(Some(approved)) if approved.active => Some(Ok(approved)),
                Ok(_) => None,
                Err(error) => Some(Err(error.into_app())),
            })
            .collect()
    }

    pub fn change_mapping_definition(
        &self,
        base: &MappingCatalog,
        manifest: &MappingManifest,
        active: bool,
    ) -> Result<ApprovedMappingDefinition, AppError> {
        self.require_attended_analyst("change mapping definition")?;
        if !matches!(
            manifest.provenance(),
            MappingProvenance::BundledDefinition { .. }
        ) {
            return Err(MappingError::InvalidDefinition.into_app());
        }
        let _lock = self.audit_log.lock_global_operations()?;
        let current = self.approved_mapping_definitions()?;
        validate_history(&self.audit_log.global_operations()?, manifest)
            .map_err(MappingError::into_app)?;
        preflight(base, &current, manifest, active).map_err(MappingError::into_app)?;
        let change = Change {
            version: 1,
            active,
            previous: current
                .iter()
                .find(|m| m.manifest.identity().id() == manifest.identity().id())
                .map(|m| crate::hex(&m.operation.hash)),
            manifest: manifest
                .snapshot()
                .map_err(MappingError::into_app)?
                .encode()
                .map_err(|_| MappingError::InvalidDefinition.into_app())?,
        };
        let payload = hex::encode(
            serde_json::to_vec(&change).map_err(|_| MappingError::InvalidDefinition.into_app())?,
        );
        if payload.len() > MAX_OPERATION {
            return Err(MappingError::InvalidDefinition.into_app());
        }
        self.append_global_operation_unlocked(format!("{PREFIX}{payload}"))?;
        self.approved_mapping_definitions()?
            .into_iter()
            .find(|m| m.manifest.identity() == manifest.identity())
            .ok_or_else(|| MappingError::InvalidDefinition.into_app())
    }
}

fn preflight(
    base: &MappingCatalog,
    current: &[ApprovedMappingDefinition],
    candidate: &MappingManifest,
    active: bool,
) -> Result<(), MappingError> {
    for selector in candidate.selectors() {
        for version in selector.versions() {
            base.decoder(selector.parser(), version)?;
        }
    }
    let mut effective = base
        .manifests()
        .map(|m| (m.identity().id().to_owned(), m.clone()))
        .collect::<BTreeMap<_, _>>();
    for prior in current {
        effective.remove(prior.manifest.identity().id());
        if prior.active {
            effective.insert(
                prior.manifest.identity().id().into(),
                prior.manifest.clone(),
            );
        }
    }
    effective.remove(candidate.identity().id());
    if active {
        effective.insert(candidate.identity().id().into(), candidate.clone());
    }
    if effective.len() > 64 {
        return Err(MappingError::InvalidManifest);
    }
    let manifests = effective.values().collect::<Vec<_>>();
    for (i, first) in manifests.iter().enumerate() {
        for second in &manifests[i + 1..] {
            for a in first.selectors() {
                for b in second.selectors() {
                    if let Some(selector) = a.overlap_witness(b) {
                        return Err(MappingError::Overlap {
                            first: first.identity().id().into(),
                            second: second.identity().id().into(),
                            selector,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_history(
    entries: &[SignedOperation],
    candidate: &MappingManifest,
) -> Result<(), MappingError> {
    let mut ids = std::collections::BTreeSet::new();
    let mut versions = BTreeMap::new();
    for entry in entries {
        if let Some(approved) = operation_definition(entry)? {
            let identity = approved.manifest.identity();
            ids.insert(identity.id().to_owned());
            versions.insert(
                (identity.id().to_owned(), identity.version().to_owned()),
                identity.implementation().clone(),
            );
        }
    }
    let identity = candidate.identity();
    ids.insert(identity.id().to_owned());
    let previous = versions.insert(
        (identity.id().to_owned(), identity.version().to_owned()),
        identity.implementation().clone(),
    );
    if ids.len() > 256
        || versions.len() > 4096
        || previous.is_some_and(|hash| hash != *identity.implementation())
    {
        return Err(MappingError::InvalidDefinition);
    }
    Ok(())
}
