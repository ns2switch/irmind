use super::{SkillLoadResult, SkillLoadV1, SkillSnapshotId, SkillSnapshotV2, invalid};
use crate::{
    Actor, AppError, AuditEventKind, GLOBAL_OPERATION_SCOPE, SignedEntry, SignedOperation,
    SkillCompiler, Verifier, hex, sha256,
};
use std::collections::{BTreeMap, BTreeSet};

type TurnBudget = (BTreeSet<SkillSnapshotId>, usize, u64);
#[derive(Default)]
pub struct SkillReceiptVerifier {
    snapshots: BTreeMap<SkillSnapshotId, SkillSnapshotV2>,
    turns: BTreeMap<String, TurnBudget>,
    bytes: usize,
    catalog_verified: BTreeSet<SkillSnapshotId>,
}
impl SkillReceiptVerifier {
    pub fn catalog_requirements(
        &self,
        proofs: &[SignedOperation],
        verifier: &dyn Verifier,
        analyst: &[u8],
    ) -> Result<Vec<crate::catalog::CatalogProofRequirement>, AppError> {
        let expected = self.admissions();
        if expected.len() != proofs.len()
            || proofs.windows(2).any(|pair| pair[0].hash >= pair[1].hash)
            || proofs
                .iter()
                .map(|proof| hex(&proof.hash))
                .collect::<BTreeSet<_>>()
                != expected
        {
            return Err(invalid());
        }
        let mut required = BTreeMap::new();
        for snapshot in self.snapshots.values() {
            let Some(reference) = snapshot.admission() else {
                continue;
            };
            let proof = proofs
                .iter()
                .find(|proof| hex(&proof.hash) == reference)
                .ok_or_else(invalid)?;
            let admission = authenticated_admission(snapshot, proof, verifier, analyst)?;
            if let Some(receipt) = &admission.catalog {
                let requirement = crate::catalog::CatalogProofRequirement::new(
                    receipt.proof_id(),
                    receipt.release_tag(),
                )?;
                if required.get(&receipt.proof_id()).is_some_and(
                    |old: &crate::catalog::CatalogProofRequirement| {
                        old.release().tag() != receipt.release_tag()
                    },
                ) {
                    return Err(invalid());
                }
                required.insert(receipt.proof_id(), requirement);
            }
        }
        Ok(required.into_values().collect())
    }

    pub fn accept(
        &mut self,
        entry: &SignedEntry,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), AppError> {
        match entry.kind {
            AuditEventKind::RetiredSkillSnapshot => {
                return Err(AppError::Fixed(crate::FixedAppError::RetiredCaseFormat));
            }
            AuditEventKind::SkillSnapshotV2 => {
                if entry.actor != Actor::Analyst || entry.evidence.is_some() {
                    return Err(invalid());
                }
                let snapshot = SkillSnapshotV2::decode(&entry.payload)?;
                snapshot.compile(compiler)?;
                let identity = snapshot.identity()?;
                if self.snapshots.contains_key(&identity) || self.snapshots.len() >= 256 {
                    return Err(invalid());
                }
                self.bytes = self
                    .bytes
                    .checked_add(snapshot.package()?.bytes())
                    .ok_or_else(invalid)?;
                if self.bytes > 16 * 1024 * 1024 {
                    return Err(invalid());
                }
                self.snapshots.insert(identity, snapshot);
            }
            AuditEventKind::SkillLoadV1 => {
                if !matches!(entry.actor, Actor::Agent(_)) || entry.evidence.is_some() {
                    return Err(invalid());
                }
                self.load(&SkillLoadV1::decode(&entry.payload)?)?;
            }
            _ => {}
        }
        Ok(())
    }
    fn load(&mut self, load: &SkillLoadV1) -> Result<(), AppError> {
        let identity = load.snapshot()?;
        let snapshot = self.snapshots.get(&identity).ok_or_else(invalid)?;
        let package = snapshot.package()?;
        let resource = package
            .resources()
            .values()
            .find(|r| r.path().as_str() == load.resource())
            .ok_or_else(invalid)?;
        let range = load.range()?;
        if resource.untrusted_text().get(range).is_none() {
            return Err(invalid());
        }
        if matches!(
            load.result(),
            SkillLoadResult::Loaded | SkillLoadResult::Blocked
        ) {
            let (packages, reads, bytes) = self.turns.entry(load.turn().into()).or_default();
            packages.insert(identity);
            *reads += 1;
            *bytes += load.bytes();
            if packages.len() > 4 || *reads > 8 || *bytes > 64 * 1024 {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn snapshots(&self) -> impl Iterator<Item = &SkillSnapshotV2> {
        self.snapshots.values()
    }
    pub fn admissions(&self) -> BTreeSet<String> {
        self.snapshots
            .values()
            .filter_map(|s| s.admission().map(str::to_owned))
            .collect()
    }
    pub fn verify_admissions(
        &self,
        proofs: &[SignedOperation],
        verifier: &dyn Verifier,
        analyst: &[u8],
    ) -> Result<(), AppError> {
        let expected = self.admissions();
        if expected.len() != proofs.len() || proofs.windows(2).any(|p| p[0].hash >= p[1].hash) {
            return Err(invalid());
        }
        let supplied: BTreeSet<_> = proofs.iter().map(|p| hex(&p.hash)).collect();
        if supplied != expected {
            return Err(invalid());
        }
        for snapshot in self.snapshots.values() {
            if let Some(reference) = snapshot.admission() {
                let proof = proofs
                    .iter()
                    .find(|p| hex(&p.hash) == reference)
                    .ok_or_else(invalid)?;
                authenticated_admission(snapshot, proof, verifier, analyst)?;
                if snapshot.origin() == crate::SkillOrigin::Catalog
                    && !self.catalog_verified.contains(&snapshot.identity()?)
                {
                    return Err(crate::catalog::CatalogError::Unavailable.into());
                }
            }
        }
        Ok(())
    }
}

impl SkillReceiptVerifier {
    /// Check exactly the required publisher proofs after independent index
    /// verification. This grants no installation, load or dispatch permission.
    pub fn verify_catalog_admissions(
        &mut self,
        proofs: &[SignedOperation],
        indices: &[crate::catalog::VerifiedCatalogIndex],
        verifier: &dyn Verifier,
        analyst: &[u8],
        compiler: &dyn SkillCompiler,
    ) -> Result<(), AppError> {
        self.catalog_verified.clear();
        if indices.len() > 256
            || indices
                .windows(2)
                .any(|pair| pair[0].proof_id() >= pair[1].proof_id())
        {
            return Err(invalid());
        }
        let mut total = 0usize;
        for index in indices {
            total = total
                .checked_add(index.raw().index().len() + 72)
                .ok_or_else(invalid)?;
            if total > 16 * 1024 * 1024 {
                return Err(invalid());
            }
        }
        let mut used = BTreeSet::new();
        let mut accepted = BTreeSet::new();
        for snapshot in self
            .snapshots
            .values()
            .filter(|snapshot| snapshot.origin() == crate::SkillOrigin::Catalog)
        {
            let reference = snapshot.admission().ok_or_else(invalid)?;
            let proof = proofs
                .iter()
                .find(|proof| hex(&proof.hash) == reference)
                .ok_or_else(invalid)?;
            let admission = authenticated_admission(snapshot, proof, verifier, analyst)?;
            let receipt = admission.catalog.as_ref().ok_or_else(invalid)?;
            let index = indices
                .iter()
                .find(|index| index.proof_id() == receipt.proof_id())
                .ok_or_else(invalid)?;
            receipt.check(index, &snapshot.compile(compiler)?)?;
            used.insert(index.proof_id());
            accepted.insert(snapshot.identity()?);
        }
        if used.len() != indices.len() {
            return Err(invalid());
        }
        self.catalog_verified = accepted;
        // The full admission set, including non-catalog packages, must match.
        if let Err(error) = self.verify_admissions(proofs, verifier, analyst) {
            self.catalog_verified.clear();
            return Err(error);
        }
        Ok(())
    }
}

pub fn skill_admission_references(entries: &[SignedEntry]) -> Result<BTreeSet<String>, AppError> {
    let mut result = BTreeSet::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SkillSnapshotV2)
    {
        if let Some(hash) = SkillSnapshotV2::decode(&entry.payload)?.admission() {
            result.insert(hash.into());
        }
        if result.len() > 256 {
            return Err(invalid());
        }
    }
    Ok(result)
}

fn authenticated_admission(
    snapshot: &SkillSnapshotV2,
    proof: &SignedOperation,
    verifier: &dyn Verifier,
    analyst: &[u8],
) -> Result<super::super::history::Snapshot, AppError> {
    if proof.seq == 0
        || (proof.seq == 1 && proof.prev != [0; 32])
        || proof.actor != Actor::Analyst
        || proof.case_id != GLOBAL_OPERATION_SCOPE
        || proof.public_key != analyst
        || sha256(&proof.canonical()) != proof.hash
        || snapshot.admission() != Some(hex(&proof.hash).as_str())
    {
        return Err(invalid());
    }
    verifier.verify(analyst, &proof.hash, &proof.sig)?;
    let wire = proof
        .operation
        .strip_prefix(super::super::history::PREFIX)
        .ok_or_else(invalid)?;
    if wire.len() > super::super::history::MAX_OPERATION_BYTES {
        return Err(invalid());
    }
    let raw = hex::decode(wire).map_err(|_| invalid())?;
    let admission: super::super::history::Snapshot =
        serde_json::from_slice(&raw).map_err(|_| invalid())?;
    if hex(&raw) != wire
        || serde_json::to_vec(&admission).map_err(|_| invalid())? != raw
        || !admission.active
        || admission.origin != snapshot.origin()
        || admission.name != snapshot.name()?.as_str()
        || admission.skill_version != snapshot.version()
        || admission.package()? != snapshot.package()?
        || admission
            .catalog
            .as_ref()
            .map(crate::catalog::CatalogReceipt::identity)
            .transpose()?
            .map(|id| hex(id.as_bytes()))
            .as_deref()
            != snapshot.catalog_receipt()
    {
        return Err(invalid());
    }
    Ok(admission)
}

/// Verifies non-catalog admission. Catalog provenance additionally requires the
/// full signed index through `SkillReceiptVerifier::verify_catalog_admissions`.
pub fn verify_skill_admission(
    snapshot: &SkillSnapshotV2,
    proof: &SignedOperation,
    verifier: &dyn Verifier,
    analyst: &[u8],
) -> Result<(), AppError> {
    authenticated_admission(snapshot, proof, verifier, analyst)?;
    if snapshot.origin() == crate::SkillOrigin::Catalog {
        return Err(crate::catalog::CatalogError::Unavailable.into());
    }
    Ok(())
}
