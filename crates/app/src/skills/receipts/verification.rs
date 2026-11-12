use super::{SkillLoadResult, SkillLoadV1, SkillSnapshotId, SkillSnapshotV1, invalid};
use crate::{
    Actor, AppError, AuditEventKind, GLOBAL_OPERATION_SCOPE, SignedEntry, SignedOperation,
    SkillCompiler, Verifier, hex, sha256,
};
use std::collections::{BTreeMap, BTreeSet};

type TurnBudget = (BTreeSet<SkillSnapshotId>, usize, u64);
#[derive(Default)]
pub struct SkillReceiptVerifier {
    snapshots: BTreeMap<SkillSnapshotId, SkillSnapshotV1>,
    turns: BTreeMap<String, TurnBudget>,
    bytes: usize,
}
impl SkillReceiptVerifier {
    pub fn accept(
        &mut self,
        entry: &SignedEntry,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), AppError> {
        match entry.kind {
            AuditEventKind::SkillSnapshotV1 => {
                if entry.actor != Actor::Analyst || entry.evidence.is_some() {
                    return Err(invalid());
                }
                let snapshot = SkillSnapshotV1::decode(&entry.payload)?;
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
    pub fn snapshots(&self) -> impl Iterator<Item = &SkillSnapshotV1> {
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
                verify_skill_admission(snapshot, proof, verifier, analyst)?;
            }
        }
        Ok(())
    }
}

pub fn skill_admission_references(entries: &[SignedEntry]) -> Result<BTreeSet<String>, AppError> {
    let mut result = BTreeSet::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SkillSnapshotV1)
    {
        if let Some(hash) = SkillSnapshotV1::decode(&entry.payload)?.admission() {
            result.insert(hash.into());
        }
        if result.len() > 256 {
            return Err(invalid());
        }
    }
    Ok(result)
}

pub fn verify_skill_admission(
    snapshot: &SkillSnapshotV1,
    proof: &SignedOperation,
    verifier: &dyn Verifier,
    analyst: &[u8],
) -> Result<(), AppError> {
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
    {
        return Err(invalid());
    }
    Ok(())
}
