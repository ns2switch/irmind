mod activation;
use super::{
    DomainError, EvidenceHash, MappingProfileV1, MappingRunV1, MappingSnapshotV1,
    ParquetArtifactV3, ParquetLayoutV1, SourceRecordSetV1, invalid,
};
use crate::{ArtifactDerivationV1, SourceManifestV2};
use std::collections::{BTreeMap, BTreeSet};

enum Pending {
    Mapping {
        profile: EvidenceHash,
        outputs: Vec<ParquetArtifactV3>,
    },
    Layout(Box<ParquetArtifactV3>),
}

/// Pure receipt-gated activation. Retired files remain in the authenticated inventory.
#[derive(Default)]
pub struct MappingLineageV1 {
    sources: BTreeMap<EvidenceHash, SourceManifestV2>,
    inputs: BTreeMap<EvidenceHash, SourceRecordSetV1>,
    snapshots: BTreeMap<EvidenceHash, MappingSnapshotV1>,
    profiles: BTreeMap<EvidenceHash, MappingProfileV1>,
    all: BTreeMap<EvidenceHash, ParquetArtifactV3>,
    active: BTreeSet<EvidenceHash>,
    paths: BTreeSet<String>,
    used_sources: BTreeSet<EvidenceHash>,
    completed_inputs: BTreeSet<EvidenceHash>,
    pending: Option<Pending>,
}
impl MappingLineageV1 {
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn source(&mut self, source: SourceManifestV2) -> Result<(), DomainError> {
        self.idle()?;
        let id = super::source_set::manifest_identity(&source)?;
        self.sources.insert(id, source);
        Ok(())
    }
    pub fn input(&mut self, input: SourceRecordSetV1) -> Result<(), DomainError> {
        self.idle()?;
        let manifest = self
            .sources
            .get(input.manifest_identity())
            .ok_or_else(invalid)?;
        input.validate_manifest(manifest)?;
        if self.used_sources.contains(input.source()) {
            return Err(invalid());
        }
        self.inputs.insert(input.identity()?, input);
        Ok(())
    }
    pub fn snapshot(&mut self, snapshot: MappingSnapshotV1) -> Result<(), DomainError> {
        self.idle()?;
        self.snapshots
            .insert(snapshot.reference()?.snapshot().clone(), snapshot);
        Ok(())
    }
    pub fn profile(&mut self, profile: MappingProfileV1) -> Result<(), DomainError> {
        self.idle()?;
        for input in profile.inputs() {
            let set = self.inputs.get(input.set()).ok_or_else(invalid)?;
            if input.source() != set.source()
                || input.records() != set.records()
                || self.used_sources.contains(input.source())
            {
                return Err(invalid());
            }
        }
        for entry in profile.catalog() {
            let snapshot = self.snapshots.get(entry.snapshot()).ok_or_else(invalid)?;
            if snapshot.mapping() != entry.mapping() {
                return Err(invalid());
            }
        }
        let id = profile.identity()?;
        if self.profiles.contains_key(&id) {
            return Err(invalid());
        }
        self.profiles.insert(id.clone(), profile);
        self.pending = Some(Pending::Mapping {
            profile: id,
            outputs: vec![],
        });
        Ok(())
    }
    pub fn artifact(&mut self, artifact: ParquetArtifactV3) -> Result<(), DomainError> {
        if self.paths.contains(&artifact.core().path)
            || self.all.contains_key(&artifact.identity()?)
        {
            return Err(invalid());
        }
        self.check_bindings(&artifact)?;
        match artifact.pipeline().derivation() {
            ArtifactDerivationV1::Mapped => {
                let Some(Pending::Mapping { profile, outputs }) = &mut self.pending else {
                    return Err(invalid());
                };
                if artifact.bindings().iter().any(|b| b.profile() != profile)
                    || outputs
                        .iter()
                        .any(|a| a.core().path == artifact.core().path)
                {
                    return Err(invalid());
                }
                outputs.push(artifact);
            }
            ArtifactDerivationV1::Layout { parents } => {
                self.idle()?;
                if parents.iter().any(|p| !self.active.contains(p.identity())) {
                    return Err(invalid());
                }
                self.pending = Some(Pending::Layout(Box::new(artifact)));
            }
        }
        Ok(())
    }
    pub fn ensure_complete(&self) -> Result<(), DomainError> {
        self.idle()?;
        if self
            .inputs
            .keys()
            .any(|id| !self.completed_inputs.contains(id))
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn all(&self) -> Result<Vec<&ParquetArtifactV3>, DomainError> {
        self.ensure_complete()?;
        Ok(self.all.values().collect())
    }
    pub fn active(&self) -> Result<Vec<&ParquetArtifactV3>, DomainError> {
        self.ensure_complete()?;
        self.active
            .iter()
            .map(|id| self.all.get(id).ok_or_else(invalid))
            .collect()
    }
    fn idle(&self) -> Result<(), DomainError> {
        if self.pending.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
    fn check_bindings(&self, artifact: &ParquetArtifactV3) -> Result<(), DomainError> {
        for binding in artifact.bindings() {
            let profile = self.profiles.get(binding.profile()).ok_or_else(invalid)?;
            let input = self.inputs.get(binding.input().set()).ok_or_else(invalid)?;
            if binding.catalog() != &profile.catalog_identity()
                || !profile.inputs().contains(binding.input())
                || binding.decoder() != input.decoder()
                || binding
                    .mapping()
                    .is_some_and(|m| !profile.catalog().iter().any(|s| s.mapping() == m))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
