use super::{
    DomainError, MappingLineageV1, MappingRunV1, ParquetArtifactV3, ParquetLayoutV1, Pending,
    invalid,
};

impl MappingLineageV1 {
    pub fn mapping_run(&mut self, receipt: &MappingRunV1) -> Result<(), DomainError> {
        let Some(Pending::Mapping { profile, outputs }) = &self.pending else {
            return Err(invalid());
        };
        let profile = self.profiles.get(profile).ok_or_else(invalid)?;
        receipt.verify(profile, outputs)?;
        let outputs = outputs.clone();
        let inputs = profile.inputs().to_vec();
        self.activate(&outputs)?;
        for input in inputs {
            self.used_sources.insert(input.source().clone());
            self.completed_inputs.insert(input.set().clone());
        }
        self.pending = None;
        Ok(())
    }
    pub fn layout(&mut self, receipt: &ParquetLayoutV1) -> Result<(), DomainError> {
        let Some(Pending::Layout(child)) = &self.pending else {
            return Err(invalid());
        };
        let crate::ArtifactDerivationV1::Layout { parents } = child.pipeline().derivation() else {
            return Err(invalid());
        };
        let originals = parents
            .iter()
            .map(|p| self.all.get(p.identity()).cloned().ok_or_else(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        receipt.verify(&originals, child)?;
        let retired = parents
            .iter()
            .map(|p| p.identity().clone())
            .collect::<Vec<_>>();
        let child = child.as_ref().clone();
        self.activate(&[child])?;
        for id in retired {
            self.active.remove(&id);
        }
        self.pending = None;
        Ok(())
    }
    fn activate(&mut self, artifacts: &[ParquetArtifactV3]) -> Result<(), DomainError> {
        // Validate the complete mutation before changing any active inventory.
        let ids = artifacts
            .iter()
            .map(ParquetArtifactV3::identity)
            .collect::<Result<Vec<_>, _>>()?;
        if artifacts
            .iter()
            .zip(&ids)
            .any(|(a, id)| self.paths.contains(&a.core().path) || self.all.contains_key(id))
        {
            return Err(invalid());
        }
        for (artifact, id) in artifacts.iter().zip(ids) {
            self.paths.insert(artifact.core().path.clone());
            self.all.insert(id.clone(), artifact.clone());
            self.active.insert(id);
        }
        Ok(())
    }
}
