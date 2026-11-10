use super::{Arc, MappingCatalog, MappingError, SourceDecoder, SourceMapper};
use irmind_domain::{MappingProfileV1, MappingSnapshotRefV1};

impl MappingCatalog {
    pub(super) fn reconstruct_profile(
        &self,
        profile: &MappingProfileV1,
    ) -> Result<Self, MappingError> {
        let mut decoders = self.decoders.clone();
        let mut mappings = Vec::new();
        for reference in profile.catalog() {
            let (mapper, decoder) = self.resolve_reference(reference)?;
            if let Some(decoder) = decoder {
                let id = decoder.identity();
                decoders
                    .entry((id.name.into(), id.version.into()))
                    .or_insert(decoder);
            }
            mappings.push(mapper);
        }
        // Recheck overlap and capacity using only implementations in the signed
        // profile. Archived definitions never enter the active ingestion catalog.
        Self::freeze_verified(
            decoders.into_values().collect(),
            mappings,
            self.proofs.clone(),
        )
    }

    fn resolve_reference(
        &self,
        reference: &MappingSnapshotRefV1,
    ) -> Result<ResolvedReference, MappingError> {
        if let Some(mapper) = self
            .mappings
            .get(reference.mapping().id())
            .filter(|mapper| mapper.manifest().identity() == reference.mapping())
        {
            check_reference(mapper.as_ref(), reference)?;
            return Ok((Arc::clone(mapper), None));
        }
        let compiled = self
            .definition_history
            .as_ref()
            .ok_or(MappingError::UnsupportedVersion)?
            .resolve(reference.mapping())?;
        let mapper = compiled.extraction_mapper();
        check_reference(mapper.as_ref(), reference)?;
        Ok((Arc::clone(mapper), Some(Arc::clone(compiled.decoder()))))
    }
}

type ResolvedReference = (Arc<dyn SourceMapper>, Option<Arc<dyn SourceDecoder>>);

fn check_reference(
    mapper: &dyn SourceMapper,
    reference: &MappingSnapshotRefV1,
) -> Result<(), MappingError> {
    if mapper
        .manifest()
        .snapshot()?
        .reference()
        .map_err(|_| MappingError::InvalidManifest)?
        != *reference
    {
        return Err(MappingError::UnsupportedVersion);
    }
    Ok(())
}
