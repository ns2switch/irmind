use super::{
    MappingError, MappingIdentityV1, MappingOutput, SourceDecoder, SourceMapper, SourceRecordV1,
};
use std::{collections::BTreeMap, sync::Arc};

/// An immutable snapshot. Replacing one does not mutate an in-flight ingestion.
#[derive(Clone, Default)]
pub struct MappingCatalog {
    decoders: BTreeMap<(String, String), Arc<dyn SourceDecoder>>,
    mappings: BTreeMap<String, Arc<dyn SourceMapper>>,
    proofs: BTreeMap<irmind_domain::EvidenceHash, crate::SignedOperation>,
    pub(crate) definition_history: Option<Arc<crate::definitions::history::DefinitionHistory>>,
}

impl MappingCatalog {
    pub fn freeze(
        decoders: Vec<Arc<dyn SourceDecoder>>,
        mappings: Vec<Arc<dyn SourceMapper>>,
    ) -> Result<Self, MappingError> {
        if mappings.iter().any(|m| {
            matches!(
                m.manifest().provenance(),
                super::MappingProvenance::InstalledDefinition { .. }
            )
        }) {
            return Err(MappingError::InvalidDefinition);
        }
        Self::freeze_verified(decoders, mappings, BTreeMap::new())
    }

    fn freeze_verified(
        decoders: Vec<Arc<dyn SourceDecoder>>,
        mappings: Vec<Arc<dyn SourceMapper>>,
        proofs: BTreeMap<irmind_domain::EvidenceHash, crate::SignedOperation>,
    ) -> Result<Self, MappingError> {
        if decoders.len() > 256 || mappings.len() > 64 {
            return Err(MappingError::InvalidManifest);
        }
        let mut result = Self::default();
        for decoder in decoders {
            let id = decoder.identity();
            let key = (id.name.to_owned(), id.version.to_owned());
            if result.decoders.insert(key, decoder).is_some() {
                return Err(MappingError::DuplicateIdentity);
            }
        }
        for mapper in mappings {
            result.check_candidate(mapper.as_ref())?;
            result
                .mappings
                .insert(mapper.manifest().identity().id().into(), mapper);
        }
        result.proofs = proofs;
        Ok(result)
    }

    /// Check the effective catalog before signing or persisting any operation.
    /// A replacement removes the previous ID atomically in the candidate only.
    pub fn changed(
        &self,
        id: &str,
        replacement: Option<Arc<dyn SourceMapper>>,
    ) -> Result<Self, MappingError> {
        let mut candidate = self.clone();
        candidate.mappings.remove(id);
        if let Some(mapper) = replacement {
            if matches!(
                mapper.manifest().provenance(),
                super::MappingProvenance::InstalledDefinition { .. }
            ) {
                return Err(MappingError::InvalidDefinition);
            }
            if mapper.manifest().identity().id() != id {
                return Err(MappingError::InvalidManifest);
            }
            candidate.check_candidate(mapper.as_ref())?;
            candidate.mappings.insert(id.into(), mapper);
        }
        Ok(candidate)
    }

    fn check_candidate(&self, mapper: &dyn SourceMapper) -> Result<(), MappingError> {
        let manifest = mapper.manifest();
        if self.mappings.contains_key(manifest.identity().id()) || self.mappings.len() >= 64 {
            return Err(MappingError::DuplicateIdentity);
        }
        for selector in manifest.selectors() {
            if selector.versions().iter().any(|v| {
                !self
                    .decoders
                    .contains_key(&(selector.parser().into(), v.clone()))
            }) {
                return Err(MappingError::UnsupportedVersion);
            }
            for previous in self.mappings.values() {
                for other in previous.manifest().selectors() {
                    if let Some(selector) = selector.overlap_witness(other) {
                        return Err(MappingError::Overlap {
                            first: previous.manifest().identity().id().into(),
                            second: manifest.identity().id().into(),
                            selector,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn supports_decoder(&self, id: &str, version: &str) -> bool {
        self.decoders.contains_key(&(id.into(), version.into()))
    }

    pub fn decoder(&self, id: &str, version: &str) -> Result<&dyn SourceDecoder, MappingError> {
        self.decoders
            .get(&(id.into(), version.into()))
            .map(AsRef::as_ref)
            .ok_or(MappingError::UnsupportedDecoder)
    }
    pub fn snapshots(&self) -> Result<Vec<irmind_domain::MappingSnapshotV1>, MappingError> {
        self.mappings
            .values()
            .map(|mapper| mapper.manifest().snapshot())
            .collect()
    }
    pub fn exact_mapper(
        &self,
        identity: &MappingIdentityV1,
    ) -> Result<&dyn SourceMapper, MappingError> {
        self.mappings
            .get(identity.id())
            .filter(|mapper| mapper.manifest().identity() == identity)
            .map(AsRef::as_ref)
            .ok_or(MappingError::UnsupportedVersion)
    }
    /// Reuse only locally registered implementations pinned by an authenticated
    /// profile. Case metadata never supplies executable mapping code.
    pub fn frozen_for_profile(
        &self,
        profile: &irmind_domain::MappingProfileV1,
    ) -> Result<Self, MappingError> {
        self.reconstruct_profile(profile)
    }

    pub fn decoder_selection(
        &self,
        id: &str,
        version: &str,
    ) -> Result<super::SourceDecoderSelection, MappingError> {
        let decoder = self
            .decoders
            .get(&(id.into(), version.into()))
            .ok_or(MappingError::UnsupportedDecoder)?;
        Ok(super::SourceDecoderSelection::new(Arc::clone(decoder)))
    }

    /// Runtime ambiguity remains a final defense after activation checks.
    pub fn select(
        &self,
        source: &SourceRecordV1,
    ) -> Result<Option<&dyn SourceMapper>, MappingError> {
        let mut selected: Option<&dyn SourceMapper> = None;
        for mapper in self.mappings.values() {
            if !mapper
                .manifest()
                .selectors()
                .iter()
                .any(|s| s.matches(source))
            {
                continue;
            }
            if let Some(previous) = selected {
                return Err(MappingError::Ambiguous {
                    first: previous.manifest().identity().id().into(),
                    second: mapper.manifest().identity().id().into(),
                });
            }
            selected = Some(mapper.as_ref());
        }
        Ok(selected)
    }

    pub fn map(
        &self,
        source: &SourceRecordV1,
    ) -> Result<(Option<MappingIdentityV1>, MappingOutput), MappingError> {
        let Some(mapper) = self.select(source)? else {
            return Ok((None, super::output::unmapped(source)?));
        };
        let output = match mapper.map(source) {
            Ok(output) => output,
            Err(MappingError::UnsupportedSourceValue) => {
                MappingOutput::unclassified(source, super::MappingDiagnostic::UnsupportedValue)?
            }
            Err(error) => return Err(error),
        };
        let common = &output.record().common;
        if common.origin() != source.origin()
            || common.timestamp() != source.timestamp()
            || (!mapper.manifest().compatibility_projection()
                && (!output.record().indexed.record.entities.is_empty()
                    || !output.record().indexed.record.relations.is_empty()))
        {
            return Err(MappingError::InvalidOutput);
        }
        Ok((Some(mapper.manifest().identity().clone()), output))
    }
    pub fn manifests(&self) -> impl ExactSizeIterator<Item = &super::MappingManifest> {
        self.mappings.values().map(|m| m.manifest())
    }
}

mod authenticated;
mod reconstruction;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
