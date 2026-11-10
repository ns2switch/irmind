use super::ModuleRegistry;
use crate::{
    AppError, SourceDecoder, SourceMapper,
    source_mapping::{MappingCatalog, MappingError},
};
use std::sync::Arc;

impl ModuleRegistry {
    pub(super) fn validate_mapping_registration(
        &self,
        manifest: &super::ModuleManifest,
        staged: &Self,
    ) -> Result<(), AppError> {
        if staged.source_decoders.iter().any(|decoder| {
            decoder.identity().name != manifest.id
                || self
                    .source_decoders
                    .iter()
                    .any(|old| old.identity() == decoder.identity())
        }) || staged.source_mappers.iter().any(|mapper| {
            mapper.manifest().identity().id() != manifest.id
                || self
                    .source_mappers
                    .iter()
                    .any(|old| old.manifest().identity().id() == mapper.manifest().identity().id())
        }) {
            return Err(MappingError::DuplicateIdentity.into_app());
        }
        Ok(())
    }
    pub fn add_source_decoder(&mut self, decoder: Arc<dyn SourceDecoder>) -> Result<(), AppError> {
        let identity = decoder.identity();
        if self
            .source_decoders
            .iter()
            .any(|d| d.identity() == identity)
        {
            return Err(MappingError::DuplicateIdentity.into_app());
        }
        self.source_decoders.push(decoder);
        Ok(())
    }

    pub fn add_source_mapper(&mut self, mapper: Arc<dyn SourceMapper>) -> Result<(), AppError> {
        if self
            .source_mappers
            .iter()
            .any(|m| m.manifest().identity().id() == mapper.manifest().identity().id())
        {
            return Err(MappingError::DuplicateIdentity.into_app());
        }
        self.source_mappers.push(mapper);
        Ok(())
    }

    /// Retain authenticated definition snapshots for exact-profile reconstruction only.
    #[must_use]
    pub fn with_definition_history(
        mut self,
        approved: crate::ApprovedDefinitions,
        compiler: Arc<dyn crate::DefinitionCompiler>,
    ) -> Self {
        self.definition_history = Some(Arc::new(
            crate::definitions::history::DefinitionHistory::new(approved, compiler),
        ));
        self
    }

    pub fn mapping_catalog(&self) -> Result<MappingCatalog, AppError> {
        let mut catalog =
            MappingCatalog::freeze(self.source_decoders.clone(), self.source_mappers.clone())
                .map_err(MappingError::into_app)?;
        catalog
            .definition_history
            .clone_from(&self.definition_history);
        Ok(catalog)
    }
}
