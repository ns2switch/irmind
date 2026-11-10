use super::ModuleRegistry;
use crate::{AppError, ApprovedDefinition};
use std::sync::Arc;
impl ModuleRegistry {
    /// Registration accepts only pipelines returned from authenticated snapshots.
    pub fn add_approved_definition(
        &mut self,
        definition: ApprovedDefinition,
    ) -> Result<(), AppError> {
        let compiled = definition.compiled();
        if self.definition_variants.len() >= 64
            || self.definition_variants.iter().any(|old| {
                old.compiled().selector().identity().name == compiled.selector().identity().name
            })
        {
            return Err(super::mapping_error());
        }
        self.add_parser_variant(Arc::clone(compiled.selector()))?;
        self.definition_variants.push(definition);
        Ok(())
    }
    pub(super) fn validate_definition_variants(
        &self,
        manifest: &super::ModuleManifest,
    ) -> Result<(), AppError> {
        if !self.definition_variants.is_empty()
            && (manifest.id != "parser-declarative"
                || self.parser_variants.len() != self.definition_variants.len())
        {
            return Err(super::mapping_error());
        }
        Ok(())
    }
}
