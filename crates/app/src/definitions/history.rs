use super::{ApprovedDefinitions, CompiledDefinition, DefinitionCompiler, compile_snapshot};
use crate::source_mapping::{MappingError, MappingIdentityV1};
use std::sync::Arc;

/// The caller can only provide snapshots authenticated by application use cases.
/// Compilation is lazy and uses the current, locally built interpreter.
pub(crate) struct DefinitionHistory {
    approved: ApprovedDefinitions,
    compiler: Arc<dyn DefinitionCompiler>,
}

impl DefinitionHistory {
    pub(crate) fn new(
        approved: ApprovedDefinitions,
        compiler: Arc<dyn DefinitionCompiler>,
    ) -> Self {
        Self { approved, compiler }
    }

    pub(crate) fn resolve(
        &self,
        identity: &MappingIdentityV1,
    ) -> Result<CompiledDefinition, MappingError> {
        let hash = identity
            .version()
            .strip_prefix("declarative-extraction-v1:")
            .filter(|hash| super::valid_hash(hash))
            .ok_or(MappingError::UnsupportedVersion)?;
        let snapshot = self
            .approved
            .versions
            .get(&(
                identity.id().into(),
                format!("declarative-v2:sha256={hash}"),
            ))
            .ok_or(MappingError::UnsupportedVersion)?;
        let compiled = compile_snapshot(snapshot, self.compiler.as_ref())
            .map_err(|_| MappingError::InvalidDefinition)?;
        if compiled.extraction_mapper().manifest().identity() != identity {
            return Err(MappingError::UnsupportedVersion);
        }
        Ok(compiled)
    }
}
