use super::{invalid, valid_hash};
use crate::{
    AppError, LogParser, SourceDecoder, SourceMapper,
    source_mapping::{MappingProvenance, SourceSelector},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A checked compilation result is not authorization to install a definition.
#[derive(Clone)]
pub struct CompiledDefinition {
    selector: Arc<dyn LogParser>,
    decoder: Arc<dyn SourceDecoder>,
    mapper: Arc<dyn SourceMapper>,
    hash: String,
}
impl CompiledDefinition {
    pub fn try_new(
        selector: Arc<dyn LogParser>,
        decoder: Arc<dyn SourceDecoder>,
        mapper: Arc<dyn SourceMapper>,
        contents: &str,
    ) -> Result<Self, AppError> {
        let hash = crate::hex(&crate::sha256(contents.as_bytes()));
        let identity = selector.identity();
        let manifest = mapper.manifest();
        let descriptor_valid = matches!(manifest.provenance(), MappingProvenance::NativeBuild { manifest } if valid_descriptor(manifest, &hash));
        if contents.len() > super::MAX_DEFINITION_BYTES
            || selector.parser_name() != "parser-declarative"
            || !identity.name.starts_with("parser-declarative-")
            || identity != decoder.identity()
            || !identity.version.ends_with(&format!(":sha256={hash}"))
            || manifest.identity().id() != identity.name
            || manifest.identity().version() != format!("declarative-extraction-v1:{hash}")
            || manifest.identity().target() != irmind_domain::COMMON_EVENT_V1
            || !manifest.compatibility_projection()
            || !descriptor_valid
            || manifest.selectors().len() != 1
            || manifest.selectors()[0]
                != SourceSelector::try_new(
                    identity.name,
                    BTreeSet::from([identity.version.into()]),
                    Some(("declarative".into(), "declarative-source-v1".into())),
                    BTreeMap::new(),
                    Vec::new(),
                )
                .map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(Self {
            selector,
            decoder,
            mapper,
            hash,
        })
    }
    pub fn selector(&self) -> &Arc<dyn LogParser> {
        &self.selector
    }
    pub fn decoder(&self) -> &Arc<dyn SourceDecoder> {
        &self.decoder
    }
    pub fn extraction_mapper(&self) -> &Arc<dyn SourceMapper> {
        &self.mapper
    }
    pub fn definition_hash(&self) -> &str {
        &self.hash
    }
}

const RECIPE: &[u8] = b"irmind-declarative-extraction-v1\0";
const BUILD: &[u8] = b"irmind-native-mapping-build-v1\0";
/// Bind the exact definition and canonical compiled implementation manifest.
pub fn definition_mapping_descriptor(
    hash: &str,
    implementation: &[u8],
) -> Result<Vec<u8>, AppError> {
    if !valid_hash(hash)
        || !implementation.starts_with(BUILD)
        || implementation.len() + RECIPE.len() + 72 > 64 * 1024
    {
        return Err(invalid());
    }
    let mut result = RECIPE.to_vec();
    result.extend_from_slice(hash.as_bytes());
    result.extend_from_slice(&(implementation.len() as u64).to_be_bytes());
    result.extend_from_slice(implementation);
    Ok(result)
}
fn valid_descriptor(bytes: &[u8], hash: &str) -> bool {
    let Some(payload) = bytes
        .strip_prefix(RECIPE)
        .and_then(|rest| rest.strip_prefix(hash.as_bytes()))
    else {
        return false;
    };
    let Some((length, implementation)) = payload.split_at_checked(8) else {
        return false;
    };
    u64::from_be_bytes(match length.try_into() {
        Ok(value) => value,
        Err(_) => return false,
    }) == implementation.len() as u64
        && implementation.starts_with(BUILD)
}

/// Only authenticated installation snapshots can create this registration token.
#[derive(Clone)]
pub struct ApprovedDefinition {
    compiled: CompiledDefinition,
}
impl ApprovedDefinition {
    pub fn compiled(&self) -> &CompiledDefinition {
        &self.compiled
    }
    pub(super) fn new(compiled: CompiledDefinition) -> Self {
        Self { compiled }
    }
}
