//! Original decoding and pure extraction share one immutable approved definition.
mod decode;
mod extract;
use crate::{AppError, DeclarativeParser, error};
use irmind_app::{
    CompiledDefinition, SourceDecoder, SourceMapper,
    source_mapping::{MappingIdentityV1, MappingManifest, MappingProvenance, SourceSelector},
};
use irmind_domain::{COMMON_EVENT_V1, EvidenceHash};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
pub(super) struct Decoder(pub(super) Arc<DeclarativeParser>);
pub(super) struct Extraction {
    parser: Arc<DeclarativeParser>,
    manifest: MappingManifest,
}
pub(super) fn compile(contents: &str) -> Result<CompiledDefinition, AppError> {
    let parser = Arc::new(DeclarativeParser::from_toml(contents)?);
    let hash = irmind_app::hex(&irmind_app::sha256(contents.as_bytes()));
    let descriptor = irmind_app::definition_mapping_descriptor(
        &hash,
        include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin")),
    )?;
    let identity = MappingIdentityV1::try_new(
        parser.id(),
        &format!("declarative-extraction-v1:{hash}"),
        COMMON_EVENT_V1,
        EvidenceHash::from_bytes(irmind_app::sha256(&descriptor)),
    )
    .map_err(|_| error("invalid extraction identity"))?;
    let selector = SourceSelector::try_new(
        parser.id(),
        BTreeSet::from([parser.definition_version().into()]),
        Some(("declarative".into(), "declarative-source-v1".into())),
        BTreeMap::new(),
        Vec::new(),
    )
    .map_err(irmind_app::source_mapping::MappingError::into_app)?;
    let manifest = MappingManifest::try_new(
        identity,
        vec![selector],
        MappingProvenance::NativeBuild {
            manifest: descriptor,
        },
        true,
    )
    .map_err(irmind_app::source_mapping::MappingError::into_app)?;
    let decoder: Arc<dyn SourceDecoder> = Arc::new(Decoder(Arc::clone(&parser)));
    let mapper: Arc<dyn SourceMapper> = Arc::new(Extraction {
        parser: Arc::clone(&parser),
        manifest,
    });
    CompiledDefinition::try_new(parser, decoder, mapper, contents)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
