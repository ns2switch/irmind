//! Benchmarks use the same decoder catalog and bundled mappings as ingestion.
use irmind_app::{
    SourceMapper,
    source_mapping::{MappingCatalog, SourceDecoderSelection},
};
use irmind_infra::LocalStore;
use irmind_mod_mapping_evtx::{PowerShellMapping, SecurityMapping, SysmonMapping, SystemMapping};
use irmind_mod_parser_evtx::EvtxParser;
use std::{path::Path, sync::Arc};

pub(super) fn store(
    root: &Path,
    parser: Arc<EvtxParser>,
) -> Result<LocalStore, Box<dyn std::error::Error>> {
    let mut mappings: Vec<Arc<dyn SourceMapper>> = Vec::new();
    for &id in SecurityMapping::EVENT_IDS {
        mappings.push(Arc::new(SecurityMapping::new(id)?));
    }
    mappings.push(Arc::new(SystemMapping::new()?));
    mappings.push(Arc::new(PowerShellMapping::new()?));
    mappings.push(Arc::new(SysmonMapping::new()?));
    let catalog = MappingCatalog::freeze(vec![parser], mappings)?;
    Ok(LocalStore::open_mapped(root, Arc::new(catalog))?)
}

pub(super) fn selection(parser: Arc<EvtxParser>) -> SourceDecoderSelection {
    SourceDecoderSelection::new(parser)
}
