//! Frozen source decoding and pure mapping, before any signed output exists.
mod decode;
mod projection;
mod rebuild;
use super::{AppError, ParquetStore};
use irmind_app::source_mapping::MappingCatalog;
pub(in crate::parquet_store) use projection::{nonempty_staging, route_from_path};
use std::{path::Path, sync::Arc};

impl ParquetStore {
    /// The opt-in writer shares the catalog with reconstruction. No untrusted
    /// module code is loaded from a case or an exported package.
    pub fn open_mapped(root: &Path, catalog: Arc<MappingCatalog>) -> Result<Self, AppError> {
        let mut store = Self::open_precise(root)?;
        store.mapping_catalog = Some(catalog);
        Ok(store)
    }
}

pub(in crate::parquet_store) use decode::projection_routes as projection_routes_for_direct;
