//! Speculative direct writing. Publication waits for the complete source hash.
mod direct;
mod producer;
pub(in crate::parquet_store::partitioning) use direct::DirectChunk;
mod scheduling;
use super::super::{AppError, CancellationToken, ParquetStore, invalid_source};
use super::Allocator;
use super::staging::Input;
pub(super) use producer::ParsedSource;
use producer::{ProducedSource, ProducerOutput, RowBatch};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

impl ParquetStore {
    fn source_parallelism(
        &self,
        parser: &dyn irmind_app::StreamingEventParser,
        source: &str,
    ) -> Result<irmind_app::SourceParallelism, AppError> {
        let id = parser.identity_for_source(source)?;
        let catalog = self.mapping_catalog.as_ref().ok_or_else(invalid_source)?;
        Ok(catalog
            .decoder(id.name, id.version)
            .map_err(irmind_app::source_mapping::MappingError::into_app)?
            .source_parallelism())
    }
}

#[cfg(test)]
mod tests;
