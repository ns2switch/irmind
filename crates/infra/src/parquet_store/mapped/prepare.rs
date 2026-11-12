//! Pure mapping and checked projection use a share of the existing source budget.
use super::super::{AppError, ParquetStore, RecordRow, invalid_source, profile::MappingPhase};
use super::{decode, ordered_pool::OrderedPool};
use crate::parquet_store::{local::stream::VerifiedInput, partitioning::temporary::DiskLease};
use irmind_app::source_mapping::{
    DecodeBudget, MappedSourceRecord, PreparedSourceRecord, SourceMetadata, SourceRecordAccumulator,
};
use irmind_domain::MappingIdentityV1;
use std::{collections::BTreeMap, io::Write, num::NonZeroUsize};
type Routes = BTreeMap<Option<MappingIdentityV1>, String>;
const LANE_BYTES: usize = 160 * 1024 * 1024;
mod batches;

pub(super) struct OrderedOutput<'a, 'catalog> {
    pub(super) acc: &'a mut SourceRecordAccumulator<'catalog>,
    pub(super) spool: &'a mut dyn Write,
    pub(super) disk: &'a mut DiskLease,
    pub(super) emit: &'a mut dyn FnMut(RecordRow) -> Result<(), AppError>,
}

pub(super) fn decode_projected(
    store: &ParquetStore,
    input: &mut VerifiedInput<'_>,
    decoder: &dyn irmind_app::SourceDecoder,
    metadata: SourceMetadata<'_>,
    routes: &Routes,
    output: OrderedOutput<'_, '_>,
) -> Result<irmind_app::ParseReport, AppError> {
    let OrderedOutput {
        acc,
        spool,
        disk,
        emit,
    } = output;
    let budget = input.decode_budget;
    let lanes = (budget.workers() / 2).min(budget.queued_bytes() / LANE_BYTES);
    let id = input.parser.identity_for_source(input.relative_path)?;
    let hash = input.hash_value;
    let project = |mapped: &MappedSourceRecord| {
        let _timer = store
            .profile
            .as_ref()
            .map(|p| p.mapping_timer(MappingPhase::Project));
        project_row(mapped, id, hash, routes)
    };
    if lanes == 0 {
        return decode::decode_source(input, decoder, metadata, &mut |source| {
            let Some(source) = source else {
                return Ok(());
            };
            let mapped = {
                let _timer = store
                    .profile
                    .as_ref()
                    .map(|p| p.mapping_timer(MappingPhase::ValidateAndMap));
                acc.accept(&source, spool)?
            };
            disk.add(49)?;
            emit(project(&mapped)?)
        });
    }
    input.decode_budget = DecodeBudget::new(
        NonZeroUsize::new(budget.workers() - lanes).ok_or_else(invalid_source)?,
        budget.queued_bytes() - lanes * LANE_BYTES,
    );
    let transform = acc.preparer();
    let prepare = |sources, send: &mut dyn FnMut(Vec<_>, bool) -> Result<(), AppError>| {
        batches::prepare(sources, send, |source| {
            let prepared = {
                let _timer = store
                    .profile
                    .as_ref()
                    .map(|p| p.mapping_timer(MappingPhase::ValidateAndMap));
                transform.prepare(source)?
            };
            let row = project(prepared.mapped())?;
            Ok((prepared, row))
        })
    };
    std::thread::scope(|scope| {
        let mut pool = OrderedPool::new(scope, lanes, &prepare)?;
        let mut commit = |outputs: Vec<(PreparedSourceRecord<'_>, RecordRow)>| {
            for (prepared, row) in outputs {
                acc.accept_prepared(prepared, spool)?;
                disk.add(49)?;
                emit(row)?;
            }
            Ok(())
        };
        let mut pending = batches::Inputs::default();
        decode::decode_source(input, decoder, metadata, &mut |source| {
            if let Some(source) = source {
                if let Some(batch) = pending.push(source) {
                    pool.submit(batch, metadata.cancel, &mut commit)?;
                }
            } else {
                if let Some(batch) = pending.take() {
                    pool.submit(batch, metadata.cancel, &mut commit)?;
                }
                pool.finish(metadata.cancel, &mut commit)?;
            }
            Ok(())
        })
    })
}
fn project_row(
    mapped: &MappedSourceRecord,
    id: irmind_app::ParserIdentity<'_>,
    hash: &irmind_domain::EvidenceHash,
    routes: &Routes,
) -> Result<RecordRow, AppError> {
    let route = routes
        .get(&mapped.identity)
        .ok_or_else(invalid_source)?
        .clone();
    let mut row = None;
    mapped.output.inspect(|output| {
        row = Some(RecordRow::from_mapping(
            output,
            mapped.output.provenance(),
            id,
            hash,
            route,
        ));
    });
    row.ok_or_else(invalid_source)?
}
