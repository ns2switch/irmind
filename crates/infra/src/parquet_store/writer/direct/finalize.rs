//! Final writers already have their deterministic file boundaries. Complete
//! independent partitions concurrently without changing admission or eviction.
use super::{
    AppError, BTreeMap, CancellationToken, DirectWriting, EvidenceHash, Live, StagedArtifact,
    invalid_source,
};
use crate::parquet_store::storage;
use irmind_app::ParserIdentity;

impl DirectWriting {
    pub(super) fn finish_partitions(
        &mut self,
        workers: usize,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if workers == 1 {
            for key in self.open.keys().cloned().collect::<Vec<_>>() {
                self.close(&key, cancel)?;
            }
            return Ok(());
        }
        let mut partitions = BTreeMap::<_, Vec<_>>::new();
        for ((partition, _), writer) in std::mem::take(&mut self.open) {
            partitions.entry(partition).or_default().push(writer);
        }
        let mut partitions = partitions.into_values();
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let group = partitions.by_ref().take(workers).collect::<Vec<_>>();
            if group.is_empty() {
                return Ok(());
            }
            let outputs = finish_group(group, &self.hash, self.parser_identity(), cancel)?;
            for output in outputs {
                self.record_finished(output)?;
            }
        }
    }
}

fn finish_group(
    group: Vec<Vec<Live>>,
    hash: &EvidenceHash,
    parser: ParserIdentity<'_>,
    cancel: &CancellationToken,
) -> Result<Vec<Option<StagedArtifact>>, AppError> {
    std::thread::scope(|scope| {
        let mut jobs = Vec::with_capacity(group.len());
        for partition in group {
            jobs.push(
                std::thread::Builder::new()
                    .name("parquet-partition".into())
                    .spawn_scoped(scope, move || {
                        partition
                            .into_iter()
                            .map(|live| finish_live(live, hash, parser, cancel))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .map_err(storage)?,
            );
        }
        let mut outputs = Ok(Vec::new());
        for job in jobs {
            let joined = job
                .join()
                .map_err(|_| invalid_source())
                .and_then(|result| result);
            if let Ok(items) = &mut outputs {
                match joined {
                    Ok(partition) => items.extend(partition),
                    Err(error) => outputs = Err(error),
                }
            }
        }
        outputs
    })
}

pub(super) fn finish_live(
    live: Live,
    hash: &EvidenceHash,
    parser: ParserIdentity<'_>,
    cancel: &CancellationToken,
) -> Result<Option<StagedArtifact>, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let mut output = live.sink.finish_cancelable(hash, parser, cancel)?;
    let core = &mut output.manifest;
    core.source_hashes = live.sources.into_iter().collect();
    Ok(output.rows.is_some_and(|rows| rows > 0).then_some(output))
}
