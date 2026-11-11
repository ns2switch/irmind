//! Rebuild a provisional mixed-order group. Only disordered sources get a row spool.
use super::super::{Allocator, ordered::DirectChunk, staging::Input};
use super::{
    AppError, CancellationToken, DirectWriting, MappedIngestRequest, ParquetStore, invalid_source,
    read::{self, OrderHints, Plan},
};
use irmind_app::MappedSourceAcquisition;
use irmind_domain::EvidenceHash;
use std::collections::BTreeMap;

pub(super) struct Replay<'a, 'source> {
    pub(super) store: &'a ParquetStore,
    pub(super) request: &'a MappedIngestRequest<'source>,
    pub(super) cancel: &'a CancellationToken,
}

impl Replay<'_, '_> {
    pub(super) fn group(
        &self,
        prefix: Vec<MappedSourceAcquisition>,
        first_disordered: (&str, &EvidenceHash),
        workers: usize,
        writing: &mut DirectWriting,
        allocator: &mut Allocator,
    ) -> Result<Vec<MappedSourceAcquisition>, AppError> {
        let ordered = prefix
            .into_iter()
            .map(|source| (source.manifest.source, source.manifest.sha256))
            .collect::<BTreeMap<_, _>>();
        let hints = OrderHints {
            ordered: &ordered,
            first_disordered,
        };
        let mut sources = Vec::new();
        for paths in self.request.relative_paths.chunks(workers) {
            let inputs = self.store.direct_inputs(self.request, paths, workers)?;
            let plan = read::plan(self.store, self.request, inputs, hints, self.cancel)?;
            self.replay_plan(plan, writing, allocator, &mut sources)?;
        }
        Ok(sources)
    }

    fn replay_plan(
        &self,
        plan: Vec<Plan>,
        writing: &mut DirectWriting,
        allocator: &mut Allocator,
        sources: &mut Vec<MappedSourceAcquisition>,
    ) -> Result<(), AppError> {
        let mut pending = plan.into_iter().peekable();
        while let Some(source) = pending.next() {
            match source {
                Plan::Stream(input, hash) => {
                    let mut group = vec![(input, hash)];
                    while matches!(pending.peek(), Some(Plan::Stream(..))) {
                        let Some(Plan::Stream(input, hash)) = pending.next() else {
                            return Err(invalid_source());
                        };
                        group.push((input, hash));
                    }
                    sources.extend(self.stream(group, writing, allocator)?);
                }
                Plan::Sorted(source) => {
                    let mut group = vec![*source];
                    while matches!(pending.peek(), Some(Plan::Sorted(_))) {
                        let Some(Plan::Sorted(source)) = pending.next() else {
                            return Err(invalid_source());
                        };
                        group.push(*source);
                    }
                    self.store.sort_staged_sources(
                        self.request.case_id,
                        &mut group,
                        self.cancel,
                    )?;
                    for source in group {
                        read::replay(
                            self.store,
                            self.request,
                            &source,
                            writing,
                            allocator,
                            self.cancel,
                        )?;
                        sources.push(read::acquisition(source)?);
                    }
                }
            }
        }
        Ok(())
    }

    fn stream(
        &self,
        group: Vec<(Input, EvidenceHash)>,
        writing: &mut DirectWriting,
        allocator: &mut Allocator,
    ) -> Result<Vec<MappedSourceAcquisition>, AppError> {
        let (inputs, expected): (Vec<_>, Vec<_>) = group.into_iter().unzip();
        let sources = match self.store.stream_direct_chunk(
            self.request,
            inputs,
            writing,
            allocator,
            self.cancel,
        )? {
            DirectChunk::Ordered(sources) => sources,
            DirectChunk::NeedsSort { path, .. } => return Err(read::source_changed(path)?),
        };
        if sources.len() != expected.len() {
            return Err(invalid_source());
        }
        for (source, hash) in sources.iter().zip(expected) {
            if source.manifest.sha256 != hash {
                return Err(read::source_changed(source.manifest.source.clone())?);
            }
        }
        Ok(sources)
    }
}
