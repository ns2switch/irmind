//! Preparation holds unsigned final files until the application commits a group.
mod fallback;
mod prepared;
mod read;
#[cfg(test)]
mod tests;
use super::super::{AppError, CancellationToken, ParquetStore, invalid_source};
use crate::parquet_store::writer::direct::DirectWriting;
use irmind_app::{MappedIngestRequest, PreparedMappedGroup, PreparedMappedIngest};
use std::collections::BTreeSet;
const RAW_GROUP_TARGET: u64 = 512 * 1024 * 1024;

struct Speculation {
    sources: Vec<irmind_app::MappedSourceAcquisition>,
    disorder: Option<(String, irmind_domain::EvidenceHash)>,
}

impl ParquetStore {
    pub(in crate::parquet_store) fn prepare_direct(
        &self,
        request: &MappedIngestRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Option<Box<dyn PreparedMappedIngest>>, AppError> {
        let Some(catalog) = self.mapping_catalog.as_ref() else {
            return Ok(None);
        };
        request.validate()?;
        let identity = request
            .parser
            .identity_for_source(&request.relative_paths[0])?;
        if !catalog.supports_decoder(identity.name, identity.version) {
            return Ok(None);
        }
        let paths = Self::direct_group_paths(request, cancel)?;
        let request = &MappedIngestRequest {
            relative_paths: &paths,
            ..*request
        };
        let workers = self.workers.count();
        self.preflight_direct_group(request, workers, cancel)?;
        let mut allocator =
            super::Allocator::from_signed_iter(request.committed_artifacts.iter(), request.limits)?;
        let hash = group_identity(request.relative_paths, identity);
        let routes = crate::parquet_store::mapped::projection_routes_for_direct(catalog)?
            .into_iter()
            .map(|(mapping, route)| (route, mapping))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut writing =
            DirectWriting::new(hash.clone(), identity, routes.clone(), self.profile.clone());
        let Speculation {
            mut sources,
            disorder,
        } = self.speculate_group(request, workers, &mut writing, &mut allocator, cancel)?;
        if let Some((path, source_hash)) = disorder {
            drop(writing);
            writing = DirectWriting::new(hash, identity, routes, self.profile.clone());
            allocator = super::Allocator::from_signed_iter(
                request.committed_artifacts.iter(),
                request.limits,
            )?;
            sources = fallback::Replay {
                store: self,
                request,
                cancel,
            }
            .group(
                sources,
                (&path, &source_hash),
                workers,
                &mut writing,
                &mut allocator,
            )?;
        }
        self.validate_direct_sources(request, &sources, cancel)?;
        let staged = writing.finish(&self.case_dir(request.case_id)?, workers, cancel)?;
        let projections = prepared::projections(catalog, &staged)?;
        let metadata = PreparedMappedGroup {
            sources,
            snapshots: catalog
                .snapshots()
                .map_err(irmind_app::source_mapping::MappingError::into_app)?,
            projections,
        };
        Ok(Some(Box::new(prepared::Prepared::new(
            self.case_dir(request.case_id)?,
            request.source_root.to_owned(),
            metadata,
            staged,
            request.copy_original,
            self.profile.clone(),
        ))))
    }
    fn speculate_group(
        &self,
        request: &MappedIngestRequest<'_>,
        workers: usize,
        writing: &mut DirectWriting,
        allocator: &mut super::Allocator,
        cancel: &CancellationToken,
    ) -> Result<Speculation, AppError> {
        let mut sources = Vec::new();
        let mut disorder = None;
        for paths in request.relative_paths.chunks(workers) {
            let inputs = self.direct_inputs(request, paths, workers)?;
            match self.stream_direct_chunk(request, inputs, writing, allocator, cancel)? {
                super::ordered::DirectChunk::Ordered(chunk) => sources.extend(chunk),
                super::ordered::DirectChunk::NeedsSort {
                    path,
                    hash,
                    ordered,
                } => {
                    sources.extend(ordered);
                    disorder = Some((path, hash));
                    break;
                }
            }
        }
        Ok(Speculation { sources, disorder })
    }

    fn direct_inputs(
        &self,
        request: &MappedIngestRequest<'_>,
        paths: &[String],
        workers: usize,
    ) -> Result<Vec<super::staging::Input>, AppError> {
        let mut inputs = self.staging_inputs(request.case_id, request.source_root, paths)?;
        let count = inputs.len().max(1);
        for (index, input) in inputs.iter_mut().enumerate() {
            // Account for the existing source worker and distribute spare slots
            // in canonical order. Nested decoders cannot oversubscribe the pool.
            let slots = workers / count + usize::from(index < workers % count);
            let slots = std::num::NonZeroUsize::new(slots).ok_or_else(invalid_source)?;
            input.decode_budget = irmind_app::source_mapping::DecodeBudget::new(
                slots,
                slots.get() * (64 * 1024 * 1024),
            );
        }
        Ok(inputs)
    }

    fn validate_direct_sources(
        &self,
        request: &MappedIngestRequest<'_>,
        sources: &[irmind_app::MappedSourceAcquisition],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut unique = BTreeSet::new();
        for source in sources {
            if !unique.insert(source.manifest.sha256.clone())
                || request
                    .committed_artifacts
                    .iter()
                    .any(|a| a.source_hashes().contains(&source.manifest.sha256))
            {
                return Err(AppError::Fixed(
                    irmind_app::FixedAppError::PolicyMappedSourceAlreadyIndexed,
                ));
            }
            self.verify_direct_source(request, &source.manifest, cancel)?;
        }
        Ok(())
    }
    fn verify_direct_source(
        &self,
        request: &MappedIngestRequest<'_>,
        manifest: &irmind_domain::SourceManifestV1,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        use irmind_app::LargeCaseStore as _;
        let _verify = self
            .profile
            .as_ref()
            .map(|p| p.measure(crate::parquet_store::PartitionPhase::SourceVerify));
        match self.verify_local_source(request.source_root, manifest, cancel) {
            Err(AppError::EvidenceMismatch(_)) => Err(AppError::SourceFailure(
                irmind_app::RejectedSource::try_new(
                    manifest.source.clone(),
                    irmind_app::SourceFailureReason::Hash,
                    vec![],
                )?,
            )),
            other => other,
        }
    }

    fn preflight_direct_group(
        &self,
        request: &MappedIngestRequest<'_>,
        workers: usize,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut sizes = Vec::new();
        for source in request.relative_paths {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            sizes.push(
                Self::open_source(request.source_root, source)?
                    .metadata()
                    .map_err(crate::parquet_store::storage)?
                    .len(),
            );
        }
        let total = sizes.iter().try_fold(0u64, |total, size| {
            total.checked_add(*size).ok_or_else(invalid_source)
        })?;
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        let scratch = sizes
            .into_iter()
            .take(workers)
            .try_fold(0u64, |total, size| {
                total.checked_add(size).ok_or_else(invalid_source)
            })?;
        let required = total
            .checked_mul(if request.copy_original { 17 } else { 16 })
            .and_then(|bytes| {
                scratch
                    .checked_mul(16)
                    .and_then(|extra| bytes.checked_add(extra))
            })
            .and_then(|bytes| bytes.checked_add(5 * 64 * 1024 * 1024))
            .ok_or_else(invalid_source)?;
        if fs4::available_space(self.spool_dir(request.case_id)?)
            .map_err(crate::parquet_store::storage)?
            < required
        {
            return Err(AppError::Storage("not enough free case storage for the complete direct group and bounded sort fallback".into()));
        }
        Ok(())
    }
    fn direct_group_paths(
        request: &MappedIngestRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<Vec<String>, AppError> {
        let mut paths = Vec::new();
        let mut bytes = 0u64;
        for path in request.relative_paths {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let size = Self::open_source(request.source_root, path)?
                .metadata()
                .map_err(crate::parquet_store::storage)?
                .len();
            let next = bytes.checked_add(size).ok_or_else(invalid_source)?;
            if !paths.is_empty() && next > RAW_GROUP_TARGET {
                break;
            }
            bytes = next;
            paths.push(path.clone());
        }
        Ok(paths)
    }
}

fn group_identity(
    paths: &[String],
    identity: irmind_app::ParserIdentity<'_>,
) -> irmind_domain::EvidenceHash {
    let mut bytes = b"irmind-direct-source-group-v1\0".to_vec();
    for path in paths {
        bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
    }
    bytes.extend_from_slice(identity.name.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(identity.version.as_bytes());
    irmind_domain::EvidenceHash::from_bytes(irmind_app::sha256(&bytes))
}
