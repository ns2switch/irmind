//! Preparation holds unsigned final files until the application commits a group.
mod fallback;
mod prepared;
mod read;
#[cfg(test)]
mod tests;
use super::super::{AppError, CancellationToken, ParquetStore, invalid_source};
use super::staging::SourceReservation;
use crate::parquet_store::writer::direct::DirectWriting;
use irmind_app::{MappedIngestRequest, PreparedMappedGroup, PreparedMappedIngest};
use std::collections::{BTreeMap, BTreeSet};
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
        let catalog = catalog.for_decoder(identity);
        let paths = Self::direct_group_paths(request, cancel)?;
        let request = &MappedIngestRequest {
            relative_paths: &paths,
            ..*request
        };
        let workers = self.workers.count();
        let budgets = self.preflight_direct_group(request, workers, cancel)?;
        let mut allocator =
            super::Allocator::from_signed_iter(request.committed_artifacts.iter(), request.limits)?;
        let hash = group_identity(request, identity);
        let routes = crate::parquet_store::mapped::projection_routes_for_direct(&catalog)?
            .into_iter()
            .map(|(mapping, route)| (route, mapping))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut writing =
            DirectWriting::new(hash.clone(), identity, routes.clone(), self.profile.clone());
        let Speculation {
            mut sources,
            disorder,
        } = self.speculate_group(
            request,
            workers,
            &mut writing,
            &mut allocator,
            &budgets,
            cancel,
        )?;
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
                budgets: &budgets,
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
        let projections = prepared::projections(&catalog, &staged)?;
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
        budgets: &BTreeMap<String, SourceReservation>,
        cancel: &CancellationToken,
    ) -> Result<Speculation, AppError> {
        let mut sources = Vec::new();
        let mut disorder = None;
        for paths in request.relative_paths.chunks(workers) {
            let inputs = self.direct_inputs(request, paths, workers, budgets, cancel)?;
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
        budgets: &BTreeMap<String, SourceReservation>,
        cancel: &CancellationToken,
    ) -> Result<Vec<super::staging::Input>, AppError> {
        let mut inputs = self.staging_inputs_reserved(
            request.case_id,
            request.source_root,
            paths,
            Some(budgets),
            cancel,
        )?;
        let count = inputs.len().max(1);
        for (index, input) in inputs.iter_mut().enumerate() {
            // Account for the existing source worker and distribute spare slots
            // in canonical order. Nested decoders cannot oversubscribe the pool.
            let slots = workers / count + usize::from(index < workers % count);
            let slots = std::num::NonZeroUsize::new(slots).ok_or_else(invalid_source)?;
            input.decode_budget = irmind_app::source_mapping::DecodeBudget::new(
                slots,
                slots.get() * (64 * 1024 * 1024),
            )
            .with_decoded_byte_ceiling(input.decode_budget.decoded_byte_ceiling());
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
    ) -> Result<BTreeMap<String, SourceReservation>, AppError> {
        self.preflight_direct_group_with_space(request, workers, cancel, || {
            fs4::available_space(self.spool_dir(request.case_id)?)
                .map_err(crate::parquet_store::storage)
        })
    }

    fn preflight_direct_group_with_space(
        &self,
        request: &MappedIngestRequest<'_>,
        workers: usize,
        cancel: &CancellationToken,
        available: impl FnOnce() -> Result<u64, AppError>,
    ) -> Result<BTreeMap<String, SourceReservation>, AppError> {
        let mut budgets = BTreeMap::new();
        let mut spool_sizes = Vec::new();
        let mut sort_sizes = Vec::new();
        let mut total = 0u64;
        for source in request.relative_paths {
            let mut file = Self::open_source(request.source_root, source)?;
            let (physical, reservation) =
                self.normalized_allowance(&mut file, request.parser, source, cancel)?;
            // Preserve the historical group formula for default decoders, while
            // including the full expanded reservation for compact-source profiles.
            let expanded = reservation
                .normalized_bytes
                .checked_sub(super::staging::MAX_STAGED_ROW)
                .ok_or_else(invalid_source)?;
            total = total
                .checked_add(expanded)
                .and_then(|n| n.checked_add(if request.copy_original { physical } else { 0 }))
                .ok_or_else(invalid_source)?;
            if request.parser.identity_for_source(source)?.name == "parser-azure-flow" {
                spool_sizes.push(reservation.normalized_bytes);
                sort_sizes.push(reservation.normalized_bytes);
            } else {
                spool_sizes.push(expanded);
            }
            budgets.insert(source.clone(), reservation);
        }
        // All active workers may stage a source. Only sort workers can also
        // have pending input runs and a replacement open at the same time.
        let spools = sum_largest(&mut spool_sizes, workers)?;
        let scratch = sum_largest(&mut sort_sizes, super::sorting::sort_workers(workers))?
            .checked_mul(super::sorting::SORT_SCRATCH_COPIES)
            .ok_or_else(invalid_source)?;
        let required = total
            .checked_add(spools)
            .and_then(|n| n.checked_add(scratch))
            .and_then(|n| n.checked_add(5 * 64 * 1024 * 1024))
            .ok_or_else(invalid_source)?;
        super::staging::check_space(available()?, required)?;
        Ok(budgets)
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

fn sum_largest(sizes: &mut [u64], workers: usize) -> Result<u64, AppError> {
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    sizes.iter().take(workers).try_fold(0u64, |sum, size| {
        sum.checked_add(*size).ok_or_else(invalid_source)
    })
}

fn group_identity(
    request: &MappedIngestRequest<'_>,
    identity: irmind_app::ParserIdentity<'_>,
) -> irmind_domain::EvidenceHash {
    let mut bytes = b"irmind-direct-source-group-v1\0".to_vec();
    for relative in request.relative_paths {
        let path = request.parser.logical_source(relative);
        bytes.extend_from_slice(&(path.len() as u64).to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
    }
    bytes.extend_from_slice(identity.name.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(identity.version.as_bytes());
    irmind_domain::EvidenceHash::from_bytes(irmind_app::sha256(&bytes))
}
