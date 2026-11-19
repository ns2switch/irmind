use super::super::local::{stream, verify_source_unchanged};
use super::super::{
    AppError, CancellationToken, CaseId, File, ParquetStore, ParseReport, Path, RecordRow,
    SourceManifestV1, StreamingEventParser, invalid_source, storage,
};
use super::temporary::DiskLease;
use irmind_app::source_mapping::{
    DecodeBudget, NormalizedExpansionProfile, NormalizedSourceBudget,
};
use std::io::{Read, Seek, SeekFrom};
mod row_spool;
pub(super) use row_spool::RowSpool;

const EXPANSION_RESERVATION: u64 = 16;
const MARGIN: u64 = 64 * 1024 * 1024;
pub(super) const MAX_STAGED_ROW: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) struct SourceReservation {
    pub(super) normalized_bytes: u64,
    pub(super) decoded_byte_ceiling: Option<u64>,
}

pub(super) struct Input {
    pub file: File,
    pub path: String,
    pub budget: u64,
    pub(super) decode_budget: irmind_app::source_mapping::DecodeBudget,
}

pub(super) struct StagedSource {
    pub mapping: irmind_app::source_mapping::DecodedSourceCommitmentV1,
    pub spool: tempfile::NamedTempFile,
    pub manifest: SourceManifestV1,
    pub report: ParseReport,
    pub sample_hash: [u8; 32],
    pub normalized_hash: [u8; 32],
    pub needs_sort: bool,
    pub disk: DiskLease,
}

impl ParquetStore {
    #[cfg(test)]
    pub(super) fn staging_inputs(
        &self,
        case: &CaseId,
        root: &Path,
        paths: &[String],
    ) -> Result<Vec<Input>, AppError> {
        self.staging_inputs_reserved(case, root, paths, None, &CancellationToken::new())
    }
    pub(super) fn staging_inputs_reserved(
        &self,
        case: &CaseId,
        root: &Path,
        paths: &[String],
        budgets: Option<&std::collections::BTreeMap<String, SourceReservation>>,
        cancel: &CancellationToken,
    ) -> Result<Vec<Input>, AppError> {
        let mut inputs = Vec::new();
        let mut required = MARGIN;
        for path in paths {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let file = Self::open_source(root, path)?;
            let physical = file.metadata().map_err(storage)?.len();
            let reservation = match budgets {
                Some(budgets) => *budgets.get(path).ok_or_else(invalid_source)?,
                None => SourceReservation {
                    normalized_bytes: standard_allowance(physical)?,
                    decoded_byte_ceiling: None,
                },
            };
            required = required
                .checked_add(reservation.normalized_bytes)
                .ok_or_else(no_space)?;
            inputs.push(Input {
                file,
                path: path.clone(),
                budget: reservation.normalized_bytes,
                decode_budget: DecodeBudget::sequential()
                    .with_decoded_byte_ceiling(reservation.decoded_byte_ceiling),
            });
        }
        let dir = self.spool_dir(case)?;
        check_space(fs4::available_space(&dir).map_err(storage)?, required)?;
        Ok(inputs)
    }
    pub(super) fn normalized_allowance(
        &self,
        file: &mut File,
        parser: &dyn StreamingEventParser,
        path: &str,
        cancel: &CancellationToken,
    ) -> Result<(u64, SourceReservation), AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let physical = file.metadata().map_err(storage)?.len();
        let id = parser.identity_for_source(path)?;
        let decoder = self
            .mapping_catalog
            .as_ref()
            .ok_or_else(invalid_source)?
            .decoder(id.name, id.version)
            .map_err(irmind_app::source_mapping::MappingError::into_app)?;
        file.rewind().map_err(storage)?;
        let result = decoder.normalized_source_budget(file, cancel);
        let rewind = file.rewind().map_err(storage);
        let declared = source_preflight_result(result, path)?;
        rewind?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let reservation = match declared {
            Some(budget) => reserve_profile(id, budget)?,
            None => SourceReservation {
                normalized_bytes: standard_allowance(physical)?,
                decoded_byte_ceiling: None,
            },
        };
        Ok((physical, reservation))
    }

    #[cfg(test)]
    pub(super) fn stage_source(
        &self,
        case: &CaseId,
        mut input: Input,
        parser: &dyn StreamingEventParser,
        copied: bool,
        cancel: &CancellationToken,
    ) -> Result<StagedSource, AppError> {
        let (metadata, hash, size) =
            stream::initial_hash(&mut input.file, cancel, self.profile.as_deref())?;
        self.stage_hashed_source(case, input, parser, copied, cancel, (metadata, hash, size))
    }

    pub(super) fn stage_hashed_source(
        &self,
        case: &CaseId,
        mut input: Input,
        parser: &dyn StreamingEventParser,
        copied: bool,
        cancel: &CancellationToken,
        initial: (std::fs::Metadata, [u8; 32], u64),
    ) -> Result<StagedSource, AppError> {
        let (metadata, hash, size) = initial;
        let _stage = self
            .profile
            .as_ref()
            .map(|p| p.measure(super::super::PartitionPhase::Stage));
        let value = irmind_domain::EvidenceHash::parse(&irmind_app::hex(&hash))
            .map_err(|_| invalid_source())?;
        let sample = source_sample(&mut input.file)?;
        let mut spool = RowSpool::new(self, case, input.budget)?;
        let mut position = None;
        let mut needs_sort = false;
        let (report, mapping) = self.decode_mapped(
            case,
            &mut stream::VerifiedInput {
                source: &mut input.file,
                sample: &sample,
                relative_path: &input.path,
                hash,
                hash_value: &value,
                size,
                cancel,
                parser,
                decode_budget: input.decode_budget,
            },
            &mut |row| {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let key = row.sort_key();
                if let Some(old) = position {
                    needs_sort |= irmind_domain::compare_record_keys(old, key, false)
                        .map_err(|_| invalid_source())?
                        .is_gt();
                }
                position = Some(key);
                spool.push(&row)
            },
        )?;
        let completed = spool.finish(report.accepted)?;
        verify_source_unchanged(&input.file, &metadata, &value)?;
        Ok(StagedSource {
            mapping,
            spool: completed.file,
            manifest: Self::source_manifest(&input.path, &metadata, size, value, copied)?,
            report,
            sample_hash: irmind_app::sha256(&sample),
            normalized_hash: completed.hash,
            needs_sort,
            disk: completed.disk,
        })
    }
}

pub(super) fn source_sample(file: &mut File) -> Result<Vec<u8>, AppError> {
    file.seek(SeekFrom::Start(0)).map_err(storage)?;
    let mut sample = Vec::new();
    file.take(64 * 1024)
        .read_to_end(&mut sample)
        .map_err(storage)?;
    Ok(sample)
}

pub(super) fn check_space(available: u64, required: u64) -> Result<(), AppError> {
    if available < required {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::StorageCaseStagingCapacity {
                required,
                available,
            },
        ));
    }
    Ok(())
}
pub(super) fn no_space() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::StorageNormalizedStagingSpace)
}

pub(super) fn normalized_source_limit(required: u64, allowance: u64) -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::StorageNormalizedSourceLimit {
        required,
        allowance,
    })
}

pub(super) fn standard_allowance(physical: u64) -> Result<u64, AppError> {
    physical
        .checked_mul(EXPANSION_RESERVATION)
        .and_then(|n| n.checked_add(MAX_STAGED_ROW))
        .ok_or_else(no_space)
}
#[cfg(test)]
#[path = "staging/budget_tests.rs"]
mod budget_tests;

fn reserve_profile(
    id: irmind_app::ParserIdentity<'_>,
    budget: NormalizedSourceBudget,
) -> Result<SourceReservation, AppError> {
    let decoded_byte_ceiling = match budget.profile() {
        NormalizedExpansionProfile::CompactFlow32 if id.name == "parser-vpc-flow" => None,
        NormalizedExpansionProfile::DecodedJson16
            if id.name == "parser-fdr" && id.version == "fdr-source-v1" =>
        {
            Some(budget.decoded_bytes())
        }
        _ => return Err(invalid_source()),
    };
    Ok(SourceReservation {
        normalized_bytes: budget.allowance()?,
        decoded_byte_ceiling,
    })
}

fn source_preflight_result(
    result: Result<Option<NormalizedSourceBudget>, AppError>,
    path: &str,
) -> Result<Option<NormalizedSourceBudget>, AppError> {
    use irmind_app::{FixedAppError, RejectedSource, SourceFailureReason};
    let reason = match result {
        Err(AppError::Fixed(FixedAppError::SourceFormat)) => SourceFailureReason::Format,
        Err(AppError::Fixed(FixedAppError::SourceLimit)) => SourceFailureReason::Limit,
        other => return other,
    };
    Err(AppError::SourceFailure(RejectedSource::try_new(
        path.into(),
        reason,
        vec![],
    )?))
}
