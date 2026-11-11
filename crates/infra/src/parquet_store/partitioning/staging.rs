use super::super::local::{stream, verify_source_unchanged};
use super::super::{
    AppError, CancellationToken, CaseId, File, ParquetStore, ParseReport, Path, RecordRow,
    SourceManifestV1, StreamingEventParser, invalid_source, storage,
};
use super::temporary::DiskLease;
use std::io::{Read, Seek, SeekFrom};
mod row_spool;
pub(super) use row_spool::RowSpool;

const EXPANSION_RESERVATION: u64 = 16;
const MARGIN: u64 = 64 * 1024 * 1024;
pub(super) const MAX_STAGED_ROW: u64 = 64 * 1024 * 1024;

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
    pub(super) fn staging_inputs(
        &self,
        case: &CaseId,
        root: &Path,
        paths: &[String],
    ) -> Result<Vec<Input>, AppError> {
        let mut inputs = Vec::new();
        let mut required = MARGIN;
        for path in paths {
            let file = Self::open_source(root, path)?;
            let budget = file
                .metadata()
                .map_err(storage)?
                .len()
                .checked_mul(EXPANSION_RESERVATION)
                .and_then(|n| n.checked_add(MAX_STAGED_ROW))
                .ok_or_else(no_space)?;
            required = required.checked_add(budget).ok_or_else(no_space)?;
            inputs.push(Input {
                file,
                path: path.clone(),
                budget,
                decode_budget: irmind_app::source_mapping::DecodeBudget::sequential(),
            });
        }
        let dir = self.spool_dir(case)?;
        check_space(fs4::available_space(&dir).map_err(storage)?, required)?;
        Ok(inputs)
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
        return Err(no_space());
    }
    Ok(())
}
pub(super) fn no_space() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::StorageNormalizedStagingSpace)
}
