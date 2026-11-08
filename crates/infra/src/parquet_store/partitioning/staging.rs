use super::super::local::{stream, verify_source_unchanged};
use super::super::{
    AppError, CancellationToken, CaseId, File, ParquetStore, ParseReport, Path, RecordRow,
    SourceManifestV1, StreamingEventParser, invalid_source, storage,
};
use super::temporary::DiskLease;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

const EXPANSION_RESERVATION: u64 = 16;
const MARGIN: u64 = 64 * 1024 * 1024;
pub(super) const MAX_STAGED_ROW: u64 = 64 * 1024 * 1024;

pub(super) struct Input {
    pub file: File,
    pub path: String,
    pub budget: u64,
}

pub(super) struct StagedSource {
    pub mapping: Option<irmind_app::source_mapping::DecodedSourceCommitmentV1>,
    pub spool: tempfile::NamedTempFile,
    pub source: File,
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
        let mut spool = self.create_normalized_spool(case)?;
        let mut writer = std::io::BufWriter::new(spool.as_file_mut());
        let mut bytes = 0u64;
        let mut normalized_hash = Sha256::new();
        let mut accepted = 0usize;
        let mut position = None;
        let mut needs_sort = false;
        let mut disk = DiskLease::new(self.profile.clone());
        let (report, mapping) = self.parse_normalized(
            case,
            stream::VerifiedInput {
                source: &mut input.file,
                sample: &sample,
                relative_path: &input.path,
                hash,
                hash_value: &value,
                size,
                cancel,
                parser,
                precise_time: true,
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
                let encoded = serde_json::to_vec(&row).map_err(storage)?;
                let count = u64::try_from(encoded.len()).map_err(storage)? + 1;
                bytes = bytes.checked_add(count).ok_or_else(no_space)?;
                if count > MAX_STAGED_ROW || bytes > input.budget {
                    return Err(no_space());
                }
                normalized_hash.update(&encoded);
                normalized_hash.update(b"\n");
                accepted = accepted.checked_add(1).ok_or_else(invalid_source)?;
                writer.write_all(&encoded).map_err(storage)?;
                writer.write_all(b"\n").map_err(storage)?;
                disk.add(count)?;
                Ok(())
            },
        )?;
        writer.flush().map_err(storage)?;
        drop(writer);
        if report.accepted == 0 || report.accepted != accepted {
            return Err(invalid_source());
        }
        verify_source_unchanged(&input.file, &metadata, &value)?;
        spool
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(storage)?;
        Ok(StagedSource {
            mapping,
            spool,
            source: input.file,
            manifest: Self::source_manifest(&input.path, &metadata, size, value, copied)?,
            report,
            sample_hash: irmind_app::sha256(&sample),
            normalized_hash: normalized_hash.finalize().into(),
            needs_sort,
            disk,
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

pub(super) fn normalized_row(
    record: &irmind_domain::Tainted<irmind_app::IndexedGraphRecord>,
    parser: &dyn StreamingEventParser,
    source: &str,
    hash: &irmind_domain::EvidenceHash,
    offset_mode: &mut Option<bool>,
    size: u64,
) -> Result<RecordRow, AppError> {
    let mut row = None;
    record.inspect(|indexed| {
        row = Some((|| {
            stream::validate_offset(offset_mode, indexed.source_offset, size)?;
            validate_time(indexed.time)?;
            let mut row = RecordRow::from_partitioned(indexed, hash)?;
            row.profile = profile(parser, source, &indexed.record)?;
            Ok(row)
        })());
    });
    row.ok_or_else(invalid_source)?
}

impl ParquetStore {
    pub(in crate::parquet_store) fn parse_normalized(
        &self,
        case: &CaseId,
        mut input: stream::VerifiedInput<'_>,
        emit: &mut dyn FnMut(RecordRow) -> Result<(), AppError>,
    ) -> Result<
        (
            ParseReport,
            Option<irmind_app::source_mapping::DecodedSourceCommitmentV1>,
        ),
        AppError,
    > {
        let id = input.parser.identity_for_source(input.relative_path)?;
        if self
            .mapping_catalog
            .as_ref()
            .is_some_and(|catalog| catalog.supports_decoder(id.name, id.version))
        {
            let (report, mapped) = self.decode_mapped(case, &mut input, emit)?;
            return Ok((report, Some(mapped)));
        }
        Ok((parse_legacy_normalized(input, emit)?, None))
    }
}

fn parse_legacy_normalized(
    input: stream::VerifiedInput<'_>,
    emit: &mut dyn FnMut(RecordRow) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let (parser, source, hash, size) = (
        input.parser,
        input.relative_path,
        input.hash_value,
        input.size,
    );
    let mut offset = None;
    stream::parse_and_verify(input, &mut |record| {
        emit(normalized_row(
            &record,
            parser,
            source,
            hash,
            &mut offset,
            size,
        )?)
    })
}

fn validate_time(time: Option<irmind_app::IndexedTime>) -> Result<(), AppError> {
    if time.is_some_and(|time| time.precision() == irmind_app::TimePrecision::Unknown) {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyInvalidIndexedTimestamp,
        ));
    }
    Ok(())
}
fn profile(
    parser: &dyn StreamingEventParser,
    source: &str,
    record: &irmind_app::GraphRecord,
) -> Result<u8, AppError> {
    Ok(match parser.partition_profile_for_source(source, record)? {
        irmind_app::PartitionProfile::Unpartitioned => 0,
        irmind_app::PartitionProfile::CloudAccountRegion => 1,
        irmind_app::PartitionProfile::EndpointHost => 2,
    })
}
