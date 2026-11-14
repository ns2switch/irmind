use super::{
    AppError, CancellationToken, CaseId, EvidenceHash, LocalStore, SourceRecordV1, Tainted, signed,
    unavailable,
};
use irmind_app::{
    AuditLog as _, EvidenceGraph as _,
    source_mapping::{SourceFileInput, SourceInput, SourceMetadata, SourceRecordReplay},
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) struct ReadJob {
    pub store: Arc<LocalStore>,
    pub case: CaseId,
    pub hash: EvidenceHash,
    pub index: u64,
    pub root: Option<PathBuf>,
    pub cancel: CancellationToken,
}
impl ReadJob {
    pub(super) fn run(self) -> Result<Tainted<SourceRecordV1>, AppError> {
        if self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        // Prove the exact pointer exists, including artifact hashes, before touching originals.
        self.store.raw_record(
            &self.case,
            self.hash.as_str(),
            usize::try_from(self.index).map_err(crate::storage)?,
        )?;
        let artifacts = self.store.query_catalog(&self.case)?;
        let source = signed::select(&self.store.entries(&self.case)?, &artifacts, &self.hash)?;
        if self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut file = self.open(&source.manifest)?;
        authenticate(&mut file, &source.manifest.source, &self.cancel)?;
        let catalog = self.store.parquet.mapping_catalog.as_ref().ok_or_else(|| {
            unavailable("The exact source decoder is unavailable in this session")
        })?;
        let catalog = if catalog
            .supports_decoder(source.set.decoder().id(), source.set.decoder().version())
        {
            catalog.as_ref().clone()
        } else {
            catalog.frozen_for_profile(&source.profile).map_err(|_| unavailable("The signed source decoder is unavailable; use the IRMind version that created this case"))?
        };
        let decoder = catalog.decoder(source.set.decoder().id(), source.set.decoder().version())
            .map_err(|_| unavailable("The signed source decoder is unavailable; use the IRMind version that created this case"))?;
        let time = source
            .set
            .time_context()
            .map(irmind_app::source_mapping::parser_time_context)
            .transpose()?;
        let metadata = SourceMetadata {
            source: source.set.reference(),
            evidence_hash: super::super::parse_hash(&self.hash)?,
            time_context: time.as_ref(),
            cluster_context: source.set.cluster_context(),
            cancel: &self.cancel,
        };
        let mut replay = SourceRecordReplay::new(
            &source.set,
            metadata,
            source.manifest.source.size,
            self.index,
        )?;
        let mut sample = vec![0; 65_536];
        let count = file.read(&mut sample).map_err(crate::storage)?;
        file.seek(SeekFrom::Start(0)).map_err(crate::storage)?;
        let report =
            if decoder.needs_random_access(source.set.reference().reference(), &sample[..count]) {
                decoder.decode_local_file(
                    SourceFileInput {
                        metadata,
                        file: &mut file,
                    },
                    &mut |r| replay.accept(&r).map_err(replay_error),
                )?
            } else {
                decoder.decode_reader(
                    SourceInput {
                        metadata,
                        reader: &mut std::io::BufReader::with_capacity(65_536, &mut file),
                    },
                    &mut |r| replay.accept(&r).map_err(replay_error),
                )?
            };
        if report.samples != source.manifest.rejected_sample {
            return Err(unavailable(
                "Original rejection samples differ from the signed source",
            ));
        }
        let record = replay.finish(&report).map_err(replay_error)?;
        file.seek(SeekFrom::Start(0)).map_err(crate::storage)?;
        authenticate(&mut file, &source.manifest.source, &self.cancel)?;
        Ok(record)
    }
    pub(super) fn open(
        &self,
        manifest: &irmind_domain::SourceManifestV2,
    ) -> Result<File, AppError> {
        let (root, path) = if manifest.source.copied {
            (
                self.store.parquet.case_dir(&self.case)?,
                format!("originals/{}", self.hash.as_str()),
            )
        } else {
            if manifest.source.source.contains("://") {
                return Err(unavailable(
                    "Remote originals are not fetched by raw_records; explicitly acquire or retain a local copy",
                ));
            }
            (self.root.clone().ok_or_else(|| unavailable("Originals are not authorized in this session; select their directory with /verify <source-root>"))?, manifest.source.source.clone())
        };
        irmind_fs::open_regular_no_follow(&root, Path::new(&path))
            .map_err(|_| unavailable("Original unavailable or unsafe source path; select the verified originals directory"))
    }
}
fn authenticate(
    file: &mut File,
    manifest: &irmind_domain::SourceManifestV1,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    if file.metadata().map_err(crate::storage)?.len() != manifest.size {
        return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
    }
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 65_536];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let n = file.read(&mut buffer).map_err(crate::storage)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > manifest.size {
            return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
        }
        digest.update(&buffer[..n]);
    }
    if bytes != manifest.size
        || EvidenceHash::from_bytes(digest.finalize().into()) != manifest.sha256
    {
        return Err(AppError::EvidenceMismatch(manifest.sha256.as_str().into()));
    }
    file.seek(SeekFrom::Start(0)).map_err(crate::storage)?;
    Ok(())
}

fn replay_error(error: AppError) -> AppError {
    if matches!(error, AppError::Cancelled) {
        error
    } else {
        unavailable(
            "Decoded original records do not reproduce the signed input set; no original was returned",
        )
    }
}
