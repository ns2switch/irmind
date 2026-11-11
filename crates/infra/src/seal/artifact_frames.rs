//! Current derived-file frames, keyed by authenticated relative paths.
use super::export_current::write_frame;
use super::frames::{read_frame, verify_raw};
use super::{AppError, CancellationToken, CaseId, LocalStore, Path, storage, storage_reason};
use irmind_domain::{ParquetArtifact, SourceManifestV1};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactFrame {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(skip)]
    common_schema: Option<irmind_domain::ArtifactSchemaV2>,
    #[serde(skip)]
    common_rows: Option<u64>,
}
impl ArtifactFrame {
    pub(super) fn from_artifact(artifact: &ParquetArtifact) -> Self {
        let ParquetArtifact::V3(value) = artifact;
        Self {
            path: artifact.path().into(),
            sha256: artifact.sha256().as_str().into(),
            size: artifact.size(),
            common_schema: Some(value.core().schema),
            common_rows: Some(value.pipeline().rows()),
        }
    }
}
impl LocalStore {
    pub(super) fn write_artifact_frames(
        &self,
        id: &CaseId,
        out: &mut File,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut files = BTreeMap::new();
        self.for_each_audit_entry(id, |entry| {
            if matches!(
                entry.kind,
                irmind_domain::AuditEventKind::ParquetArtifactV1
                    | irmind_domain::AuditEventKind::ParquetArtifactV2
            ) {
                return Err(AppError::Fixed(
                    irmind_app::FixedAppError::RetiredCaseFormat,
                ));
            }
            if entry.kind == irmind_domain::AuditEventKind::ParquetArtifactV3 {
                let artifact = ParquetArtifact::decode(entry.kind, &entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                let frame = ArtifactFrame::from_artifact(&artifact);
                if files.insert(frame.path.clone(), frame).is_some() {
                    return Err(AppError::InvalidChain(entry.seq));
                }
            }
            Ok(())
        })?;
        out.write_all(&(files.len() as u64).to_be_bytes())
            .map_err(storage)?;
        let root = self.parquet.case_dir(id)?;
        for frame in files.values() {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let mut file = irmind_fs::open_regular_no_follow(&root, Path::new(&frame.path))
                .map_err(storage)?;
            write_frame(out, &serde_json::to_vec(frame).map_err(storage)?)?;
            let manifest = SourceManifestV1 {
                source: frame.path.clone(),
                size: frame.size,
                sha256: irmind_domain::EvidenceHash::parse(&frame.sha256)
                    .map_err(|_| AppError::InvalidChain(0))?,
                modified_unix_seconds: None,
                version: None,
                provider_checksum: None,
                copied: false,
            };
            super::export_current::copy_verified(&mut file, out, &manifest, cancel)?;
        }
        Ok(())
    }
}

pub(super) fn verify_artifact_frames(
    input: &mut File,
    expected: &BTreeMap<String, ArtifactFrame>,
) -> Result<(), AppError> {
    // Empty pre-inventory V5 seeds have no derived files. Cases with signed
    // artifacts require the complete section; EOF cannot downgrade coverage.
    let mut first = [0u8; 1];
    if input.read(&mut first).map_err(storage)? == 0 {
        return if expected.is_empty() {
            Ok(())
        } else {
            Err(storage_reason("missing derived files from V5 export"))
        };
    }
    let mut count = [0u8; 8];
    count[0] = first[0];
    input.read_exact(&mut count[1..]).map_err(storage)?;
    if u64::from_be_bytes(count) != expected.len() as u64 {
        return Err(storage_reason(
            "derived-file count differs from signed inventory",
        ));
    }
    for (path, artifact) in expected {
        let frame: ArtifactFrame = serde_json::from_slice(&read_frame(input)?).map_err(storage)?;
        if &frame.path != path || frame.sha256 != artifact.sha256 || frame.size != artifact.size {
            return Err(storage_reason(
                "derived-file frame differs from signed inventory order or metadata",
            ));
        }
        if let Some(schema) = artifact.common_schema {
            super::parquet_frame::verify_common(
                input,
                frame.size,
                &frame.sha256,
                schema,
                artifact.common_rows,
            )?;
        } else {
            verify_raw(input, frame.size, &frame.sha256)?;
        }
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra).map_err(storage)? != 0 {
        return Err(storage_reason("export has trailing bytes"));
    }
    Ok(())
}
