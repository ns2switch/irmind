//! Bounded direct local ingestion contracts. The application owns all signatures.
mod binding;
mod rejection;
use crate::source_mapping::DecodedSourceCommitmentV1;
use crate::{
    AppError, CancellationToken, CaseId, ParseReport, PartitionLimits, StreamingEventParser,
};
pub use binding::{BoundMappedGroup, PreparedMappedGroup};
use irmind_domain::{ParquetArtifact, SourceManifestV1};
pub use rejection::{RejectedSource, SourceFailureReason};
use std::collections::BTreeMap;
use std::path::Path;

pub const MAPPED_GROUP_SOURCES: usize = 128;
pub const MAPPED_GROUP_EXCLUSIONS: usize = 16;

#[derive(Clone, Copy)]
pub struct MappedIngestRequest<'a> {
    pub case_id: &'a CaseId,
    pub source_root: &'a Path,
    pub relative_paths: &'a [String],
    pub copy_original: bool,
    pub parser: &'a dyn StreamingEventParser,
    pub committed_artifacts: CommittedArtifacts<'a>,
    pub limits: PartitionLimits,
}

/// Borrow the authenticated inventory without copying it to probe an optional
/// preparation path. Historical adapters return None without traversing it.
#[derive(Clone, Copy)]
pub enum CommittedArtifacts<'a> {
    Slice(&'a [ParquetArtifact]),
    Indexed(&'a BTreeMap<String, ParquetArtifact>),
}
impl<'a> CommittedArtifacts<'a> {
    pub fn iter(self) -> impl Iterator<Item = &'a ParquetArtifact> {
        let (slice, indexed) = match self {
            Self::Slice(values) => (Some(values.iter()), None),
            Self::Indexed(values) => (None, Some(values.values())),
        };
        slice
            .into_iter()
            .flatten()
            .chain(indexed.into_iter().flatten())
    }
}
impl MappedIngestRequest<'_> {
    pub fn validate(&self) -> Result<(), AppError> {
        self.limits.validate()?;
        if self.relative_paths.is_empty()
            || self.relative_paths.len() > MAPPED_GROUP_SOURCES
            || !self.relative_paths.windows(2).all(|p| p[0] < p[1])
        {
            return Err(AppError::Policy(
                "invalid bounded direct source group".into(),
            ));
        }
        let first = self.parser.identity_for_source(&self.relative_paths[0])?;
        for path in self.relative_paths {
            irmind_domain::SourceReferenceV1::file(path)
                .map_err(|_| AppError::Policy("invalid direct source path".into()))?;
            let identity = self.parser.identity_for_source(path)?;
            if identity.name != first.name || identity.version != first.version {
                return Err(AppError::Policy(
                    "direct group contains incompatible decoders".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MappedSourceAcquisition {
    pub manifest: SourceManifestV1,
    pub report: ParseReport,
    pub format_sample_sha256: [u8; 32],
    pub decoded: DecodedSourceCommitmentV1,
}

pub trait PreparedMappedIngest: Send {
    fn metadata(&self) -> &PreparedMappedGroup;
    fn publish(&mut self, cancel: &CancellationToken) -> Result<(), AppError>;
    /// No I/O after the atomic signed append; Drop must retain this group.
    fn retain_committed(&mut self);
}
