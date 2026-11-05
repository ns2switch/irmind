//! Informational extraction limits, separate from chain authentication.
use crate::{AppError, AuditEventKind, SignedEntry, SourceManifestV1, SourceManifestV2};
use irmind_domain::{EvidenceHash, ParquetArtifact};
use std::collections::{BTreeMap, BTreeSet};

const LARGE_FIRST_LINE: u64 = 4 * 1024 * 1024;

/// A display-only notice; it carries no evidence content or verification verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserExtractionWarning {
    sources: usize,
}

const REFERENCES: &str = concat!(
    "Details: https://github.com/ns2switch/irmind/blob/v0.1.6/CHANGELOG.md#known-issue-fixed ",
    "Re-ingestion: https://github.com/ns2switch/irmind/blob/v0.1.6/docs/parsers.md#current-readers-and-existing-cases"
);

impl ParserExtractionWarning {
    /// Screen the generated summary and retain fixed, trusted project links.
    /// References never come from a source, parser definition or case field.
    pub fn display(&self, guard: &dyn crate::ContentGuard) -> Result<String, AppError> {
        let screened = guard.screen(&summary(self.sources))?;
        Ok(format!("{} {REFERENCES}", screened.text))
    }
}

impl std::fmt::Display for ParserExtractionWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {REFERENCES}", summary(self.sources))
    }
}

/// Inspect already authenticated history without loading or re-parsing sources.
/// The warning never changes verification success or enters model context.
pub fn parser_extraction_warning(
    entries: &[SignedEntry],
) -> Result<Option<ParserExtractionWarning>, AppError> {
    let mut sizes = BTreeMap::<EvidenceHash, u64>::new();
    let mut affected = BTreeSet::new();
    for entry in entries {
        let invalid = || AppError::InvalidChain(entry.seq);
        match entry.kind {
            AuditEventKind::SourceManifestV1 => {
                let source = SourceManifestV1::decode(&entry.payload).map_err(|_| invalid())?;
                sizes
                    .entry(source.sha256.clone())
                    .and_modify(|n| *n = (*n).max(source.size))
                    .or_insert(source.size);
                affected.insert(source.sha256);
            }
            AuditEventKind::SourceManifestV2 => {
                let manifest = SourceManifestV2::decode(&entry.payload).map_err(|_| invalid())?;
                sizes
                    .entry(manifest.source.sha256.clone())
                    .and_modify(|n| *n = (*n).max(manifest.source.size))
                    .or_insert(manifest.source.size);
                if affected_version(&manifest.parser_version) {
                    affected.insert(manifest.source.sha256);
                }
            }
            AuditEventKind::ParquetArtifactV1 | AuditEventKind::ParquetArtifactV2 => {
                let artifact =
                    ParquetArtifact::decode(entry.kind, &entry.payload).map_err(|_| invalid())?;
                if affected_version(artifact.parser_version()) {
                    affected.extend(artifact.source_hashes().iter().cloned());
                }
            }
            AuditEventKind::GraphIndexed => {
                let hash = entry.evidence.as_deref().ok_or_else(invalid)?;
                affected.insert(EvidenceHash::parse(hash).map_err(|_| invalid())?);
            }
            _ => {}
        }
    }
    let count = affected
        .iter()
        .filter(|hash| sizes.get(*hash).is_none_or(|size| *size > LARGE_FIRST_LINE))
        .count();
    Ok((count != 0).then_some(ParserExtractionWarning { sources: count }))
}

fn affected_version(version: &str) -> bool {
    let version = version.strip_suffix("+compact-v1").unwrap_or(version);
    matches!(
        version,
        "json-stream-v2"
            | "ecs-ndjson-v1"
            | "ocsf-stream-v1"
            | "velociraptor-json-v1"
            | "hayabusa-json-csv-v1"
            | "chainsaw-json-v1"
            | "plaso-json-v1"
            | "declarative-v1"
    ) || version
        .strip_prefix("declarative-v1:sha256=")
        .is_some_and(|hash| EvidenceHash::parse(hash).is_ok())
}

fn summary(count: usize) -> String {
    let noun = if count == 1 { "source" } else { "sources" };
    format!(
        "Warning: the signed chain is valid, but extraction may be incomplete. \
         {count} {noun} used a retired reader affected by the v0.1.1–v0.1.5 issue: \
         a first line over 4 MiB could omit records. Create a new case and re-ingest \
         verified originals with current readers."
    )
}

#[cfg(test)]
mod tests;
