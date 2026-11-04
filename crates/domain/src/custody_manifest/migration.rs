//! Bounded commitments bind arbitrarily large artifact inventories without
//! duplicating them in a single signed event. Original manifests stay intact.
mod lineage;
pub use lineage::ArtifactLineage;

use super::{DomainError, EvidenceHash, Reader, decode_payload, encode_payload, put};
use crate::{ARTIFACT_V2_TIME_SEMANTICS, ParquetArtifact};
use std::collections::{BTreeMap, BTreeSet};

const TAG: &[u8] = b"irmind-parquet-migration-v1\0";
pub type ByteStream<'a> = dyn FnMut(&mut dyn FnMut(&[u8])) + 'a;
pub type DigestStream = fn(&mut ByteStream<'_>) -> [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetCommitment {
    pub count: u64,
    pub sha256: EvidenceHash,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ParserTransition {
    pub old_id: String,
    pub old_version: String,
    pub new_id: String,
    pub new_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParquetMigrationV1 {
    pub sources: SetCommitment,
    pub previous: SetCommitment,
    pub replacement: SetCommitment,
    pub parsers: Vec<(ParserTransition, SetCommitment)>,
    pub builder_version: String,
    pub time_semantics: String,
}

fn invalid() -> DomainError {
    DomainError::InvalidManifest
}

fn fingerprint(bytes: [u8; 32]) -> EvidenceHash {
    // Bytes always produce a valid lowercase SHA-256 value.
    EvidenceHash::from_bytes(bytes)
}

fn commitment(
    tag: &[u8],
    count: usize,
    parts: impl Iterator<Item = Vec<u8>>,
    digest: DigestStream,
) -> SetCommitment {
    let mut parts = parts;
    let hash = digest(&mut |feed| {
        feed(tag);
        feed(&(count as u64).to_be_bytes());
        for bytes in parts.by_ref() {
            feed(&(bytes.len() as u64).to_be_bytes());
            feed(&bytes);
        }
    });
    SetCommitment {
        count: count as u64,
        sha256: fingerprint(hash),
    }
}

fn source_commitment(values: &BTreeSet<EvidenceHash>, digest: DigestStream) -> SetCommitment {
    commitment(
        b"irmind-migration-sources-v1\0",
        values.len(),
        values.iter().map(|v| v.as_str().as_bytes().to_vec()),
        digest,
    )
}

fn artifact_commitment(
    values: &[ParquetArtifact],
    digest: DigestStream,
) -> Result<SetCommitment, DomainError> {
    let mut sorted = values.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.path().cmp(b.path()));
    // Validate first; the subsequent streaming encoding is infallible for these values.
    for artifact in &sorted {
        artifact.validate()?;
    }
    let mut failed = false;
    let result = commitment(
        b"irmind-migration-artifacts-v1\0",
        sorted.len(),
        sorted.into_iter().map(|a| {
            if let Ok(v) = a.encode() {
                v.into_bytes()
            } else {
                failed = true;
                Vec::new()
            }
        }),
        digest,
    );
    if failed {
        return Err(invalid());
    }
    Ok(result)
}

impl ParquetMigrationV1 {
    pub fn generation(
        previous: &[ParquetArtifact],
        digest: DigestStream,
    ) -> Result<EvidenceHash, DomainError> {
        Ok(artifact_commitment(previous, digest)?.sha256)
    }

    pub fn between(
        previous: &[ParquetArtifact],
        replacement: &[ParquetArtifact],
        original_parsers: &BTreeMap<EvidenceHash, (String, String)>,
        digest: DigestStream,
    ) -> Result<Self, DomainError> {
        let old_sources = sources(previous);
        if previous.is_empty() || replacement.is_empty() || old_sources != sources(replacement) {
            return Err(invalid());
        }
        let mut groups: BTreeMap<ParserTransition, BTreeSet<EvidenceHash>> = BTreeMap::new();
        let mut builder = None;
        for a in replacement {
            let ParquetArtifact::V2(new) = a else {
                return Err(invalid());
            };
            if builder.as_ref().is_some_and(|b| b != &new.builder_version) {
                return Err(invalid());
            }
            builder = Some(new.builder_version.clone());
            for hash in &new.source_hashes {
                let (old_id, old_version) = original_parsers.get(hash).ok_or_else(invalid)?;
                let transition = ParserTransition {
                    old_id: old_id.clone(),
                    old_version: old_version.clone(),
                    new_id: new.parser_id.clone(),
                    new_version: new.parser_version.clone(),
                };
                groups.entry(transition).or_default().insert(hash.clone());
            }
        }
        let value = Self {
            sources: source_commitment(&old_sources, digest),
            previous: artifact_commitment(previous, digest)?,
            replacement: artifact_commitment(replacement, digest)?,
            parsers: groups
                .into_iter()
                .map(|(k, v)| (k, source_commitment(&v, digest)))
                .collect(),
            builder_version: builder.ok_or_else(invalid)?,
            time_semantics: ARTIFACT_V2_TIME_SEMANTICS.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.sources.count == 0
            || self.previous.count == 0
            || self.replacement.count == 0
            || self.previous.sha256 == self.replacement.sha256
            || self.parsers.is_empty()
            || self
                .parsers
                .iter()
                .try_fold(0u64, |count, (_, group)| count.checked_add(group.count))
                != Some(self.sources.count)
            || self.parsers.len() > 32
            || !self.parsers.windows(2).all(|p| p[0].0 < p[1].0)
            || self.time_semantics != ARTIFACT_V2_TIME_SEMANTICS
            || !valid_name(&self.builder_version, 128)
            || self.parsers.iter().any(|(p, s)| {
                s.count == 0
                    || s.count > self.sources.count
                    || !valid_name(&p.old_id, 64)
                    || !valid_name(&p.new_id, 64)
                    || !valid_name(&p.old_version, 128)
                    || !valid_name(&p.new_version, 128)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<String, DomainError> {
        self.validate()?;
        let mut bytes = TAG.to_vec();
        for value in [&self.sources, &self.previous, &self.replacement] {
            write_set(&mut bytes, value);
        }
        bytes.extend_from_slice(&(self.parsers.len() as u64).to_be_bytes());
        for (p, sources) in &self.parsers {
            for text in [&p.old_id, &p.old_version, &p.new_id, &p.new_version] {
                put(&mut bytes, text.as_bytes());
            }
            write_set(&mut bytes, sources);
        }
        put(&mut bytes, self.builder_version.as_bytes());
        put(&mut bytes, self.time_semantics.as_bytes());
        encode_payload(&bytes)
    }

    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = decode_payload(payload, TAG)?;
        let mut reader = Reader::new(&bytes[TAG.len()..]);
        let sources = read_set(&mut reader)?;
        let previous = read_set(&mut reader)?;
        let replacement = read_set(&mut reader)?;
        let count = reader.u64()?;
        if count > 32 {
            return Err(invalid());
        }
        let mut parsers = Vec::new();
        for _ in 0..count {
            let p = ParserTransition {
                old_id: reader.string_limit(64)?,
                old_version: reader.string_limit(128)?,
                new_id: reader.string_limit(64)?,
                new_version: reader.string_limit(128)?,
            };
            parsers.push((p, read_set(&mut reader)?));
        }
        let value = Self {
            sources,
            previous,
            replacement,
            parsers,
            builder_version: reader.string_limit(128)?,
            time_semantics: reader.string_limit(128)?,
        };
        reader.end()?;
        value.validate()?;
        Ok(value)
    }
}

fn valid_name(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_graphic())
}
fn sources(artifacts: &[ParquetArtifact]) -> BTreeSet<EvidenceHash> {
    artifacts
        .iter()
        .flat_map(|a| a.source_hashes().iter().cloned())
        .collect()
}
fn write_set(bytes: &mut Vec<u8>, set: &SetCommitment) {
    bytes.extend_from_slice(&set.count.to_be_bytes());
    put(bytes, set.sha256.as_str().as_bytes());
}
fn read_set(reader: &mut Reader<'_>) -> Result<SetCommitment, DomainError> {
    Ok(SetCommitment {
        count: reader.u64()?,
        sha256: EvidenceHash::parse(&reader.string_limit(64)?)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
