mod partitions;
pub use partitions::*;

use super::{
    DomainError, EvidenceHash, Reader, decode_payload, encode_payload, put, valid_relative_path,
};

const TAG: &[u8] = b"irmind-parquet-artifact-v2\0";
pub const ARTIFACT_V2_TIME_SEMANTICS: &str = "utc-microseconds-residual-ns-v1";
pub const ARTIFACT_V2_STABLE_ORDER: &str = "instant-source-offset-record-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactSchemaV2 {
    Events,
    Entities,
    Coobservations,
    CommonEvents,
    CommonEntities,
    CommonCoobservations,
}

impl ArtifactSchemaV2 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Events => "irmind-events-v3",
            Self::Entities => "irmind-entities-v3",
            Self::Coobservations => "irmind-coobservations-v2",
            Self::CommonEvents => "irmind-events-v4",
            Self::CommonEntities => "irmind-entities-v4",
            Self::CommonCoobservations => "irmind-coobservations-v3",
        }
    }

    pub const fn is_common(self) -> bool {
        matches!(
            self,
            Self::CommonEvents | Self::CommonEntities | Self::CommonCoobservations
        )
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "irmind-events-v3" => Ok(Self::Events),
            "irmind-entities-v3" => Ok(Self::Entities),
            "irmind-coobservations-v2" => Ok(Self::Coobservations),
            "irmind-events-v4" => Ok(Self::CommonEvents),
            "irmind-entities-v4" => Ok(Self::CommonEntities),
            "irmind-coobservations-v3" => Ok(Self::CommonCoobservations),
            _ => Err(DomainError::InvalidManifest),
        }
    }
}

/// Additive signed envelope. No V1 field, wire value or decoder is reused for V2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParquetArtifactV2 {
    pub path: String,
    pub size: u64,
    pub sha256: EvidenceHash,
    pub parser_id: String,
    pub parser_version: String,
    pub schema: ArtifactSchemaV2,
    pub partition: ArtifactPartitionV2,
    pub source_hashes: Vec<EvidenceHash>,
    pub time_semantics: String,
    pub stable_order: String,
    pub builder_version: String,
    pub superseded_hashes: Vec<EvidenceHash>,
}

impl ParquetArtifactV2 {
    pub fn encode(&self) -> Result<String, DomainError> {
        self.validate()?;
        let mut bytes = TAG.to_vec();
        put(&mut bytes, self.path.as_bytes());
        bytes.extend_from_slice(&self.size.to_be_bytes());
        put(&mut bytes, self.sha256.as_str().as_bytes());
        put(&mut bytes, self.parser_id.as_bytes());
        put(&mut bytes, self.parser_version.as_bytes());
        put(&mut bytes, self.schema.as_str().as_bytes());
        self.partition.write(&mut bytes);
        write_hashes(&mut bytes, &self.source_hashes);
        put(&mut bytes, self.time_semantics.as_bytes());
        put(&mut bytes, self.stable_order.as_bytes());
        put(&mut bytes, self.builder_version.as_bytes());
        write_hashes(&mut bytes, &self.superseded_hashes);
        encode_payload(&bytes)
    }

    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = decode_payload(payload, TAG)?;
        let mut reader = Reader::new(&bytes[TAG.len()..]);
        let value = Self {
            path: reader.string_limit(1024)?,
            size: reader.u64()?,
            sha256: EvidenceHash::parse(&reader.string_limit(64)?)?,
            parser_id: reader.string_limit(64)?,
            parser_version: reader.string_limit(128)?,
            schema: ArtifactSchemaV2::parse(&reader.string_limit(128)?)?,
            partition: ArtifactPartitionV2::read(&mut reader)?,
            source_hashes: read_hashes(&mut reader)?,
            time_semantics: reader.string_limit(128)?,
            stable_order: reader.string_limit(128)?,
            builder_version: reader.string_limit(128)?,
            superseded_hashes: read_hashes(&mut reader)?,
        };
        reader.end()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.partition.validate()?;
        if self.path.len() > 1024
            || !self
                .path
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/._=-".contains(&b))
            || !valid_relative_path(&self.path)
            || !self.path.ends_with(".parquet")
            || !self.path.starts_with(&self.partition.path_prefix()?)
            || self.parser_id.is_empty()
            || self.parser_id.len() > 64
            || !self
                .parser_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !version(&self.parser_version)
            || !version(&self.builder_version)
            || self.time_semantics != ARTIFACT_V2_TIME_SEMANTICS
            || self.stable_order != ARTIFACT_V2_STABLE_ORDER
            || self.source_hashes.is_empty()
            || !hashes_valid(&self.source_hashes)
            || !hashes_valid(&self.superseded_hashes)
            || self.superseded_hashes.contains(&self.sha256)
        {
            return Err(DomainError::InvalidManifest);
        }
        Ok(())
    }
}

fn version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}

fn hashes_valid(values: &[EvidenceHash]) -> bool {
    values.len() <= 128 && values.windows(2).all(|p| p[0] < p[1])
}

fn write_hashes(bytes: &mut Vec<u8>, values: &[EvidenceHash]) {
    bytes.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for hash in values {
        put(bytes, hash.as_str().as_bytes());
    }
}

fn read_hashes(reader: &mut Reader<'_>) -> Result<Vec<EvidenceHash>, DomainError> {
    let count = usize::try_from(reader.u64()?).map_err(|_| DomainError::InvalidManifest)?;
    if count > 128 {
        return Err(DomainError::InvalidManifest);
    }
    (0..count)
        .map(|_| EvidenceHash::parse(&reader.string_limit(64)?))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
