use crate::custody_manifest::{HEX_DIGITS, hex_digit};
use crate::{DomainError, ParquetArtifactV1};

const SEALED_MIGRATION_TAG: &str = "sealed-parquet-artifact-v1:";
const SEALED_MIGRATION_FAMILY: &str = "sealed-parquet-artifact-v";

/// A derived artifact recorded after the case seal in the separate signed
/// operational chain. The original case chain and seal remain immutable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedParquetMigrationV1 {
    pub seal_hash: [u8; 32],
    pub artifact: ParquetArtifactV1,
}

impl SealedParquetMigrationV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        let mut seal = String::with_capacity(64);
        for byte in self.seal_hash {
            seal.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            seal.push(char::from(HEX_DIGITS[usize::from(byte & 15)]));
        }
        Ok(format!(
            "{SEALED_MIGRATION_TAG}{seal}:{}",
            self.artifact.encode()?
        ))
    }

    pub fn decode(value: &str) -> Result<Option<Self>, DomainError> {
        let Some(rest) = value.strip_prefix(SEALED_MIGRATION_TAG) else {
            if value.starts_with(SEALED_MIGRATION_FAMILY) {
                return Err(DomainError::InvalidManifest);
            }
            return Ok(None);
        };
        let (seal, artifact) = rest.split_once(':').ok_or(DomainError::InvalidManifest)?;
        if seal.len() != 64 {
            return Err(DomainError::InvalidManifest);
        }
        let mut seal_hash = [0u8; 32];
        for (out, pair) in seal_hash.iter_mut().zip(seal.as_bytes().chunks_exact(2)) {
            *out = hex_digit(pair[0])? << 4 | hex_digit(pair[1])?;
        }
        Ok(Some(Self {
            seal_hash,
            artifact: ParquetArtifactV1::decode(artifact)?,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sealed_migration_tests {
    use super::*;
    use crate::EvidenceHash;

    #[test]
    fn sealed_artifact_is_bound_to_a_seal_and_unknown_version_fails_closed() {
        let source = EvidenceHash::parse(&"a".repeat(64)).unwrap();
        let artifact = ParquetArtifactV1 {
            path: format!(
                "date=2026-10-28/account=unknown/region=unknown/{}.events.parquet",
                source.as_str()
            ),
            size: 42,
            sha256: EvidenceHash::parse(&"b".repeat(64)).unwrap(),
            parser_version: "json-stream-v2".into(),
            schema_version: "records-v1".into(),
            partition_date: "2026-10-28".into(),
            partition_account: "unknown".into(),
            partition_region: "unknown".into(),
            source_hashes: vec![source],
        };
        let record = SealedParquetMigrationV1 {
            seal_hash: [42; 32],
            artifact,
        };
        let wire = record.encode().unwrap();
        assert_eq!(
            SealedParquetMigrationV1::decode(&wire).unwrap(),
            Some(record)
        );
        assert!(
            SealedParquetMigrationV1::decode(&wire.replace("artifact-v1", "artifact-v2")).is_err()
        );
    }
}
