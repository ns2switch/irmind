mod codec;
use super::{
    ArtifactDerivationV1, ArtifactParentV1, DomainError, MappingBindingV1, ParquetArtifactV3,
    commitments, invalid,
};
use crate::{ArtifactPartitionV2, ArtifactSchemaV2, SetCommitment};
use std::collections::BTreeMap;

pub(super) const TAG: &[u8] = b"irmind-parquet-layout-v1\0";
const PARENTS: &[u8] = b"irmind-layout-parents-v1\0";
const REPLACEMENTS: &[u8] = b"irmind-layout-replacements-v1\0";
const BINDINGS: &[u8] = b"irmind-layout-bindings-v1\0";

/// A physical transformation receipt. It makes no claim of another mapping run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParquetLayoutV1 {
    parents: SetCommitment,
    replacements: SetCommitment,
    bindings: SetCommitment,
    schema: ArtifactSchemaV2,
    partition: ArtifactPartitionV2,
    rows: u64,
}
impl ParquetLayoutV1 {
    /// Deterministic metadata for preflight and the physical writer. The path
    /// depends on earlier parent envelopes, never on the child's own hash.
    pub fn replacement(
        parents: &[ParquetArtifactV3],
        size: u64,
        file_hash: super::EvidenceHash,
    ) -> Result<ParquetArtifactV3, DomainError> {
        use crate::custody_manifest::put;
        use crate::{ArtifactPipelineV1, PARQUET_LAYOUT_BUILDER_V1};
        use sha2::{Digest, Sha256};
        let bindings = Self::preserved_bindings(parents)?;
        let commitment = commitments::artifacts(parents, PARENTS)?;
        let first = parents.first().ok_or_else(invalid)?;
        let mut seed = b"irmind-layout-path-v1\0".to_vec();
        put(&mut seed, PARQUET_LAYOUT_BUILDER_V1.as_bytes());
        seed.extend_from_slice(&commitment.count.to_be_bytes());
        put(&mut seed, commitment.sha256.as_str().as_bytes());
        put(&mut seed, first.core().schema.as_str().as_bytes());
        first.core().partition.write(&mut seed);
        seed.extend_from_slice(&0u64.to_be_bytes());
        let digest = super::EvidenceHash::from_bytes(Sha256::digest(seed).into());
        let mut core = first.core().clone();
        core.path = format!(
            "{}layout-{}.parquet",
            core.partition.path_prefix()?,
            digest.as_str()
        );
        core.size = size;
        core.sha256 = file_hash;
        core.builder_version = PARQUET_LAYOUT_BUILDER_V1.into();
        core.source_hashes = bindings
            .iter()
            .map(|b| b.input().source().clone())
            .collect();
        let rows = parents.iter().try_fold(0u64, |n, p| {
            n.checked_add(p.pipeline().rows()).ok_or_else(invalid)
        })?;
        let mut references = parents
            .iter()
            .map(ArtifactParentV1::from_artifact)
            .collect::<Result<Vec<_>, _>>()?;
        references.sort_by(|a, b| a.path().cmp(b.path()));
        ParquetArtifactV3::try_new(
            core,
            ArtifactPipelineV1::layout(bindings, rows, references)?,
        )
    }
    pub fn between(
        parents: &[ParquetArtifactV3],
        replacement: &ParquetArtifactV3,
    ) -> Result<Self, DomainError> {
        let expected = Self::replacement(
            parents,
            replacement.core().size,
            replacement.core().sha256.clone(),
        )?;
        if expected != *replacement {
            return Err(invalid());
        }
        let preserved = Self::preserved_bindings(parents)?;
        let first = parents.first().ok_or_else(invalid)?;
        let rows = parents.iter().try_fold(0u64, |sum, a| {
            sum.checked_add(a.pipeline().rows()).ok_or_else(invalid)
        })?;
        let ArtifactDerivationV1::Layout {
            parents: references,
        } = replacement.pipeline().derivation()
        else {
            return Err(invalid());
        };
        let mut expected = parents
            .iter()
            .map(ArtifactParentV1::from_artifact)
            .collect::<Result<Vec<_>, _>>()?;
        expected.sort_by(|a, b| a.path().cmp(b.path()));
        if references != &expected
            || replacement.bindings() != preserved
            || replacement.pipeline().rows() != rows
            || !physical_compatible(first, replacement)
            || parents
                .iter()
                .any(|p| p.core().path == replacement.core().path)
        {
            return Err(invalid());
        }
        Ok(Self {
            parents: commitments::artifacts(parents, PARENTS)?,
            replacements: commitments::artifacts(std::slice::from_ref(replacement), REPLACEMENTS)?,
            bindings: commitments::bindings(&preserved, BINDINGS)?,
            schema: first.core().schema,
            partition: first.core().partition.clone(),
            rows,
        })
    }
    /// Required before activating a replacement; supplied commitments alone prove nothing.
    pub fn verify(
        &self,
        parents: &[ParquetArtifactV3],
        replacement: &ParquetArtifactV3,
    ) -> Result<(), DomainError> {
        if *self != Self::between(parents, replacement)? {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn preserved_bindings(
        parents: &[ParquetArtifactV3],
    ) -> Result<Vec<MappingBindingV1>, DomainError> {
        if !(2..=128).contains(&parents.len()) {
            return Err(invalid());
        }
        let first = parents.first().ok_or_else(invalid)?;
        let mut bindings = BTreeMap::new();
        for parent in parents {
            if !physical_compatible(first, parent) {
                return Err(invalid());
            }
            for binding in parent.bindings() {
                if let Some(previous) =
                    bindings.insert(binding.input().source().clone(), binding.clone())
                    && previous != *binding
                {
                    return Err(invalid());
                }
            }
        }
        let bindings = bindings.into_values().collect::<Vec<_>>();
        super::binding::validate_bindings(&bindings)?;
        Ok(bindings)
    }
    pub const fn parents(&self) -> &SetCommitment {
        &self.parents
    }
    pub const fn replacements(&self) -> &SetCommitment {
        &self.replacements
    }
    pub const fn bindings(&self) -> &SetCommitment {
        &self.bindings
    }
    pub const fn schema(&self) -> ArtifactSchemaV2 {
        self.schema
    }
    pub const fn partition(&self) -> &ArtifactPartitionV2 {
        &self.partition
    }
    pub const fn rows(&self) -> u64 {
        self.rows
    }
}
fn physical_compatible(a: &ParquetArtifactV3, b: &ParquetArtifactV3) -> bool {
    let (x, y) = (a.core(), b.core());
    x.schema == y.schema
        && x.partition == y.partition
        && x.parser_id == y.parser_id
        && x.parser_version == y.parser_version
        && x.time_semantics == y.time_semantics
        && x.stable_order == y.stable_order
        && a.bindings()
            .first()
            .zip(b.bindings().first())
            .is_some_and(|(a, b)| a.compatible(b))
}
