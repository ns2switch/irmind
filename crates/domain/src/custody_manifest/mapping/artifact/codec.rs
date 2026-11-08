use super::{
    ArtifactDerivationV1, ArtifactParentV1, ArtifactPipelineV1, DomainError, ParquetArtifactV3,
    TAG, invalid,
};
use crate::custody_manifest::mapping::{MappingBindingV1, wire};
use crate::custody_manifest::{Reader, put};
use crate::{
    COMMON_DOMAIN_LOOKUP_POLICY, COMMON_EVENT_V1, EvidenceHash, ParquetArtifactV2, SOURCE_RECORD_V1,
};

const CORE_TAG: &[u8] = b"irmind-parquet-artifact-v2\0";
impl ParquetArtifactV3 {
    pub fn encode(&self) -> Result<String, DomainError> {
        let mut bytes = TAG.to_vec();
        let core = wire::decode(&self.core.encode()?, CORE_TAG, wire::MAX_SMALL)?;
        put(&mut bytes, &core);
        put(&mut bytes, b"irmind-artifact-pipeline-v1");
        put(
            &mut bytes,
            match self.pipeline.derivation() {
                ArtifactDerivationV1::Mapped => b"mapped",
                ArtifactDerivationV1::Layout { .. } => b"layout",
            },
        );
        for value in [
            SOURCE_RECORD_V1,
            COMMON_EVENT_V1,
            COMMON_DOMAIN_LOOKUP_POLICY,
        ] {
            put(&mut bytes, value.as_bytes());
        }
        super::super::contracts::write(&mut bytes);
        bytes.extend_from_slice(&(self.bindings().len() as u64).to_be_bytes());
        for binding in self.bindings() {
            binding.write(&mut bytes);
        }
        bytes.extend_from_slice(&self.pipeline.rows().to_be_bytes());
        if let ArtifactDerivationV1::Layout { parents } = self.pipeline.derivation() {
            put(&mut bytes, self.pipeline.builder().as_bytes());
            bytes.extend_from_slice(&(parents.len() as u64).to_be_bytes());
            for parent in parents {
                put(&mut bytes, parent.path().as_bytes());
                put(&mut bytes, parent.identity().as_str().as_bytes());
            }
        }
        wire::encode(&bytes, wire::MAX_ARTIFACT)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = wire::decode(payload, TAG, wire::MAX_ARTIFACT)?;
        let mut r = Reader::new(&bytes[TAG.len()..]);
        let core = ParquetArtifactV2::decode(&wire::encode(
            r.bytes_limit(wire::MAX_SMALL)?,
            wire::MAX_SMALL,
        )?)?;
        if r.string_limit(128)? != "irmind-artifact-pipeline-v1" {
            return Err(invalid());
        }
        let stage = r.string_limit(16)?;
        for expected in [
            SOURCE_RECORD_V1,
            COMMON_EVENT_V1,
            COMMON_DOMAIN_LOOKUP_POLICY,
        ] {
            if r.string_limit(128)? != expected {
                return Err(invalid());
            }
        }
        super::super::contracts::read(&mut r)?;
        let count = r.u64()?;
        if count == 0 || count > 128 {
            return Err(invalid());
        }
        let mut bindings = Vec::new();
        for _ in 0..count {
            bindings.push(MappingBindingV1::read(&mut r)?);
        }
        let rows = r.u64()?;
        let pipeline = read_pipeline(&mut r, &stage, bindings, rows)?;
        r.end()?;
        Self::try_new(core, pipeline)
    }
}
fn read_pipeline(
    r: &mut Reader<'_>,
    stage: &str,
    bindings: Vec<MappingBindingV1>,
    rows: u64,
) -> Result<ArtifactPipelineV1, DomainError> {
    match stage {
        "mapped" => ArtifactPipelineV1::mapped(bindings, rows),
        "layout" => {
            if r.string_limit(128)? != super::PARQUET_LAYOUT_BUILDER_V1 {
                return Err(invalid());
            }
            let count = r.u64()?;
            if !(2..=128).contains(&count) {
                return Err(invalid());
            }
            let mut parents = Vec::new();
            for _ in 0..count {
                parents.push(ArtifactParentV1::try_new(
                    r.string_limit(1024)?,
                    EvidenceHash::parse(&r.string_limit(64)?)?,
                )?);
            }
            ArtifactPipelineV1::layout(bindings, rows, parents)
        }
        _ => Err(invalid()),
    }
}
