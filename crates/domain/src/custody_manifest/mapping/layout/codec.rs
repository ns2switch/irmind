use super::{
    ArtifactPartitionV2, ArtifactSchemaV2, DomainError, ParquetLayoutV1, SetCommitment, TAG,
    invalid,
};
use crate::EvidenceHash;
use crate::custody_manifest::mapping::{PARQUET_LAYOUT_BUILDER_V1, wire};
use crate::custody_manifest::{Reader, put};

impl ParquetLayoutV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        self.partition.validate()?;
        if !(2..=128).contains(&self.parents.count)
            || self.replacements.count != 1
            || !(1..=128).contains(&self.bindings.count)
            || self.rows == 0
            || !self.schema.is_common()
        {
            return Err(invalid());
        }
        let mut out = TAG.to_vec();
        put(&mut out, PARQUET_LAYOUT_BUILDER_V1.as_bytes());
        for set in [&self.parents, &self.replacements, &self.bindings] {
            out.extend_from_slice(&set.count.to_be_bytes());
            put(&mut out, set.sha256.as_str().as_bytes());
        }
        put(&mut out, self.schema.as_str().as_bytes());
        self.partition.write(&mut out);
        out.extend_from_slice(&self.rows.to_be_bytes());
        wire::encode(&out, wire::MAX_SMALL)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = wire::decode(payload, TAG, wire::MAX_SMALL)?;
        let mut r = Reader::new(&bytes[TAG.len()..]);
        if r.string_limit(128)? != PARQUET_LAYOUT_BUILDER_V1 {
            return Err(invalid());
        }
        let mut set = || {
            Ok::<_, DomainError>(SetCommitment {
                count: r.u64()?,
                sha256: EvidenceHash::parse(&r.string_limit(64)?)?,
            })
        };
        let (parents, replacements, bindings) = (set()?, set()?, set()?);
        let result = Self {
            parents,
            replacements,
            bindings,
            schema: ArtifactSchemaV2::parse(&r.string_limit(128)?)?,
            partition: ArtifactPartitionV2::read(&mut r)?,
            rows: r.u64()?,
        };
        r.end()?;
        if result.encode()? != payload {
            return Err(invalid());
        }
        Ok(result)
    }
}
