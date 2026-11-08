use super::{
    DomainError, MAPPING_SELECTION_V1, MappingInputRefV1, MappingProfileV1, MappingSnapshotRefV1,
    MappingSnapshotV1, SNAPSHOT_TAG, TAG, invalid,
};
use crate::custody_manifest::mapping::wire::{self, read_mapping, write_mapping};
use crate::custody_manifest::{Reader, put};
use crate::{COMMON_DOMAIN_LOOKUP_POLICY, COMMON_EVENT_V1, EvidenceHash, SOURCE_RECORD_V1};

impl MappingSnapshotV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        let mut out = SNAPSHOT_TAG.to_vec();
        write_mapping(&mut out, &self.mapping);
        put(&mut out, self.content.as_bytes());
        wire::encode(&out, wire::MAX_METADATA)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = wire::decode(payload, SNAPSHOT_TAG, wire::MAX_METADATA)?;
        let mut r = Reader::new(&bytes[SNAPSHOT_TAG.len()..]);
        let mapping = read_mapping(&mut r)?;
        let content = r.string_limit(448 * 1024)?;
        r.end()?;
        Self::try_new(mapping, content)
    }
}
impl MappingProfileV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        let mut out = TAG.to_vec();
        for value in [
            SOURCE_RECORD_V1,
            COMMON_EVENT_V1,
            MAPPING_SELECTION_V1,
            COMMON_DOMAIN_LOOKUP_POLICY,
        ] {
            put(&mut out, value.as_bytes());
        }
        super::super::contracts::write(&mut out);
        out.extend_from_slice(&(self.inputs.len() as u64).to_be_bytes());
        for input in &self.inputs {
            put(&mut out, input.source.as_str().as_bytes());
            put(&mut out, input.set.as_str().as_bytes());
            out.extend_from_slice(&input.records.to_be_bytes());
        }
        out.extend_from_slice(&(self.catalog.len() as u64).to_be_bytes());
        for entry in &self.catalog {
            write_mapping(&mut out, &entry.mapping);
            put(&mut out, entry.snapshot.as_str().as_bytes());
        }
        wire::encode(&out, wire::MAX_METADATA)
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        let bytes = wire::decode(payload, TAG, wire::MAX_METADATA)?;
        let mut r = Reader::new(&bytes[TAG.len()..]);
        for expected in [
            SOURCE_RECORD_V1,
            COMMON_EVENT_V1,
            MAPPING_SELECTION_V1,
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
        let mut inputs = Vec::new();
        for _ in 0..count {
            inputs.push(MappingInputRefV1::try_new(
                EvidenceHash::parse(&r.string_limit(64)?)?,
                EvidenceHash::parse(&r.string_limit(64)?)?,
                r.u64()?,
            )?);
        }
        let count = r.u64()?;
        if count > 64 {
            return Err(invalid());
        }
        let mut catalog = Vec::new();
        for _ in 0..count {
            catalog.push(MappingSnapshotRefV1::try_new(
                read_mapping(&mut r)?,
                EvidenceHash::parse(&r.string_limit(64)?)?,
            ));
        }
        r.end()?;
        Self::try_new(inputs, catalog)
    }
}
