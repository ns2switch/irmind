mod codec;
use super::{DomainError, EvidenceHash, SourceRecordSetV1, hash_payload, invalid};
use crate::MappingIdentityV1;

pub const MAPPING_SELECTION_V1: &str = "irmind-mapping-selection-v1";
pub(super) const TAG: &[u8] = b"irmind-mapping-profile-v1\0";
pub(super) const SNAPSHOT_TAG: &[u8] = b"irmind-mapping-snapshot-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MappingInputRefV1 {
    source: EvidenceHash,
    set: EvidenceHash,
    records: u64,
}
impl MappingInputRefV1 {
    pub fn from_set(set: &SourceRecordSetV1) -> Result<Self, DomainError> {
        Self::try_new(set.source().clone(), set.identity()?, set.records())
    }
    pub fn try_new(
        source: EvidenceHash,
        set: EvidenceHash,
        records: u64,
    ) -> Result<Self, DomainError> {
        if records == 0 || records > 10_000_000 {
            return Err(invalid());
        }
        Ok(Self {
            source,
            set,
            records,
        })
    }
    pub const fn source(&self) -> &EvidenceHash {
        &self.source
    }
    pub const fn set(&self) -> &EvidenceHash {
        &self.set
    }
    pub const fn records(&self) -> u64 {
        self.records
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MappingSnapshotRefV1 {
    mapping: MappingIdentityV1,
    snapshot: EvidenceHash,
}
impl MappingSnapshotRefV1 {
    pub fn try_new(mapping: MappingIdentityV1, snapshot: EvidenceHash) -> Self {
        Self { mapping, snapshot }
    }
    pub const fn mapping(&self) -> &MappingIdentityV1 {
        &self.mapping
    }
    pub const fn snapshot(&self) -> &EvidenceHash {
        &self.snapshot
    }
}

/// Each bounded snapshot has a separate signed frame; the profile freezes their
/// complete ordered references without depending on outputs or a final receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct MappingSnapshotV1 {
    mapping: MappingIdentityV1,
    content: String,
}
impl MappingSnapshotV1 {
    pub fn try_new(mapping: MappingIdentityV1, content: String) -> Result<Self, DomainError> {
        if content.is_empty() || content.len() > 448 * 1024 {
            return Err(invalid());
        }
        Ok(Self { mapping, content })
    }
    pub const fn mapping(&self) -> &MappingIdentityV1 {
        &self.mapping
    }
    pub fn content(&self) -> &str {
        &self.content
    }
    pub fn reference(&self) -> Result<MappingSnapshotRefV1, DomainError> {
        Ok(MappingSnapshotRefV1::try_new(
            self.mapping.clone(),
            hash_payload(&self.encode()?, SNAPSHOT_TAG)?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingProfileV1 {
    inputs: Vec<MappingInputRefV1>,
    catalog: Vec<MappingSnapshotRefV1>,
}
impl MappingProfileV1 {
    pub fn try_new(
        inputs: Vec<MappingInputRefV1>,
        catalog: Vec<MappingSnapshotRefV1>,
    ) -> Result<Self, DomainError> {
        if inputs.is_empty()
            || inputs.len() > 128
            || catalog.len() > 64
            || !inputs.windows(2).all(|p| p[0].source < p[1].source)
            || !catalog
                .windows(2)
                .all(|p| p[0].mapping.id() < p[1].mapping.id())
        {
            return Err(invalid());
        }
        Ok(Self { inputs, catalog })
    }
    pub fn inputs(&self) -> &[MappingInputRefV1] {
        &self.inputs
    }
    pub fn catalog(&self) -> &[MappingSnapshotRefV1] {
        &self.catalog
    }
    pub fn identity(&self) -> Result<EvidenceHash, DomainError> {
        hash_payload(&self.encode()?, TAG)
    }
    pub fn catalog_identity(&self) -> EvidenceHash {
        catalog_identity(&self.catalog)
    }
}

/// The catalog is known before any source manifest, profile or output exists.
pub fn mapping_catalog_commitment(
    catalog: &[MappingSnapshotRefV1],
) -> Result<EvidenceHash, DomainError> {
    if catalog.len() > 64
        || !catalog
            .windows(2)
            .all(|p| p[0].mapping.id() < p[1].mapping.id())
    {
        return Err(invalid());
    }
    Ok(catalog_identity(catalog))
}
fn catalog_identity(catalog: &[MappingSnapshotRefV1]) -> EvidenceHash {
    use sha2::{Digest, Sha256};
    let mut bytes = b"irmind-mapping-catalog-v1\0".to_vec();
    bytes.extend_from_slice(&(catalog.len() as u64).to_be_bytes());
    for entry in catalog {
        super::wire::write_mapping(&mut bytes, entry.mapping());
        crate::custody_manifest::put(&mut bytes, entry.snapshot().as_str().as_bytes());
    }
    EvidenceHash::from_bytes(Sha256::digest(&bytes).into())
}

/// Explicit domains share an audit kind while retaining strict wire dispatch.
#[derive(Clone, Eq, PartialEq)]
pub enum MappingProfileRecordV1 {
    Snapshot(MappingSnapshotV1),
    Profile(MappingProfileV1),
}
impl MappingProfileRecordV1 {
    pub fn encode(&self) -> Result<String, DomainError> {
        match self {
            Self::Snapshot(v) => v.encode(),
            Self::Profile(v) => v.encode(),
        }
    }
    pub fn decode(payload: &str) -> Result<Self, DomainError> {
        if let Ok(snapshot) = MappingSnapshotV1::decode(payload) {
            return Ok(Self::Snapshot(snapshot));
        }
        MappingProfileV1::decode(payload).map(Self::Profile)
    }
}
