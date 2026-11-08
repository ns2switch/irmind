mod codec;
mod validation;
use super::{DomainError, EvidenceHash, MappingProfileV1, ParquetArtifactV3, commitments, invalid};
use crate::{MappingIdentityV1, SetCommitment};

pub(super) const TAG: &[u8] = b"irmind-mapping-run-v1\0";
const OUTPUTS: &[u8] = b"irmind-mapping-outputs-v1\0";

/// Counts describe execution of an exact mapper, not truth or analyst confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingRouteV1 {
    source: EvidenceHash,
    mapping: Option<MappingIdentityV1>,
    counts: MappingCountsV1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingCountsV1 {
    accepted: u64,
    unclassified: u64,
    unsupported: u64,
    missing: u64,
}
impl MappingCountsV1 {
    pub fn try_new(
        accepted: u64,
        unclassified: u64,
        unsupported: u64,
        missing: u64,
    ) -> Result<Self, DomainError> {
        if !(1..=10_000_000).contains(&accepted)
            || unclassified > accepted
            || unsupported > unclassified
            || missing > unclassified
        {
            return Err(invalid());
        }
        Ok(Self {
            accepted,
            unclassified,
            unsupported,
            missing,
        })
    }
    pub const fn accepted(self) -> u64 {
        self.accepted
    }
    pub const fn unclassified(self) -> u64 {
        self.unclassified
    }
    pub const fn unsupported(self) -> u64 {
        self.unsupported
    }
    pub const fn missing(self) -> u64 {
        self.missing
    }
}
impl MappingRouteV1 {
    pub fn try_new(
        source: EvidenceHash,
        mapping: Option<MappingIdentityV1>,
        counts: MappingCountsV1,
    ) -> Result<Self, DomainError> {
        if mapping.is_none() && counts.accepted != counts.unclassified {
            return Err(invalid());
        }
        Ok(Self {
            source,
            mapping,
            counts,
        })
    }
    pub const fn source(&self) -> &EvidenceHash {
        &self.source
    }
    pub const fn mapping(&self) -> Option<&MappingIdentityV1> {
        self.mapping.as_ref()
    }
    pub const fn counts(&self) -> MappingCountsV1 {
        self.counts
    }
}

/// Final receipt references outputs. Outputs reference the earlier profile only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingRunV1 {
    profile: EvidenceHash,
    catalog: EvidenceHash,
    routes: Vec<MappingRouteV1>,
    outputs: SetCommitment,
}
impl MappingRunV1 {
    pub fn between(
        profile: &MappingProfileV1,
        routes: Vec<MappingRouteV1>,
        outputs: &[ParquetArtifactV3],
    ) -> Result<Self, DomainError> {
        let result = Self {
            profile: profile.identity()?,
            catalog: profile.catalog_identity(),
            routes,
            outputs: commitments::artifacts(outputs, OUTPUTS)?,
        };
        result.validate_accounting(profile, outputs)?;
        result.encode()?;
        Ok(result)
    }
    /// Recalculates complete inventories; it does not replace full source replay.
    pub fn verify(
        &self,
        profile: &MappingProfileV1,
        outputs: &[ParquetArtifactV3],
    ) -> Result<(), DomainError> {
        if *self != Self::between(profile, self.routes.clone(), outputs)? {
            return Err(invalid());
        }
        Ok(())
    }
    pub const fn profile(&self) -> &EvidenceHash {
        &self.profile
    }
    pub const fn catalog(&self) -> &EvidenceHash {
        &self.catalog
    }
    pub fn routes(&self) -> &[MappingRouteV1] {
        &self.routes
    }
    pub const fn outputs(&self) -> &SetCommitment {
        &self.outputs
    }
}
