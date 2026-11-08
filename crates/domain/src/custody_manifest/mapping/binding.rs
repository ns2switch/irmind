mod codec;
use super::{DomainError, EvidenceHash, MappingInputRefV1, SourceDecoderIdentityV1, invalid};
use crate::MappingIdentityV1;

/// Immutable interpretation binding. Physical layout never replaces its profile.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MappingBindingV1 {
    input: MappingInputRefV1,
    profile: EvidenceHash,
    catalog: EvidenceHash,
    decoder: SourceDecoderIdentityV1,
    mapping: Option<MappingIdentityV1>,
}
impl MappingBindingV1 {
    pub fn new(
        input: MappingInputRefV1,
        profile: EvidenceHash,
        catalog: EvidenceHash,
        decoder: SourceDecoderIdentityV1,
        mapping: Option<MappingIdentityV1>,
    ) -> Self {
        Self {
            input,
            profile,
            catalog,
            decoder,
            mapping,
        }
    }
    pub const fn input(&self) -> &MappingInputRefV1 {
        &self.input
    }
    pub const fn profile(&self) -> &EvidenceHash {
        &self.profile
    }
    pub const fn catalog(&self) -> &EvidenceHash {
        &self.catalog
    }
    pub const fn decoder(&self) -> &SourceDecoderIdentityV1 {
        &self.decoder
    }
    pub const fn mapping(&self) -> Option<&MappingIdentityV1> {
        self.mapping.as_ref()
    }
    pub fn compatible(&self, other: &Self) -> bool {
        self.decoder == other.decoder && self.mapping == other.mapping
    }
}

pub(super) fn validate_bindings(bindings: &[MappingBindingV1]) -> Result<u64, DomainError> {
    let Some(first) = bindings.first() else {
        return Err(invalid());
    };
    if bindings.len() > 128
        || !bindings
            .windows(2)
            .all(|p| p[0].input.source() < p[1].input.source())
        || bindings.iter().any(|b| !first.compatible(b))
    {
        return Err(invalid());
    }
    bindings.iter().try_fold(0u64, |count, b| {
        count.checked_add(b.input.records()).ok_or_else(invalid)
    })
}
