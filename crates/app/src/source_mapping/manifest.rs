use super::{MappingError, MappingIdentityV1, SourceSelector};
use irmind_domain::EvidenceHash;

/// Trust material is retained with the profile, not inferred from a file path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MappingProvenance {
    NativeBuild {
        manifest: Vec<u8>,
    },
    BundledDefinition {
        canonical: Vec<u8>,
        interpreter: String,
    },
    InstalledDefinition {
        canonical: Vec<u8>,
        interpreter: String,
        operation: EvidenceHash,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingManifest {
    identity: MappingIdentityV1,
    selectors: Vec<SourceSelector>,
    provenance: MappingProvenance,
    compatibility_projection: bool,
}
impl MappingManifest {
    pub fn try_new(
        identity: MappingIdentityV1,
        mut selectors: Vec<SourceSelector>,
        provenance: MappingProvenance,
        compatibility_projection: bool,
    ) -> Result<Self, MappingError> {
        if selectors.is_empty() || selectors.len() > 256 {
            return Err(MappingError::InvalidManifest);
        }
        selectors.sort();
        if selectors.windows(2).any(|p| p[0] == p[1]) {
            return Err(MappingError::InvalidManifest);
        }
        let content = match &provenance {
            MappingProvenance::NativeBuild { manifest } => manifest,
            MappingProvenance::BundledDefinition {
                canonical,
                interpreter,
            }
            | MappingProvenance::InstalledDefinition {
                canonical,
                interpreter,
                ..
            } => {
                if interpreter != "irmind-mapping-tables-v1" {
                    return Err(MappingError::InvalidManifest);
                }
                canonical
            }
        };
        if content.is_empty()
            || content.len() > 64 * 1024
            || EvidenceHash::from_bytes(crate::sha256(content)) != *identity.implementation()
        {
            return Err(MappingError::InvalidManifest);
        }
        Ok(Self {
            identity,
            selectors,
            provenance,
            compatibility_projection,
        })
    }
    pub const fn identity(&self) -> &MappingIdentityV1 {
        &self.identity
    }
    pub fn selectors(&self) -> &[SourceSelector] {
        &self.selectors
    }
    pub const fn provenance(&self) -> &MappingProvenance {
        &self.provenance
    }
    pub const fn compatibility_projection(&self) -> bool {
        self.compatibility_projection
    }
}
