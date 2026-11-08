mod selectors;
mod wire;
use super::{MappingError, MappingManifest, MappingProvenance, SourceSelector};
use irmind_domain::{EvidenceHash, MappingIdentityV1, MappingSnapshotV1};

const CONTRACT: &str = "irmind-mapping-snapshot-content-v1";
impl MappingManifest {
    pub fn snapshot(&self) -> Result<MappingSnapshotV1, MappingError> {
        let value = wire::Manifest {
            contract: CONTRACT.into(),
            identity: self.identity().into(),
            selectors: self.selectors().iter().map(Into::into).collect(),
            provenance: self.provenance().into(),
            compatibility_projection: self.compatibility_projection(),
        };
        let content = serde_json::to_string(&value).map_err(|_| MappingError::InvalidManifest)?;
        MappingSnapshotV1::try_new(self.identity().clone(), content)
            .map_err(|_| MappingError::InvalidManifest)
    }
    /// Metadata decoding only: never loads or executes native mapping code.
    pub fn from_snapshot(snapshot: &MappingSnapshotV1) -> Result<Self, MappingError> {
        if snapshot.content().len() > 448 * 1024 {
            return Err(MappingError::InvalidManifest);
        }
        let value: wire::Manifest =
            serde_json::from_str(snapshot.content()).map_err(|_| MappingError::InvalidManifest)?;
        if value.contract != CONTRACT {
            return Err(MappingError::InvalidManifest);
        }
        let identity = value.identity.try_into()?;
        if &identity != snapshot.mapping() {
            return Err(MappingError::InvalidManifest);
        }
        let result = Self::try_new(
            identity,
            value
                .selectors
                .into_iter()
                .map(SourceSelector::try_from)
                .collect::<Result<_, _>>()?,
            value.provenance.try_into()?,
            value.compatibility_projection,
        )?;
        if result.snapshot()?.content() != snapshot.content() {
            return Err(MappingError::InvalidManifest);
        }
        Ok(result)
    }
}
impl From<&MappingIdentityV1> for wire::Identity {
    fn from(value: &MappingIdentityV1) -> Self {
        Self {
            id: value.id().into(),
            version: value.version().into(),
            target: value.target().into(),
            implementation: value.implementation().as_str().into(),
        }
    }
}
impl TryFrom<wire::Identity> for MappingIdentityV1 {
    type Error = MappingError;
    fn try_from(v: wire::Identity) -> Result<Self, Self::Error> {
        Self::try_new(
            &v.id,
            &v.version,
            &v.target,
            EvidenceHash::parse(&v.implementation).map_err(|_| MappingError::InvalidManifest)?,
        )
        .map_err(|_| MappingError::InvalidManifest)
    }
}
impl From<&MappingProvenance> for wire::Provenance {
    fn from(value: &MappingProvenance) -> Self {
        match value {
            MappingProvenance::NativeBuild { manifest } => Self::NativeBuild {
                manifest: hex::encode(manifest),
            },
            MappingProvenance::BundledDefinition {
                canonical,
                interpreter,
            } => Self::BundledDefinition {
                canonical: hex::encode(canonical),
                interpreter: interpreter.clone(),
            },
            MappingProvenance::InstalledDefinition {
                canonical,
                interpreter,
                operation,
            } => Self::InstalledDefinition {
                canonical: hex::encode(canonical),
                interpreter: interpreter.clone(),
                operation: operation.as_str().into(),
            },
        }
    }
}
impl TryFrom<wire::Provenance> for MappingProvenance {
    type Error = MappingError;
    fn try_from(value: wire::Provenance) -> Result<Self, Self::Error> {
        let decode = |s: &str| {
            if s.len() > 128 * 1024 {
                return Err(MappingError::InvalidManifest);
            }
            hex::decode(s).map_err(|_| MappingError::InvalidManifest)
        };
        Ok(match value {
            wire::Provenance::NativeBuild { manifest } => Self::NativeBuild {
                manifest: decode(&manifest)?,
            },
            wire::Provenance::BundledDefinition {
                canonical,
                interpreter,
            } => Self::BundledDefinition {
                canonical: decode(&canonical)?,
                interpreter,
            },
            wire::Provenance::InstalledDefinition {
                canonical,
                interpreter,
                operation,
            } => Self::InstalledDefinition {
                canonical: decode(&canonical)?,
                interpreter,
                operation: EvidenceHash::parse(&operation)
                    .map_err(|_| MappingError::InvalidManifest)?,
            },
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
