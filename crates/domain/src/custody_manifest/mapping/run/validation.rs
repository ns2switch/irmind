use super::{DomainError, MappingProfileV1, MappingRunV1, ParquetArtifactV3, invalid};
use crate::{ArtifactDerivationV1, ArtifactSchemaV2};
use std::collections::BTreeMap;

impl MappingRunV1 {
    pub(super) fn validate_order(&self) -> Result<(), DomainError> {
        if self.routes.is_empty()
            || self.routes.len() > 8192
            || !self
                .routes
                .windows(2)
                .all(|p| (&p[0].source, &p[0].mapping) < (&p[1].source, &p[1].mapping))
            || self.outputs.count == 0
            || self.outputs.count > 10_000_000
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn validate_accounting(
        &self,
        profile: &MappingProfileV1,
        outputs: &[ParquetArtifactV3],
    ) -> Result<(), DomainError> {
        self.validate_order()?;
        let mut sources = BTreeMap::new();
        let mut expected = BTreeMap::new();
        for route in &self.routes {
            if !profile
                .inputs()
                .iter()
                .any(|i| i.source() == route.source())
                || route
                    .mapping()
                    .is_some_and(|m| !profile.catalog().iter().any(|s| s.mapping() == m))
            {
                return Err(invalid());
            }
            add(&mut sources, route.source().clone(), route.counts.accepted)?;
            add(&mut expected, route.mapping.clone(), route.counts.accepted)?;
        }
        if profile
            .inputs()
            .iter()
            .any(|i| sources.get(i.source()) != Some(&i.records()))
        {
            return Err(invalid());
        }
        let mut actual = BTreeMap::new();
        for artifact in outputs {
            if artifact.pipeline().derivation() != &ArtifactDerivationV1::Mapped {
                return Err(invalid());
            }
            for binding in artifact.bindings() {
                if binding.profile() != &self.profile
                    || binding.catalog() != &self.catalog
                    || !profile.inputs().contains(binding.input())
                    || !self.routes.iter().any(|r| {
                        r.source() == binding.input().source() && r.mapping() == binding.mapping()
                    })
                {
                    return Err(invalid());
                }
            }
            if artifact.core().schema == ArtifactSchemaV2::CommonEvents {
                let mapping = artifact
                    .bindings()
                    .first()
                    .ok_or_else(invalid)?
                    .mapping()
                    .cloned();
                add(&mut actual, mapping, artifact.pipeline().rows())?;
            }
        }
        if actual != expected {
            return Err(invalid());
        }
        Ok(())
    }
}
fn add<K: Ord>(counts: &mut BTreeMap<K, u64>, key: K, n: u64) -> Result<(), DomainError> {
    let count = counts.entry(key).or_default();
    *count = count.checked_add(n).ok_or_else(invalid)?;
    Ok(())
}
