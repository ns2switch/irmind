use super::{MappingCatalog, MappingError};
use crate::ParserIdentity;
use crate::source_mapping::MappingManifest;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

const REGISTERED_MAPPINGS: usize = 128;
const PROFILE_MAPPINGS: usize = 64;

impl MappingCatalog {
    /// The direct writer accepts a single decoder identity per group. Include
    /// all of its candidates, even for formats absent from this batch.
    pub fn for_decoder(&self, decoder: ParserIdentity<'_>) -> Cow<'_, Self> {
        if self.mappings.len() <= PROFILE_MAPPINGS {
            return Cow::Borrowed(self);
        }
        let mut scoped = self.clone();
        scoped.mappings.retain(|_, mapper| {
            mapper.manifest().selectors().iter().any(|selector| {
                selector.parser() == decoder.name && selector.versions().contains(decoder.version)
            })
        });
        Cow::Owned(scoped)
    }
}

pub(in crate::source_mapping) fn validate_capacity<'a>(
    manifests: impl ExactSizeIterator<Item = &'a MappingManifest> + Clone,
) -> Result<(), MappingError> {
    validate_registry_size(manifests.clone())?;
    let mut candidates = BTreeMap::<_, Vec<_>>::new();
    for manifest in manifests {
        // A module can select several record kinds for the same decoder.
        // Count each snapshot only once for that decoder.
        let decoders = manifest
            .selectors()
            .iter()
            .flat_map(|selector| {
                selector
                    .versions()
                    .iter()
                    .map(move |version| (selector.parser(), version.as_str()))
            })
            .collect::<BTreeSet<_>>();
        for decoder in decoders {
            candidates.entry(decoder).or_default().push(manifest);
        }
    }
    for ((name, version), manifests) in candidates {
        if manifests.len() > PROFILE_MAPPINGS {
            return Err(MappingError::Capacity {
                limit: PROFILE_MAPPINGS,
                count: manifests.len(),
                decoder: Some((name.into(), version.into())),
                modules: contributions(manifests.into_iter()),
            });
        }
    }
    Ok(())
}

fn contributions<'a>(
    manifests: impl Iterator<Item = &'a MappingManifest>,
) -> BTreeMap<String, usize> {
    let mut modules = BTreeMap::new();
    for manifest in manifests {
        *modules.entry(manifest.identity().id().into()).or_default() += 1;
    }
    modules
}

pub(super) fn validate_registry_size<'a>(
    manifests: impl ExactSizeIterator<Item = &'a MappingManifest>,
) -> Result<(), MappingError> {
    if manifests.len() > REGISTERED_MAPPINGS {
        let count = manifests.len();
        return Err(MappingError::Capacity {
            limit: REGISTERED_MAPPINGS,
            count,
            decoder: None,
            modules: contributions(manifests),
        });
    }
    Ok(())
}
