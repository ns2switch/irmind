use super::ParquetArtifactV3;
use crate::custody_manifest::mapping::{contracts, wire};
use crate::custody_manifest::put;

impl ParquetArtifactV3 {
    pub(in crate::custody_manifest) fn same_mapping_generation(&self, other: &Self) -> bool {
        let compatible = self
            .bindings()
            .first()
            .zip(other.bindings().first())
            .is_some_and(|(a, b)| a.compatible(b));
        compatible
            && self.bindings().iter().all(|a| {
                other
                    .bindings()
                    .iter()
                    .find(|b| a.input().source() == b.input().source())
                    .is_none_or(|b| a == b)
            })
    }
    pub(in crate::custody_manifest) fn write_compaction_key(&self, bytes: &mut Vec<u8>) {
        bytes.push(3);
        self.core().partition.write(bytes);
        for value in [
            self.core().schema.as_str(),
            self.core().parser_id.as_str(),
            &self.core().parser_version,
            &self.core().time_semantics,
            &self.core().stable_order,
            crate::SOURCE_RECORD_V1,
            crate::COMMON_EVENT_V1,
            crate::COMMON_DOMAIN_LOOKUP_POLICY,
        ] {
            put(bytes, value.as_bytes());
        }
        contracts::write(bytes);
        // Profiles remain per source. Compatibility depends on interpretation,
        // not the profile's other inputs or the parents' physical layout recipe.
        if let Some(binding) = self.bindings().first() {
            bytes.push(u8::from(binding.mapping().is_some()));
            if let Some(mapping) = binding.mapping() {
                wire::write_mapping(bytes, mapping);
            }
        }
    }
}
