mod batch;
mod consolidate;
mod normalize;
mod staging;
#[cfg(test)]
mod tests;
pub(super) use batch::supported_builder;
pub(super) use normalize::normalize;

use super::{AppError, ParquetArtifact, invalid_source};
use irmind_app::{PartitionLimits, PartitionProfile};
use irmind_domain::{
    ARTIFACT_V2_MAX_DATE_TUPLES, ARTIFACT_V2_SCOPE_KEYS, ArtifactPartitionV2,
    PartitionOverflowReason as Reason, ScopePartitionKey as Key, ScopePartitionV2,
    ScopePartitionValue as Value,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const BUILDER: &str = "parquet-builder-v3";

/// Constructed afresh for each locked batch. Nothing unsigned is persisted.
pub(super) struct Allocator {
    limits: PartitionLimits,
    keys: BTreeMap<String, (u16, BTreeSet<String>)>,
    tuples: BTreeMap<String, BTreeSet<String>>,
}

impl Allocator {
    pub(super) fn from_signed(
        artifacts: &[ParquetArtifact],
        limits: PartitionLimits,
    ) -> Result<Self, AppError> {
        limits.validate()?;
        if normalize::policy_id() != irmind_domain::ARTIFACT_V2_PARTITION_POLICY {
            return Err(invalid_source());
        }
        let mut out = Self {
            limits,
            keys: BTreeMap::new(),
            tuples: BTreeMap::new(),
        };
        for artifact in artifacts {
            artifact.validate().map_err(|_| invalid_source())?;
            if let ParquetArtifact::V2(v) = artifact {
                if v.builder_version == super::writer::precise::BUILDER {
                    if !v.partition.scopes.is_empty() || v.partition.all_scope_overflow {
                        return Err(invalid_source());
                    }
                    continue;
                }
                if v.builder_version != BUILDER {
                    return Err(invalid_source());
                }
                out.observe(&v.partition)?;
            }
        }
        Ok(out)
    }

    fn observe(&mut self, partition: &ArtifactPartitionV2) -> Result<(), AppError> {
        for scope in &partition.scopes {
            let state = self
                .keys
                .entry(scope.key.as_str().into())
                .or_insert_with(|| (scope.cap, BTreeSet::new()));
            if state.0 != scope.cap {
                return Err(invalid_source());
            }
            if let Value::Ordinary(value) = &scope.value {
                state.1.insert(value.clone());
            }
            if state.1.len() > usize::from(state.0) {
                return Err(invalid_source());
            }
        }
        if !partition.all_scope_overflow {
            let tuples = self.tuples.entry(partition.date.clone()).or_default();
            tuples.insert(partition.path_prefix().map_err(|_| invalid_source())?);
            if tuples.len() > 4096 {
                return Err(invalid_source());
            }
        }
        Ok(())
    }

    pub(super) fn assign(
        &mut self,
        date: &str,
        profile: PartitionProfile,
        values: [&str; 3],
    ) -> Result<ArtifactPartitionV2, AppError> {
        let mut partition = ArtifactPartitionV2 {
            date: date.into(),
            key_set: ARTIFACT_V2_SCOPE_KEYS.into(),
            policy: normalize::policy_id(),
            tuple_cap: ARTIFACT_V2_MAX_DATE_TUPLES,
            all_scope_overflow: false,
            scopes: Vec::new(),
        };
        let wanted: &[(Key, &str)] = match profile {
            PartitionProfile::Unpartitioned => &[],
            PartitionProfile::CloudAccountRegion => {
                &[(Key::Account, values[0]), (Key::Region, values[1])]
            }
            PartitionProfile::EndpointHost => &[(Key::Host, values[2])],
        };
        // Do not consume values for an all-scope overflow tuple.
        let mut additions = Vec::new();
        for &(key, raw) in wanted {
            if raw.is_empty() {
                continue;
            }
            let cap = self.cap(key);
            let value = match normalize(raw) {
                None => Value::Overflow(Reason::UnrepresentableValue),
                Some(value) => self.slot(key, value, cap, &mut additions),
            };
            partition.scopes.push(ScopePartitionV2 { key, cap, value });
        }
        let path = partition.path_prefix().map_err(|_| invalid_source())?;
        let tuples = self.tuples.entry(date.into()).or_default();
        if !tuples.contains(&path) && tuples.len() >= 4096 && !partition.scopes.is_empty() {
            partition.all_scope_overflow = true;
            for scope in &mut partition.scopes {
                scope.value = Value::Overflow(Reason::TupleBudget);
            }
        } else {
            tuples.insert(path);
            for (key, value, cap) in additions {
                self.keys
                    .entry(key)
                    .or_insert_with(|| (cap, BTreeSet::new()))
                    .1
                    .insert(value);
            }
        }
        partition.validate().map_err(|_| invalid_source())?;
        Ok(partition)
    }

    fn cap(&self, key: Key) -> u16 {
        self.keys.get(key.as_str()).map_or_else(
            || match key {
                Key::Account => self.limits.account,
                Key::Region => self.limits.region,
                _ => self.limits.host,
            },
            |state| state.0,
        )
    }

    fn slot(
        &self,
        key: Key,
        value: String,
        cap: u16,
        additions: &mut Vec<(String, String, u16)>,
    ) -> Value {
        let allocated = self.keys.get(key.as_str());
        if allocated.is_some_and(|s| s.1.contains(&value)) {
            return Value::Ordinary(value);
        }
        if allocated.is_some_and(|s| s.1.len() >= usize::from(cap)) {
            return Value::Overflow(Reason::Cardinality);
        }
        additions.push((key.as_str().into(), value.clone(), cap));
        Value::Ordinary(value)
    }
}

pub(super) fn replay_limits(artifacts: &[ParquetArtifact]) -> Result<PartitionLimits, AppError> {
    let allocation = Allocator::from_signed(artifacts, PartitionLimits::default())?;
    Ok(PartitionLimits {
        account: allocation.cap(Key::Account),
        region: allocation.cap(Key::Region),
        host: allocation.cap(Key::Host),
    })
}
