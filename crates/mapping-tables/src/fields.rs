mod convert;
pub use convert::copy_common_value;
mod observation;
use super::{
    definition::{Conversion, Field, Partition},
    invalid,
};
use irmind_app::{
    PartitionProfile,
    source_mapping::{MappingError, MappingPartition, SourcePath, SourceRecordV1},
};
use irmind_domain::{CommonField, CommonFieldType};
use observation::CompiledObservation;
use std::collections::BTreeSet;

pub(super) struct CompiledField {
    pub path: SourcePath,
    pub target: CommonField,
    pub conversion: Conversion,
    pub observation: Option<CompiledObservation>,
    pub observations: Vec<CompiledObservation>,
    conditions: Vec<irmind_app::source_mapping::SelectorCondition>,
    omit_text: BTreeSet<String>,
}
pub(super) fn compile_fields(fields: Vec<Field>) -> Result<Vec<CompiledField>, MappingError> {
    let mut targets = BTreeSet::new();
    fields
        .into_iter()
        .map(|f| {
            if f.when.len() > 8 || f.observations.len() > 8 {
                return Err(MappingError::InvalidDefinition);
            }
            let target = CommonField::parse(&f.target).map_err(invalid)?;
            if target == CommonField::IrmindClusterIdentity
                || !targets.insert(target)
                || !compatible(target.value_type(), f.conversion)
            {
                return Err(MappingError::InvalidDefinition);
            }
            let observation = f
                .observation
                .map(|o| CompiledObservation::compile(o, target))
                .transpose()?;
            Ok(CompiledField {
                path: indexed_path(&f.source, f.source_index)?,
                target,
                conversion: f.conversion,
                observation,
                observations: f
                    .observations
                    .into_iter()
                    .map(|o| CompiledObservation::compile(o, target))
                    .collect::<Result<_, _>>()?,
                omit_text: compile_omit_text(f.omit_text)?,
                conditions: f
                    .when
                    .iter()
                    .map(super::compile::condition)
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}
impl CompiledField {
    pub(super) fn applies(&self, source: &SourceRecordV1) -> bool {
        self.conditions
            .iter()
            .all(|c| c.predicate.matches(c.path.resolve(source.fields())))
    }
    pub(super) fn omits(&self, value: &irmind_app::source_mapping::SourceValue) -> bool {
        matches!(value, irmind_app::source_mapping::SourceValue::Text(text) if self.omit_text.contains(text) || (matches!(self.conversion, Conversion::KubernetesServiceAccountName) && !text.starts_with("system:serviceaccount:")))
    }
}
fn compile_omit_text(values: Vec<String>) -> Result<BTreeSet<String>, MappingError> {
    if values.len() > 8
        || values
            .iter()
            .any(|v| v.len() > 256 || v.chars().any(char::is_control))
    {
        return Err(MappingError::InvalidDefinition);
    }
    let count = values.len();
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.len() != count {
        return Err(MappingError::InvalidDefinition);
    }
    Ok(values)
}

fn compatible(kind: CommonFieldType, conversion: Conversion) -> bool {
    use CommonFieldType as T;
    use Conversion as C;
    match conversion {
        C::Copy => !matches!(kind, T::Time | T::DnsAnswers),
        C::Decimal | C::Hex => matches!(kind, T::Unsigned | T::Port | T::Pid | T::HttpStatus),
        C::Ip => kind == T::Ip,
        C::Domain | C::KubernetesServiceAccountName => kind == T::Text,
        C::Md5 => kind == T::Md5,
        C::Sha1 => kind == T::Sha1,
        C::Sha256 => kind == T::Sha256,
    }
}
pub(super) fn path(keys: &[String]) -> Result<SourcePath, MappingError> {
    SourcePath::keys(&keys.iter().map(String::as_str).collect::<Vec<_>>()).map_err(invalid)
}
fn indexed_path(keys: &[String], index: Option<u16>) -> Result<SourcePath, MappingError> {
    let mut parts = path(keys)?.segments().to_vec();
    if let Some(index) = index {
        if index >= 4096 {
            return Err(MappingError::InvalidDefinition);
        }
        parts.push(irmind_app::source_mapping::SourcePathSegment::Index(index));
    }
    SourcePath::try_new(parts).map_err(invalid)
}

pub(super) struct CompiledPartition {
    host: Option<SourcePath>,
    account: Option<SourcePath>,
    region: Option<SourcePath>,
}
impl CompiledPartition {
    pub(super) fn compile(value: &Partition) -> Result<Self, MappingError> {
        if value.host.is_some() && (value.account.is_some() || value.region.is_some()) {
            return Err(MappingError::InvalidDefinition);
        }
        Ok(Self {
            host: value.host.as_deref().map(path).transpose()?,
            account: value.account.as_deref().map(path).transpose()?,
            region: value.region.as_deref().map(path).transpose()?,
        })
    }
    pub(super) fn project(
        &self,
        source: &SourceRecordV1,
    ) -> Result<MappingPartition, MappingError> {
        let read = |p: &Option<SourcePath>| -> Result<&str, MappingError> {
            match p.as_ref().and_then(|path| path.resolve(source.fields())) {
                None => Ok(""),
                Some(value) => value.as_text().ok_or(MappingError::UnsupportedSourceValue),
            }
        };
        let profile = if source.cluster_identity().is_some() {
            PartitionProfile::KubernetesCluster
        } else if self.host.is_some() {
            PartitionProfile::EndpointHost
        } else if self.account.is_some() || self.region.is_some() {
            PartitionProfile::CloudAccountRegion
        } else {
            PartitionProfile::Unpartitioned
        };
        let partition = MappingPartition::try_new(
            profile,
            read(&self.account)?,
            read(&self.region)?,
            read(&self.host)?,
        )?;
        if let Some(cluster) = source.cluster_identity() {
            partition.with_cluster(cluster)
        } else {
            Ok(partition)
        }
    }
}

fn service_account_parts(value: &str) -> Result<(&str, &str), MappingError> {
    let bad = || MappingError::UnsupportedSourceValue;
    let raw = value
        .strip_prefix("system:serviceaccount:")
        .ok_or_else(bad)?;
    if raw.len() > 63 + 1 + 253 {
        return Err(bad());
    }
    let (namespace, name) = raw.split_once(':').ok_or_else(bad)?;
    if namespace.is_empty()
        || namespace.len() > 63
        || name.is_empty()
        || name.len() > 253
        || name.contains(':')
    {
        return Err(bad());
    }
    Ok((namespace, name))
}
