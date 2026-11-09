mod convert;
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
}
pub(super) fn compile_fields(fields: Vec<Field>) -> Result<Vec<CompiledField>, MappingError> {
    let mut targets = BTreeSet::new();
    fields
        .into_iter()
        .map(|f| {
            let target = CommonField::parse(&f.target).map_err(invalid)?;
            if !targets.insert(target) || !compatible(target.value_type(), f.conversion) {
                return Err(MappingError::InvalidDefinition);
            }
            let observation = f
                .observation
                .map(|o| CompiledObservation::compile(o, target))
                .transpose()?;
            Ok(CompiledField {
                path: path(&f.source)?,
                target,
                conversion: f.conversion,
                observation,
            })
        })
        .collect()
}
fn compatible(kind: CommonFieldType, conversion: Conversion) -> bool {
    use CommonFieldType as T;
    use Conversion as C;
    match conversion {
        C::Copy => !matches!(kind, T::Time | T::DnsAnswers),
        C::Decimal | C::Hex => matches!(kind, T::Unsigned | T::Port | T::Pid | T::HttpStatus),
        C::Ip => kind == T::Ip,
        C::Domain => kind == T::Text,
        C::Md5 => kind == T::Md5,
        C::Sha1 => kind == T::Sha1,
        C::Sha256 => kind == T::Sha256,
    }
}
pub(super) fn path(keys: &[String]) -> Result<SourcePath, MappingError> {
    SourcePath::keys(&keys.iter().map(String::as_str).collect::<Vec<_>>()).map_err(invalid)
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
        let profile = if self.host.is_some() {
            PartitionProfile::EndpointHost
        } else if self.account.is_some() || self.region.is_some() {
            PartitionProfile::CloudAccountRegion
        } else {
            PartitionProfile::Unpartitioned
        };
        MappingPartition::try_new(
            profile,
            read(&self.account)?,
            read(&self.region)?,
            read(&self.host)?,
        )
    }
}
