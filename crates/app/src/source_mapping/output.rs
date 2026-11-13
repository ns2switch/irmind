mod time;
use super::{MappingError, SourceRecordV1};
use crate::{CommonGraphRecord, IndexedGraphRecord};
use irmind_domain::{BoundedObservations, CommonEventV1, EventContextV1, EventHeaderV1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingDiagnostic {
    Unclassified,
    UnsupportedValue,
    MissingRequiredValue,
}

/// Source-derived values only. The storage adapter owns normalization, caps,
/// hash-derived paths and organization/case scope enforcement.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct MappingPartition {
    profile: crate::PartitionProfile,
    account: String,
    region: String,
    host: String,
    cluster: String,
}
impl MappingPartition {
    pub fn try_new(
        profile: crate::PartitionProfile,
        account: &str,
        region: &str,
        host: &str,
    ) -> Result<Self, MappingError> {
        let value = Self {
            profile,
            account: account.into(),
            region: region.into(),
            host: host.into(),
            cluster: String::new(),
        };
        if !value.valid() {
            return Err(MappingError::InvalidOutput);
        }
        Ok(value)
    }
    pub fn with_cluster(
        mut self,
        identity: &irmind_domain::ClusterIdentity,
    ) -> Result<Self, MappingError> {
        if self.profile != crate::PartitionProfile::KubernetesCluster {
            return Err(MappingError::InvalidOutput);
        }
        self.cluster = identity.qualified();
        if !self.valid() {
            return Err(MappingError::InvalidOutput);
        }
        Ok(self)
    }
    pub fn cluster(&self) -> &str {
        &self.cluster
    }
    fn valid(&self) -> bool {
        [&self.account, &self.region, &self.host, &self.cluster]
            .iter()
            .all(|value| value.len() <= 1024)
    }
    pub const fn profile(&self) -> crate::PartitionProfile {
        self.profile
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn host(&self) -> &str {
        &self.host
    }
}

pub(super) fn unmapped(source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
    let indexed = IndexedGraphRecord {
        record: crate::GraphRecord {
            index: usize::try_from(source.origin().record())
                .map_err(|_| MappingError::InvalidOutput)?,
            at: source
                .timestamp()
                .map_or_else(String::new, irmind_domain::IndexedTime::to_rfc3339),
            event: String::new(),
            text: if source.cluster_identity().is_some() {
                "Cluster source has no selected semantic mapping; original fields are retained in the signed source.".into()
            } else {
                super::json::render_source_fields(source.fields())
                    .map_err(|_| MappingError::InvalidOutput)?
            },
            entities: Vec::new(),
            relations: Vec::new(),
        },
        time: source.timestamp(),
        source_offset: source.origin().offset(),
    };
    MappingOutput::try_new(
        source,
        indexed,
        MappingOutput::unclassified_common(source)?,
        if let Some(cluster) = source.cluster_identity() {
            MappingPartition::try_new(crate::PartitionProfile::KubernetesCluster, "", "", "")?
                .with_cluster(cluster)?
        } else {
            MappingPartition::default()
        },
        vec![MappingDiagnostic::Unclassified],
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct MappingOutput {
    record: CommonGraphRecord,
    partition: MappingPartition,
    diagnostics: Vec<MappingDiagnostic>,
}
impl MappingOutput {
    pub fn unclassified(
        source: &SourceRecordV1,
        diagnostic: MappingDiagnostic,
    ) -> Result<Self, MappingError> {
        let mut output = unmapped(source)?;
        output.diagnostics = vec![diagnostic];
        Ok(output)
    }
    pub fn try_new(
        source: &SourceRecordV1,
        indexed: IndexedGraphRecord,
        common: CommonEventV1,
        partition: MappingPartition,
        diagnostics: Vec<MappingDiagnostic>,
    ) -> Result<Self, MappingError> {
        if common.origin() != source.origin()
            || common.timestamp() != source.timestamp()
            || indexed.time != source.timestamp()
            || indexed.source_offset != source.origin().offset()
            || u64::try_from(indexed.record.index).ok() != Some(source.origin().record())
            || !time::valid_display_time(&indexed.record.at, source.timestamp())
            || !valid_projection(&indexed.record)
            || !partition.valid()
            || (partition.profile == crate::PartitionProfile::KubernetesCluster
                && partition.cluster.is_empty())
            || (partition.profile != crate::PartitionProfile::KubernetesCluster
                && !partition.cluster.is_empty())
            || (partition.profile == crate::PartitionProfile::KubernetesCluster
                && source
                    .cluster_identity()
                    .is_none_or(|id| !id.matches_qualified(&partition.cluster)))
            || !valid_acquisition(source, common.context(), &partition)
            || diagnostics.len() > 8
        {
            return Err(MappingError::InvalidOutput);
        }
        Ok(Self {
            record: CommonGraphRecord { indexed, common },
            partition,
            diagnostics,
        })
    }

    pub fn unclassified_common(source: &SourceRecordV1) -> Result<CommonEventV1, MappingError> {
        let mut context = EventContextV1::default();
        if let Some(cluster) = source.cluster_identity() {
            context
                .try_insert(
                    irmind_domain::CommonField::IrmindClusterIdentity,
                    irmind_domain::CommonValue::Text(
                        irmind_domain::EventText::new(&cluster.qualified())
                            .map_err(|_| MappingError::InvalidOutput)?,
                    ),
                )
                .map_err(|_| MappingError::InvalidOutput)?;
        }
        CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            EventHeaderV1::default(),
            context,
            BoundedObservations::default(),
        )
        .map_err(|_| MappingError::InvalidOutput)
    }
    pub const fn record(&self) -> &CommonGraphRecord {
        &self.record
    }
    /// Consume this validated pure projection without cloning its indexed record.
    /// A Tainted wrapper still controls access when the output crosses a boundary.
    pub fn into_record(self) -> CommonGraphRecord {
        self.record
    }
    pub const fn partition(&self) -> &MappingPartition {
        &self.partition
    }
    pub fn diagnostics(&self) -> &[MappingDiagnostic] {
        &self.diagnostics
    }
}

fn valid_projection(record: &crate::GraphRecord) -> bool {
    let entity = |kind: &str, value: &str| {
        !kind.is_empty()
            && kind.len() <= 64
            && kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            && !value.is_empty()
            && value.len() <= 4096
    };
    record.event.len() <= irmind_domain::SOURCE_MAX_BYTES
        && record.text.len() <= irmind_domain::SOURCE_MAX_BYTES
        && record.entities.len() <= 128
        && record.relations.len() <= 256
        && record
            .entities
            .iter()
            .all(|(kind, value)| entity(kind, value))
        && record.relations.iter().all(|r| {
            entity(&r.from_kind, &r.from_value)
                && entity(&r.to_kind, &r.to_value)
                && !r.relation.is_empty()
                && r.relation.len() <= 64
                && r.relation
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        })
}

fn valid_acquisition(
    source: &SourceRecordV1,
    context: &EventContextV1,
    partition: &MappingPartition,
) -> bool {
    let projected = context.get(irmind_domain::CommonField::IrmindClusterIdentity);
    match (source.cluster_identity(), projected) {
        (None, None) => partition.cluster().is_empty(),
        (Some(cluster), Some(irmind_domain::CommonValue::Text(value))) => {
            cluster.matches_qualified(value.as_str())
                && partition.profile == crate::PartitionProfile::KubernetesCluster
                && partition.cluster == value.as_str()
        }
        _ => false,
    }
}
