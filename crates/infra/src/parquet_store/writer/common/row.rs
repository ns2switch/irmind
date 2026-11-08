use crate::parquet_store::{AppError, RecordRow, invalid_source, storage};
use irmind_app::common_event::CheckedCommonRecord;
use irmind_app::common_event::{CommonField, CommonValue, encode_identity_scope};
use irmind_domain::EvidenceHash;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct ObservationRow {
    pub(super) field: u16,
    pub(super) kind: String,
    pub(super) role: u8,
    pub(super) scope: String,
    pub(super) value: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "super::spool::StoredCommonRow")]
pub(in crate::parquet_store) struct CommonRow {
    pub(super) payload: String,
    pub(super) categories: u32,
    pub(super) types: u32,
    pub(super) outcome: u8,
    pub(super) kind: u8,
    pub(super) role_bits: u16,
    pub(super) observations: Vec<ObservationRow>,
    #[serde(skip_serializing)]
    pub(super) co_observations: String,
}
impl CommonRow {
    fn from_record(checked: &CheckedCommonRecord<'_>) -> Result<Self, AppError> {
        let record = checked.record();
        let common = &record.common;
        let header = common.event();
        let mut observations = common
            .observations()
            .values()
            .iter()
            .map(|observation| {
                Ok(ObservationRow {
                    kind: observation.entity().kind().as_str().into(),
                    value: observation.entity().value().into(),
                    scope: encode_identity_scope(observation.entity().scope())?,
                    role: u8::try_from(observation.role().code()).map_err(|_| invalid_source())?,
                    field: observation.field().code(),
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let role_bits = observations
            .iter()
            .fold(0u16, |bits, o| bits | (1u16 << o.role));
        let mut seen = common
            .observations()
            .values()
            .iter()
            .map(|o| (o.entity().kind().as_str(), o.entity().value()))
            .collect::<std::collections::BTreeSet<_>>();
        for (kind, value) in &record.indexed.record.entities {
            if seen.insert((kind.as_str(), value.as_str())) {
                observations.push(ObservationRow {
                    kind: kind.clone(),
                    value: value.clone(),
                    scope: "legacy-unspecified".into(),
                    role: 0,
                    field: 0,
                });
            }
        }
        observations.sort_by(|a, b| {
            (&a.kind, &a.value, &a.scope, a.role, a.field)
                .cmp(&(&b.kind, &b.value, &b.scope, b.role, b.field))
        });
        observations.dedup_by(|a, b| {
            a.kind == b.kind
                && a.value == b.value
                && a.scope == b.scope
                && a.role == b.role
                && a.field == b.field
        });
        let co_observations = typed_peers(&observations)?;
        Ok(Self {
            payload: checked.encoded().to_owned(),
            categories: header.categories().bits(),
            types: header.types().bits(),
            outcome: u8::try_from(header.outcome().code()).map_err(|_| invalid_source())?,
            kind: u8::try_from(header.kind().code()).map_err(|_| invalid_source())?,
            role_bits,
            observations,
            co_observations,
        })
    }
    pub(in crate::parquet_store) fn estimated_bytes(&self) -> usize {
        self.payload.len()
            + self
                .co_observations
                .len()
                .saturating_mul(self.observations.len() + 1)
            + self
                .observations
                .iter()
                .map(|o| o.kind.len() + o.value.len() + o.scope.len() + 32)
                .sum::<usize>()
    }
}

pub(super) fn typed_peers(observations: &[ObservationRow]) -> Result<String, AppError> {
    let typed = observations
        .iter()
        .filter(|o| o.role != 0)
        .collect::<Vec<_>>();
    serde_json::to_string(&typed).map_err(storage)
}

impl RecordRow {
    pub(in crate::parquet_store) fn from_common(
        checked: &CheckedCommonRecord<'_>,
        hash: &EvidenceHash,
    ) -> Result<Self, AppError> {
        let record = checked.record();
        if record.common.origin().source() != hash {
            return Err(invalid_source());
        }
        let mut row = Self::from_partitioned(&record.indexed, hash)?;
        let projection = CommonRow::from_record(checked)?;
        let unchanged = record.common.observations().values().is_empty()
            && row.entity_pairs.windows(2).all(|pair| pair[0] < pair[1]);
        if !unchanged {
            row.entity_pairs
                .extend(record.common.observations().values().iter().map(|o| {
                    (
                        o.entity().kind().as_str().to_owned(),
                        o.entity().value().to_owned(),
                    )
                }));
            row.entity_pairs.sort();
            row.entity_pairs.dedup();
            row.entities = serde_json::to_string(&row.entity_pairs).map_err(storage)?;
        }
        let context = record.common.context();
        let scalar = |field| match context.get(field) {
            Some(CommonValue::Text(value)) => Some(value.as_str()),
            _ => None,
        };
        if let Some(account) =
            scalar(CommonField::CloudAccountId).or_else(|| scalar(CommonField::CloudProjectId))
        {
            row.scope_account = account.into();
        }
        if let Some(region) = scalar(CommonField::CloudRegion) {
            row.scope_region = region.into();
        }
        if let Some(host) = scalar(CommonField::HostName)
            .or_else(|| scalar(CommonField::HostHostname))
            .or_else(|| scalar(CommonField::HostId))
        {
            row.scope_host = host.into();
        }
        row.common = Some(projection);
        Ok(row)
    }
}

impl RecordRow {
    pub(in crate::parquet_store) fn from_mapping(
        output: &irmind_app::source_mapping::MappingOutput,
        provenance: &irmind_domain::Provenance,
        decoder: irmind_app::ParserIdentity<'_>,
        hash: &EvidenceHash,
        route: String,
    ) -> Result<Self, AppError> {
        let record = output.record();
        let checked = irmind_app::common_event::check_common_record(record, provenance, decoder)?;
        if record.common.origin().source() != hash {
            return Err(invalid_source());
        }
        let indexed = &record.indexed;
        let source = &indexed.record;
        let partition = output.partition();
        let mut entity_pairs = source.entities.clone();
        entity_pairs.extend(record.common.observations().values().iter().map(|o| {
            (
                o.entity().kind().as_str().to_owned(),
                o.entity().value().to_owned(),
            )
        }));
        entity_pairs.sort();
        entity_pairs.dedup();
        let relations = source
            .relations
            .iter()
            .map(|r| {
                [
                    r.from_kind.as_str(),
                    r.from_value.as_str(),
                    r.relation.as_str(),
                    r.to_kind.as_str(),
                    r.to_value.as_str(),
                ]
            })
            .collect::<Vec<_>>();
        Ok(Self {
            partition: super::super::Partition {
                date: indexed
                    .time
                    .map_or_else(|| "unknown".into(), |t| t.instant().utc_date()),
                account: String::new(),
                region: String::new(),
                scope: None,
                segment: 0,
                mapping_route: Some(route),
            },
            hash: hash.as_str().into(),
            index: u64::try_from(source.index).map_err(storage)?,
            at: indexed
                .time
                .map_or_else(String::new, irmind_app::IndexedTime::to_rfc3339),
            event: source.event.clone(),
            text: source.text.clone(),
            entities: serde_json::to_string(&entity_pairs).map_err(storage)?,
            entity_pairs,
            relations: serde_json::to_string(&relations).map_err(storage)?,
            time: indexed.time,
            source_offset: indexed.source_offset,
            precise: true,
            common: Some(CommonRow::from_record(&checked)?),
            profile: match partition.profile() {
                irmind_app::PartitionProfile::Unpartitioned => 0,
                irmind_app::PartitionProfile::CloudAccountRegion => 1,
                irmind_app::PartitionProfile::EndpointHost => 2,
            },
            scope_account: partition.account().into(),
            scope_region: partition.region().into(),
            scope_host: partition.host().into(),
        })
    }
}
