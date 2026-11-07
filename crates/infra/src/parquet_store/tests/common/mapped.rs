use super::*;
use irmind_app::common_event::*;
use irmind_app::{CommonGraphRecord, IndexedGraphRecord, ParseReport, StreamingEventParser};
use irmind_domain::{EvidenceHash, Tainted};
use std::io::Read;

pub(super) struct Mapped;
impl irmind_app::EventParser for Mapped {
    fn version(&self) -> &'static str {
        "common-fixture-v1"
    }
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<irmind_app::GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        irmind_app::EventParser::parse_each(&JsonParser, source, bytes, cancel, emit)
    }
}
impl StreamingEventParser for Mapped {
    fn streaming_version(&self) -> &'static str {
        "common-fixture-v1"
    }
    fn parser_name(&self) -> &'static str {
        "parser-common-fixture"
    }
    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<irmind_app::GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        JsonParser.parse_reader(source, reader, hash, cancel, emit)
    }
    fn parse_common_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<CommonGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        JsonParser.parse_indexed_reader_report(source, reader, hash, cancel, &mut |tainted| {
            let provenance = tainted.provenance().clone();
            let mut record = None;
            tainted.inspect(|indexed| {
                record = Some(mapped(indexed.clone(), hash));
            });
            emit(Tainted::from_external(record.unwrap()?, provenance))
        })
    }
    fn parse_common_local_file_report(
        &self,
        source: &str,
        file: &mut File,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<CommonGraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.parse_common_reader_report(source, file, hash, cancel, emit)
    }
}
fn mapped(mut indexed: IndexedGraphRecord, hash: [u8; 32]) -> Result<CommonGraphRecord, AppError> {
    let invalid = || AppError::Fixed(irmind_app::FixedAppError::PolicyInvalidCommonEvent);
    let raw: serde_json::Value =
        serde_json::from_str(&indexed.record.text).map_err(|_| invalid())?;
    let source = EvidenceHash::parse(&irmind_app::hex(&hash)).map_err(|_| invalid())?;
    let origin = EventOrigin::try_new(
        source.clone(),
        indexed.record.index as u64,
        indexed.source_offset,
        "parser-common-fixture",
        "common-fixture-v1",
    )
    .map_err(|_| invalid())?;
    let outcome = raw["outcome"]
        .as_str()
        .map(EventOutcome::parse)
        .transpose()
        .map_err(|_| invalid())?
        .unwrap_or(EventOutcome::Unknown);
    let header = EventHeaderV1::new(
        CategorySet::new([EventCategory::Authentication]),
        EventTypeSet::new([EventType::Start]),
        outcome,
        EventKind::Event,
    )
    .with_action(&indexed.record.event)
    .map_err(|_| invalid())?;
    let mut context = EventContextV1::default();
    let mut observations = Vec::new();
    for (name, field, role) in [
        ("source_ip", CommonField::SourceIp, EntityRole::Source),
        (
            "destination_ip",
            CommonField::DestinationIp,
            EntityRole::Destination,
        ),
    ] {
        if let Some(value) = raw[name].as_str() {
            context
                .try_insert(
                    field,
                    CommonValue::Ip(value.parse().map_err(|_| invalid())?),
                )
                .map_err(|_| invalid())?;
            let entity =
                ObservedEntity::try_new(ObservedEntityKind::Ip, value, EntityIdentityScope::Global)
                    .map_err(|_| invalid())?;
            observations
                .push(EntityObservation::try_new(entity, role, field).map_err(|_| invalid())?);
        }
    }
    if let Some(pid) = raw["pid"].as_u64() {
        context
            .try_insert(CommonField::ProcessPid, CommonValue::Unsigned(pid))
            .map_err(|_| invalid())?;
        let scope = EntityIdentityScope::SourceRecord {
            source,
            record: indexed.record.index as u64,
        };
        let entity = ObservedEntity::try_new(ObservedEntityKind::Process, &pid.to_string(), scope)
            .map_err(|_| invalid())?;
        observations.push(
            EntityObservation::try_new(entity, EntityRole::Subject, CommonField::ProcessPid)
                .map_err(|_| invalid())?,
        );
    }
    indexed.record.entities.clear();
    indexed.record.relations.clear();
    let common = CommonEventV1::try_new(
        origin,
        indexed.time,
        header,
        context,
        BoundedObservations::try_new(observations).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    Ok(CommonGraphRecord { indexed, common })
}
