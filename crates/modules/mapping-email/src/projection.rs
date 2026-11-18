use irmind_app::source_mapping::{
    MappingDiagnostic, MappingError, MappingOutput, SourceRecordV1, SourceValue,
};
use irmind_domain::{
    BoundedObservations, CommonEventV1, CommonField as F, CommonValue, EntityIdentityScope,
    EntityObservation, EntityRole, EventContextV1, EventText, ObservedEntity, ObservedEntityKind,
};
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}
pub(super) fn project(
    source: &SourceRecordV1,
    output: MappingOutput,
) -> Result<MappingOutput, MappingError> {
    let partition = output.partition().clone();
    let mut record = output.into_record();
    record.indexed.record.entities.push((
        "email_message".into(),
        source.origin().source().as_str().into(),
    ));
    let mut context = record.common.context().clone();
    let mut observations = record.common.observations().values().to_vec();
    let mut diagnostics = Vec::new();
    header_projection(
        source,
        &mut record.indexed.record,
        &mut context,
        &mut observations,
        &mut diagnostics,
    )?;

    if let Some(url) = source.fields().field("url").and_then(SourceValue::as_text) {
        record
            .indexed
            .record
            .entities
            .push(("url".into(), url.into()));
    }
    record.indexed.record.entities.sort();
    record.indexed.record.entities.dedup();
    if record.indexed.record.entities.len() > 128 {
        record.indexed.record.entities.truncate(128);
        diagnostics.push(MappingDiagnostic::UnsupportedValue);
    }
    let label = source
        .format()
        .discriminators()
        .get(&irmind_app::source_mapping::SourceDiscriminator::RecordType)
        .map_or("record", String::as_str);
    record.indexed.record.event = format!("Email {label}");
    record.common = CommonEventV1::try_new(
        source.origin().clone(),
        source.timestamp(),
        record.common.event().clone(),
        context,
        BoundedObservations::try_new(observations).map_err(bad)?,
    )
    .map_err(bad)?;
    MappingOutput::try_new(
        source,
        record.indexed,
        record.common,
        partition,
        diagnostics,
    )
}
fn header_projection(
    source: &SourceRecordV1,
    record: &mut irmind_app::GraphRecord,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    if let Some(headers) = source.fields().field("decoded_headers") {
        for (name, field, role) in [
            ("from", F::UserName, EntityRole::Actor),
            ("to", F::UserTargetName, EntityRole::Target),
        ] {
            let addresses = addresses(headers.field(name));
            if let Some(address) = addresses.first()
                && user(source, address, field, role, context, observations).is_err()
            {
                diagnostics.push(MappingDiagnostic::UnsupportedValue);
            }
            for address in addresses.iter().take(120) {
                if !address.is_empty() && address.len() <= 4096 {
                    record.entities.push(("user".into(), (*address).into()));
                }
            }
            if addresses.len() > 1 {
                diagnostics.push(MappingDiagnostic::UnsupportedValue);
            }
        }
        if let Some(ip) = text(headers.field("x-originating-ip")).and_then(|v| {
            v.trim()
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        }) {
            context
                .try_insert(F::SourceIp, CommonValue::Ip(ip))
                .map_err(bad)?;
            observations.push(
                EntityObservation::try_new(
                    ObservedEntity::try_new(
                        ObservedEntityKind::Ip,
                        &ip.to_string(),
                        EntityIdentityScope::Global,
                    )
                    .map_err(bad)?,
                    EntityRole::Source,
                    F::SourceIp,
                )
                .map_err(bad)?,
            );
        }
    }
    Ok(())
}

fn user(
    source: &SourceRecordV1,
    value: &str,
    field: F,
    role: EntityRole,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
) -> Result<(), MappingError> {
    let entity = ObservedEntity::try_new(
        ObservedEntityKind::User,
        value,
        EntityIdentityScope::SourceRecord {
            source: source.origin().source().clone(),
            record: source.origin().record(),
        },
    )
    .map_err(bad)?;
    let observation = EntityObservation::try_new(entity, role, field).map_err(bad)?;
    context
        .try_insert(
            field,
            CommonValue::Text(EventText::new(value).map_err(bad)?),
        )
        .map_err(bad)?;
    observations.push(observation);
    Ok(())
}
fn addresses(value: Option<&SourceValue>) -> Vec<&str> {
    let Some(SourceValue::Array(headers)) = value else {
        return Vec::new();
    };
    headers
        .iter()
        .filter_map(|v| {
            if let SourceValue::Array(v) = v {
                Some(v)
            } else {
                None
            }
        })
        .flatten()
        .filter_map(|v| v.field("address").and_then(SourceValue::as_text))
        .collect()
}
fn text(value: Option<&SourceValue>) -> Option<&str> {
    match value? {
        SourceValue::Text(v) => Some(v),
        SourceValue::Array(values) => values.iter().find_map(|v| text(Some(v))),
        _ => None,
    }
}
