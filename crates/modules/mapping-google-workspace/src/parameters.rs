use irmind_domain::{
    BoundedObservations, CommonEventV1, CommonField, CommonValue, EntityIdentityScope,
    EntityObservation, EntityRole, EventHeaderV1, EventText, EventType, EventTypeSet,
    ObservedEntity, ObservedEntityKind,
};
use irmind_mapping_contracts::source_mapping::{
    MappingError, MappingOutput, SourceRecordV1, SourceValue,
};

type ParameterField = (&'static str, CommonField, Option<ObservedEntityKind>);
const ADMIN_FIELDS: &[ParameterField] = &[(
    "USER_EMAIL",
    CommonField::UserTargetName,
    Some(ObservedEntityKind::User),
)];
const TOKEN_FIELDS: &[ParameterField] = &[(
    "client_id",
    CommonField::IrmindResourceId,
    Some(ObservedEntityKind::Resource),
)];
const DRIVE_FIELDS: &[ParameterField] = &[
    (
        "doc_id",
        CommonField::IrmindResourceId,
        Some(ObservedEntityKind::Resource),
    ),
    ("doc_title", CommonField::FileName, None),
    (
        "target_user",
        CommonField::UserTargetName,
        Some(ObservedEntityKind::User),
    ),
];

fn named_value<'a>(parameters: &'a SourceValue, name: &str) -> Option<&'a SourceValue> {
    let SourceValue::Array(values) = parameters else {
        return None;
    };
    let mut matching = values
        .iter()
        .filter(|parameter| parameter.field("name").and_then(SourceValue::as_text) == Some(name));
    let value = matching.next()?;
    matching.next().is_none().then_some(value)
}

fn parameter<'a>(event: &'a SourceValue, name: &str) -> Option<&'a str> {
    let value = named_value(event.field("parameters")?, name)?
        .field("value")?
        .as_text()?;
    (!value.is_empty()).then_some(value)
}

fn gmail_code(event: &SourceValue) -> Option<&str> {
    if event.field("name")?.as_text()? != "delivery" {
        return None;
    }
    let info = named_value(event.field("parameters")?, "event_info")?.field("messageValue")?;
    match named_value(info.field("parameter")?, "mail_event_type")?.field("intValue")? {
        SourceValue::Text(value) => Some(value.as_str()),
        SourceValue::Number(value) => Some(value.as_str()),
        _ => None,
    }
}

fn gmail_header(
    event: &SourceValue,
    header: &EventHeaderV1,
) -> Result<EventHeaderV1, MappingError> {
    let Some(code) = gmail_code(event) else {
        return Ok(header.clone());
    };
    let kind = match code {
        "10" | "11" => EventType::Change,
        "7" | "15" | "16" | "17" => EventType::Access,
        "1" | "2" => EventType::Info,
        _ => return Ok(header.clone()),
    };
    EventHeaderV1::new(
        header.categories(),
        EventTypeSet::new([kind]),
        header.outcome(),
        header.kind(),
    )
    .with_action("delivery")
    .and_then(|header| header.with_code(code))
    .map_err(|_| MappingError::InvalidOutput)
}

pub(super) fn project(
    source: &SourceRecordV1,
    output: MappingOutput,
) -> Result<MappingOutput, MappingError> {
    let fields = source.fields();
    let Some(app) = fields
        .field("activity")
        .and_then(|activity| activity.field("id"))
        .and_then(|id| id.field("applicationName"))
        .and_then(SourceValue::as_text)
    else {
        return Ok(output);
    };
    let Some(event) = fields.field("event") else {
        return Ok(output);
    };
    let selected = match app {
        "admin" => ADMIN_FIELDS,
        "token" => TOKEN_FIELDS,
        "drive" => DRIVE_FIELDS,
        "gmail" => &[],
        _ => return Ok(output),
    };
    let partition = output.partition().clone();
    let diagnostics = output.diagnostics().to_vec();
    let mut record = output.into_record();
    let mut context = record.common.context().clone();
    let mut observations = record.common.observations().values().to_vec();
    for &(name, field, kind) in selected {
        let Some(raw) = parameter(event, name) else {
            continue;
        };
        let Ok(value) = EventText::new(raw) else {
            continue;
        };
        context
            .try_insert(field, CommonValue::Text(value))
            .map_err(|_| MappingError::InvalidOutput)?;
        if let Some(kind) = kind {
            let entity = ObservedEntity::try_new(
                kind,
                raw,
                EntityIdentityScope::SourceRecord {
                    source: source.origin().source().clone(),
                    record: source.origin().record(),
                },
            );
            if let Ok(entity) = entity {
                observations.push(
                    EntityObservation::try_new(entity, EntityRole::Target, field)
                        .map_err(|_| MappingError::InvalidOutput)?,
                );
            }
        }
    }
    let header = if app == "gmail" {
        gmail_header(event, record.common.event())?
    } else {
        record.common.event().clone()
    };
    record.common = CommonEventV1::try_new(
        source.origin().clone(),
        source.timestamp(),
        header,
        context,
        BoundedObservations::try_new(observations).map_err(|_| MappingError::InvalidOutput)?,
    )
    .map_err(|_| MappingError::InvalidOutput)?;
    MappingOutput::try_new(
        source,
        record.indexed,
        record.common,
        partition,
        diagnostics,
    )
}
