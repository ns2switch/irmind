mod observation;
pub(super) mod time;
use super::{invalid, values};
use crate::AppError;
use irmind_domain::{
    BoundedObservations, COMMON_EVENT_MAX_BYTES, COMMON_EVENT_V1, CategorySet, CommonEventV1,
    CommonField, EventCategory, EventContextV1, EventHeaderV1, EventKind, EventOrigin,
    EventOutcome, EventType, EventTypeSet, EvidenceHash,
};
use observation::WireObservation;
pub(super) use observation::{decode_scope, encode_scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use time::WireTime;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOrigin {
    offset: Option<u64>,
    parser: String,
    parser_version: String,
    record: u64,
    source: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    category: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dataset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    kind: String,
    outcome: String,
    #[serde(rename = "type")]
    event_type: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCommon {
    context: BTreeMap<String, Value>,
    event: WireHeader,
    observations: Vec<WireObservation>,
    origin: WireOrigin,
    schema: String,
    timestamp: Option<WireTime>,
}

/// Canonical keys are explicit, including when `serde_json/preserve_order` is enabled.
fn ordered(value: Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, ordered(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(ordered).collect()),
        value => value,
    }
}

pub fn encode_common_event(event: &CommonEventV1) -> Result<String, AppError> {
    let origin = event.origin();
    let header = event.event();
    let wire = WireCommon {
        schema: COMMON_EVENT_V1.to_owned(),
        origin: WireOrigin {
            source: origin.source().as_str().into(),
            record: origin.record(),
            offset: origin.offset(),
            parser: origin.parser().into(),
            parser_version: origin.parser_version().into(),
        },
        timestamp: event.timestamp().map(WireTime::from),
        event: WireHeader {
            category: header
                .categories()
                .iter()
                .map(|v| v.as_str().into())
                .collect(),
            event_type: header.types().iter().map(|v| v.as_str().into()).collect(),
            outcome: header.outcome().as_str().into(),
            kind: header.kind().as_str().into(),
            action: header.action().map(str::to_owned),
            code: header.code().map(str::to_owned),
            id: header.id().map(str::to_owned),
            dataset: header.dataset().map(str::to_owned),
        },
        context: event
            .context()
            .fields()
            .map(|(field, value)| (field.as_str().into(), ordered(values::encode(value))))
            .collect(),
        observations: event
            .observations()
            .values()
            .iter()
            .map(WireObservation::from)
            .collect(),
    };
    // Wire struct fields are explicitly lexical. Only sparse context values
    // and scope variants need recursive ordering, not a second whole-event tree.
    let encoded = serde_json::to_string(&wire).map_err(|_| invalid())?;
    if encoded.len() > COMMON_EVENT_MAX_BYTES {
        return Err(invalid());
    }
    Ok(encoded)
}

/// Reject duplicate/unknown fields, unsupported codes, invalid values and noncanonical input.
pub fn decode_common_event(input: &str) -> Result<CommonEventV1, AppError> {
    if input.len() > COMMON_EVENT_MAX_BYTES {
        return Err(invalid());
    }
    let wire: WireCommon = serde_json::from_str(input).map_err(|_| invalid())?;
    if wire.schema != COMMON_EVENT_V1
        || wire.observations.len() > 32
        || wire.context.len() > CommonField::ALL.len()
    {
        return Err(invalid());
    }
    let origin = EventOrigin::try_new(
        EvidenceHash::parse(&wire.origin.source).map_err(|_| invalid())?,
        wire.origin.record,
        wire.origin.offset,
        &wire.origin.parser,
        &wire.origin.parser_version,
    )
    .map_err(|_| invalid())?;
    let timestamp = wire.timestamp.map(WireTime::checked).transpose()?;
    let header = checked_header(wire.event)?;
    let mut context = EventContextV1::default();
    for (field, value) in wire.context {
        let field = CommonField::parse(&field).map_err(|_| invalid())?;
        context
            .try_insert(field, values::decode(field, &value)?)
            .map_err(|_| invalid())?;
    }
    let observations = wire
        .observations
        .into_iter()
        .map(WireObservation::checked)
        .collect::<Result<_, _>>()?;
    let event = CommonEventV1::try_new(
        origin,
        timestamp,
        header,
        context,
        BoundedObservations::try_new(observations).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    if encode_common_event(&event)? != input {
        return Err(invalid());
    }
    Ok(event)
}

fn checked_header(wire: WireHeader) -> Result<EventHeaderV1, AppError> {
    if wire.category.len() > EventCategory::ALL.len()
        || wire.event_type.len() > EventType::ALL.len()
    {
        return Err(invalid());
    }
    let categories = wire
        .category
        .iter()
        .map(|v| EventCategory::parse(v).map_err(|_| invalid()))
        .collect::<Result<Vec<_>, _>>()?;
    let types = wire
        .event_type
        .iter()
        .map(|v| EventType::parse(v).map_err(|_| invalid()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut event = EventHeaderV1::new(
        CategorySet::new(categories),
        EventTypeSet::new(types),
        EventOutcome::parse(&wire.outcome).map_err(|_| invalid())?,
        EventKind::parse(&wire.kind).map_err(|_| invalid())?,
    );
    if let Some(value) = wire.action {
        event = event.with_action(&value).map_err(|_| invalid())?;
    }
    if let Some(value) = wire.code {
        event = event.with_code(&value).map_err(|_| invalid())?;
    }
    if let Some(value) = wire.id {
        event = event.with_id(&value).map_err(|_| invalid())?;
    }
    if let Some(value) = wire.dataset {
        event = event.with_dataset(&value).map_err(|_| invalid())?;
    }
    Ok(event)
}
