use super::invalid;
use crate::AppError;
use irmind_domain::{
    CommonField, CommonFieldType, CommonValue, ContentHash, DnsAnswer, DnsAnswers, EventText,
    EventTextList, HashAlgorithm, NetworkDirection,
};
use serde_json::{Value, json};

pub(super) fn encode(value: &CommonValue) -> Value {
    match value {
        CommonValue::Text(v) => json!(v.as_str()),
        CommonValue::Unsigned(v) => json!(v),
        CommonValue::Ip(v) => json!(v.to_string()),
        CommonValue::Hash(v) => json!(v.value()),
        CommonValue::Time(v) => json!(super::codec::time::WireTime::from(*v)),
        CommonValue::Direction(v) => json!(v.as_str()),
        CommonValue::TextList(v) => {
            json!(v.values().iter().map(EventText::as_str).collect::<Vec<_>>())
        }
        CommonValue::DnsAnswers(v) => Value::Array(
            v.values()
                .iter()
                .map(|a| json!({"name":a.name(),"type":a.record_type(),"data":a.data()}))
                .collect(),
        ),
    }
}
fn text(value: &Value) -> Result<&str, AppError> {
    value.as_str().ok_or_else(invalid)
}
fn event_text(value: &Value) -> Result<EventText, AppError> {
    EventText::new(text(value)?).map_err(|_| invalid())
}

pub(super) fn decode(field: CommonField, value: &Value) -> Result<CommonValue, AppError> {
    let value = match field.value_type() {
        CommonFieldType::Text | CommonFieldType::LongText => CommonValue::Text(event_text(value)?),
        CommonFieldType::Ip => CommonValue::Ip(text(value)?.parse().map_err(|_| invalid())?),
        CommonFieldType::Unsigned
        | CommonFieldType::Port
        | CommonFieldType::Pid
        | CommonFieldType::HttpStatus => CommonValue::Unsigned(value.as_u64().ok_or_else(invalid)?),
        CommonFieldType::Md5 | CommonFieldType::Sha1 | CommonFieldType::Sha256 => {
            let algorithm = match field.value_type() {
                CommonFieldType::Md5 => HashAlgorithm::Md5,
                CommonFieldType::Sha1 => HashAlgorithm::Sha1,
                _ => HashAlgorithm::Sha256,
            };
            CommonValue::Hash(ContentHash::new(algorithm, text(value)?).map_err(|_| invalid())?)
        }
        CommonFieldType::Direction => {
            CommonValue::Direction(NetworkDirection::parse(text(value)?).map_err(|_| invalid())?)
        }
        CommonFieldType::Time => {
            let time: super::codec::time::WireTime =
                serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            CommonValue::Time(time.checked()?)
        }
        CommonFieldType::TextList => {
            let values = value
                .as_array()
                .filter(|v| v.len() <= 16)
                .ok_or_else(invalid)?;
            CommonValue::TextList(
                EventTextList::new(values.iter().map(event_text).collect::<Result<_, _>>()?)
                    .map_err(|_| invalid())?,
            )
        }
        CommonFieldType::DnsAnswers => {
            let values = value
                .as_array()
                .filter(|v| v.len() <= 16)
                .ok_or_else(invalid)?;
            let answers = values
                .iter()
                .map(|v| {
                    DnsAnswer::new(
                        event_text(&v["name"])?,
                        event_text(&v["type"])?,
                        event_text(&v["data"])?,
                    )
                    .map_err(|_| invalid())
                })
                .collect::<Result<_, _>>()?;
            CommonValue::DnsAnswers(DnsAnswers::new(answers).map_err(|_| invalid())?)
        }
    };
    Ok(value)
}
