use super::view::View;
use irmind_app::source_mapping::{MappingError, SourceValue};
use irmind_domain::{
    CommonField, CommonFieldType, CommonValue, DnsAnswer, DnsAnswers, EventContextV1, EventText,
    IndexedTime,
};
pub(super) fn project(view: &View<'_>) -> Result<EventContextV1, MappingError> {
    let mut context = EventContextV1::default();
    for field in CommonField::all().filter(|field| !field.as_str().starts_with("irmind.")) {
        let Some(value) = view.get(field.as_str())? else {
            continue;
        };
        if matches!(value, SourceValue::Null)
            || matches!(value, SourceValue::Text(text) if text.is_empty())
        {
            continue;
        }
        let typed = match field.value_type() {
            CommonFieldType::Time => CommonValue::Time(
                IndexedTime::from_rfc3339(value.as_text().ok_or_else(invalid)?, false)
                    .map_err(|_| invalid())?,
            ),
            CommonFieldType::DnsAnswers => CommonValue::DnsAnswers(dns_answers(value)?),
            _ => irmind_mapping_tables::copy_common_value(field, value)?,
        };
        context.try_insert(field, typed).map_err(|_| invalid())?;
    }
    Ok(context)
}
fn dns_answers(value: &SourceValue) -> Result<DnsAnswers, MappingError> {
    let SourceValue::Array(values) = value else {
        return Err(invalid());
    };
    if values.len() > 16 {
        return Err(invalid());
    }
    let text = |value: &SourceValue, key| {
        EventText::new(
            value
                .field(key)
                .and_then(SourceValue::as_text)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())
    };
    let values = values
        .iter()
        .map(|value| {
            DnsAnswer::new(
                text(value, "name")?,
                text(value, "type")?,
                text(value, "data")?,
            )
            .map_err(|_| invalid())
        })
        .collect::<Result<_, _>>()?;
    DnsAnswers::new(values).map_err(|_| invalid())
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
