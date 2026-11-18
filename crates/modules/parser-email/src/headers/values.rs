use crate::{invalid, limit};
use irmind_app::{AppError, source_mapping::SourceValue};
use mail_parser::{HeaderValue, Host};
fn text(value: impl Into<String>) -> SourceValue {
    SourceValue::Text(value.into())
}
pub(super) fn value(value: &HeaderValue<'_>, raw: &[u8]) -> Result<SourceValue, AppError> {
    Ok(match value {
        HeaderValue::Address(addresses) => SourceValue::Array(
            addresses
                .iter()
                .map(|address| {
                    let mut fields = Vec::new();
                    if let Some(value) = &address.name {
                        fields.push(("name".into(), text(value.to_string())));
                    }
                    if let Some(value) = &address.address {
                        fields.push(("address".into(), text(value.to_string())));
                    }
                    SourceValue::object(fields).map_err(|_| limit())
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        HeaderValue::Text(value) => text(value.to_string()),
        HeaderValue::TextList(values) => {
            SourceValue::Array(values.iter().map(|v| text(v.to_string())).collect())
        }
        HeaderValue::ContentType(kind) => {
            let mut parameters = Vec::new();
            for parameter in kind.attributes().unwrap_or_default() {
                if parameters.len() >= 64
                    || parameters
                        .iter()
                        .any(|(key, _)| key == parameter.name.as_ref())
                {
                    return Err(invalid());
                }
                parameters.push((
                    parameter.name.to_string(),
                    text(parameter.value.to_string()),
                ));
            }
            SourceValue::object(vec![
                ("type".into(), text(kind.c_type.to_string())),
                (
                    "subtype".into(),
                    text(kind.c_subtype.as_deref().unwrap_or_default()),
                ),
                (
                    "parameters".into(),
                    SourceValue::object(parameters).map_err(|_| limit())?,
                ),
            ])
            .map_err(|_| limit())?
        }
        HeaderValue::Received(received) => {
            let mut fields = vec![(
                "raw".into(),
                text(String::from_utf8_lossy(raw).into_owned()),
            )];
            if let Some(host) = received.from() {
                fields.push(("from".into(), host_value(host)));
            }
            if let Some(host) = received.by() {
                fields.push(("by".into(), host_value(host)));
            }
            if let Some(ip) = received.from_ip() {
                fields.push(("from_ip".into(), text(ip.to_string())));
            }
            if let Some(address) = received.for_() {
                fields.push(("for".into(), text(address)));
            }
            if let Some(id) = received.id() {
                fields.push(("id".into(), text(id)));
            }
            SourceValue::object(fields).map_err(|_| limit())?
        }
        // Do not invent a timezone when a Date header is malformed or obsolete.
        HeaderValue::DateTime(_) | HeaderValue::Empty => {
            text(String::from_utf8_lossy(raw).trim().to_owned())
        }
    })
}
fn host_value(host: &Host<'_>) -> SourceValue {
    match host {
        Host::Name(name) => text(name.to_string()),
        Host::IpAddr(ip) => text(ip.to_string()),
    }
}
