//! Canonical retained Sigma fields for the enrolled cluster audit mappings.
use super::{InvalidCommonEvent, encode_common_event, invalid};
use crate::source_mapping::SourceValue;
use irmind_domain::{COMMON_EVENT_MAX_BYTES, CommonEventV1};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};

pub const FORMAT: &str = "irmind-kubernetes-sigma-projection-v1";
pub const MAX_DECORATION_BYTES: usize = 2048;
pub const MAX_ENVELOPE_BYTES: usize = COMMON_EVENT_MAX_BYTES + MAX_DECORATION_BYTES;

#[derive(Clone, Copy)]
pub enum AuditExactField {
    SourceIps,
    WrappedSourceIps,
    GkeStatus,
}

impl AuditExactField {
    pub const fn key(self) -> &'static str {
        match self {
            Self::SourceIps => "sourceIPs",
            Self::WrappedSourceIps => "audit_event.sourceIPs",
            Self::GkeStatus => "protoPayload.status.code",
        }
    }

    pub const fn path(self) -> &'static [&'static str] {
        match self {
            Self::SourceIps => &["sourceIPs"],
            Self::WrappedSourceIps => &["audit_event", "sourceIPs"],
            Self::GkeStatus => &["protoPayload", "status", "code"],
        }
    }
}

pub fn encode(
    common: &CommonEventV1,
    fields: &SourceValue,
    field: AuditExactField,
) -> Result<String, InvalidCommonEvent> {
    let (original, unavailable) = match lookup(fields, field.path())
        .and_then(|value| value.map(|value| exact_value(field, value)).transpose())
    {
        Ok(Some(mut value)) => {
            for key in field.path().iter().rev() {
                value = json!({ *key: value });
            }
            (value, json!({}))
        }
        Ok(None) => (json!({}), json!({})),
        Err(reason) => (json!({}), json!({ field.key(): reason })),
    };
    let common = encode_common_event(common)?;
    let row = format!(
        r#"{{"common":{common},"format":"{FORMAT}","original":{original},"unavailable":{unavailable}}}"#
    );
    if row.len() - common.len() > MAX_DECORATION_BYTES || row.len() > MAX_ENVELOPE_BYTES {
        return Err(invalid());
    }
    Ok(row)
}

fn lookup<'a>(
    mut fields: &'a SourceValue,
    path: &[&str],
) -> Result<Option<&'a SourceValue>, &'static str> {
    for key in path {
        let SourceValue::Object(object) = fields else {
            return Err("unexpected_type");
        };
        let Some(value) = object.get(*key) else {
            return Ok(None);
        };
        fields = value;
    }
    Ok(Some(fields))
}

fn exact_value(field: AuditExactField, value: &SourceValue) -> Result<Value, &'static str> {
    if matches!(field, AuditExactField::GkeStatus) {
        let SourceValue::Number(number) = value else {
            return Err("unexpected_type");
        };
        let digits = number.as_str().strip_prefix('-').unwrap_or(number.as_str());
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("unexpected_type");
        }
        let code = number
            .as_str()
            .parse::<u8>()
            .ok()
            .filter(|code| *code <= 16)
            .ok_or("overflow")?;
        return Ok(json!(code));
    }
    let SourceValue::Array(values) = value else {
        return Err("unexpected_type");
    };
    if values.len() > 32 {
        return Err("overflow");
    }
    let mut seen = BTreeSet::new();
    let mut strings = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_text().ok_or("unexpected_type")?;
        if text.len() > 45 {
            return Err("overflow");
        }
        let address: IpAddr = text.parse().map_err(|_| "invalid_ip")?;
        if !seen.insert(address) {
            return Err("duplicate");
        }
        strings.push(text);
    }
    Ok(json!(strings))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::source_mapping::json::{SourceJsonLimits, decode_json_fields};

    #[test]
    fn approved_cluster_audit_vectors_round_trip() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../testkit/fixtures/contracts/sigma_exact_source_fields.json"
        ))
        .unwrap();
        for vector in vectors["retained_text"].as_array().unwrap() {
            let label = vector["case"].as_str().unwrap();
            let common =
                super::super::decode_common_event(&vector["retained"]["common"].to_string())
                    .unwrap();
            let raw = vector["source"].to_string();
            let fields = decode_json_fields(raw.as_bytes(), SourceJsonLimits::default()).unwrap();
            let field = if common.origin().parser() == "parser-gcp-audit" {
                AuditExactField::GkeStatus
            } else if fields.field("audit_event").is_some() {
                AuditExactField::WrappedSourceIps
            } else {
                AuditExactField::SourceIps
            };
            let output = encode(&common, &fields, field).unwrap();
            assert_eq!(
                crate::hex(output.as_bytes()),
                vector["bytes_hex"],
                "{label}"
            );
            if let Some(header) = vector["request"]["X-Forwarded-For"].as_str() {
                assert_eq!(header.split(", ").count(), 33);
                assert!(
                    matches!(fields.field("sourceIPs"), Some(SourceValue::Array(ips)) if ips.len() == 33)
                );
            }
        }
    }
}
