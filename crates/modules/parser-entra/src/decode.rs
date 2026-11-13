use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_envelope_source},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;

pub struct EntraSourceDecoder;
pub(crate) const SOURCE_VERSION: &str = "entra-source-v1";
impl SourceDecoder for EntraSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-entra",
            version: SOURCE_VERSION,
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }
    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        decode_json_envelope_source(input.into_reader(), self.identity(), budget, &prepare, emit)
    }
}

/// Source layout only; event interpretation belongs to the selected mapping.
pub(crate) fn layout(fields: &SourceValue) -> Option<(&'static str, &'static [&'static str])> {
    let table = fields.field("Type").and_then(SourceValue::as_text);
    let category = fields.field("category").and_then(SourceValue::as_text);
    if let Some(category) = category {
        if !matches!(fields.field("properties"), Some(SourceValue::Object(_))) {
            return None;
        }
        return match category {
            "SignInLogs"
            | "NonInteractiveUserSignInLogs"
            | "ServicePrincipalSignInLogs"
            | "ManagedIdentitySignInLogs" => Some((
                "entra-signin-resource",
                &["properties.createdDateTime", "time"],
            )),
            "AuditLogs" => Some((
                "entra-audit-resource",
                &["properties.activityDateTime", "time"],
            )),
            _ => None,
        };
    }
    match table? {
        "SigninLogs"
        | "AADNonInteractiveUserSignInLogs"
        | "AADServicePrincipalSignInLogs"
        | "AADManagedIdentitySignInLogs" => {
            Some(("entra-signin-table", &["CreatedDateTime", "TimeGenerated"]))
        }
        "AuditLogs" => Some(("entra-audit-table", &["ActivityDateTime", "TimeGenerated"])),
        _ => None,
    }
}
fn timestamp(fields: &SourceValue, keys: &[&str]) -> Result<IndexedTime, AppError> {
    for key in keys {
        let value = key
            .split('.')
            .try_fold(fields, |fields, key| fields.field(key));
        if let Some(value) = value {
            return IndexedTime::from_rfc3339(value.as_text().ok_or_else(invalid)?, false)
                .map_err(|_| invalid());
        }
    }
    Err(invalid())
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let (format, time_keys) = layout(&fields).ok_or_else(invalid)?;
    let timestamp = Some(timestamp(&fields, time_keys)?);
    Ok(DecodedSourceFrame {
        fields,
        timestamp,
        format: SourceFormatV1::try_new(format, SOURCE_VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
