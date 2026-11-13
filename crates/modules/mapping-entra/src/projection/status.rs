use super::{MappingDiagnostic, SourceRecordV1, SourceValue, warning};
use irmind_domain::EventOutcome;
pub(super) fn outcome(
    source: &SourceRecordV1,
    format: &str,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> EventOutcome {
    let resource = format.ends_with("resource");
    let signin = format.starts_with("entra-signin");
    let body = if resource {
        source.fields().field("properties")
    } else {
        Some(source.fields())
    };
    let primary = if signin && resource {
        body.and_then(|v| v.field("status"))
            .and_then(|v| v.field("errorCode"))
    } else {
        body.and_then(|v| {
            v.field(if signin {
                "ResultType"
            } else if resource {
                "result"
            } else {
                "Result"
            })
        })
    };
    let secondary = if resource {
        source.fields().field("resultType")
    } else if signin {
        None
    } else {
        source.fields().field("ResultType")
    };
    let enums = !signin
        || resource
        || matches!(
            source.fields().field("Type").and_then(SourceValue::as_text),
            Some("AADServicePrincipalSignInLogs" | "AADManagedIdentitySignInLogs")
        );
    let a = parse(primary, signin, !resource, enums);
    let b = parse(secondary, signin, true, enums);
    match (a, b) {
        (Ok(Some(a)), Ok(Some(b))) if a != b => {
            warning(diagnostics, MappingDiagnostic::UnsupportedValue);
            EventOutcome::Unknown
        }
        (Err(()), _) | (_, Err(())) => {
            warning(diagnostics, MappingDiagnostic::UnsupportedValue);
            EventOutcome::Unknown
        }
        (Ok(Some(a)), _) | (_, Ok(Some(a))) => a,
        _ => EventOutcome::Unknown,
    }
}
fn parse(
    value: Option<&SourceValue>,
    signin: bool,
    text_code: bool,
    enums: bool,
) -> Result<Option<EventOutcome>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    if matches!(value, SourceValue::Null) {
        return Ok(None);
    }
    let text = match value {
        SourceValue::Text(t) if !signin || text_code => t.as_str(),
        SourceValue::Number(n) if signin && !text_code => n.as_str(),
        _ => return Err(()),
    };
    if signin {
        if text.len() <= 10 && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            let code = text.parse::<u32>().map_err(|_| ())?;
            if code > i32::MAX as u32 {
                return Err(());
            }
            return Ok(Some(if code == 0 {
                EventOutcome::Success
            } else {
                EventOutcome::Failure
            }));
        }
        if !enums {
            return Err(());
        }
    }
    match text {
        "success" | "Success" => Ok(Some(EventOutcome::Success)),
        "failure" | "Failure" | "timeout" => Ok(Some(EventOutcome::Failure)),
        "unknownFutureValue" => Ok(None),
        _ => Err(()),
    }
}
