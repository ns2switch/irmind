use super::AppError;
use irmind_domain::{AuthorizedCall, SiemQuery};
use serde_json::Value;
pub(super) fn validate(raw: &[u8], call: &AuthorizedCall) -> Result<(), AppError> {
    irmind_app::source_mapping::json::validate_json_value(
        raw,
        irmind_app::source_mapping::json::SourceJsonLimits::default(),
    )
    .map_err(|_| AppError::RemoteTool)?;
    let body: Value = serde_json::from_slice(raw).map_err(|_| AppError::RemoteTool)?;
    if !body.is_object() {
        return Err(AppError::RemoteTool);
    }
    let query = SiemQuery::parse(call.proposal_args()).ok_or(AppError::RemoteTool)?;
    if let Some(events) = body.get("events")
        && events
            .as_array()
            .is_none_or(|v| v.len() > usize::from(query.limit()))
    {
        return Err(AppError::RemoteTool);
    }
    if let Some(stats) = body.get("stats") {
        let columns = stats
            .get("results")
            .and_then(Value::as_array)
            .ok_or(AppError::RemoteTool)?;
        if columns.len() > 16
            || columns.iter().any(|column| {
                column
                    .get("values")
                    .and_then(Value::as_array)
                    .is_none_or(|v| v.len() > usize::from(query.limit()))
            })
        {
            return Err(AppError::RemoteTool);
        }
    }
    if body
        .get("moreDataAvailable")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(AppError::RemoteTool);
    }
    Ok(())
}
