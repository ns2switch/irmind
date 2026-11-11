use super::{AppError, Value};
use irmind_domain::{AuthorizedCall, SiemAggregation, SiemQuery, Tool};
/// Validate the bounded response shape without converting partial provider data into complete results.
pub(super) fn validate(raw: &[u8], call: &AuthorizedCall) -> Result<(), AppError> {
    irmind_app::source_mapping::json::validate_json_value(
        raw,
        irmind_app::source_mapping::json::SourceJsonLimits {
            bytes: irmind_domain::SOURCE_MAX_BYTES,
            nodes: irmind_domain::SOURCE_MAX_NODES,
            fields: irmind_domain::SOURCE_MAX_NODES,
            depth: irmind_domain::SOURCE_MAX_DEPTH,
        },
    )
    .map_err(|_| AppError::RemoteTool)?;
    let response: Value = serde_json::from_slice(raw).map_err(|_| AppError::RemoteTool)?;
    if !response.get("timed_out").is_some_and(Value::is_boolean)
        || response
            .pointer("/_shards/failed")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(AppError::RemoteTool);
    }
    let query = (call.tool() == &Tool::SiemSearch)
        .then(|| SiemQuery::parse(call.proposal_args()))
        .flatten();
    if query
        .as_ref()
        .is_some_and(|q| q.aggregation() != SiemAggregation::Events)
    {
        let buckets = response
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .ok_or(AppError::RemoteTool)?;
        if buckets.len() > usize::from(query.as_ref().ok_or(AppError::RemoteTool)?.limit()) {
            return Err(AppError::RemoteTool);
        }
    } else {
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or(AppError::RemoteTool)?;
        let limit = query.as_ref().map_or(1, SiemQuery::limit);
        if hits.len() > usize::from(limit) {
            return Err(AppError::RemoteTool);
        }
    }
    Ok(())
}
