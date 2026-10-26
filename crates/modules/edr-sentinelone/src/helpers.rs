use crate::{AppError, AuthorizedCall, DateTime, Value};

pub(super) fn data_array(value: &Value) -> Result<&Vec<Value>, AppError> {
    value["data"].as_array().ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::SentinelOneResponseHasNoDataArray,
        ))
    })
}
pub(super) fn select_agent(response: &Value, host: &str, site_id: &str) -> Result<Value, AppError> {
    let data = data_array(response)?;
    if data.len() != 1
        || !data[0]["computerName"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(host))
        || data[0]["siteId"].as_str() != Some(site_id)
    {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::SentinelOneHostIsMissingOrAmbiguous,
        )));
    }
    Ok(data[0].clone())
}
pub(super) fn validate_threats(
    response: &Value,
    id: &str,
    site_id: &str,
    from: &str,
    to: &str,
) -> Result<(), AppError> {
    for threat in data_array(response)? {
        if threat["agentRealtimeInfo"]["agentId"].as_str() != Some(id)
            || threat["agentRealtimeInfo"]["siteId"].as_str() != Some(site_id)
            || !within(threat["threatInfo"]["createdAt"].as_str(), from, to)
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                irmind_app::AdapterPolicyError::SentinelOneReturnedAThreatOutsideTheHostOrWindow,
            )));
        }
    }
    Ok(())
}
pub(super) fn encode(value: &Value) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(value).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
            irmind_app::AdapterStorageError::CannotEncodeSentinelOneEvidence,
        ))
    })
}
pub(super) fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}
pub(super) fn digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|b| b.is_ascii_digit())
}
pub(super) fn safe_host(value: &str) -> bool {
    safe_id(value) && value.len() <= 253
}
pub(super) fn window(call: &AuthorizedCall) -> Result<(&str, &str), AppError> {
    let from = call.arg("from").ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::MissingStartTime,
        ))
    })?;
    let to = call.arg("to").ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::MissingEndTime,
        ))
    })?;
    let start = DateTime::parse_from_rfc3339(from).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidStartTime,
        ))
    })?;
    let end = DateTime::parse_from_rfc3339(to).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::InvalidEndTime,
        ))
    })?;
    if !(1..=86_400).contains(&end.signed_duration_since(start).num_seconds()) {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::SentinelOneDetectionWindowMustBeAtMost24Hours,
        )));
    }
    Ok((from, to))
}
pub(super) fn within(value: Option<&str>, from: &str, to: &str) -> bool {
    let Some(value) = value else { return false };
    let (Ok(value), Ok(from), Ok(to)) = (
        DateTime::parse_from_rfc3339(value),
        DateTime::parse_from_rfc3339(from),
        DateTime::parse_from_rfc3339(to),
    ) else {
        return false;
    };
    value >= from && value <= to
}
