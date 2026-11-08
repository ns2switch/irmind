use super::view::LegacyView;
use irmind_app::{
    PartitionProfile,
    source_mapping::{MappingError, MappingPartition, SourceValue as Value},
};

pub(super) fn project(
    value: &Value,
    entities: &[(String, String)],
) -> Result<MappingPartition, MappingError> {
    let account = first(
        value,
        &[
            "/account_id",
            "/recipientAccountId",
            "/userIdentity/accountId",
            "/resource/labels/project_id",
            "/protoPayload/resourceName",
            "/subscriptionId",
        ],
    );
    let region = first(
        value,
        &[
            "/provider",
            "/awsRegion",
            "/resource/labels/location",
            "/region",
            "/location",
        ],
    );
    let region = if region.is_empty()
        && value.get("event_id").is_some()
        && value
            .get("principal")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with("arn:aws:"))
    {
        "aws"
    } else {
        region
    };
    let host = first(
        value,
        &[
            "/host",
            "/hostname",
            "/hostName",
            "/event/host",
            "/Computer",
            "/Host",
            "/host/name",
            "/device/hostname",
            "/attributes/host/name",
            "/attributes/device/hostname",
        ],
    );
    let profile = if [
        "eventSource",
        "recipientAccountId",
        "protoPayload",
        "subscriptionId",
        "account_id",
    ]
    .iter()
    .any(|key| value.get(key).is_some())
    {
        PartitionProfile::CloudAccountRegion
    } else if value.get("host").and_then(Value::as_str).is_some()
        || entities.iter().any(|(kind, _)| kind == "host")
    {
        PartitionProfile::EndpointHost
    } else {
        PartitionProfile::Unpartitioned
    };
    MappingPartition::try_new(profile, account, region, host)
}
fn first<'a>(value: &'a Value, paths: &[&str]) -> &'a str {
    paths
        .iter()
        .find_map(|path| value.pointer(path).and_then(Value::as_str))
        .unwrap_or("")
}
