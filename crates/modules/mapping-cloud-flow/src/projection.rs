//! Original provider metadata supplies partitions. Missing identities stay missing.
use super::{MappingError, MappingPartition, SourceKind, SourceRecordV1, SourceValue, bad};
use irmind_domain::{CommonField as F, CommonValue, EventContextV1, EventText};
use irmind_mapping_contracts::PartitionProfile;
fn text(value: Option<&SourceValue>) -> &str {
    value
        .and_then(SourceValue::as_text)
        .filter(|v| !matches!(*v, "" | "-"))
        .unwrap_or_default()
}
fn at<'a>(value: &'a SourceValue, path: &[&str]) -> Option<&'a SourceValue> {
    path.iter().try_fold(value, |v, key| v.field(key))
}
fn count(value: Option<&SourceValue>) -> Option<u64> {
    match value {
        Some(SourceValue::Number(v)) => v.as_str().parse().ok(),
        Some(SourceValue::Text(v)) => v.parse().ok(),
        _ => None,
    }
}
pub(super) fn project(
    source: &SourceRecordV1,
    kind: SourceKind,
    context: &mut EventContextV1,
    observations: &mut Vec<irmind_domain::EntityObservation>,
) -> Result<MappingPartition, MappingError> {
    let fields = source.fields();
    let (account, region, host, provider) = match kind {
        SourceKind::Aws => (
            text(at(fields, &["columns", "account-id"])),
            text(at(fields, &["columns", "region"])),
            text(at(fields, &["columns", "instance-id"])),
            "aws",
        ),
        SourceKind::Gcp => gcp(source, context, observations)?,
        SourceKind::AzureVnet | SourceKind::AzureNsg => azure(source, kind, context)?,
    };
    context
        .try_insert(
            F::CloudProvider,
            CommonValue::Text(EventText::new(provider).map_err(bad)?),
        )
        .map_err(bad)?;
    MappingPartition::try_new(
        if host.is_empty() {
            PartitionProfile::CloudAccountRegion
        } else {
            PartitionProfile::EndpointHost
        },
        account,
        region,
        host,
    )
}

type Scope<'a> = (&'a str, &'a str, &'a str, &'static str);
fn gcp<'a>(
    source: &'a SourceRecordV1,
    context: &mut EventContextV1,
    observations: &mut Vec<irmind_domain::EntityObservation>,
) -> Result<Scope<'a>, MappingError> {
    let fields = source.fields();
    let payload = fields
        .field("jsonPayload")
        .ok_or(MappingError::UnsupportedSourceValue)?;
    let instance = match text(payload.field("reporter")) {
        "SRC" => payload.field("src_instance"),
        "DEST" => payload.field("dest_instance"),
        _ => None,
    };
    let host = text(instance.and_then(|v| v.field("vm_name")));
    if !host.is_empty() {
        context
            .try_insert(
                F::HostName,
                CommonValue::Text(EventText::new(host).map_err(bad)?),
            )
            .map_err(bad)?;
        let scope = irmind_domain::EntityIdentityScope::SourceRecord {
            source: source.origin().source().clone(),
            record: source.origin().record(),
        };
        let entity = irmind_domain::ObservedEntity::try_new(
            irmind_domain::ObservedEntityKind::Host,
            host,
            scope,
        )
        .map_err(bad)?;
        observations.push(
            irmind_domain::EntityObservation::try_new(
                entity,
                irmind_domain::EntityRole::Observer,
                F::HostName,
            )
            .map_err(bad)?,
        );
    }

    for (key, target) in [
        ("bytes_sent", F::NetworkBytes),
        ("packets_sent", F::NetworkPackets),
    ] {
        if let Some(value) = count(payload.field(key)) {
            context
                .try_insert(target, CommonValue::Unsigned(value))
                .map_err(bad)?;
        }
    }
    Ok((
        text(at(fields, &["resource", "labels", "project_id"])),
        text(at(fields, &["resource", "labels", "location"])),
        host,
        "gcp",
    ))
}
fn azure<'a>(
    source: &'a SourceRecordV1,
    kind: SourceKind,
    context: &mut EventContextV1,
) -> Result<Scope<'a>, MappingError> {
    let fields = source.fields();
    let resource = text(at(
        fields,
        &[
            "record",
            if matches!(kind, SourceKind::AzureVnet) {
                "flowLogResourceID"
            } else {
                "resourceId"
            },
        ],
    ));
    let mut segments = resource.split('/').filter(|v| !v.is_empty());
    let account = if segments
        .next()
        .is_some_and(|v| v.eq_ignore_ascii_case("subscriptions"))
    {
        segments.next().unwrap_or_default()
    } else {
        ""
    };
    let columns = fields.field("columns");
    for (sent, received, target) in [
        ("bytesSent", "bytesReceived", F::NetworkBytes),
        ("packetsSent", "packetsReceived", F::NetworkPackets),
    ] {
        if let Some(total) = columns
            .and_then(|c| count(c.field(sent)).zip(count(c.field(received))))
            .and_then(|(a, b)| a.checked_add(b))
        {
            context
                .try_insert(target, CommonValue::Unsigned(total))
                .map_err(bad)?;
        }
    }
    if !account.is_empty() {
        context
            .try_insert(
                F::CloudAccountId,
                CommonValue::Text(EventText::new(account).map_err(bad)?),
            )
            .map_err(bad)?;
    }
    Ok((account, "", "", "azure"))
}
