use super::{
    AppError, DecodedSourceFrame, IndexedTime, SourceFormatV1, SourceFrameEmitter, SourceRecordV1,
    SourceValue, Tainted, invalid,
};
use irmind_domain::{IndexedInstant, SourceDiscriminator, TimePrecision};
use std::collections::BTreeMap;
const VNET: &[&str] = &[
    "timestamp",
    "sourceIP",
    "destinationIP",
    "sourcePort",
    "destinationPort",
    "protocol",
    "flowDirection",
    "flowState",
    "flowEncryption",
    "packetsSent",
    "bytesSent",
    "packetsReceived",
    "bytesReceived",
    "plsLinkIdentifier",
    "sourceNatIP",
    "sourceNatPort",
];
const NSG: &[&str] = &[
    "timestamp",
    "sourceIP",
    "destinationIP",
    "sourcePort",
    "destinationPort",
    "protocol",
    "flowDirection",
    "trafficDecision",
    "flowState",
    "packetsSent",
    "bytesSent",
    "packetsReceived",
    "bytesReceived",
];
fn array(value: Option<&SourceValue>) -> &[SourceValue] {
    match value {
        Some(SourceValue::Array(values)) => values,
        _ => &[],
    }
}
fn version(value: Option<&SourceValue>) -> Option<u16> {
    match value {
        Some(SourceValue::Number(n)) => n.as_str().parse().ok(),
        _ => None,
    }
}
pub(super) fn expand(
    source: &SourceRecordV1,
    output: &mut SourceFrameEmitter<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let fields = source.fields();
    let vnet = fields.field("category").and_then(SourceValue::as_text) == Some("FlowLogFlowEvent");
    let properties = fields.field("properties");
    let version = if vnet {
        version(fields.field("flowLogVersion"))
    } else {
        version(properties.and_then(|v| v.field("Version")))
    };
    if !matches!(
        (vnet, version),
        (true, Some(2 | 4 | 5)) | (false, Some(1 | 2))
    ) {
        return output.frame(
            b"unknown Azure flow version",
            source.origin().offset(),
            unknown(source, vnet),
            emit,
        );
    }
    let flows = if vnet {
        fields.field("flowRecords").and_then(|v| v.field("flows"))
    } else {
        properties.and_then(|v| v.field("flows"))
    };
    let mut found = false;
    for flow in array(flows) {
        for group in array(flow.field(if vnet { "flowGroups" } else { "flows" })) {
            for raw in array(group.field("flowTuples")) {
                found = true;
                let raw = raw.as_text();
                let bytes = raw.map_or(b"non-text flow tuple".as_slice(), str::as_bytes);
                let prepared = raw.ok_or_else(invalid).and_then(|tuple| {
                    prepare(
                        source,
                        vnet,
                        version.unwrap_or_default(),
                        flow,
                        group,
                        tuple,
                    )
                });
                // Nested tuple byte positions are not claimed: the JSON container can escape strings.
                output.frame(bytes, None, prepared, emit)?;
            }
        }
    }
    if !found {
        return output.frame(
            b"empty or unknown Azure flow payload",
            source.origin().offset(),
            unknown(source, vnet),
            emit,
        );
    }
    Ok(())
}
fn unknown(source: &SourceRecordV1, vnet: bool) -> Result<DecodedSourceFrame, AppError> {
    Ok(DecodedSourceFrame {
        fields: source.fields().clone(),
        timestamp: source.timestamp(),
        format: format(vnet)?,
    })
}
fn format(vnet: bool) -> Result<SourceFormatV1, AppError> {
    SourceFormatV1::try_new(
        if vnet {
            "azure-vnet-flow"
        } else {
            "azure-nsg-flow"
        },
        "azure-flow-source-v1",
        BTreeMap::new(),
    )
    .map_err(|_| invalid())
}
fn prepare(
    source: &SourceRecordV1,
    vnet: bool,
    version: u16,
    flow: &SourceValue,
    group: &SourceValue,
    tuple: &str,
) -> Result<DecodedSourceFrame, AppError> {
    let values: Vec<_> = tuple.split(',').collect();
    let names = if vnet { VNET } else { NSG };
    let count = if vnet {
        if version == 5 { 16 } else { 13 }
    } else if version == 1 {
        8
    } else {
        13
    };
    if values.len() != count {
        return Err(invalid());
    }
    let columns = SourceValue::object(
        names
            .iter()
            .take(count)
            .zip(&values)
            .map(|(name, value)| ((*name).to_owned(), SourceValue::Text((*value).to_owned())))
            .collect(),
    )
    .map_err(|_| invalid())?;
    let timestamp = if vnet {
        let millis = values[0].parse::<i64>().map_err(|_| invalid())?;
        IndexedTime::new(
            IndexedInstant::new(millis.checked_mul(1000).ok_or_else(invalid)?, 0)
                .map_err(|_| invalid())?,
            TimePrecision::Millisecond,
            false,
        )
        .map_err(|_| invalid())?
    } else {
        IndexedTime::from_epoch_decimal(values[0], false).map_err(|_| invalid())?
    };
    let fields = original_fields(source, vnet, version, flow, group, tuple, columns)?;
    let mut format = format(vnet)?;
    let mut discriminators = format.discriminators().clone();
    discriminators.insert(SourceDiscriminator::RecordType, version.to_string());
    format = SourceFormatV1::try_new(format.id(), format.version(), discriminators)
        .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields: SourceValue::object(fields).map_err(|_| invalid())?,
        timestamp: Some(timestamp),
        format,
    })
}

fn without(value: &SourceValue, excluded: &[&str]) -> Result<SourceValue, AppError> {
    let SourceValue::Object(fields) = value else {
        return Err(invalid());
    };
    SourceValue::object(
        fields
            .iter()
            .filter(|(key, _)| !excluded.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
    .map_err(|_| invalid())
}
fn original_fields(
    source: &SourceRecordV1,
    vnet: bool,
    version: u16,
    flow: &SourceValue,
    group: &SourceValue,
    tuple: &str,
    columns: SourceValue,
) -> Result<Vec<(String, SourceValue)>, AppError> {
    let metadata = without(source.fields(), &["flowRecords", "properties"])?;
    let mac = if vnet {
        source.fields().field("macAddress")
    } else {
        group.field("mac")
    }
    .cloned()
    .unwrap_or(SourceValue::Null);
    let rule = if vnet {
        group.field("rule")
    } else {
        flow.field("rule")
    }
    .cloned()
    .unwrap_or(SourceValue::Null);
    let mut fields = vec![
        ("record".into(), metadata),
        ("flowTuple".into(), SourceValue::Text(tuple.into())),
        ("columns".into(), columns),
        ("mac".into(), mac),
        ("rule".into(), rule),
        (
            "version".into(),
            SourceValue::Number(
                irmind_domain::SourceNumber::try_new(&version.to_string())
                    .map_err(|_| invalid())?,
            ),
        ),
        (
            "flow".into(),
            without(flow, &[if vnet { "flowGroups" } else { "flows" }])?,
        ),
        ("group".into(), without(group, &["flowTuples"])?),
    ];
    if let Some(properties) = source.fields().field("properties") {
        fields.push(("properties".into(), without(properties, &["flows"])?));
    }
    Ok(fields)
}
