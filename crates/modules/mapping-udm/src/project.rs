use irmind_app::{
    PartitionProfile,
    source_mapping::{
        MappingDiagnostic, MappingError, MappingOutput, MappingPartition, SourceRecordV1,
        SourceValue,
    },
};
use irmind_domain::{
    BoundedObservations, CategorySet, CommonEventV1, CommonField as F, CommonValue,
    EntityIdentityScope, EntityObservation, EntityRole as R, EventCategory as C, EventContextV1,
    EventHeaderV1, EventKind, EventOutcome, EventType as T, EventTypeSet, ObservedEntity,
    ObservedEntityKind as K,
};
struct Binding {
    path: &'static [&'static str],
    field: F,
    observation: Option<(K, R)>,
}
const FIELDS: &[Binding] = &[
    Binding {
        path: &["principal", "user", "userid"],
        field: F::UserId,
        observation: Some((K::User, R::Actor)),
    },
    Binding {
        path: &["principal", "user", "userDisplayName"],
        field: F::UserName,
        observation: Some((K::User, R::Actor)),
    },
    Binding {
        path: &["target", "user", "userid"],
        field: F::UserTargetId,
        observation: Some((K::User, R::Target)),
    },
    Binding {
        path: &["target", "user", "userDisplayName"],
        field: F::UserTargetName,
        observation: Some((K::User, R::Target)),
    },
    Binding {
        path: &["principal", "ip"],
        field: F::SourceIp,
        observation: Some((K::Ip, R::Source)),
    },
    Binding {
        path: &["principal", "port"],
        field: F::SourcePort,
        observation: None,
    },
    Binding {
        path: &["principal", "process", "pid"],
        field: F::ProcessPid,
        observation: Some((K::Process, R::Subject)),
    },
    Binding {
        path: &["principal", "process", "commandLine"],
        field: F::ProcessCommandLine,
        observation: None,
    },
    Binding {
        path: &["principal", "process", "file", "fullPath"],
        field: F::ProcessExecutable,
        observation: None,
    },
    Binding {
        path: &["target", "file", "fullPath"],
        field: F::FilePath,
        observation: Some((K::File, R::Target)),
    },
    Binding {
        path: &["network", "applicationProtocol"],
        field: F::NetworkProtocol,
        observation: None,
    },
    Binding {
        path: &["network", "http", "method"],
        field: F::HttpRequestMethod,
        observation: None,
    },
    Binding {
        path: &["network", "http", "responseCode"],
        field: F::HttpResponseStatusCode,
        observation: None,
    },
];
fn get<'a>(root: &'a SourceValue, path: &[&str]) -> Option<&'a SourceValue> {
    path.iter().try_fold(root, |v, key| v.field(key))
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
fn classifications(kind: &str) -> (CategorySet, EventTypeSet) {
    let labels = match kind {
        "USER_LOGIN" => Some((C::Authentication, T::Start)),
        "USER_LOGOUT" => Some((C::Authentication, T::End)),
        "PROCESS_LAUNCH" => Some((C::Process, T::Start)),
        "PROCESS_TERMINATION" => Some((C::Process, T::End)),
        "NETWORK_CONNECTION" => Some((C::Network, T::Connection)),
        "NETWORK_DNS" | "NETWORK_HTTP" => Some((C::Network, T::Protocol)),
        "FILE_CREATION" => Some((C::File, T::Creation)),
        "FILE_DELETION" => Some((C::File, T::Deletion)),
        "FILE_MODIFICATION" => Some((C::File, T::Change)),
        "FILE_READ" => Some((C::File, T::Access)),
        "REGISTRY_CREATION" => Some((C::Registry, T::Creation)),
        "REGISTRY_MODIFICATION" => Some((C::Registry, T::Change)),
        "REGISTRY_DELETION" => Some((C::Registry, T::Deletion)),
        _ => None,
    };
    labels.map_or_else(
        || (CategorySet::default(), EventTypeSet::default()),
        |(c, t)| (CategorySet::new([c]), EventTypeSet::new([t])),
    )
}
pub(super) fn map(source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
    let udm = source.fields().field("udm").ok_or_else(invalid)?;
    let metadata = udm.field("metadata").ok_or_else(invalid)?;
    let kind = metadata
        .field("eventType")
        .and_then(SourceValue::as_text)
        .unwrap_or("");
    let header = header(metadata, kind)?;
    let mut context = EventContextV1::default();
    let mut observations = Vec::new();
    let mut diagnostics = vec![];
    if header.categories().bits() == 0 {
        diagnostics.push(MappingDiagnostic::Unclassified);
    }
    for field in FIELDS {
        project(
            source,
            udm,
            field,
            &mut context,
            &mut observations,
            &mut diagnostics,
        )?;
    }
    // Target is a network endpoint only for explicit network event types.
    if matches!(kind, "NETWORK_CONNECTION" | "NETWORK_DNS" | "NETWORK_HTTP") {
        for field in [
            Binding {
                path: &["target", "ip"],
                field: F::DestinationIp,
                observation: Some((K::Ip, R::Destination)),
            },
            Binding {
                path: &["target", "port"],
                field: F::DestinationPort,
                observation: None,
            },
        ] {
            project(
                source,
                udm,
                &field,
                &mut context,
                &mut observations,
                &mut diagnostics,
            )?;
        }
    }
    let common = CommonEventV1::try_new(
        source.origin().clone(),
        source.timestamp(),
        header,
        context,
        BoundedObservations::try_new(observations).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    let indexed = projection(source, &common)?;
    diagnostics.sort_by_key(|value| match value {
        MappingDiagnostic::Unclassified => 0,
        MappingDiagnostic::UnsupportedValue => 1,
        MappingDiagnostic::MissingRequiredValue => 2,
    });
    diagnostics.dedup();
    MappingOutput::try_new(
        source,
        indexed,
        common,
        MappingPartition::try_new(PartitionProfile::Unpartitioned, "", "", "")?,
        diagnostics,
    )
}
fn project(
    source: &SourceRecordV1,
    udm: &SourceValue,
    field: &Binding,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    let Some(value) = get(udm, field.path) else {
        return Ok(());
    };
    let value = match value {
        SourceValue::Null => return Ok(()),
        SourceValue::Array(values) if values.len() == 1 => &values[0],
        SourceValue::Array(_) => {
            diagnostics.push(MappingDiagnostic::UnsupportedValue);
            return Ok(());
        }
        value => value,
    };
    let number;
    let value = if matches!(
        field.field,
        F::ProcessPid | F::SourcePort | F::DestinationPort | F::HttpResponseStatusCode
    ) && let SourceValue::Text(text) = value
    {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let decimal = text.parse::<u64>().map_err(|_| invalid())?.to_string();
        number = SourceValue::Number(
            irmind_app::source_mapping::SourceNumber::try_new(&decimal).map_err(|_| invalid())?,
        );
        &number
    } else {
        value
    };
    let typed = irmind_mapping_tables::copy_common_value(field.field, value)?;
    if let Some((kind, role)) = field.observation {
        let text = match &typed {
            CommonValue::Text(v) => v.as_str().into(),
            CommonValue::Ip(v) => v.to_string(),
            CommonValue::Unsigned(v) => v.to_string(),
            _ => return Err(invalid()),
        };
        let scope = if kind == K::Ip {
            EntityIdentityScope::Global
        } else {
            EntityIdentityScope::SourceRecord {
                source: source.origin().source().clone(),
                record: source.origin().record(),
            }
        };
        observations.push(
            EntityObservation::try_new(
                ObservedEntity::try_new(kind, &text, scope).map_err(|_| invalid())?,
                role,
                field.field,
            )
            .map_err(|_| invalid())?,
        );
    }
    context
        .try_insert(field.field, typed)
        .map_err(|_| invalid())
}

fn projection(
    source: &SourceRecordV1,
    common: &CommonEventV1,
) -> Result<irmind_app::IndexedGraphRecord, MappingError> {
    let mut indexed = MappingOutput::unclassified(source, MappingDiagnostic::Unclassified)?
        .into_record()
        .indexed;
    indexed.record.event = common.event().action().unwrap_or_default().into();
    for observation in common.observations().values() {
        indexed.record.entities.push((
            observation.entity().kind().as_str().into(),
            observation.entity().value().into(),
        ));
    }
    preserve_repeated_ips(source, &mut indexed.record.entities)?;
    indexed.record.entities.sort();
    indexed.record.entities.dedup();
    Ok(indexed)
}

// A scalar typed field cannot represent multiple values. Keep validated original
// IPs queryable without inventing a scalar role or changing the common schema.
fn preserve_repeated_ips(
    source: &SourceRecordV1,
    entities: &mut Vec<(String, String)>,
) -> Result<(), MappingError> {
    let udm = source.fields().field("udm").ok_or_else(invalid)?;
    for noun in ["principal", "target"] {
        if let Some(SourceValue::Array(values)) = get(udm, &[noun, "ip"]) {
            for value in values {
                let value = value.as_text().ok_or_else(invalid)?;
                let address = value.parse::<std::net::IpAddr>().map_err(|_| invalid())?;
                entities.push(("ip".into(), address.to_string()));
            }
        }
    }
    Ok(())
}

fn header(metadata: &SourceValue, kind: &str) -> Result<EventHeaderV1, MappingError> {
    let (categories, types) = classifications(kind);
    let mut header = EventHeaderV1::new(categories, types, EventOutcome::Unknown, EventKind::Event);
    if let Some(action) = metadata
        .field("productEventType")
        .and_then(SourceValue::as_text)
    {
        header = header.with_action(action).map_err(|_| invalid())?;
    }
    if let Some(id) = metadata
        .field("productLogId")
        .and_then(SourceValue::as_text)
    {
        header = header.with_id(id).map_err(|_| invalid())?;
    }
    Ok(header)
}
