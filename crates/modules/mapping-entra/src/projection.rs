mod fields;
mod status;
use irmind_app::source_mapping::{MappingDiagnostic, MappingError, SourceRecordV1, SourceValue};
use irmind_domain::{
    BoundedObservations, CommonEventV1, CommonField as F, CommonValue, EntityIdentityScope,
    EntityObservation, EntityRole, EventContextV1, EventHeaderV1, EventText, ObservedEntity,
    ObservedEntityKind,
};
use irmind_mapping_tables::TableMapping;
use std::borrow::Cow;

pub(super) fn project(
    source: &SourceRecordV1,
    format: &str,
    base: &CommonEventV1,
    table: Option<&TableMapping>,
) -> Result<(CommonEventV1, Vec<MappingDiagnostic>), MappingError> {
    let mut context = base.context().clone();
    let mut observations = base.observations().values().to_vec();
    let mut diagnostics = Vec::new();
    let mut header = base.event().clone();
    if let Some(table) = table {
        let explicit = table.event_header(source)?;
        if explicit.categories().bits() != 0 {
            header = explicit;
        }
    }
    let outcome = status::outcome(source, format, &mut diagnostics);
    header = EventHeaderV1::new(header.categories(), header.types(), outcome, header.kind());
    if let Some(action) = base.event().action() {
        header = header.with_action(action).map_err(bad)?;
    }
    context
        .try_insert(
            F::CloudProvider,
            CommonValue::Text(EventText::new("azure").map_err(bad)?),
        )
        .map_err(bad)?;
    fields::project(
        source,
        format,
        &mut context,
        &mut observations,
        &mut diagnostics,
    )?;
    let common = CommonEventV1::try_new(
        source.origin().clone(),
        source.timestamp(),
        header,
        context,
        BoundedObservations::try_new(observations).map_err(bad)?,
    )
    .map_err(bad)?;
    Ok((common, diagnostics))
}
fn body<'a>(source: &'a SourceRecordV1, format: &str) -> Result<&'a SourceValue, MappingError> {
    if format.ends_with("resource") {
        source.fields().field("properties").ok_or_else(|| bad(()))
    } else {
        Ok(source.fields())
    }
}
fn scope(source: &SourceRecordV1, context: &EventContextV1) -> EntityIdentityScope {
    if let Some(CommonValue::Text(tenant)) = context.get(F::CloudAccountId) {
        EntityIdentityScope::Account(tenant.clone())
    } else {
        EntityIdentityScope::SourceRecord {
            source: source.origin().source().clone(),
            record: source.origin().record(),
        }
    }
}
fn insert(
    source: &SourceRecordV1,
    value: &str,
    field: F,
    entity: Option<(ObservedEntityKind, EntityRole)>,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
) -> Result<(), MappingError> {
    if value.is_empty() || context.get(field).is_some() {
        return Ok(());
    }
    let common = if field == F::SourceIp {
        CommonValue::Ip(value.parse().map_err(bad)?)
    } else {
        CommonValue::Text(EventText::new(value).map_err(bad)?)
    };
    let observation = if let Some((kind, role)) = entity {
        let scope = if kind == ObservedEntityKind::Ip {
            EntityIdentityScope::Global
        } else {
            scope(source, context)
        };
        let value = if let CommonValue::Ip(ip) = &common {
            ip.to_string()
        } else {
            value.into()
        };
        Some(
            EntityObservation::try_new(
                ObservedEntity::try_new(kind, &value, scope).map_err(bad)?,
                role,
                field,
            )
            .map_err(bad)?,
        )
    } else {
        None
    };
    context.try_insert(field, common).map_err(bad)?;
    if let Some(observation) = observation {
        observations.push(observation);
    }
    Ok(())
}
fn dynamic(value: &SourceValue) -> Result<Cow<'_, SourceValue>, MappingError> {
    if let SourceValue::Text(text) = value {
        if text.len() > 65536 {
            return Err(bad(()));
        }
        irmind_app::source_mapping::json::decode_json_value(
            text.as_bytes(),
            irmind_app::source_mapping::json::SourceJsonLimits {
                bytes: 65536,
                nodes: 4096,
                fields: 1024,
                depth: 32,
            },
        )
        .map(Cow::Owned)
        .map_err(bad)
    } else {
        Ok(Cow::Borrowed(value))
    }
}
fn warning(diagnostics: &mut Vec<MappingDiagnostic>, diagnostic: MappingDiagnostic) {
    if !diagnostics.contains(&diagnostic) {
        diagnostics.push(diagnostic);
    }
}
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}
