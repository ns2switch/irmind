use super::{
    MappingDiagnostic, MappingError, SourceRecordV1, SourceValue, body, dynamic, insert, warning,
};
use irmind_domain::{
    CommonField as F, EntityObservation, EntityRole as R, EventContextV1, ObservedEntityKind as K,
};
pub(super) fn project(
    source: &SourceRecordV1,
    format: &str,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    let table = format.ends_with("table");
    let signin = format.starts_with("entra-signin");
    let fields = body(source, format)?;
    if context.get(F::CloudAccountId).is_none() {
        warning(diagnostics, MappingDiagnostic::MissingRequiredValue);
    }
    if signin {
        signin_fields(source, fields, table, context, observations)?;
    } else {
        audit_actor(source, fields, table, context, observations)?;
        targets(source, fields, table, context, observations, diagnostics)?;
    }
    Ok(())
}
fn text<'a>(fields: &'a SourceValue, pascal: &str, camel: &str, table: bool) -> Option<&'a str> {
    fields
        .field(if table { pascal } else { camel })
        .and_then(SourceValue::as_text)
        .filter(|v| !v.is_empty())
}
fn signin_fields(
    source: &SourceRecordV1,
    fields: &SourceValue,
    table: bool,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
) -> Result<(), MappingError> {
    let has_user = context.get(F::UserId).is_some() || context.get(F::UserName).is_some();
    let attributes = if has_user {
        &[][..]
    } else if text(fields, "UserId", "userId", table).is_some()
        || text(fields, "UserPrincipalName", "userPrincipalName", table).is_some()
    {
        &[
            ("UserId", "userId", F::UserId),
            ("UserPrincipalName", "userPrincipalName", F::UserName),
        ][..]
    } else {
        &[
            ("ServicePrincipalId", "servicePrincipalId", F::UserId),
            ("ServicePrincipalName", "servicePrincipalName", F::UserName),
        ][..]
    };
    for &(pascal, camel, field) in attributes {
        if let Some(value) = text(fields, pascal, camel, table) {
            insert(
                source,
                value,
                field,
                Some((K::User, R::Actor)),
                context,
                observations,
            )?;
        }
    }
    if let Some(value) = text(fields, "AppId", "appId", table) {
        insert(
            source,
            value,
            F::IrmindResourceId,
            Some((K::Resource, R::Subject)),
            context,
            observations,
        )?;
    }
    Ok(())
}
fn audit_actor(
    source: &SourceRecordV1,
    fields: &SourceValue,
    table: bool,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
) -> Result<(), MappingError> {
    let Some(raw) = fields.field(if table { "InitiatedBy" } else { "initiatedBy" }) else {
        return Ok(());
    };
    let initiator = dynamic(raw)?;
    let user = initiator.field("user");
    let has_user = user.is_some_and(|u| {
        ["id", "userPrincipalName"].iter().any(|p| {
            u.field(p)
                .and_then(SourceValue::as_text)
                .is_some_and(|s| !s.is_empty())
        })
    });
    let principal = if has_user {
        user
    } else {
        initiator.field("app")
    };
    let Some(principal) = principal else {
        return Ok(());
    };
    if context.get(F::UserId).is_none() && context.get(F::UserName).is_none() {
        let keys = if has_user {
            [("id", F::UserId), ("userPrincipalName", F::UserName)]
        } else {
            [
                ("servicePrincipalId", F::UserId),
                ("displayName", F::UserName),
            ]
        };
        for (key, field) in keys {
            if let Some(value) = principal.field(key).and_then(SourceValue::as_text) {
                insert(
                    source,
                    value,
                    field,
                    Some((K::User, R::Actor)),
                    context,
                    observations,
                )?;
            }
        }
        if !has_user
            && context.get(F::UserId).is_none()
            && let Some(value) = principal.field("appId").and_then(SourceValue::as_text)
        {
            insert(
                source,
                value,
                F::UserId,
                Some((K::User, R::Actor)),
                context,
                observations,
            )?;
        }
    }
    if let Some(value) = principal.field("ipAddress").and_then(SourceValue::as_text) {
        insert(
            source,
            value,
            F::SourceIp,
            Some((K::Ip, R::Source)),
            context,
            observations,
        )?;
    }
    Ok(())
}
fn targets(
    source: &SourceRecordV1,
    fields: &SourceValue,
    table: bool,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    let Some(raw) = fields.field(if table {
        "TargetResources"
    } else {
        "targetResources"
    }) else {
        return Ok(());
    };
    let targets = dynamic(raw)?;
    let SourceValue::Array(values) = targets.as_ref() else {
        warning(diagnostics, MappingDiagnostic::UnsupportedValue);
        return Ok(());
    };
    if values.len() > 16 {
        warning(diagnostics, MappingDiagnostic::UnsupportedValue);
    }
    for target in values.iter().take(16) {
        let kind = target
            .field("type")
            .and_then(SourceValue::as_text)
            .unwrap_or("");
        let (field, entity) = match kind {
            "User" => (F::UserTargetId, K::User),
            "Role" | "RoleTemplate" => (F::IrmindIamRoleId, K::IamRole),
            _ => (F::IrmindResourceId, K::Resource),
        };
        if let Some(value) = target.field("id").and_then(SourceValue::as_text) {
            target_field(
                source,
                value,
                field,
                entity,
                context,
                observations,
                diagnostics,
            )?;
        }
        if kind == "User"
            && let Some(value) = target
                .field("userPrincipalName")
                .and_then(SourceValue::as_text)
        {
            target_field(
                source,
                value,
                F::UserTargetName,
                K::User,
                context,
                observations,
                diagnostics,
            )?;
        }
    }
    Ok(())
}
fn target_field(
    source: &SourceRecordV1,
    value: &str,
    field: F,
    entity: K,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    if let Some(irmind_domain::CommonValue::Text(previous)) = context.get(field)
        && previous.as_str() != value
    {
        warning(diagnostics, MappingDiagnostic::UnsupportedValue);
        return Ok(());
    }
    insert(
        source,
        value,
        field,
        Some((entity, R::Target)),
        context,
        observations,
    )
}
