use super::{View, bad};
use irmind_app::source_mapping::{MappingDiagnostic, MappingError, SourceRecordV1};
use irmind_domain::{
    CommonField as F, CommonFieldType, CommonValue, EntityIdentityScope, EntityObservation,
    EntityRole as R, EventContextV1, EventText, ObservedEntity, ObservedEntityKind as K,
};
type Field = (&'static str, F, Option<(K, R)>);
const ZEEK: &[Field] = &[
    ("id.orig_h", F::SourceIp, Some((K::Ip, R::Source))),
    ("id.resp_h", F::DestinationIp, Some((K::Ip, R::Destination))),
    ("id.orig_p", F::SourcePort, None),
    ("id.resp_p", F::DestinationPort, None),
    ("sensor_host", F::HostName, Some((K::Host, R::Observer))),
    ("uid", F::IrmindFlowRef, Some((K::Flow, R::Subject))),
    ("query", F::DnsQuestionName, Some((K::Domain, R::Subject))),
    ("qtype_name", F::DnsQuestionType, None),
    ("qclass_name", F::DnsQuestionClass, None),
    ("rcode_name", F::DnsResponseCode, None),
    ("method", F::HttpRequestMethod, None),
    ("uri", F::UrlOriginal, None),
    ("user_agent", F::UserAgentOriginal, None),
    ("status_code", F::HttpResponseStatusCode, None),
    (
        "server_name",
        F::DestinationDomain,
        Some((K::Domain, R::Destination)),
    ),
    ("filename", F::FileName, Some((K::File, R::Subject))),
    ("note", F::RuleName, Some((K::Rule, R::Subject))),
    ("name", F::RuleName, Some((K::Rule, R::Subject))),
];
const SURICATA: &[Field] = &[
    ("src_ip", F::SourceIp, Some((K::Ip, R::Source))),
    ("dest_ip", F::DestinationIp, Some((K::Ip, R::Destination))),
    ("src_port", F::SourcePort, None),
    ("dest_port", F::DestinationPort, None),
    ("host", F::HostName, Some((K::Host, R::Observer))),
    ("flow_id", F::IrmindFlowRef, Some((K::Flow, R::Subject))),
    ("alert.signature", F::RuleName, Some((K::Rule, R::Subject))),
    ("alert.signature_id", F::RuleId, Some((K::Rule, R::Subject))),
    (
        "dns.rrname",
        F::DnsQuestionName,
        Some((K::Domain, R::Subject)),
    ),
    ("dns.rrtype", F::DnsQuestionType, None),
    ("dns.rcode", F::DnsResponseCode, None),
    (
        "http.hostname",
        F::UrlDomain,
        Some((K::Domain, R::Destination)),
    ),
    ("http.url", F::UrlOriginal, None),
    ("http.http_method", F::HttpRequestMethod, None),
    ("http.http_user_agent", F::UserAgentOriginal, None),
    ("http.status", F::HttpResponseStatusCode, None),
    (
        "tls.sni",
        F::DestinationDomain,
        Some((K::Domain, R::Destination)),
    ),
    (
        "fileinfo.filename",
        F::FilePath,
        Some((K::File, R::Subject)),
    ),
];
fn protocol_field(kind: &str, field: F) -> bool {
    match field {
        F::RuleName | F::RuleId => matches!(kind, "notice" | "weird" | "alert"),
        F::DnsQuestionName | F::DnsQuestionType | F::DnsQuestionClass | F::DnsResponseCode => {
            kind == "dns"
        }
        F::HttpRequestMethod
        | F::HttpResponseStatusCode
        | F::UrlOriginal
        | F::UrlDomain
        | F::UserAgentOriginal => kind == "http",
        F::DestinationDomain => matches!(kind, "ssl" | "tls"),
        F::FileName | F::FilePath => matches!(kind, "files" | "fileinfo"),
        _ => true,
    }
}
pub(super) fn project(
    source: &SourceRecordV1,
    view: &View<'_>,
    zeek: bool,
    kind: &str,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    for &(path, field, observation) in if zeek { ZEEK } else { SURICATA } {
        if !protocol_field(kind, field) {
            continue;
        }
        if (path == "note" && kind != "notice") || (path == "name" && kind != "weird") {
            continue;
        }
        let Some(text) = view.get(path) else {
            continue;
        };
        if let Err(error) = insert(source, text, field, observation, context, observations) {
            if error != MappingError::UnsupportedSourceValue {
                return Err(error);
            }
            if !diagnostics.contains(&MappingDiagnostic::UnsupportedValue) {
                diagnostics.push(MappingDiagnostic::UnsupportedValue);
            }
        }
    }
    if !zeek && kind == "dns" {
        dns_questions(source, view, context, observations, diagnostics)?;
    }
    if zeek
        && kind == "http"
        && let Some(text) = view.get("host")
    {
        insert(
            source,
            text,
            F::UrlDomain,
            Some((K::Domain, R::Destination)),
            context,
            observations,
        )?;
    }
    Ok(())
}
fn insert(
    source: &SourceRecordV1,
    text: &str,
    field: F,
    observation: Option<(K, R)>,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
) -> Result<(), MappingError> {
    let value = match field.value_type() {
        CommonFieldType::Ip => CommonValue::Ip(text.parse().map_err(bad)?),
        CommonFieldType::Port | CommonFieldType::HttpStatus => {
            CommonValue::Unsigned(text.parse().map_err(bad)?)
        }
        _ => CommonValue::Text(EventText::new(text).map_err(bad)?),
    };
    let entity = if let Some((kind, role)) = observation {
        let scope = if matches!(kind, K::Ip | K::Domain) {
            EntityIdentityScope::Global
        } else {
            EntityIdentityScope::SourceRecord {
                source: source.origin().source().clone(),
                record: source.origin().record(),
            }
        };
        let text = match &value {
            CommonValue::Ip(ip) => ip.to_string(),
            _ => text.into(),
        };
        Some(
            EntityObservation::try_new(
                ObservedEntity::try_new(kind, &text, scope).map_err(bad)?,
                role,
                field,
            )
            .map_err(bad)?,
        )
    } else {
        None
    };
    context.try_insert(field, value).map_err(bad)?;
    if let Some(entity) = entity {
        observations.push(entity);
    }
    Ok(())
}

fn dns_questions(
    source: &SourceRecordV1,
    view: &View<'_>,
    context: &mut EventContextV1,
    observations: &mut Vec<EntityObservation>,
    diagnostics: &mut Vec<MappingDiagnostic>,
) -> Result<(), MappingError> {
    if context.get(F::DnsQuestionName).is_some() {
        return Ok(());
    }
    let Some(irmind_app::source_mapping::SourceValue::Array(questions)) = view.raw("dns.queries")
    else {
        return Ok(());
    };
    // The common schema has one question slot. Preserve all other questions in
    // the original projection, with explicit coverage instead of fabricating fields.
    if questions.len() > 1 {
        diagnostics.push(MappingDiagnostic::UnsupportedValue);
    }
    let Some(question) = questions.first() else {
        return Ok(());
    };
    if let Some(name) = question
        .field("rrname")
        .and_then(irmind_app::source_mapping::SourceValue::as_text)
    {
        insert(
            source,
            name,
            F::DnsQuestionName,
            Some((K::Domain, R::Subject)),
            context,
            observations,
        )?;
    }
    if let Some(kind) = question
        .field("rrtype")
        .and_then(irmind_app::source_mapping::SourceValue::as_text)
    {
        insert(
            source,
            kind,
            F::DnsQuestionType,
            None,
            context,
            observations,
        )?;
    }
    Ok(())
}
