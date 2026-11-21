use super::{
    CompiledSourceQueryV1, QueryAccounting, ResolvedQuerySourceV1, SourceQueryError,
    SourceQueryLimits, SourceQueryModuleV1, SourceQueryV1, canonical_query_json, json,
};
use irmind_app::source_queries::{QueryResultKind, check_query_capabilities};

pub(super) const MODULE: &str = "query-azure-log-analytics";
pub(super) const TABLES: &[(&str, &str)] = &[
    ("entra-signins", "SigninLogs"),
    (
        "entra-noninteractive-signins",
        "AADNonInteractiveUserSignInLogs",
    ),
    ("entra-audit", "AuditLogs"),
    ("azure-activity", "AzureActivity"),
];

pub(super) fn descriptor() -> SourceQueryModuleV1 {
    SourceQueryModuleV1 {
        id: MODULE.into(),
        version: "1".into(),
        datasets: TABLES
            .iter()
            .map(|(dataset, _)| (*dataset).into())
            .collect(),
        fields: vec!["@timestamp".into()],
        operators: vec![],
        result_kinds: vec![QueryResultKind::Events],
        accounting: QueryAccounting::AnalyticsNoQueryCharge,
        recoverable_submit: false,
        cancellation: false,
        api_version: "v1".into(),
    }
}

pub(super) fn translate(
    source: &ResolvedQuerySourceV1,
    query: &SourceQueryV1,
    limits: &SourceQueryLimits,
) -> Result<CompiledSourceQueryV1, SourceQueryError> {
    check_query_capabilities(query, source, &descriptor(), limits)?;
    let table = TABLES
        .iter()
        .find_map(|(dataset, table)| {
            (*dataset == source.dataset() && *table == source.table()).then_some(*table)
        })
        .ok_or(SourceQueryError::Unsupported)?;
    let nanos_from = query.from().as_str();
    let nanos_to = query.to().as_str();
    if nanos_from.as_bytes()[27..29] != *b"00" || nanos_to.as_bytes()[27..29] != *b"00" {
        return Err(SourceQueryError::Unsupported);
    }
    let text = format!(
        "{table} | where TimeGenerated >= datetime({nanos_from}) and TimeGenerated < datetime({nanos_to}) | order by TimeGenerated asc | take {}",
        query.limit()
    );
    let wire = json!({"text":text,"bindings":[
        {"name":"from","type":"timestamp","value":nanos_from},
        {"name":"to","type":"timestamp","value":nanos_to}
    ],"required_fields":["TimeGenerated"],"order":["TimeGenerated"],
    "translator":{"id":"azure-analytics","version":"1","sha256":irmind_app::hex(&irmind_app::sha256(b"irmind-azure-analytics-v1"))}});
    CompiledSourceQueryV1::decode(&canonical_query_json(&wire)?)
}
