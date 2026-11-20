use super::{
    CompiledSourceQueryV1, QueryAccounting, ResolvedQuerySourceV1, SourceQueryError,
    SourceQueryLimits, SourceQueryModuleV1, SourceQueryV1, canonical_query_json, json,
};
use irmind_app::source_queries::{QueryOperator, QueryResultKind, check_query_capabilities};

pub(super) const MODULE: &str = "query-bigquery";
const DATASET: &str = "cloud-audit-logs";

pub(super) fn descriptor() -> SourceQueryModuleV1 {
    SourceQueryModuleV1 {
        id: MODULE.into(),
        version: "1".into(),
        datasets: vec![DATASET.into()],
        fields: vec!["@timestamp".into(), "event.action".into()],
        operators: vec![QueryOperator::Eq],
        result_kinds: vec![QueryResultKind::Events],
        accounting: QueryAccounting::ScanPriced,
        recoverable_submit: true,
        cancellation: true,
        api_version: "v2".into(),
    }
}

pub(super) fn translate(
    source: &ResolvedQuerySourceV1,
    query: &SourceQueryV1,
    limits: &SourceQueryLimits,
) -> Result<CompiledSourceQueryV1, SourceQueryError> {
    check_query_capabilities(query, source, &descriptor(), limits)?;
    let (dataset, table) = source
        .table()
        .split_once('.')
        .ok_or(SourceQueryError::Invalid)?;
    if !identifier(source.owner(), true)
        || !identifier(dataset, false)
        || !identifier(table, false)
        || !source
            .partitions()
            .iter()
            .any(|part| part.name == "partition_date")
        || !query.from().as_str()[26..29].eq("000")
        || !query.to().as_str()[26..29].eq("000")
    {
        return Err(SourceQueryError::Unsupported);
    }
    let mut predicates = vec![
        "timestamp >= @from AND timestamp < @to".to_owned(),
        "_PARTITIONDATE BETWEEN DATE(@from) AND DATE(TIMESTAMP_SUB(@to, INTERVAL 1 MICROSECOND))"
            .to_owned(),
        "resource.labels.project_id = @project".to_owned(),
    ];
    let mut bindings = vec![
        json!({"name":"from","type":"timestamp","value":query.from().as_str()}),
        json!({"name":"to","type":"timestamp","value":query.to().as_str()}),
        json!({"name":"project","type":"text","value":source.owner()}),
    ];
    for (index, filter) in query.filters().iter().enumerate() {
        if filter.field != "event.action" {
            return Err(SourceQueryError::Unsupported);
        }
        let parameter = format!("filter{index}");
        predicates.push(format!("protopayload_auditlog.methodName = @{parameter}"));
        bindings.push(json!({"name":parameter,"type":"text","value":filter.value}));
    }
    let sql = format!(
        "SELECT timestamp,insertId,resource,protopayload_auditlog FROM `{}.{dataset}.{table}` WHERE {} ORDER BY timestamp,insertId LIMIT {}",
        source.owner(),
        predicates.join(" AND "),
        query.limit(),
    );
    let wire = json!({
        "text":sql, "bindings":bindings,
        "order":["timestamp","insertId"],
        "required_fields":["insertId","protopayload_auditlog","resource","timestamp"],
        "translator":{"id":"bigquery-cloud-audit","version":"1","sha256":irmind_app::hex(&irmind_app::sha256(b"irmind-bigquery-cloud-audit-v1"))}
    });
    CompiledSourceQueryV1::decode(&canonical_query_json(&wire)?)
}

pub(super) fn identifier(text: &str, hyphen: bool) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || hyphen && byte == b'-')
}
