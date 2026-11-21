use super::{
    CompiledSourceQueryV1, QueryAccounting, ResolvedQuerySourceV1, SourceQueryError,
    SourceQueryLimits, SourceQueryModuleV1, SourceQueryV1, canonical_query_json, json,
};
use irmind_app::source_queries::{QueryOperator, QueryResultKind, check_query_capabilities};
use irmind_calendar::{DateTime, Duration, FixedOffset};

#[derive(Clone, Copy)]
pub(super) enum TableLayout {
    TimestampPartitioned,
    DateSharded,
}

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
    let (dataset, table, layout) = table_layout(source)?;
    if &query.from().as_str()[26..29] != "000" || &query.to().as_str()[26..29] != "000" {
        return Err(SourceQueryError::Unsupported);
    }
    let mut predicates = vec![
        "timestamp >= @from AND timestamp < @to".to_owned(),
        "resource.labels.project_id = @project".to_owned(),
    ];
    let mut bindings = vec![
        json!({"name":"from","type":"timestamp","value":query.from().as_str()}),
        json!({"name":"to","type":"timestamp","value":query.to().as_str()}),
        json!({"name":"project","type":"text","value":source.owner()}),
    ];
    let table = match layout {
        TableLayout::TimestampPartitioned => table.to_owned(),
        TableLayout::DateSharded => {
            let from = DateTime::<FixedOffset>::parse_from_rfc3339(query.from().as_str())
                .map_err(|_| SourceQueryError::Invalid)?;
            let last = DateTime::<FixedOffset>::parse_from_rfc3339(query.to().as_str())
                .map_err(|_| SourceQueryError::Invalid)?
                .checked_sub_signed(Duration::microseconds(1))
                .ok_or(SourceQueryError::Invalid)?;
            let first_day = from.date_naive().format("%Y%m%d").to_string();
            let last_day = last.date_naive().format("%Y%m%d").to_string();
            if [&first_day, &last_day]
                .iter()
                .any(|date| date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(SourceQueryError::Unsupported);
            }
            predicates.push("_TABLE_SUFFIX BETWEEN @first_day AND @last_day".to_owned());
            bindings.push(json!({"name":"first_day","type":"text","value":first_day}));
            bindings.push(json!({"name":"last_day","type":"text","value":last_day}));
            format!("{table}_*")
        }
    };
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

pub(super) fn table_layout(
    source: &ResolvedQuerySourceV1,
) -> Result<(&str, &str, TableLayout), SourceQueryError> {
    let (dataset, table) = source
        .table()
        .split_once('.')
        .ok_or(SourceQueryError::Invalid)?;
    if !identifier(source.owner(), true)
        || !identifier(dataset, false)
        || !matches!(
            table,
            "cloudaudit_googleapis_com_activity"
                | "cloudaudit_googleapis_com_data_access"
                | "cloudaudit_googleapis_com_system_event"
        )
    {
        return Err(SourceQueryError::Unsupported);
    }
    let [binding] = source.partitions() else {
        return Err(SourceQueryError::Invalid);
    };
    if binding.name != "layout" || binding.kind != "text" {
        return Err(SourceQueryError::Invalid);
    }
    let layout = match binding.value.as_str() {
        Some("timestamp-partitioned") => TableLayout::TimestampPartitioned,
        Some("date-sharded") => TableLayout::DateSharded,
        _ => return Err(SourceQueryError::Unsupported),
    };
    Ok((dataset, table, layout))
}

pub(super) fn identifier(text: &str, hyphen: bool) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || hyphen && byte == b'-')
}
