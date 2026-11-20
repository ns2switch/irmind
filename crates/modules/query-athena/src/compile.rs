use irmind_app::source_queries::{
    CompiledSourceQueryV1, QueryBinding, QueryOperator, QueryResultKind, ResolvedQuerySourceV1,
    SourceQueryError, SourceQueryLimits, SourceQueryModuleV1, SourceQueryV1, canonical_query_json,
    check_query_capabilities,
};
use serde_json::{Value, json};

pub(super) const MODULE: &str = "query-athena";
const DATASET: &str = "cloudtrail-management";
const FIELDS: &[(&str, &str)] = &[
    ("@timestamp", "eventtime"),
    ("event.action", "eventname"),
    ("source.ip", "sourceipaddress"),
    ("cloud.account.id", "recipientaccountid"),
];

pub(super) fn descriptor() -> SourceQueryModuleV1 {
    SourceQueryModuleV1 {
        id: MODULE.into(),
        version: "1".into(),
        datasets: vec![DATASET.into()],
        fields: FIELDS.iter().map(|(field, _)| (*field).into()).collect(),
        operators: vec![QueryOperator::Eq],
        result_kinds: vec![QueryResultKind::Events],
        accounting: irmind_app::source_queries::QueryAccounting::ScanPriced,
        recoverable_submit: true,
        cancellation: true,
        api_version: "2017-05-18".into(),
    }
}

pub fn translate(
    source: &ResolvedQuerySourceV1,
    query: &SourceQueryV1,
    limits: &SourceQueryLimits,
) -> Result<CompiledSourceQueryV1, SourceQueryError> {
    check_query_capabilities(query, source, &descriptor(), limits)?;
    let (database, table) = source
        .table()
        .split_once('.')
        .ok_or(SourceQueryError::Invalid)?;
    if !identifier(database)
        || !identifier(table)
        || source.owner().len() != 12
        || !source.owner().bytes().all(|b| b.is_ascii_digit())
        || !query.from().as_str().ends_with(".000000000Z")
        || !query.to().as_str().ends_with(".000000000Z")
    {
        return Err(SourceQueryError::Unsupported);
    }
    let from = query.from().as_str();
    let to = query.to().as_str();
    let mut bindings = vec![
        binding("from", "timestamp", json!(from)),
        binding("to", "timestamp", json!(to)),
        binding("account", "text", json!(source.owner())),
    ];
    let mut where_parts = vec![
        "from_iso8601_timestamp(eventtime) >= from_iso8601_timestamp(?)".to_owned(),
        "from_iso8601_timestamp(eventtime) < from_iso8601_timestamp(?)".to_owned(),
        "recipientaccountid = ?".to_owned(),
    ];
    for (index, filter) in query.filters().iter().enumerate() {
        let (_, column) = FIELDS
            .iter()
            .find(|(field, _)| *field == filter.field)
            .filter(|(_, column)| *column == "eventname")
            .ok_or(SourceQueryError::Unsupported)?;
        let kind = if filter.field == "source.ip" {
            "ip"
        } else {
            "text"
        };
        where_parts.push(format!("{column} = ?"));
        bindings.push(binding(
            &format!("filter{index}"),
            kind,
            filter.value.clone(),
        ));
    }
    // The adopted partition declaration identifies the physical key. The
    // compiler derives a contiguous interval instead of trusting a model list.
    if source.partitions().is_empty()
        || source
            .partitions()
            .iter()
            .any(|part| part.name != "event_date" || part.kind != "text")
    {
        return Err(SourceQueryError::Unsupported);
    }
    where_parts.push("event_date BETWEEN ? AND ?".into());
    bindings.push(binding("date_from", "text", json!(&from[..10])));
    bindings.push(binding("date_to", "text", json!(&to[..10])));
    let sql = format!(
        "SELECT eventtime,eventname,eventid,recipientaccountid,sourceipaddress,useridentity FROM {database}.{table} WHERE {} ORDER BY eventtime,eventid LIMIT {}",
        where_parts.join(" AND "),
        query.limit()
    );
    let snapshot = json!({
        "text": sql, "bindings": bindings,
        "translator": {
            "id": "athena-cloudtrail",
            "version": "1",
            "sha256": irmind_app::hex(&irmind_app::sha256(b"irmind-athena-cloudtrail-v1"))
        },
        "required_fields": ["eventid", "eventname", "eventtime", "recipientaccountid", "sourceipaddress", "useridentity"],
        "order": ["eventtime", "eventid"]
    });
    CompiledSourceQueryV1::decode(&canonical_query_json(&snapshot)?)
}

fn binding(name: &str, kind: &str, value: Value) -> QueryBinding {
    QueryBinding {
        name: name.into(),
        kind: kind.into(),
        value,
    }
}

pub(super) fn identifier(text: &str) -> bool {
    text.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
