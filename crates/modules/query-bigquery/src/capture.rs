//! Decode the retained `BigQuery` REST row encoding without floating-point timestamps.
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::SourceInput,
    source_queries::{SourceQueryError, read_query_capture_pages},
};
use irmind_domain::{
    DecodeAnnotationsV1, EventOrigin, EvidenceHash, IndexedInstant, IndexedTime, Provenance,
    SOURCE_MAX_DEPTH, SOURCE_MAX_NODES, SourceFormatV1, SourceKind, SourceNumber, SourceRecordV1,
    SourceValue, Tainted, TimePrecision,
};
use serde_json::Value;
use std::{collections::BTreeMap, io::BufReader};

const COLUMNS: [(&str, &str); 4] = [
    ("timestamp", "TIMESTAMP"),
    ("insertId", "STRING"),
    ("resource", "RECORD"),
    ("protopayload_auditlog", "RECORD"),
];

/// Decodes the raw `jobs.getQueryResults` pages in a retained acquisition.
pub struct BigQueryCaptureDecoder;

impl SourceDecoder for BigQueryCaptureDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "query-bigquery-cloud-audit",
            version: "1",
        }
    }

    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let meta = input.metadata;
        if meta.source.kind() != SourceKind::ToolResult || meta.source.acquisition().is_none() {
            return Err(SourceQueryError::Scope.into());
        }
        let id = self.identity();
        let hash = EvidenceHash::from_bytes(meta.evidence_hash);
        let format = SourceFormatV1::try_new("bigquery-cloud-audit", "1", BTreeMap::new())
            .map_err(|_| SourceQueryError::Invalid)?;
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: vec![],
        };
        let mut ordinal = 0;
        let mut schema = None;
        let summary = read_query_capture_pages(input.reader, meta.cancel, |page, reader| {
            if page.body_bytes > super::protocol::PAGE_LIMIT as u64 {
                return Err(SourceQueryError::Limit.into());
            }
            let wire: Value = serde_json::from_reader(BufReader::new(reader))
                .map_err(|_| SourceQueryError::Invalid)?;
            let rows = checked_rows(&wire, &mut schema)?;
            if rows.len() as u64 != page.rows
                || page.columns.len() != COLUMNS.len()
                || page
                    .columns
                    .iter()
                    .zip(COLUMNS)
                    .any(|(signed, (name, kind))| signed.name != name || signed.native_type != kind)
            {
                return Err(SourceQueryError::Invalid.into());
            }
            let fields = schema.as_deref().ok_or(SourceQueryError::Invalid)?;
            for row in rows {
                if meta.cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let origin = EventOrigin::try_new(hash.clone(), ordinal, None, id.name, id.version)
                    .map_err(|_| SourceQueryError::Invalid)?;
                ordinal += 1;
                let record = decode_row(fields, row).and_then(|(time, values)| {
                    SourceRecordV1::try_from_source(
                        origin,
                        meta.source.clone(),
                        Some(time),
                        format.clone(),
                        values,
                        DecodeAnnotationsV1::default(),
                    )
                    .ok()
                });
                if let Some(record) = record {
                    emit(Tainted::from_external(
                        record,
                        Provenance::new(meta.evidence_hash, None, SourceKind::ToolResult),
                    ))?;
                    report.accepted += 1;
                } else {
                    report.rejected += 1;
                }
            }
            Ok(())
        })?;
        if summary.identity().0 != &hash {
            return Err(SourceQueryError::Invalid.into());
        }
        Ok(report)
    }
}

fn checked_rows<'a>(
    wire: &'a Value,
    stable_schema: &mut Option<Vec<Value>>,
) -> Result<&'a [Value], SourceQueryError> {
    if wire["jobComplete"] != true {
        return Err(SourceQueryError::Unresolved);
    }
    if let Some(schema) = wire.get("schema") {
        let fields = schema["fields"]
            .as_array()
            .ok_or(SourceQueryError::Invalid)?;
        if fields.len() != COLUMNS.len()
            || fields.iter().zip(COLUMNS).any(|(raw, (name, kind))| {
                raw["name"] != name
                    || raw["type"] != kind
                    || !matches!(raw["mode"].as_str(), None | Some("NULLABLE" | "REQUIRED"))
            })
        {
            return Err(SourceQueryError::Unsupported);
        }
        match stable_schema {
            Some(prior) if prior != fields => return Err(SourceQueryError::Invalid),
            None => *stable_schema = Some(fields.clone()),
            Some(_) => {}
        }
    }
    if stable_schema.is_none() {
        return Err(SourceQueryError::Invalid);
    }
    match wire.get("rows") {
        Some(Value::Array(rows)) if rows.len() <= 1_000 => Ok(rows),
        Some(Value::Array(_)) => Err(SourceQueryError::Limit),
        Some(_) => Err(SourceQueryError::Invalid),
        None => Ok(&[]),
    }
}

fn decode_row(schema: &[Value], row: &Value) -> Option<(IndexedTime, SourceValue)> {
    let cells = row["f"].as_array()?;
    let micros = cells.first()?.get("v")?.as_str()?.parse().ok()?;
    let time = IndexedTime::new(
        IndexedInstant::new(micros, 0).ok()?,
        TimePrecision::Microsecond,
        false,
    )
    .ok()?;
    let mut remaining = SOURCE_MAX_NODES;
    let mut values = decode_fields(schema, cells, 0, &mut remaining)?;
    values.insert("timestamp".into(), SourceValue::Text(time.to_rfc3339()));
    let payload = values.remove("protopayload_auditlog")?;
    values.insert("protoPayload".into(), payload);
    Some((time, SourceValue::Object(values)))
}

fn decode_fields(
    fields: &[Value],
    cells: &[Value],
    depth: usize,
    remaining: &mut usize,
) -> Option<BTreeMap<String, SourceValue>> {
    if depth > SOURCE_MAX_DEPTH || fields.len() != cells.len() || fields.len() > *remaining {
        return None;
    }
    let mut result = BTreeMap::new();
    for (schema, cell) in fields.iter().zip(cells) {
        let name = schema["name"].as_str()?.to_owned();
        let decoded = decode_value(schema, cell.get("v")?, depth, remaining)?;
        if result.insert(name, decoded).is_some() {
            return None;
        }
    }
    Some(result)
}

fn decode_value(
    schema: &Value,
    value: &Value,
    depth: usize,
    remaining: &mut usize,
) -> Option<SourceValue> {
    *remaining = remaining.checked_sub(1)?;
    match schema["mode"].as_str() {
        Some("REPEATED") => {
            let cells = value.as_array()?;
            if cells.len() > *remaining {
                return None;
            }
            let mut result = Vec::with_capacity(cells.len());
            for cell in cells {
                *remaining = remaining.checked_sub(1)?;
                result.push(decode_single(schema, cell.get("v")?, depth + 1, remaining)?);
            }
            Some(SourceValue::Array(result))
        }
        Some("REQUIRED") if value.is_null() => None,
        None | Some("NULLABLE" | "REQUIRED") => decode_single(schema, value, depth, remaining),
        Some(_) => None,
    }
}

fn decode_single(
    schema: &Value,
    value: &Value,
    depth: usize,
    remaining: &mut usize,
) -> Option<SourceValue> {
    if depth > SOURCE_MAX_DEPTH {
        return None;
    }
    if value.is_null() {
        return Some(SourceValue::Null);
    }
    match schema["type"].as_str()? {
        "RECORD" => decode_fields(
            schema["fields"].as_array()?,
            value["f"].as_array()?,
            depth + 1,
            remaining,
        )
        .map(SourceValue::Object),
        "INTEGER" | "FLOAT" | "NUMERIC" | "BIGNUMERIC" => value
            .as_str()
            .and_then(|bytes| SourceNumber::try_new(bytes).ok())
            .map(SourceValue::Number),
        "BOOLEAN" => match value.as_str()? {
            "true" => Some(SourceValue::Boolean(true)),
            "false" => Some(SourceValue::Boolean(false)),
            _ => None,
        },
        "TIMESTAMP" | "STRING" | "BYTES" | "DATE" | "TIME" | "DATETIME" | "JSON" | "GEOGRAPHY" => {
            value.as_str().map(|s| SourceValue::Text(s.into()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cloud_audit_rows_keep_signed_column_positions_and_exact_times() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/logging-sink-tables.json")).unwrap();
        let row = json!({"f":[
            {"v":"1767225600123456"},
            {"v":"entry-id"},
            {"v":{"f":[{"v":"audited_resource"},{"v":{"f":[{"v":"synthetic-project"}]}}]}},
            {"v":{"f":[
                {"v":"compute.googleapis.com"},
                {"v":"v1.compute.instances.insert"},
                {"v":"synthetic-vm"},
                {"v":{"f":[{"v":"synthetic@example.invalid"}]}},
                {"v":{"f":[{"v":"203.0.113.77"}]}},
                {"v":null},
                {"v":null}
            ]}}
        ]});
        let first = json!({"jobComplete":true,"schema":fixture["schema"],"rows":[row]});
        let mut schema = None;
        let rows = checked_rows(&first, &mut schema).unwrap();
        let (time, fields) = decode_row(schema.as_deref().unwrap(), &rows[0]).unwrap();
        assert_eq!(time.instant().unix_micros(), 1_767_225_600_123_456);
        assert_eq!(
            fields
                .field("protoPayload")
                .and_then(|value| value.field("requestMetadata"))
                .and_then(|value| value.field("callerIp"))
                .and_then(SourceValue::as_text),
            Some("203.0.113.77")
        );
        let later = json!({"jobComplete":true,"rows":[row]});
        assert_eq!(checked_rows(&later, &mut schema).unwrap().len(), 1);
        let mut malformed = first;
        malformed["schema"]["fields"][3]["fields"][0]["name"] = json!("swapped");
        assert!(checked_rows(&malformed, &mut schema).is_err());
        assert!(decode_row(schema.as_deref().unwrap(), &json!({"f":[{"v":"1e9"}]})).is_none());
    }
}
