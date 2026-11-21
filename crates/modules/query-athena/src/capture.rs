//! Read-only decoding of captured Athena REST pages.
use irmind_app::source_mapping::{
    SourceInput,
    json::{SourceJsonLimits, decode_json_fields},
};
use irmind_app::source_queries::{SourceQueryError, read_query_capture_pages};
use irmind_app::{AppError, ParseReport, ParserIdentity, SourceDecoder};
use irmind_domain::{
    DecodeAnnotationsV1, EventOrigin, EvidenceHash, IndexedTime, Provenance, SourceFormatV1,
    SourceKind, SourceRecordV1, SourceValue, Tainted,
};
use serde_json::Value;
use std::{collections::BTreeMap, io::BufReader};

const MAX_PAGE_ROWS: usize = 1_000;
const COLUMNS: [(&str, &str); 6] = [
    ("eventtime", "eventTime"),
    ("eventname", "eventName"),
    ("eventid", "eventID"),
    ("recipientaccountid", "recipientAccountId"),
    ("sourceipaddress", "sourceIPAddress"),
    ("useridentity", "userIdentity"),
];

/// Decodes the exact raw `GetQueryResults` pages in a retained acquisition.
pub struct AthenaCaptureDecoder;

impl SourceDecoder for AthenaCaptureDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "query-athena-cloudtrail",
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
        let format = SourceFormatV1::try_new("athena-cloudtrail", "1", BTreeMap::new())
            .map_err(|_| SourceQueryError::Invalid)?;
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: vec![],
        };
        let mut ordinal = 0;
        let summary = read_query_capture_pages(input.reader, meta.cancel, |page, reader| {
            if page.body_bytes > super::protocol::PAGE_LIMIT as u64 {
                return Err(SourceQueryError::Limit.into());
            }
            let wire: Value = serde_json::from_reader(BufReader::new(reader))
                .map_err(|_| SourceQueryError::Invalid)?;
            let rows = checked_rows(&wire, page.ordinal == 0)?;
            let native = columns(&wire)?;
            if rows.len() as u64 != page.rows
                || page.columns.len() != native.len()
                || page.columns.iter().zip(native).any(|(signed, raw)| {
                    raw["Name"] != signed.name || raw["Type"] != signed.native_type
                })
            {
                return Err(SourceQueryError::Invalid.into());
            }
            for row in rows {
                if meta.cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let origin = EventOrigin::try_new(hash.clone(), ordinal, None, id.name, id.version)
                    .map_err(|_| SourceQueryError::Invalid)?;
                ordinal += 1;
                let Some((time, fields)) = decode_row(row) else {
                    report.rejected += 1;
                    continue;
                };
                let record = SourceRecordV1::try_from_source(
                    origin,
                    meta.source.clone(),
                    Some(time),
                    format.clone(),
                    fields,
                    DecodeAnnotationsV1::default(),
                );
                match record {
                    Ok(record) => {
                        emit(Tainted::from_external(
                            record,
                            Provenance::new(meta.evidence_hash, None, SourceKind::ToolResult),
                        ))?;
                        report.accepted += 1;
                    }
                    Err(_) => report.rejected += 1,
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

fn columns(wire: &Value) -> Result<&[Value], SourceQueryError> {
    let columns = wire["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
        .as_array()
        .ok_or(SourceQueryError::Invalid)?;
    if columns.len() != COLUMNS.len()
        || columns.iter().zip(COLUMNS).any(|(column, (name, _))| {
            column["Name"] != name
                || column["Type"]
                    .as_str()
                    .is_none_or(|kind| kind.is_empty() || kind.len() > 128)
        })
    {
        return Err(SourceQueryError::Unsupported);
    }
    Ok(columns)
}

fn checked_rows(wire: &Value, first: bool) -> Result<&[Value], SourceQueryError> {
    let rows = wire["ResultSet"]["Rows"]
        .as_array()
        .ok_or(SourceQueryError::Invalid)?;
    let first_is_header = first
        && rows.first().is_some_and(|row| {
            row["Data"].as_array().is_some_and(|cells| {
                cells.len() == COLUMNS.len()
                    && cells
                        .iter()
                        .zip(COLUMNS)
                        .all(|(cell, (name, _))| cell["VarCharValue"] == name)
            })
        });
    let rows = &rows[usize::from(first_is_header)..];
    if rows.len() > MAX_PAGE_ROWS {
        return Err(SourceQueryError::Limit);
    }
    Ok(rows)
}

fn decode_row(row: &Value) -> Option<(IndexedTime, SourceValue)> {
    let cells = row["Data"].as_array()?;
    if cells.len() != COLUMNS.len() {
        return None;
    }
    let at = cells[0]["VarCharValue"].as_str()?;
    let time = IndexedTime::from_rfc3339(at, false).ok()?;
    for required in &cells[1..4] {
        if required["VarCharValue"].as_str().is_none_or(str::is_empty) {
            return None;
        }
    }
    let mut fields = Vec::with_capacity(COLUMNS.len());
    for (cell, (_, field)) in cells.iter().zip(COLUMNS) {
        let Some(value) = cell.get("VarCharValue") else {
            continue;
        };
        let value = value.as_str()?;
        let decoded = if field == "userIdentity" {
            // Structured JSON is optional. Preserve non-JSON native cell text.
            decode_json_fields(value.as_bytes(), SourceJsonLimits::default())
                .unwrap_or_else(|_| SourceValue::Text(value.into()))
        } else {
            SourceValue::Text(value.into())
        };
        fields.push((field.into(), decoded));
    }
    Some((time, SourceValue::object(fields).ok()?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{CancellationToken, source_mapping::SourceMetadata};
    use irmind_domain::SourceReferenceV1;

    #[test]
    fn native_pages_decode_events_without_inventing_offsets_or_including_headers() {
        let bytes =
            include_str!("../../../../docs/development/source-query-format-vectors/capture.hex");
        let bytes: Vec<u8> = bytes
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
            .collect();
        let digest = irmind_app::sha256(&bytes);
        let source = SourceReferenceV1::try_new(
            "queries/synthetic.sqc",
            SourceKind::ToolResult,
            Some(EvidenceHash::from_bytes([1; 32])),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let mut reader = bytes.as_slice();
        let mut accepted = Vec::new();
        let report = AthenaCaptureDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: digest,
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut reader,
                },
                &mut |row| {
                    row.inspect(|source| accepted.push(source.clone()));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!((report.accepted, report.rejected), (2, 0));
        assert!(accepted.iter().all(|record| record.timestamp().is_some()));
        assert_eq!(accepted[0].origin().record(), 0);
        assert_eq!(accepted[1].origin().record(), 1);
        assert!(
            accepted
                .iter()
                .all(|record| record.origin().offset().is_none())
        );
        assert_eq!(
            accepted[0]
                .fields()
                .field("eventID")
                .and_then(SourceValue::as_text),
            Some("synthetic-event-1")
        );
        assert_eq!(
            accepted[1]
                .fields()
                .field("eventID")
                .and_then(SourceValue::as_text),
            Some("synthetic-event-2")
        );
    }
}
