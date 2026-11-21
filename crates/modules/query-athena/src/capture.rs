//! Read-only decoding of captured Athena REST pages.
use irmind_app::source_mapping::{
    SourceInput,
    json::{SourceJsonLimits, decode_json_fields},
};
use irmind_app::source_queries::{
    CaptureColumn, InspectedQueryPage, QueryPageInput, QueryPageSchema, SourceQueryError,
    SourceQueryPageDecoder, canonical_query_json, decode_query_capture, read_query_json_page,
};
use irmind_app::{AppError, ParseReport, ParserIdentity, SourceDecoder};
use irmind_domain::{IndexedTime, SourceFormatV1, SourceRecordV1, SourceValue, Tainted};
use serde_json::Value;
use std::{collections::BTreeMap, io::BufReader};

const MAX_PAGE_ROWS: usize = 1_000;
const COLUMNS: [(&str, &str); 15] = [
    ("eventtime", "eventTime"),
    ("eventname", "eventName"),
    ("eventid", "eventID"),
    ("recipientaccountid", "recipientAccountId"),
    ("sourceipaddress", "sourceIPAddress"),
    ("useridentity", "userIdentity"),
    ("eventversion", "eventVersion"),
    ("eventsource", "eventSource"),
    ("awsregion", "awsRegion"),
    ("useragent", "userAgent"),
    ("errorcode", "errorCode"),
    ("errormessage", "errorMessage"),
    ("requestparameters", "requestParameters"),
    ("responseelements", "responseElements"),
    ("eventtype", "eventType"),
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
        let format = SourceFormatV1::try_new("json", "source-json-v1", BTreeMap::new())
            .map_err(|_| SourceQueryError::Invalid)?;
        decode_query_capture(
            input,
            self.identity(),
            format,
            emit,
            |page, reader, output| {
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
                    output.row(|| decode_row(row))?;
                }
                Ok(())
            },
        )
    }
}

impl SourceQueryPageDecoder for AthenaCaptureDecoder {
    fn inspect_page(
        &self,
        input: &mut dyn QueryPageInput,
        ordinal: u64,
        _: Option<&QueryPageSchema>,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<InspectedQueryPage, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let wire = read_query_json_page(input, super::protocol::PAGE_LIMIT as u64)?;
        let native = columns(&wire)?;
        let schema = QueryPageSchema::new(
            native
                .iter()
                .filter_map(|raw| {
                    Some(CaptureColumn {
                        name: raw["Name"].as_str()?.into(),
                        native_type: raw["Type"].as_str()?.into(),
                    })
                })
                .collect(),
            canonical_query_json(&native)?,
        )?;
        let rows = checked_rows(&wire, ordinal == 0)?;
        let mut rejected = 0;
        for row in rows {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            rejected += u64::from(decode_row(row).is_none());
        }
        let (next_token, partial_token) = match wire.get("NextToken") {
            None => (None, false),
            Some(Value::String(token)) if !token.is_empty() && token.len() <= 4096 => {
                (Some(token.clone()), false)
            }
            Some(_) => (None, true),
        };
        Ok(InspectedQueryPage {
            schema,
            rows: rows.len() as u64,
            rejected,
            provider_partial: partial_token,
            total_rows: None,
            next_token,
        })
    }
}

pub(super) fn columns(wire: &Value) -> Result<&[Value], SourceQueryError> {
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
    if cells[6]["VarCharValue"].as_str().is_none_or(str::is_empty) {
        return None;
    }
    let mut fields = Vec::with_capacity(COLUMNS.len());
    for (cell, (_, field)) in cells.iter().zip(COLUMNS) {
        let Some(value) = cell.get("VarCharValue") else {
            continue;
        };
        let value = value.as_str()?;
        let decoded = match field {
            "userIdentity" => normalize_identity(value)?,
            "requestParameters" | "responseElements" => {
                decode_json_fields(value.as_bytes(), SourceJsonLimits::default())
                    .unwrap_or_else(|_| SourceValue::Text(value.into()))
            }
            _ => SourceValue::Text(value.into()),
        };
        fields.push((field.into(), decoded));
    }
    let fields = SourceValue::object(fields).ok()?;
    if fields.validate().ok()? > irmind_domain::SOURCE_MAX_BYTES - 4096 {
        return None;
    }
    Some((time, fields))
}

fn normalize_identity(value: &str) -> Option<SourceValue> {
    let original = decode_json_fields(value.as_bytes(), SourceJsonLimits::default()).ok()?;
    let SourceValue::Object(original) = original else {
        return None;
    };
    let fields = original
        .into_iter()
        .map(|(name, value)| {
            let canonical = match name.as_str() {
                "principalid" => "principalId",
                "accountid" => "accountId",
                "username" => "userName",
                _ => name.as_str(),
            };
            (canonical.into(), value)
        })
        .collect();
    SourceValue::object(fields).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::CancellationToken;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn header_is_skipped_only_on_first_page_and_bad_rows_count() {
        let header = COLUMNS
            .iter()
            .map(|(name, _)| json!({"VarCharValue": name}))
            .collect::<Vec<_>>();
        let columns = COLUMNS
            .iter()
            .map(|(name, _)| json!({"Name": name,"Type":"varchar"}))
            .collect::<Vec<_>>();
        let wire = json!({"ResultSet":{
            "ResultSetMetadata":{"ColumnInfo":columns},
            "Rows":[{"Data":header},{"Data":[{}]}]
        }});
        let first = AthenaCaptureDecoder
            .inspect_page(
                &mut Cursor::new(wire.to_string()),
                0,
                None,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!((first.rows, first.rejected), (1, 1));
        assert!(!first.provider_partial);
        let second = AthenaCaptureDecoder
            .inspect_page(
                &mut Cursor::new(wire.to_string()),
                1,
                Some(&first.schema),
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!((second.rows, second.rejected), (2, 2));
    }

    #[test]
    fn captured_cloudtrail_and_local_cloudtrail_map_to_the_same_common_event() {
        use irmind_mod_mapping_cloudtrail::CloudTrailMapping;
        use irmind_mod_parser_json::JsonSourceDecoder;
        let file = serde_json::json!({
            "eventTime":"2026-01-01T00:00:00Z","eventName":"ConsoleLogin",
            "eventID":"synthetic-event","recipientAccountId":"111111111111",
            "sourceIPAddress":"203.0.113.8",
        "userIdentity":{"principalId":"synthetic-id","accountId":"111111111111","userName":"synthetic"},
        "eventVersion":"1.09",
            "eventSource":"signin.amazonaws.com","awsRegion":"us-east-1","userAgent":"synthetic",
            "errorCode":"","errorMessage":"","requestParameters":{},
            "responseElements":{"ConsoleLogin":"Failure"},"eventType":"AwsConsoleSignIn"
        });
        irmind_testkit::assert_capture_mapping_equivalent(
            file.to_string().as_bytes(),
            include_bytes!("../../../../fuzz/seeds/query_page_athena/page.json"),
            &JsonSourceDecoder,
            &AthenaCaptureDecoder,
            &CloudTrailMapping::new().unwrap(),
            &CloudTrailMapping::for_capture().unwrap(),
        );
    }
}
