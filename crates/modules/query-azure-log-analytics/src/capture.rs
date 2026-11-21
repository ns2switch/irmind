//! Stream rows from a retained Log Analytics tabular response.
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceInput,
        json::{SourceJsonLimits, decode_json_value},
    },
    source_queries::{
        CaptureColumn, QUERY_MAX_RECORD_BYTES, QUERY_MAX_ROWS, SourceQueryError,
        read_query_capture_pages,
    },
};
use irmind_domain::{
    DecodeAnnotationsV1, EventOrigin, EvidenceHash, IndexedTime, Provenance, SOURCE_MAX_BYTES,
    SourceFormatV1, SourceKind, SourceRecordV1, SourceValue, Tainted,
};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, BufReader, Read},
};

/// Decoder for the primary event table in a retained Analytics acquisition.
pub struct AzureAnalyticsCaptureDecoder;

impl SourceDecoder for AzureAnalyticsCaptureDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "query-azure-analytics",
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
        let format = SourceFormatV1::try_new("azure-analytics", "1", BTreeMap::new())
            .map_err(|_| SourceQueryError::Invalid)?;
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: vec![],
        };
        let summary = read_query_capture_pages(input.reader, meta.cancel, |page, reader| {
            if page.ordinal != 0 {
                return Err(SourceQueryError::Invalid.into());
            }
            check_columns(page.columns)?;
            let mut ordinal = 0;
            let facts = read_page(reader, page.columns, &mut |raw| {
                if meta.cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let origin = EventOrigin::try_new(hash.clone(), ordinal, None, id.name, id.version)
                    .map_err(|_| SourceQueryError::Invalid)?;
                ordinal += 1;
                let record = decode_row(page.columns, raw).and_then(|(time, fields)| {
                    SourceRecordV1::try_from_source(
                        origin,
                        meta.source.clone(),
                        Some(time),
                        format.clone(),
                        fields,
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
                Ok(())
            })?;
            if facts.rows != page.rows || facts.provider_partial != page.provider_partial {
                return Err(SourceQueryError::Invalid.into());
            }
            Ok(())
        })?;
        if summary.identity().0 != &hash {
            return Err(SourceQueryError::Invalid.into());
        }
        Ok(report)
    }
}

fn check_columns(columns: &[CaptureColumn]) -> Result<(), SourceQueryError> {
    let mut names = BTreeSet::new();
    if columns.len() > 1024
        || columns.iter().any(|column| {
            column.name.is_empty() || column.name.len() > 256 || !names.insert(column.name.as_str())
        })
        || !columns
            .iter()
            .any(|column| column.name == "TimeGenerated" && column.native_type == "datetime")
    {
        return Err(SourceQueryError::Invalid);
    }
    Ok(())
}

fn decode_row(columns: &[CaptureColumn], raw: &RawValue) -> Option<(IndexedTime, SourceValue)> {
    let SourceValue::Array(cells) =
        decode_json_value(raw.get().as_bytes(), SourceJsonLimits::default()).ok()?
    else {
        return None;
    };
    if cells.len() != columns.len() {
        return None;
    }
    let fields = SourceValue::object(
        columns
            .iter()
            .zip(cells)
            .map(|(column, cell)| (column.name.clone(), cell))
            .collect(),
    )
    .ok()?;
    let time = IndexedTime::from_rfc3339(fields.field("TimeGenerated")?.as_text()?, false).ok()?;
    Some((time, fields))
}

#[derive(Debug, PartialEq, Eq)]
struct PageFacts {
    rows: u64,
    provider_partial: bool,
}

fn read_page(
    input: &mut dyn Read,
    columns: &[CaptureColumn],
    emit: &mut dyn FnMut(&RawValue) -> Result<(), AppError>,
) -> Result<PageFacts, AppError> {
    let budget = Cell::new(QUERY_MAX_RECORD_BYTES);
    let exhausted = Cell::new(false);
    let mut callback_error = None;
    let mut callback = |value: &RawValue| emit(value).map_err(|error| callback_error = Some(error));
    let reader = FragmentBudget {
        remaining: &budget,
        exhausted: &exhausted,
        input: BufReader::new(input),
    };
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let document = WireReader {
        columns,
        budget: &budget,
        row: &mut callback,
    };
    let facts = deserializer.deserialize_map(document).and_then(|facts| {
        budget.set(QUERY_MAX_RECORD_BYTES);
        deserializer.end().map(|()| facts)
    });
    facts.map_err(|_| {
        callback_error.unwrap_or_else(|| {
            if exhausted.get() {
                SourceQueryError::Limit.into()
            } else {
                SourceQueryError::Invalid.into()
            }
        })
    })
}

/// Each JSON row or control fragment is bounded before serde allocates for it.
struct FragmentBudget<'a> {
    remaining: &'a Cell<usize>,
    exhausted: &'a Cell<bool>,
    input: BufReader<&'a mut dyn Read>,
}

impl Read for FragmentBudget<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let left = self.remaining.get();
        if left == 0 {
            self.exhausted.set(true);
            return Err(io::Error::other("Azure capture fragment limit"));
        }
        let bound = left.min(out.len());
        let count = self.input.read(&mut out[..bound])?;
        self.remaining.set(left - count);
        Ok(count)
    }
}

#[derive(serde::Deserialize)]
struct ProviderStatus {
    code: String,
}

struct WireReader<'a> {
    columns: &'a [CaptureColumn],
    budget: &'a Cell<usize>,
    row: &'a mut dyn FnMut(&RawValue) -> Result<(), ()>,
}

impl<'de> Visitor<'de> for WireReader<'_> {
    type Value = PageFacts;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a Log Analytics response")
    }

    fn visit_map<M: MapAccess<'de>>(mut self, mut map: M) -> Result<PageFacts, M::Error> {
        let mut keys = BTreeSet::new();
        let mut rows = None;
        let mut provider_partial = false;
        while let Some(key) = map.next_key::<String>()? {
            if keys.len() >= 4 || !keys.insert(key.clone()) {
                return Err(de::Error::custom(
                    "duplicate or extra Analytics response member",
                ));
            }
            self.budget.set(QUERY_MAX_RECORD_BYTES);
            match key.as_str() {
                "tables" => rows = Some(map.next_value_seed(Tables(&mut self))?),
                "error" => {
                    let error = map.next_value::<ProviderStatus>()?;
                    if error.code != "PartialError" {
                        return Err(de::Error::custom("unsupported Analytics result status"));
                    }
                    provider_partial = true;
                }
                "statistics" | "render" => {
                    map.next_value::<de::IgnoredAny>()?;
                }
                _ => return Err(de::Error::custom("unknown Analytics response member")),
            }
            self.budget.set(QUERY_MAX_RECORD_BYTES);
        }
        Ok(PageFacts {
            rows: rows.ok_or_else(|| de::Error::missing_field("tables"))?,
            provider_partial,
        })
    }
}

struct Tables<'a, 'b>(&'a mut WireReader<'b>);
impl<'de> DeserializeSeed<'de> for Tables<'_, '_> {
    type Value = u64;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<u64, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Tables<'_, '_> {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("one Analytics result table")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<u64, S::Error> {
        let rows = seq
            .next_element_seed(Table(self.0))?
            .ok_or_else(|| de::Error::custom("missing Analytics result table"))?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom("unexpected extra Analytics result table"));
        }
        Ok(rows)
    }
}

struct Table<'a, 'b>(&'a mut WireReader<'b>);
impl<'de> DeserializeSeed<'de> for Table<'_, '_> {
    type Value = u64;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<u64, D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for Table<'_, '_> {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the PrimaryResult table")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<u64, M::Error> {
        let mut keys = BTreeSet::new();
        let mut rows = None;
        while let Some(key) = map.next_key::<String>()? {
            if keys.len() >= 3 || !keys.insert(key.clone()) {
                return Err(de::Error::custom(
                    "duplicate or extra Analytics table member",
                ));
            }
            self.0.budget.set(QUERY_MAX_RECORD_BYTES);
            match key.as_str() {
                "name" if map.next_value::<String>()? == "PrimaryResult" => {}
                "columns" => {
                    let columns = map.next_value::<Vec<CaptureColumn>>()?;
                    if columns.len() != self.0.columns.len()
                        || columns.iter().zip(self.0.columns).any(|(raw, signed)| {
                            raw.name != signed.name || raw.native_type != signed.native_type
                        })
                    {
                        return Err(de::Error::custom(
                            "Analytics columns differ from capture metadata",
                        ));
                    }
                }
                "rows" => rows = Some(map.next_value_seed(Rows(self.0))?),
                _ => return Err(de::Error::custom("unexpected Analytics table member")),
            }
            self.0.budget.set(QUERY_MAX_RECORD_BYTES);
        }
        if !keys.contains("name") || !keys.contains("columns") {
            return Err(de::Error::custom("incomplete Analytics table metadata"));
        }
        rows.ok_or_else(|| de::Error::missing_field("rows"))
    }
}

struct Rows<'a, 'b>(&'a mut WireReader<'b>);
impl<'de> DeserializeSeed<'de> for Rows<'_, '_> {
    type Value = u64;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<u64, D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Rows<'_, '_> {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Analytics event rows")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<u64, S::Error> {
        let mut rows = 0;
        loop {
            self.0.budget.set(SOURCE_MAX_BYTES);
            let Some(raw) = seq.next_element::<Box<RawValue>>()? else {
                return Ok(rows);
            };
            rows += 1;
            if rows > QUERY_MAX_ROWS {
                return Err(de::Error::custom("too many Analytics result rows"));
            }
            (self.0.row)(&raw).map_err(|()| de::Error::custom("Analytics row rejected"))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_provider_status_matches_the_authenticated_page_marker() {
        use irmind_app::{
            CancellationToken,
            source_mapping::SourceMetadata,
            source_queries::{CapturePageCompleteness, CapturePageMetadata, QueryCaptureWriter},
        };
        use irmind_domain::{SourceDecoderIdentityV1, SourceReferenceV1};
        use std::io::Cursor;

        let wire = br#"{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"}],"rows":[["2026-01-01T00:00:00Z"]]}],"error":{"code":"PartialError"}}"#;
        let decoder = AzureAnalyticsCaptureDecoder;
        let id = decoder.identity();
        let identity = SourceDecoderIdentityV1::try_new(id.name, id.version).unwrap();
        let cancel = CancellationToken::new();
        let source = SourceReferenceV1::try_new(
            "queries/synthetic.sqc",
            SourceKind::ToolResult,
            Some(EvidenceHash::from_bytes([7; 32])),
        )
        .unwrap();
        for completeness in [
            CapturePageCompleteness::Complete,
            CapturePageCompleteness::ProviderPartial,
        ] {
            let mut container = Vec::new();
            let mut writer = QueryCaptureWriter::new(
                Cursor::new(Vec::new()),
                EvidenceHash::from_bytes([3; 32]),
                identity.clone(),
                32_768,
                10,
            )
            .unwrap();
            writer
                .stage_page(
                    CapturePageMetadata {
                        columns: vec![CaptureColumn {
                            name: "TimeGenerated".into(),
                            native_type: "datetime".into(),
                        }],
                        completeness,
                        rows: 1,
                    },
                    wire.as_slice(),
                    &cancel,
                )
                .unwrap();
            writer.finish(&mut container, &cancel).unwrap();
            let digest = irmind_app::sha256(&container);
            let report = decoder.decode_reader(
                SourceInput {
                    reader: &mut container.as_slice(),
                    metadata: SourceMetadata {
                        source: &source,
                        evidence_hash: digest,
                        time_context: None,
                        cluster_context: None,
                        cancel: &cancel,
                    },
                },
                &mut |_| Ok(()),
            );
            if completeness == CapturePageCompleteness::ProviderPartial {
                assert_eq!(report.unwrap().accepted, 1);
            } else {
                assert!(report.is_err());
            }
        }
    }

    #[test]
    fn oversized_fragments_and_duplicate_status_codes_fail_closed() {
        let oversized = format!(
            r#"{{"tables":[{{"name":"{}"}}]}}"#,
            "a".repeat(QUERY_MAX_RECORD_BYTES)
        );
        let error = read_page(&mut oversized.as_bytes(), &[], &mut |_| Ok(())).unwrap_err();
        assert!(
            matches!(error, AppError::Policy(reason) if reason == SourceQueryError::Limit.to_string())
        );
        let duplicate = br#"{"error":{"code":"Failure","code":"PartialError"},"tables":[{"name":"PrimaryResult","columns":[],"rows":[]}]}"#;
        assert!(read_page(&mut duplicate.as_slice(), &[], &mut |_| Ok(())).is_err());
    }

    #[test]
    fn rows_stream_in_wire_order_and_keep_exact_values_when_schema_arrives_later() {
        let wire = br#"{"tables":[{"rows":[["2026-01-01T00:00:00.1234567Z",123456789.123456789],["2026-01-01T00:00:01Z",2]],"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"SyntheticValue","type":"decimal"}]}],"error":{"code":"PartialError"}}"#;
        let columns = [
            CaptureColumn {
                name: "TimeGenerated".into(),
                native_type: "datetime".into(),
            },
            CaptureColumn {
                name: "SyntheticValue".into(),
                native_type: "decimal".into(),
            },
        ];
        let mut timestamps = Vec::new();
        let facts = read_page(&mut wire.as_slice(), &columns, &mut |raw| {
            let (time, fields) = decode_row(&columns, raw).unwrap();
            timestamps.push(time);
            if timestamps.len() == 1 {
                let value = fields
                    .field("SyntheticValue")
                    .and_then(|value| match value {
                        SourceValue::Number(value) => Some(value.as_str()),
                        _ => None,
                    });
                assert_eq!(value, Some("123456789.123456789"));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            facts,
            PageFacts {
                rows: 2,
                provider_partial: true
            }
        );
        assert_eq!(timestamps[0].instant().submicro_nanos(), 700);
        assert!(timestamps[0].instant() < timestamps[1].instant());

        let mut mismatched = columns;
        mismatched[1].native_type = "string".into();
        assert!(read_page(&mut wire.as_slice(), &mismatched, &mut |_| Ok(())).is_err());
    }
}
