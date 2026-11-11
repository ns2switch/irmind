use super::{AppError, Decoder, error};
use crate::{config::Format, input::Frames};
use irmind_app::{
    ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeAnnotationsV1, DecodeBudget, DecodeInput, SourceFormatV1, SourceInput,
        SourceMetadata, SourceRecordV1, SourceValue, ordered_decode::decode_ordered,
    },
};
use irmind_domain::{EventOrigin, EvidenceHash, ParserLocation, Provenance, Tainted};
use std::{collections::BTreeMap, io::BufReader, sync::Arc};
impl SourceDecoder for Decoder {
    fn identity(&self) -> ParserIdentity<'_> {
        irmind_app::StreamingEventParser::identity(self.0.as_ref())
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }
    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let SourceInput { metadata, reader } = input.into_reader();
        let mut frames = Frames::new(
            BufReader::new(reader),
            self.0.definition.input.format,
            self.0.definition.limits.record_bytes,
        );
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: Vec::new(),
        };
        let mut header: Option<Arc<[String]>> = None;
        let mut header_bytes = 0usize;
        let mut offset = 0u64;
        let mut seen = 0usize;
        decode_ordered(
            budget,
            metadata.cancel,
            || loop {
                let Some(frame) = frames.next(metadata.cancel)? else {
                    return Ok(None);
                };
                let current = offset + frame.leading;
                offset = offset
                    .checked_add(frame.consumed)
                    .ok_or_else(|| error("source size overflow"))?;
                if !frame.invalid
                    && frame.consumed <= self.0.definition.limits.record_bytes as u64
                    && frame.bytes.iter().all(u8::is_ascii_whitespace)
                {
                    continue;
                }
                if seen >= self.0.definition.limits.records {
                    return Err(error("declarative source exceeds record limit"));
                }
                if self.0.definition.input.format == Format::Csv
                    && self.0.definition.input.header
                    && header.is_none()
                {
                    header_bytes = frame.bytes.len();
                    header = Some(self.0.csv_header(&frame.bytes)?.into());
                    continue;
                }
                seen += 1;
                let weight = frame
                    .bytes
                    .len()
                    .saturating_add(header_bytes)
                    .saturating_mul(64);
                return Ok(Some(((frame, current, header.clone()), weight)));
            },
            |(frame, current, header)| {
                let parsed =
                    if frame.invalid || frame.bytes.len() > self.0.definition.limits.record_bytes {
                        Err(error("invalid or oversized record"))
                    } else {
                        self.prepare(&frame.bytes, header.as_deref())
                    };
                (frame.bytes, current, parsed)
            },
            |(bytes, offset, parsed)| {
                self.emit_record(metadata, &bytes, offset, parsed, &mut report, emit)
            },
        )?;
        Ok(report)
    }
}

struct RecordFields {
    fields: SourceValue,
    timestamp: irmind_domain::IndexedTime,
    original: String,
}

impl Decoder {
    fn prepare(&self, bytes: &[u8], header: Option<&[String]>) -> Result<RecordFields, AppError> {
        let raw =
            std::str::from_utf8(bytes).map_err(|_| error("declarative record is not UTF-8"))?;
        let fields = self.fields(bytes, header)?;
        let path = self
            .0
            .definition
            .mapping
            .get("time")
            .ok_or_else(|| error("missing timestamp mapping"))?;
        let time = super::extract::read_value(&self.0, &fields, path)?
            .ok_or_else(|| error("mapped time is missing"))?;
        let at = crate::mapping::timestamp(&time, &self.0.definition.timestamp)?;
        let timestamp = crate::indexed::timestamp(&self.0, &time, &at)?;
        Ok(RecordFields {
            fields,
            timestamp,
            original: raw.into(),
        })
    }

    fn emit_record(
        &self,
        metadata: SourceMetadata<'_>,
        bytes: &[u8],
        offset: u64,
        parsed: Result<RecordFields, AppError>,
        report: &mut ParseReport,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        match parsed.and_then(|fields| self.record(metadata, fields, report.accepted, offset)) {
            Ok(record) => {
                let location =
                    ParserLocation::new(metadata.source.reference(), self.0.id(), offset)
                        .map_err(|_| error("invalid source location"))?;
                emit(Tainted::from_external(
                    record,
                    Provenance::new(
                        metadata.evidence_hash,
                        Some(report.accepted as u64),
                        metadata.source.kind(),
                    )
                    .with_parser_location(location),
                ))?;
                report.accepted += 1;
            }
            Err(_) => reject(report, bytes),
        }
        Ok(())
    }

    fn record(
        &self,
        metadata: SourceMetadata<'_>,
        RecordFields {
            fields,
            timestamp,
            original,
        }: RecordFields,
        index: usize,
        offset: u64,
    ) -> Result<SourceRecordV1, AppError> {
        let origin = EventOrigin::try_new(
            EvidenceHash::from_bytes(metadata.evidence_hash),
            index as u64,
            Some(offset),
            self.0.id(),
            self.0.definition_version(),
        )
        .map_err(|_| error("invalid source origin"))?;
        SourceRecordV1::try_from_source(
            origin,
            metadata.source.clone(),
            Some(timestamp),
            SourceFormatV1::try_new("declarative", "declarative-source-v1", BTreeMap::new())
                .map_err(|_| error("invalid source format"))?,
            fields,
            DecodeAnnotationsV1::try_new(false, Vec::new(), Some(original))
                .map_err(|_| error("invalid source annotations"))?,
        )
        .map_err(|_| error("source record exceeds limits"))
    }
    fn fields(&self, bytes: &[u8], header: Option<&[String]>) -> Result<SourceValue, AppError> {
        let parser = &self.0;
        let pairs: Vec<(String, SourceValue)> = match parser.definition.input.format {
            Format::Json | Format::Ndjson => {
                return irmind_app::source_mapping::json::decode_json_fields(
                    bytes,
                    irmind_app::source_mapping::json::SourceJsonLimits {
                        bytes: parser.definition.limits.record_bytes,
                        depth: parser.definition.limits.depth,
                        fields: parser.definition.limits.fields,
                        nodes: parser
                            .definition
                            .limits
                            .fields
                            .saturating_add(1)
                            .min(irmind_domain::SOURCE_MAX_NODES),
                    },
                )
                .map_err(|_| error("invalid JSON source or parser limit"));
            }
            Format::Csv => {
                let values = parser.csv_values(bytes)?;
                if header.is_some_and(|h| h.len() != values.len()) {
                    return Err(error("CSV column count differs from header"));
                }
                values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        (
                            header.map_or_else(|| i.to_string(), |h| h[i].clone()),
                            SourceValue::Text(v),
                        )
                    })
                    .collect()
            }
            Format::Regex => {
                let text = std::str::from_utf8(bytes).map_err(|_| error("invalid source UTF-8"))?;
                let regex = parser
                    .input_regex
                    .as_ref()
                    .ok_or_else(|| error("regex input is unavailable"))?;
                let captures = regex
                    .captures(text.trim_end_matches(['\r', '\n']))
                    .ok_or_else(|| error("record does not match declared pattern"))?;
                regex
                    .capture_names()
                    .flatten()
                    .filter_map(|name| {
                        captures
                            .name(name)
                            .map(|v| (name.into(), SourceValue::Text(v.as_str().into())))
                    })
                    .collect()
            }
        };
        if pairs.len() > parser.definition.limits.fields {
            return Err(error("source field limit exceeded"));
        }
        SourceValue::object(pairs).map_err(|_| error("invalid source fields"))
    }
}
fn reject(report: &mut ParseReport, bytes: &[u8]) {
    report.rejected += 1;
    if report.samples.len() < 3 {
        report.samples.push(
            String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}
