//! Original CSV/JSON fields and timestamps; interpretation belongs to a mapping module.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceDecoderSelection, SourceDiscriminator, SourceFormatV1,
        SourceInput, SourceMetadata, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, decode_json_source, source_datetime},
    },
};
use irmind_domain::Tainted;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    sync::Arc,
};
pub struct HayabusaSourceDecoder;
impl SourceDecoder for HayabusaSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-hayabusa",
            version: "hayabusa-source-v1",
        }
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
        let input = input.into_reader();
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut reader = BufReader::new(input.reader);
        if reader
            .fill_buf()
            .map_err(|_| invalid())?
            .starts_with(b"Timestamp,")
        {
            csv_decode(&mut reader, input.metadata, budget, emit)
        } else {
            let context = input.metadata.time_context;
            decode_json_source(
                SourceInput {
                    metadata: input.metadata,
                    reader: &mut reader,
                },
                self.identity(),
                budget,
                &|fields| frame(fields, context, "json", "timeline"),
                emit,
            )
        }
    }
}
fn csv_decode(
    reader: &mut impl BufRead,
    metadata: SourceMetadata<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let (header, size) = super::csv::csv_record(reader, metadata.cancel)?;
    if size == 0 || header.len() > irmind_domain::SOURCE_MAX_BYTES {
        return Err(invalid());
    }
    let headers = super::csv::decode_csv(&header)?;
    if headers.len() > 1024 || headers.iter().collect::<BTreeSet<_>>().len() != headers.len() {
        return Err(invalid());
    }
    if !["Timestamp", "RuleTitle", "Computer"]
        .iter()
        .all(|k| headers.iter().any(|v| v == *k))
    {
        return Err(invalid());
    }
    let dataset = "timeline";
    let mut state = SourceFrameEmitter::new(metadata, HayabusaSourceDecoder.identity());
    let mut offset = size;
    state.decode_frames(
        budget,
        || {
            let (bytes, size) = super::csv::csv_record(reader, metadata.cancel)?;
            if size == 0 {
                return Ok(None);
            }
            let start = offset;
            offset = offset.checked_add(size).ok_or_else(invalid)?;
            if offset > 50 * 1024 * 1024 * 1024 {
                return Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit));
            }
            Ok(Some((bytes, Some(start), ())))
        },
        |bytes, ()| {
            csv_fields(&headers, bytes)
                .and_then(|fields| frame(fields, metadata.time_context, "csv", dataset))
        },
        emit,
    )?;
    Ok(state.finish())
}

fn csv_fields(headers: &::csv::StringRecord, bytes: &[u8]) -> Result<SourceValue, AppError> {
    if bytes.len() > irmind_domain::SOURCE_MAX_BYTES {
        return Err(invalid());
    }
    let values = super::csv::decode_csv(bytes)?;
    if values.len() != headers.len() {
        return Err(invalid());
    }
    SourceValue::object(
        headers
            .iter()
            .zip(values.iter())
            .map(|(k, v)| (k.to_owned(), SourceValue::Text(v.to_owned())))
            .collect(),
    )
    .map_err(|_| invalid())
}
fn frame(
    fields: SourceValue,
    context: Option<&irmind_app::ParserTimeContext>,
    encoding: &str,
    dataset: &str,
) -> Result<DecodedSourceFrame, AppError> {
    let raw = fields
        .field("Timestamp")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = source_datetime(raw, context)?;
    let format = SourceFormatV1::try_new(
        &format!("hayabusa-{encoding}"),
        "hayabusa-source-v1",
        BTreeMap::from([(SourceDiscriminator::Dataset, dataset.into())]),
    )
    .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format,
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(HayabusaSourceDecoder))
            .with_detector(|source, sample| super::HayabusaParser.detect(source, sample))
            .with_time_detector(|source, sample| {
                super::HayabusaParser.time_context_requirement(source, sample)
            }),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::source_mapping::SourceReferenceV1;
    use irmind_app::{CancellationToken, sha256};
    use std::{io::Cursor, num::NonZeroUsize};

    #[test]
    fn parallel_csv_preserves_quoted_newlines_rejections_and_original_offsets() {
        let header = "Timestamp,RuleTitle,Computer,Details\r\n";
        let first = "2026-11-01T00:00:00Z,Synthetic,host,\"line one\r\nline two\"\r\n";
        let bad = "invalid,Rejected,host,synthetic\r\n";
        let last = "2026-11-01T00:01:00Z,Other,host,synthetic\r\n";
        let input = format!("{header}{first}{bad}{last}");
        let cancel = CancellationToken::new();
        let source = SourceReferenceV1::file("synthetic.csv").unwrap();
        let decode = |workers| {
            let mut seen = Vec::new();
            let report = HayabusaSourceDecoder
                .decode_with_budget(
                    DecodeInput::Reader(SourceInput {
                        metadata: SourceMetadata {
                            source: &source,
                            evidence_hash: sha256(input.as_bytes()),
                            time_context: None,
                            cancel: &cancel,
                        },
                        reader: &mut Cursor::new(input.as_bytes()),
                    }),
                    DecodeBudget::new(NonZeroUsize::new(workers).unwrap(), 1024 * 1024),
                    &mut |record| {
                        record.inspect(|row| {
                            let mut bytes = Vec::new();
                            row.feed_canonical(&mut |part| bytes.extend_from_slice(part));
                            seen.push((row.origin().offset(), sha256(&bytes)));
                        });
                        Ok(())
                    },
                )
                .unwrap();
            ((report.accepted, report.rejected, report.samples), seen)
        };
        let expected = decode(1);
        assert_eq!(expected.0.0, 2);
        assert_eq!(expected.0.1, 1);
        assert_eq!(expected.1[0].0, Some(header.len() as u64));
        assert_eq!(
            expected.1[1].0,
            Some((header.len() + first.len() + bad.len()) as u64)
        );
        assert_eq!(decode(4), expected);
    }
}
