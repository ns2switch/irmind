//! Decode original Zeek JSON or TSV columns and measured locations without classification.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceDecoderSelection, SourceDiscriminator, SourceFormatV1, SourceInput, SourceMetadata,
        SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, decode_json_source},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader},
    sync::Arc,
};
pub struct ZeekSourceDecoder;
impl SourceDecoder for ZeekSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-zeek",
            version: "zeek-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut reader = BufReader::new(input.reader);
        if reader.fill_buf().map_err(|_| invalid())?.starts_with(b"#") {
            tsv(&mut reader, input.metadata, emit)
        } else {
            decode_json_source(
                SourceInput {
                    reader: &mut reader,
                    metadata: input.metadata,
                },
                self.identity(),
                &mut json_frame,
                emit,
            )
        }
    }
}
fn json_frame(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    let raw = match fields.field("ts") {
        Some(SourceValue::Text(v)) => v.as_str(),
        Some(SourceValue::Number(v)) => v.as_str(),
        _ => return Err(invalid()),
    };
    let timestamp = IndexedTime::from_epoch_decimal(raw, false).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: format("zeek-json", None)?,
    })
}
fn format(id: &str, dataset: Option<&str>) -> Result<SourceFormatV1, AppError> {
    SourceFormatV1::try_new(
        id,
        "zeek-source-v1",
        dataset
            .map(|v| (SourceDiscriminator::Dataset, v.into()))
            .into_iter()
            .collect(),
    )
    .map_err(|_| invalid())
}
fn tsv(
    reader: &mut impl BufRead,
    metadata: SourceMetadata<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut header = crate::stream::TsvHeader::default();
    let mut state = SourceFrameEmitter::new(metadata, ZeekSourceDecoder.identity());
    let mut offset = 0u64;
    loop {
        let (bytes, size) = crate::stream::bounded_line(reader, metadata.cancel)?;
        if size == 0 {
            return Ok(state.finish());
        }
        let start = offset;
        offset = offset.checked_add(size).ok_or_else(limit)?;
        if offset > 50 * 1024 * 1024 * 1024 {
            return Err(limit());
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if bytes.len() <= 4 * 1024 * 1024 && header.metadata(&bytes)? {
            continue;
        }
        let decoded = tsv_frame(&bytes, &header);
        state.frame(&bytes, Some(start), decoded, emit)?;
    }
}
fn tsv_frame(
    bytes: &[u8],
    header: &crate::stream::TsvHeader,
) -> Result<DecodedSourceFrame, AppError> {
    if bytes.len() > 4 * 1024 * 1024
        || !header.ready()
        || header.fields.iter().collect::<BTreeSet<_>>().len() != header.fields.len()
    {
        return Err(invalid());
    }
    let raw = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .trim_end_matches(['\r', '\n']);
    let cells = raw.split('\t').collect::<Vec<_>>();
    if cells.len() != header.fields.len() {
        return Err(invalid());
    }
    let columns = SourceValue::object(
        header
            .fields
            .iter()
            .zip(cells)
            .map(|(k, v)| (k.clone(), SourceValue::Text(v.into())))
            .collect(),
    )
    .map_err(|_| invalid())?;
    let raw_time = columns
        .field("ts")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_epoch_decimal(raw_time, false).map_err(|_| invalid())?;
    let types = SourceValue::object(
        header
            .fields
            .iter()
            .cloned()
            .zip(header.types.iter().cloned().map(SourceValue::Text))
            .collect(),
    )
    .map_err(|_| invalid())?;
    let fields = SourceValue::object(vec![("columns".into(), columns), ("types".into(), types)])
        .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: format("zeek-tsv", header.path.as_deref())?,
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
fn limit() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceLimit)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(ZeekSourceDecoder))
            .with_detector(|source, sample| crate::ZeekParser.detect(source, sample)),
    )
}
