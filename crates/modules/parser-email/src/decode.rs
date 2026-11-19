//! File size, MIME depth and header counts are enforced before library traversal.
use crate::{body, headers, invalid, limit, mime, number};
use irmind_app::{
    AppError, CancellationToken, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceDiscriminator, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::{collections::BTreeMap, io::Read};
pub struct EmailSourceDecoder;
pub(super) struct PendingFrame {
    pub kind: &'static str,
    pub fields: BTreeMap<String, SourceValue>,
    pub offset: Option<usize>,
    pub part: usize,
}
impl SourceDecoder for EmailSourceDecoder {
    fn normalized_source_budget(
        &self,
        file: &mut std::fs::File,
        cancel: &CancellationToken,
    ) -> Result<Option<irmind_app::source_mapping::NormalizedSourceBudget>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if file.metadata().map_err(|_| invalid())?.len() > 32 * 1024 * 1024 {
            return Err(limit());
        }
        Ok(None)
    }
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-email",
            version: "email-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let bytes = read_source(input.reader, input.metadata.cancel)?;
        let (frames, timestamp) = frames(&bytes, input.metadata.cancel)?;
        let mut output = SourceFrameEmitter::new(input.metadata, self.identity());
        // The stream contract is uniform: transformed MIME subrecords have no
        // physical byte offset. Preserve other exact positions as source fields.
        let physical_offsets = frames.iter().all(|frame| frame.offset.is_some());
        for mut frame in frames {
            if let Some(offset) = frame.offset {
                frame
                    .fields
                    .insert("source_byte_offset".into(), number(offset)?);
            }
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            frame
                .fields
                .insert("mime_part_index".into(), number(frame.part)?);
            let format = SourceFormatV1::try_new(
                "rfc5322",
                "email-source-v1",
                BTreeMap::from([(SourceDiscriminator::RecordType, frame.kind.into())]),
            )
            .map_err(|_| invalid())?;
            let fields =
                SourceValue::object(frame.fields.into_iter().collect()).map_err(|_| limit())?;
            let offset = if physical_offsets {
                frame.offset.map(|v| v as u64)
            } else {
                None
            };
            let sample_start = frame.offset.unwrap_or(0).min(bytes.len());
            let sample = &bytes[sample_start..(sample_start + 256).min(bytes.len())];
            output.frame(
                sample,
                offset,
                Ok(DecodedSourceFrame {
                    fields,
                    timestamp,
                    format,
                }),
                emit,
            )?;
        }
        Ok(output.finish())
    }
}
fn read_source(reader: &mut dyn Read, cancel: &CancellationToken) -> Result<Vec<u8>, AppError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let count = reader.read(&mut chunk).map_err(|_| {
            if cancel.is_cancelled() {
                AppError::Cancelled
            } else {
                invalid()
            }
        })?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() + count > 32 * 1024 * 1024 {
            return Err(limit());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}
fn frames(
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<(Vec<PendingFrame>, Option<IndexedTime>), AppError> {
    let mut pending = vec![mime::Part {
        start: 0,
        end: bytes.len(),
        depth: 0,
    }];
    let mut output = Vec::new();
    let mut parts = 0;
    let mut header_count = 0;
    let mut timestamp = None;
    while let Some(part) = pending.pop() {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if parts >= 256 {
            return Err(limit());
        }
        let bytes = bytes.get(part.start..part.end).ok_or_else(invalid)?;
        let mut headers = headers::parse(bytes, part.depth != 0)?;
        header_count += headers.count;
        if header_count > 1024 {
            return Err(limit());
        }
        if parts == 0 {
            timestamp = headers.time;
        }
        headers
            .fields
            .insert("mime_depth".into(), number(part.depth)?);
        headers.fields.insert(
            "declared_type".into(),
            SourceValue::Text(headers.media.clone()),
        );
        headers
            .fields
            .insert("raw_body_size".into(), number(bytes.len() - headers.body)?);
        headers.fields.insert(
            "raw_body_sha256".into(),
            SourceValue::Text(irmind_app::hex(&irmind_app::sha256(&bytes[headers.body..]))),
        );
        if headers.media.starts_with("multipart/") {
            if !matches!(headers.encoding.as_str(), "7bit" | "8bit" | "binary" | "") {
                return Err(invalid());
            }
            let boundary = headers.boundary.as_deref().ok_or_else(invalid)?;
            let children = mime::children(bytes, headers.body, boundary, part.depth, cancel)?;
            if pending.len() + children.len() + parts + 1 > 256 {
                return Err(limit());
            }
            for child in children.into_iter().rev() {
                pending.push(mime::Part {
                    start: part.start + child.start,
                    end: part.start + child.end,
                    depth: child.depth,
                });
            }
        } else {
            output.extend(body::leaf(bytes, &headers, part.start, parts, cancel)?);
        }
        output.push(PendingFrame {
            kind: "header",
            fields: headers.fields,
            offset: Some(part.start),
            part: parts,
        });
        parts += 1;
    }
    // Record order follows original offsets, with stable insertion order for
    // decoded content whose encoded byte offset cannot honestly be stated.
    output.sort_by_key(|frame| {
        (
            frame.part,
            usize::from(frame.kind != "header"),
            frame.offset,
        )
    });
    Ok((output, timestamp))
}
