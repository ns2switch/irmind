//! Only wholly valid frames with bounded, exact replay locators are eligible.
//! Otherwise use ordinary decoding for exact rejection and offset behavior.
use super::{AzureFlowSourceDecoder, SourceValue, invalid, prepare, tuples};
use irmind_app::{
    AppError, FixedAppError, SourceDecoder,
    source_mapping::{
        CompactRecordLocator, CompactSourceOrdering, CompactSourceReplay, SourceFileInput,
        SourceInput, SourceMetadata, SourceRecordV1,
        framed::{SourceFrameEmitter, has_json_document_framing},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::Tainted;
use std::io::{BufRead, BufReader, Read as _, Seek as _, SeekFrom};

const FRAME_LIMIT: usize = 64 * 1024;
const SOURCE_LIMIT: u64 = 50 * 1024 * 1024 * 1024;
const RECORD_LIMIT: u64 = 10_000_000;

impl CompactSourceOrdering for AzureFlowSourceDecoder {
    fn scan(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(CompactRecordLocator) -> Result<(), AppError>,
    ) -> Result<bool, AppError> {
        let mut reader = BufReader::new(input.reader);
        let cancel = input.metadata.cancel;
        let keys = &["records"];
        let document = has_json_document_framing(
            &mut reader,
            input.metadata.source.reference(),
            keys,
            cancel,
        )?;
        let mut index = 0;
        let mut visit = |start, bytes: &[u8]| scan_frame(start, bytes, &mut index, emit);
        let accepted = if document {
            let mut limited = reader.take(SOURCE_LIMIT + 1);
            let mut frames = JsonFrames::new(&mut limited, cancel).with_record_array_keys(keys)?;
            loop {
                match frames.next_frame() {
                    Ok(Some(frame)) if !frame.oversized() && frame.bytes().len() <= FRAME_LIMIT => {
                        if !visit(frame.offset(), frame.bytes())? {
                            return Ok(false);
                        }
                    }
                    Ok(None) => break limited.limit() != 0,
                    Err(AppError::Cancelled) => return Err(AppError::Cancelled),
                    _ => return Ok(false),
                }
            }
        } else {
            scan_lines(&mut reader, cancel, &mut visit)?
        };
        Ok(accepted && index != 0)
    }

    fn replay<'a>(&self, input: SourceFileInput<'a>) -> Box<dyn CompactSourceReplay + 'a> {
        Box::new(Replay {
            metadata: input.metadata,
            file: input.file,
            cached: None,
        })
    }
}

fn scan_lines(
    reader: &mut impl BufRead,
    cancel: &irmind_app::CancellationToken,
    visit: &mut impl FnMut(u64, &[u8]) -> Result<bool, AppError>,
) -> Result<bool, AppError> {
    let mut bytes = Vec::new();
    let mut offset = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        bytes.clear();
        let len = reader
            .by_ref()
            .take((FRAME_LIMIT + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| AppError::Fixed(FixedAppError::SourceFormat))?;
        if len == 0 {
            return Ok(true);
        }
        if len > FRAME_LIMIT || offset + len as u64 > SOURCE_LIMIT {
            return Ok(false);
        }
        if !bytes.iter().all(u8::is_ascii_whitespace) && !visit(offset, &bytes)? {
            return Ok(false);
        }
        offset += len as u64;
    }
}

fn scan_frame(
    offset: u64,
    bytes: &[u8],
    index: &mut u64,
    emit: &mut dyn FnMut(CompactRecordLocator) -> Result<(), AppError>,
) -> Result<bool, AppError> {
    let Some(fields) = eligible_fields(bytes) else {
        return Ok(false);
    };
    let (vnet, version, flows) = tuples::layout(&fields);
    let Some(version) = version else {
        return Ok(false);
    };
    let hash = irmind_app::sha256(bytes);
    let mut ordinal = 0u32;
    for flow in tuples::array(flows) {
        for group in tuples::array(flow.field(if vnet { "flowGroups" } else { "flows" })) {
            for value in tuples::array(group.field("flowTuples")) {
                let Some(time) = tuple_time(value, vnet, version) else {
                    return Ok(false);
                };
                if *index == RECORD_LIMIT {
                    return Ok(false);
                }
                emit(CompactRecordLocator {
                    time,
                    index: *index,
                    frame_start: offset,
                    frame_len: u32::try_from(bytes.len()).map_err(|_| invalid())?,
                    frame_hash: hash,
                    tuple: ordinal,
                })?;
                ordinal += 1;
                *index += 1;
            }
        }
    }
    Ok(ordinal != 0)
}

fn eligible_fields(bytes: &[u8]) -> Option<SourceValue> {
    // A much smaller node/depth bound guarantees that adding the tuple
    // fields and copying the bounded originals fits SourceRecord's limits.
    let mut fields = decode_json_fields(
        bytes,
        SourceJsonLimits {
            depth: 20,
            nodes: 384,
            ..SourceJsonLimits::default()
        },
    )
    .ok()?;
    if fields.field("records").is_some()
        || fields
            .field("properties")
            .is_some_and(|v| !matches!(v, SourceValue::Object(_)))
    {
        return None;
    }
    // Share the original validation of the envelope category and time.
    fields = prepare(fields).ok()?.fields;
    Some(fields)
}

fn tuple_time(value: &SourceValue, vnet: bool, version: u16) -> Option<irmind_domain::IndexedTime> {
    let text = value.as_text()?;
    let mut columns = text.split(',');
    let time = tuples::timestamp(vnet, columns.next()?).ok()?;
    let count = tuples::column_count(vnet, version);
    (columns.take(count).count() + 1 == count).then_some(time)
}

struct Replay<'a> {
    metadata: SourceMetadata<'a>,
    file: &'a mut std::fs::File,
    cached: Option<(u64, u32, [u8; 32], Tainted<SourceRecordV1>)>,
}

impl CompactSourceReplay for Replay<'_> {
    fn read(&mut self, locator: CompactRecordLocator) -> Result<Tainted<SourceRecordV1>, AppError> {
        if self.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let frame = (locator.frame_start, locator.frame_len, locator.frame_hash);
        let emitter = SourceFrameEmitter::new(self.metadata, AzureFlowSourceDecoder.identity());
        if self
            .cached
            .as_ref()
            .is_none_or(|(start, len, hash, _)| (*start, *len, *hash) != frame)
        {
            let length = locator.frame_len as usize;
            if length == 0 || length > FRAME_LIMIT {
                return Err(invalid());
            }
            self.file
                .seek(SeekFrom::Start(locator.frame_start))
                .map_err(|error| AppError::Storage(error.to_string()))?;
            let mut bytes = vec![0; length];
            self.file
                .read_exact(&mut bytes)
                .map_err(|error| AppError::Storage(error.to_string()))?;
            if irmind_app::sha256(&bytes) != locator.frame_hash {
                return Err(AppError::EvidenceMismatch(irmind_app::hex(
                    &self.metadata.evidence_hash,
                )));
            }
            let fields = eligible_fields(&bytes).ok_or_else(invalid)?;
            let record = emitter.record_at(prepare(fields)?, Some(locator.frame_start), 0, 0)?;
            self.cached = Some((frame.0, frame.1, frame.2, record));
        }
        let mut result = Err(invalid());
        self.cached
            .as_ref()
            .ok_or_else(invalid)?
            .3
            .inspect(|source| {
                result = replay_tuple(source, &emitter, locator);
            });
        result
    }
}

fn replay_tuple(
    source: &SourceRecordV1,
    emitter: &SourceFrameEmitter<'_>,
    locator: CompactRecordLocator,
) -> Result<Tainted<SourceRecordV1>, AppError> {
    let (vnet, version, flows) = tuples::layout(source.fields());
    let version = version.ok_or_else(invalid)?;
    let mut ordinal = locator.tuple as usize;
    for flow in tuples::array(flows) {
        for group in tuples::array(flow.field(if vnet { "flowGroups" } else { "flows" })) {
            let values = tuples::array(group.field("flowTuples"));
            if let Some(value) = values.get(ordinal) {
                let tuple = value.as_text().ok_or_else(invalid)?;
                let decoded = tuples::prepare(source, vnet, version, flow, group, tuple)?;
                if decoded.timestamp != Some(locator.time) {
                    return Err(invalid());
                }
                return emitter.record_at(decoded, None, locator.index, locator.index);
            }
            ordinal -= values.len();
        }
    }
    Err(invalid())
}
