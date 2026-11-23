//! Only simple, wholly valid line framing is eligible. Any other source uses
//! the ordinary decoder so that rejection, envelope and offset rules stay exact.
use super::{AzureFlowSourceDecoder, SourceValue, invalid, prepare, tuples};
use irmind_app::{
    AppError, FixedAppError, SourceDecoder,
    source_mapping::{
        CompactRecordLocator, CompactSourceOrdering, CompactSourceReplay, SourceFileInput,
        SourceInput, SourceMetadata, SourceRecordV1,
        framed::SourceFrameEmitter,
        json::{SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::Tainted;
use std::io::{BufRead, BufReader, Read as _, Seek as _, SeekFrom};

const FRAME_LIMIT: usize = 64 * 1024;
const RECORD_LIMIT: u64 = 10_000_000;

impl CompactSourceOrdering for AzureFlowSourceDecoder {
    fn scan(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(CompactRecordLocator) -> Result<(), AppError>,
    ) -> Result<bool, AppError> {
        let path = std::path::Path::new(input.metadata.source.reference());
        if !path.extension().is_some_and(|ext| {
            ext.eq_ignore_ascii_case("ndjson") || ext.eq_ignore_ascii_case("jsonl")
        }) {
            return Ok(false);
        }
        let mut reader = BufReader::new(input.reader);
        let mut bytes = Vec::new();
        let mut offset = 0u64;
        let mut index = 0u64;
        loop {
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            bytes.clear();
            let len = (&mut reader)
                .take((FRAME_LIMIT + 1) as u64)
                .read_until(b'\n', &mut bytes)
                .map_err(|_| AppError::Fixed(FixedAppError::SourceFormat))?;
            if len == 0 {
                return Ok(index != 0);
            }
            if len > FRAME_LIMIT {
                return Ok(false);
            }
            let Some(fields) = eligible_fields(&bytes) else {
                return Ok(false);
            };
            let (vnet, version, flows) = tuples::layout(&fields);
            let Some(version) = version else {
                return Ok(false);
            };
            let hash = irmind_app::sha256(&bytes);
            let mut ordinal = 0u32;
            for flow in tuples::array(flows) {
                for group in tuples::array(flow.field(if vnet { "flowGroups" } else { "flows" })) {
                    for value in tuples::array(group.field("flowTuples")) {
                        let Some(time) = tuple_time(value, vnet, version) else {
                            return Ok(false);
                        };
                        if index == RECORD_LIMIT {
                            return Ok(false);
                        }
                        emit(CompactRecordLocator {
                            time,
                            index,
                            frame_start: offset,
                            frame_len: u32::try_from(len).map_err(|_| invalid())?,
                            frame_hash: hash,
                            tuple: ordinal,
                        })?;
                        ordinal += 1;
                        index += 1;
                    }
                }
            }
            if ordinal == 0 {
                return Ok(false);
            }
            offset = offset.checked_add(len as u64).ok_or_else(invalid)?;
        }
    }

    fn replay<'a>(&self, input: SourceFileInput<'a>) -> Box<dyn CompactSourceReplay + 'a> {
        Box::new(Replay {
            metadata: input.metadata,
            file: input.file,
            cached: None,
        })
    }
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
        if !self
            .cached
            .as_ref()
            .is_some_and(|(start, len, hash, _)| (*start, *len, *hash) == frame)
        {
            let length = locator.frame_len as usize;
            if length == 0 || length > FRAME_LIMIT {
                return Err(invalid());
            }
            self.file
                .seek(SeekFrom::Start(locator.frame_start))
                .map_err(read_error)?;
            let mut bytes = vec![0; length];
            self.file.read_exact(&mut bytes).map_err(read_error)?;
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

fn read_error(error: std::io::Error) -> AppError {
    AppError::Storage(error.to_string())
}
