mod record;

use irmind_app::{
    AppError, CancellationToken, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceInput, SourceMetadata, SourceRecordV1,
        framed::{SourceFrameEmitter, text_frame},
    },
};
use irmind_domain::Tainted;
use std::io::{BufRead, BufReader, Cursor, Read};

pub struct ElbSourceDecoder;

const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
const MAX_GZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const GZIP: &[u8] = &[0x1f, 0x8b];

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

impl SourceDecoder for ElbSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: super::PARSER,
            version: super::VERSION,
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
        if reader.fill_buf().map_err(|_| invalid())?.starts_with(GZIP) {
            let mut compressed = CancelRead {
                reader,
                cancel: input.metadata.cancel,
            }
            .take(MAX_GZIP_BYTES + 1);
            let mut decoded = flate2::read::MultiGzDecoder::new(&mut compressed);
            let result = lines(&mut decoded, input.metadata, true, budget, emit);
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if compressed.limit() == 0 {
                return Err(AppError::Fixed(FixedAppError::SourceLimit));
            }
            result
        } else {
            lines(&mut reader, input.metadata, false, budget, emit)
        }
    }
}

struct CancelRead<'a, R> {
    reader: R,
    cancel: &'a CancellationToken,
}

impl<R: Read> Read for CancelRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(std::io::Error::other("source decoding cancelled"));
        }
        self.reader.read(buf)
    }
}

fn lines(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    compressed: bool,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let limit = if compressed {
        MAX_GZIP_BYTES
    } else {
        MAX_SOURCE
    };
    let mut reader = BufReader::new(reader);
    let mut offset = 0;
    let mut state = SourceFrameEmitter::new(metadata, ElbSourceDecoder.identity());
    state.decode_frames(
        budget,
        || loop {
            let Some((bytes, size)) = text_frame(&mut reader, metadata.cancel, limit - offset)?
            else {
                return Ok(None);
            };
            let start = offset;
            offset += size;
            if size > 65_536 || !bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(Some((bytes, (!compressed).then_some(start), ())));
            }
        },
        |bytes, ()| record::prepare(bytes),
        |()| 0,
        emit,
    )?;
    Ok(state.finish())
}

pub(super) fn detect(sample: &[u8]) -> bool {
    let sample = &sample[..sample.len().min(65_536)];
    let mut expanded = Vec::new();
    let text = if sample.starts_with(GZIP) {
        let _ = flate2::read::MultiGzDecoder::new(Cursor::new(sample))
            .take(8192)
            .read_to_end(&mut expanded);
        expanded.as_slice()
    } else {
        sample
    };
    text.trim_ascii_start()
        .split(|&byte| byte == b'\n')
        .next()
        .is_some_and(|line| record::prepare(line).is_ok())
}
