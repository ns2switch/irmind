mod record;

use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceInput, SourceRecordV1,
        framed::{SourceFrameEmitter, text_frame},
    },
};
use irmind_domain::Tainted;
use std::io::BufReader;

pub struct S3AccessSourceDecoder;

const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
const MAX_ROW: u64 = 65_536;

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

impl SourceDecoder for S3AccessSourceDecoder {
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
        let cancel = input.metadata.cancel;
        let mut reader = BufReader::new(input.reader);
        let mut offset = 0;
        let mut state = SourceFrameEmitter::new(input.metadata, self.identity());
        state.decode_frames(
            budget,
            || loop {
                let Some((bytes, size)) = text_frame(&mut reader, cancel, MAX_SOURCE - offset)?
                else {
                    return Ok(None);
                };
                let start = offset;
                offset += size;
                if size > MAX_ROW || !bytes.iter().all(u8::is_ascii_whitespace) {
                    return Ok(Some((bytes, Some(start), ())));
                }
            },
            |bytes, ()| record::prepare(bytes),
            |()| 0,
            emit,
        )?;
        Ok(state.finish())
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    let sample = &sample[..sample.len().min(65_536)];
    sample
        .trim_ascii_start()
        .split(|&byte| byte == b'\n')
        .next()
        .is_some_and(|line| record::prepare(line).is_ok())
}
