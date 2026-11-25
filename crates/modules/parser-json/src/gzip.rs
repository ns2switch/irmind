use flate2::read::MultiGzDecoder;
use irmind_app::{
    AppError, CancellationToken, FixedAppError,
    source_mapping::{BoundedSourceReader, NormalizedExpansionProfile, NormalizedSourceBudget},
};
use std::{
    fs::File,
    io::{Cursor, Read, Seek},
};

const LIMIT: u64 = NormalizedSourceBudget::MAX_DECODED_BYTES;
pub(super) const SAMPLE_BYTES: usize = 64 * 1024;

pub(super) fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

pub(super) fn prefix(mut input: impl Read) -> Result<(bool, impl Read), AppError> {
    let mut prefix = Vec::with_capacity(2);
    (&mut input)
        .take(2)
        .read_to_end(&mut prefix)
        .map_err(|_| invalid())?;
    Ok((is_gzip(&prefix), Cursor::new(prefix).chain(input)))
}

pub(super) fn sample(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    // A truncated sample can positively identify the format. Admission reads
    // every member and verifies its trailer before reserving staging space.
    let _ = MultiGzDecoder::new(&input[..input.len().min(SAMPLE_BYTES)])
        .take(SAMPLE_BYTES as u64)
        .read_to_end(&mut output);
    output
}

pub(super) type Reader<'a, R> = BoundedSourceReader<'a, MultiGzDecoder<BoundedSourceReader<'a, R>>>;

pub(super) fn reader<R: Read>(input: R, cancel: &CancellationToken, ceiling: u64) -> Reader<'_, R> {
    let compressed = BoundedSourceReader::new(input, cancel, LIMIT);
    BoundedSourceReader::new(MultiGzDecoder::new(compressed), cancel, ceiling.min(LIMIT))
}

pub(super) fn check<R: Read, T>(
    input: &Reader<'_, R>,
    cancel: &CancellationToken,
    result: Result<T, AppError>,
) -> Result<T, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if input.exceeded() || input.inner().get_ref().exceeded() {
        return Err(AppError::Fixed(FixedAppError::SourceLimit));
    }
    result
}

pub(super) fn preflight(
    file: &mut File,
    cancel: &CancellationToken,
) -> Result<Option<NormalizedSourceBudget>, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let size = file.metadata().map_err(|_| invalid())?.len();
    file.rewind().map_err(|_| invalid())?;
    let (compressed, input) = prefix(file)?;
    if !compressed {
        return Ok(None);
    }
    if size > LIMIT {
        return Err(AppError::Fixed(FixedAppError::SourceLimit));
    }
    let mut input = reader(input, cancel, LIMIT);
    let mut buffer = [0; 16 * 1024];
    let mut decoded = 0u64;
    loop {
        let result = input.read(&mut buffer).map_err(|_| invalid());
        let count = check(&input, cancel, result)?;
        if count == 0 {
            break;
        }
        decoded += count as u64;
    }
    NormalizedSourceBudget::try_new(decoded, NormalizedExpansionProfile::DecodedJson16).map(Some)
}

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
