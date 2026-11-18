//! Read-only gzip counting. No decoded evidence is written during admission.
use irmind_app::source_mapping::{NormalizedExpansionProfile, NormalizedSourceBudget};
use irmind_app::{AppError, CancellationToken, FixedAppError};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
pub(super) fn preflight(
    file: &mut File,
    cancel: &CancellationToken,
) -> Result<NormalizedSourceBudget, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let size = file.metadata().map_err(|_| invalid())?.len();
    if size > NormalizedSourceBudget::MAX_DECODED_BYTES {
        return Err(limit());
    }
    file.rewind().map_err(|_| invalid())?;
    let mut magic = [0u8; 2];
    if size >= 2 {
        file.read_exact(&mut magic).map_err(|_| invalid())?;
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| invalid())?;
    let decoded = if size >= 2 && magic == [0x1f, 0x8b] {
        count_gzip(file, cancel)?
    } else {
        size
    };
    NormalizedSourceBudget::try_new(decoded, NormalizedExpansionProfile::CompactFlow32)
}
fn count_gzip(file: &mut File, cancel: &CancellationToken) -> Result<u64, AppError> {
    let compressed = crate::gzip::bounded(file, cancel);
    let gzip = flate2::read::MultiGzDecoder::new(compressed);
    let mut reader = crate::gzip::bounded(gzip, cancel);
    let mut buffer = vec![0u8; 32768].into_boxed_slice();
    let mut bytes = 0u64;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(n) => bytes = bytes.checked_add(n as u64).ok_or_else(limit)?,
            Err(_) if cancel.is_cancelled() => return Err(AppError::Cancelled),
            Err(_) if reader.exceeded() || reader.inner().get_ref().exceeded() => {
                return Err(limit());
            }
            Err(_) => return Err(invalid()),
        }
    }
}
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn limit() -> AppError {
    AppError::Fixed(FixedAppError::SourceLimit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        out.write_all(bytes).unwrap();
        out.finish().unwrap()
    }
    fn run(bytes: &[u8], cancel: &CancellationToken) -> Result<NormalizedSourceBudget, AppError> {
        let case = tempfile::tempdir().unwrap();
        let source = case.path().join("synthetic-source");
        std::fs::write(&source, bytes).unwrap();
        let mut file = File::open(&source).unwrap();
        let before = std::fs::read_dir(case.path()).unwrap().count();
        let result = preflight(&mut file, cancel);
        assert_eq!(before, std::fs::read_dir(case.path()).unwrap().count());
        assert_eq!(std::fs::read(source).unwrap(), bytes);
        result
    }
    #[test]
    fn plain_gzip_and_concatenated_members_have_the_same_decoded_allowance() {
        let first = b"synthetic first member\n";
        let second = b"synthetic second member\n";
        let cancel = CancellationToken::new();
        let plain = [first.as_slice(), second.as_slice()].concat();
        let members = [gzip(first), gzip(second)].concat();
        let expected = run(&plain, &cancel).unwrap();
        assert_eq!(expected.decoded_bytes(), plain.len() as u64);
        assert_eq!(run(&gzip(&plain), &cancel).unwrap(), expected);
        assert_eq!(run(&members, &cancel).unwrap(), expected);
    }
    #[test]
    fn corrupt_gzip_and_cancelled_preflight_fail_without_writes() {
        let mut bytes = gzip(b"synthetic evidence");
        let crc = bytes.len() - 8;
        bytes[crc] ^= 1;
        assert!(matches!(
            run(&bytes, &CancellationToken::new()),
            Err(AppError::Fixed(FixedAppError::SourceFormat))
        ));
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(run(&bytes, &cancel), Err(AppError::Cancelled)));
    }
    #[cfg(unix)]
    #[test]
    fn sparse_source_over_the_decoded_ceiling_is_rejected_before_reading() {
        let case = tempfile::tempdir().unwrap();
        let path = case.path().join("synthetic-sparse");
        File::create(&path)
            .unwrap()
            .set_len(NormalizedSourceBudget::MAX_DECODED_BYTES + 1)
            .unwrap();
        let mut file = File::open(path).unwrap();
        assert!(matches!(
            preflight(&mut file, &CancellationToken::new()),
            Err(AppError::Fixed(FixedAppError::SourceLimit))
        ));
    }
}
