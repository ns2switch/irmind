//! Count a complete gzip stream before reserving case disk space.
use crate::{decode::MAX_SOURCE, gzip};
use irmind_app::{
    AppError, CancellationToken, FixedAppError,
    source_mapping::{NormalizedExpansionProfile, NormalizedSourceBudget},
};
use std::{
    fs::File,
    io::{Read, Seek},
};

const COUNT_BUFFER_BYTES: usize = 16 * 1024;

pub(super) fn preflight(
    file: &mut File,
    cancel: &CancellationToken,
) -> Result<NormalizedSourceBudget, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let size = file.metadata().map_err(|_| invalid())?.len();
    if size > MAX_SOURCE {
        return Err(limit());
    }
    file.rewind().map_err(|_| invalid())?;
    let (prefix, count) = gzip::prefix(file).map_err(|_| invalid())?;
    let decoded = if prefix == [0x1f, 0x8b] {
        count_gzip(prefix[..count].chain(file), cancel)?
    } else {
        size
    };
    NormalizedSourceBudget::try_new(decoded, NormalizedExpansionProfile::DecodedJson16)
}

fn count_gzip(reader: impl Read, cancel: &CancellationToken) -> Result<u64, AppError> {
    let compressed = gzip::bounded(reader, cancel, MAX_SOURCE);
    let gzip = flate2::read::MultiGzDecoder::new(compressed);
    let mut reader = gzip::bounded(gzip, cancel, MAX_SOURCE);
    // Reused for every member and every read, regardless of decoded size.
    let mut buffer = [0; COUNT_BUFFER_BYTES];
    let mut bytes = 0u64;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(count) => bytes = bytes.checked_add(count as u64).ok_or_else(limit)?,
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
    use std::io::Write as _;

    #[test]
    fn count_reuses_fixed_buffer_across_members_and_validates_the_last_trailer() {
        // Generate a large decoded stream on disk without allocating its body.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic.gz");
        let mut file = File::create(&path).unwrap();
        let block = [b'a'; COUNT_BUFFER_BYTES];
        let blocks_per_member = 2048;
        for _ in 0..2 {
            let mut gzip = flate2::write::GzEncoder::new(&mut file, flate2::Compression::fast());
            for _ in 0..blocks_per_member {
                gzip.write_all(&block).unwrap();
            }
            gzip.finish().unwrap();
        }
        drop(file);
        let cancel = CancellationToken::new();
        let before = std::fs::metadata(&path).unwrap().len();
        let count = preflight(&mut File::open(&path).unwrap(), &cancel).unwrap();
        assert_eq!(
            count.decoded_bytes(),
            (2 * blocks_per_member * COUNT_BUFFER_BYTES) as u64
        );
        assert_eq!(
            count.allowance().unwrap(),
            count.decoded_bytes() * 16 + 64 * 1024 * 1024
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(before - 1)
            .unwrap();
        assert!(matches!(
            preflight(&mut File::open(&path).unwrap(), &cancel),
            Err(AppError::Fixed(FixedAppError::SourceFormat))
        ));
        cancel.cancel();
        assert!(matches!(
            preflight(&mut File::open(&path).unwrap(), &cancel),
            Err(AppError::Cancelled)
        ));
    }
}
