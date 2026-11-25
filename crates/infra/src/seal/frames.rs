use super::export_current::MAX_FRAME_BYTES;
use super::{AppError, CancellationToken, hex, storage, storage_reason};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

pub(super) fn read_frame(input: &mut File) -> Result<Vec<u8>, AppError> {
    let length = read_u64(input)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(storage_reason("invalid export metadata frame length"));
    }
    let mut bytes = vec![0u8; usize::try_from(length).map_err(storage)?];
    input.read_exact(&mut bytes).map_err(storage)?;
    Ok(bytes)
}

pub(super) fn read_u64(input: &mut File) -> Result<u64, AppError> {
    let mut bytes = [0u8; 8];
    input.read_exact(&mut bytes).map_err(storage)?;
    Ok(u64::from_be_bytes(bytes))
}

pub(super) fn read_hash(input: &mut File) -> Result<String, AppError> {
    let mut bytes = [0u8; 64];
    input.read_exact(&mut bytes).map_err(storage)?;
    let hash = std::str::from_utf8(&bytes).map_err(storage)?;
    irmind_domain::EvidenceHash::parse(hash).map_err(|_| storage_reason("invalid export hash"))?;
    Ok(hash.into())
}

pub(super) fn verify_raw(input: &mut File, size: u64, expected: &str) -> Result<(), AppError> {
    verify_raw_with_cancel(input, size, expected, None)
}

pub(super) fn verify_raw_with_cancel(
    input: &mut File,
    size: u64,
    expected: &str,
    cancel: Option<&CancellationToken>,
) -> Result<(), AppError> {
    verify_raw_guarded(input, size, expected, || {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            Err(AppError::Cancelled)
        } else {
            Ok(())
        }
    })
}

pub(super) fn verify_raw_guarded(
    input: &mut File,
    size: u64,
    expected: &str,
    mut check: impl FnMut() -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut left = size;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    while left > 0 {
        check()?;
        let count = usize::try_from(left.min(chunk.len() as u64)).map_err(storage)?;
        input.read_exact(&mut chunk[..count]).map_err(storage)?;
        hasher.update(&chunk[..count]);
        left -= count as u64;
    }
    check()?;
    if hex(&hasher.finalize()) != expected {
        return Err(AppError::EvidenceMismatch(expected.into()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{Seek, Write};

    #[test]
    fn verification_stops_between_hash_chunks() {
        let bytes = vec![0x53; 2 * 1024 * 1024];
        let expected = hex(&Sha256::digest(&bytes));
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        file.rewind().unwrap();
        let mut checks = 0;
        let stopped = verify_raw_guarded(&mut file, bytes.len() as u64, &expected, || {
            checks += 1;
            if checks == 2 {
                Err(AppError::Cancelled)
            } else {
                Ok(())
            }
        });
        assert!(matches!(stopped, Err(AppError::Cancelled)));
        assert_eq!(file.stream_position().unwrap(), 1024 * 1024);
        file.rewind().unwrap();
        verify_raw(&mut file, bytes.len() as u64, &expected).unwrap();
    }
}
