use flate2::read::MultiGzDecoder;
use irmind_app::CancellationToken;
use irmind_app::source_mapping::BoundedSourceReader;
use std::io::{Cursor, Read};

const MAX_GZIP_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub(super) fn sample(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    // A detector inspects a bounded prefix, not the stream's validity.
    let _ = MultiGzDecoder::new(Cursor::new(input))
        .take(65536)
        .read_to_end(&mut output);
    output
}

pub(super) fn bounded<R: Read>(inner: R, cancel: &CancellationToken) -> BoundedSourceReader<'_, R> {
    BoundedSourceReader::new(inner, cancel, MAX_GZIP_BYTES)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn decoded_ceiling_and_cancellation_are_enforced_between_reads() {
        let cancel = CancellationToken::new();
        let mut reader = BoundedSourceReader::new(Cursor::new(b"synthetic"), &cancel, 3);
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        assert!(reader.exceeded());
        let cancel = CancellationToken::new();
        let mut reader = bounded(Cursor::new(b"synthetic"), &cancel);
        assert_eq!(reader.read(&mut [0u8; 2]).unwrap(), 2);
        cancel.cancel();
        assert!(reader.read(&mut [0u8; 2]).is_err());
    }
}
