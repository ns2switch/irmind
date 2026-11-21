use super::CancellationToken;
use flate2::read::MultiGzDecoder;
use irmind_app::source_mapping::BoundedSourceReader;
use std::io::{Cursor, Read};

const MAX_GZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(super) fn sample(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    // A detector inspects a bounded prefix, not the stream's validity.
    let _ = MultiGzDecoder::new(Cursor::new(input))
        .take(4096)
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
    fn decompressed_limit_and_cancellation_fail_closed() {
        let cancel = CancellationToken::new();
        let mut reader = BoundedSourceReader::new(Cursor::new(b"12345678"), &cancel, 4);
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        cancel.cancel();
        assert!(reader.read(&mut [0; 1]).is_err());
    }
}
