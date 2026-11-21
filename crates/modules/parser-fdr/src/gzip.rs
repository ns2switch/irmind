use flate2::read::MultiGzDecoder;
use std::io::{self, Cursor, Read};

/// Read the magic without assuming the input fills a single read.
pub(super) fn prefix(reader: &mut impl Read) -> io::Result<([u8; 2], usize)> {
    let mut prefix = [0; 2];
    let mut count = 0;
    while count < prefix.len() {
        match reader.read(&mut prefix[count..]) {
            Ok(0) => break,
            Ok(bytes) => count += bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok((prefix, count))
}

pub(super) fn sample(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    // A detector inspects a bounded prefix, not the stream's validity.
    let _ = MultiGzDecoder::new(Cursor::new(input))
        .take(65536)
        .read_to_end(&mut output);
    output
}

pub(super) use irmind_app::source_mapping::BoundedSourceReader;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::CancellationToken;
    #[test]
    fn decoded_ceiling_and_cancellation_are_enforced_between_reads() {
        let cancel = CancellationToken::new();
        let mut reader = BoundedSourceReader::new(Cursor::new(b"synthetic"), &cancel, 3);
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        assert!(reader.exceeded());
        let cancel = CancellationToken::new();
        let mut reader = BoundedSourceReader::new(Cursor::new(b"synthetic"), &cancel, 50);
        assert_eq!(reader.read(&mut [0u8; 2]).unwrap(), 2);
        cancel.cancel();
        assert!(reader.read(&mut [0u8; 2]).is_err());
    }
}
