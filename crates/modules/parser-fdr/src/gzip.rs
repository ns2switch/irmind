use flate2::read::MultiGzDecoder;
use irmind_app::CancellationToken;
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

pub(super) struct Bounded<'a, R> {
    inner: R,
    bytes: u64,
    limit: u64,
    cancel: &'a CancellationToken,
    exceeded: bool,
}
pub(super) fn bounded<R: Read>(inner: R, cancel: &CancellationToken, limit: u64) -> Bounded<'_, R> {
    Bounded {
        inner,
        bytes: 0,
        limit,
        cancel,
        exceeded: false,
    }
}
impl<R> Bounded<'_, R> {
    pub(super) fn exceeded(&self) -> bool {
        self.exceeded
    }
    pub(super) fn inner(&self) -> &R {
        &self.inner
    }
}
impl<R: Read> Read for Bounded<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.exceeded {
            return Err(io::Error::other("gzip size limit exceeded"));
        }
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("cancelled"));
        }
        let capacity = output.len().min(
            usize::try_from(self.limit.saturating_sub(self.bytes))
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        let count = self.inner.read(&mut output[..capacity])?;
        self.bytes = self.bytes.saturating_add(count as u64);
        if self.bytes > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("gzip size limit exceeded"));
        }
        Ok(count)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn decoded_ceiling_and_cancellation_are_enforced_between_reads() {
        let cancel = CancellationToken::new();
        let mut reader = bounded(Cursor::new(b"synthetic"), &cancel, 3);
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        assert!(reader.exceeded());
        let cancel = CancellationToken::new();
        let mut reader = bounded(Cursor::new(b"synthetic"), &cancel, 50);
        assert_eq!(reader.read(&mut [0u8; 2]).unwrap(), 2);
        cancel.cancel();
        assert!(reader.read(&mut [0u8; 2]).is_err());
    }
}
