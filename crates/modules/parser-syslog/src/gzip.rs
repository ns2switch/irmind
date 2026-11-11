use super::CancellationToken;
use flate2::read::MultiGzDecoder;
use std::io::{self, Cursor, Read};

const MAX_GZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(super) fn sample(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    // A detector inspects a bounded prefix, not the stream's validity.
    let _ = MultiGzDecoder::new(Cursor::new(input))
        .take(4096)
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
pub(super) fn bounded<R: Read>(inner: R, cancel: &CancellationToken) -> Bounded<'_, R> {
    Bounded {
        inner,
        bytes: 0,
        limit: MAX_GZIP_BYTES,
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
    fn decompressed_limit_and_cancellation_fail_closed() {
        let cancel = CancellationToken::new();
        let mut reader = Bounded {
            inner: Cursor::new(b"12345678"),
            bytes: 0,
            limit: 4,
            cancel: &cancel,
            exceeded: false,
        };
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        cancel.cancel();
        assert!(reader.read(&mut [0; 1]).is_err());
    }
}
