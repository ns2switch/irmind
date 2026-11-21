use crate::CancellationToken;
use std::io::{self, Read};

/// A cancellable reader with a separate byte ceiling at each transport or
/// decoding layer. A one-byte probe distinguishes exact-limit EOF from overflow.
pub struct BoundedSourceReader<'a, R> {
    inner: R,
    bytes: u64,
    limit: u64,
    cancel: &'a CancellationToken,
    exceeded: bool,
}
impl<'a, R> BoundedSourceReader<'a, R> {
    pub fn new(inner: R, cancel: &'a CancellationToken, limit: u64) -> Self {
        Self {
            inner,
            bytes: 0,
            limit,
            cancel,
            exceeded: false,
        }
    }
    pub fn exceeded(&self) -> bool {
        self.exceeded
    }
    pub fn inner(&self) -> &R {
        &self.inner
    }
}
impl<R: Read> Read for BoundedSourceReader<'_, R> {
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
        if count as u64 > self.limit - self.bytes {
            self.exceeded = true;
            return Err(io::Error::other("gzip size limit exceeded"));
        }
        self.bytes += count as u64;
        Ok(count)
    }
}
