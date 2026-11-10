use crate::MAX_RECORD;
use std::io::{self, Write};

pub(super) struct Output<'a> {
    sink: &'a mut dyn Write,
    remaining: u64,
    budget: u64,
}
impl<'a> Output<'a> {
    pub(super) fn new(sink: &'a mut dyn Write, size: u64) -> Self {
        Self {
            sink,
            remaining: (size.saturating_mul(32).saturating_add(1 << 20)).min(8 << 30),
            budget: (size.saturating_mul(32).saturating_add(1 << 20)).min(8 << 30),
        }
    }
    pub(super) fn frame(&mut self, frame: &serde_json::Value) -> io::Result<()> {
        self.encoded(&encode(frame)?)
    }
    pub(super) fn encoded(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("EVTX output byte limit reached ({} bytes); entire file rejected; no partial ingestion", self.budget)))?;
        self.sink.write_all(bytes)
    }
    pub(super) fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}
pub(super) fn encode(frame: &serde_json::Value) -> io::Result<Vec<u8>> {
    let mut bytes = Frame(Vec::new());
    serde_json::to_writer(&mut bytes, frame).map_err(|_| limit())?;
    bytes.write_all(b"\n")?;
    Ok(bytes.0)
}

fn limit() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "EVTX frame byte limit reached (4194304 bytes); entire file rejected; no partial ingestion",
    )
}
struct Frame(Vec<u8>);
impl Write for Frame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_RECORD {
            return Err(limit());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
