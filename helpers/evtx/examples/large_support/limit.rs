use super::Error;
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    time::Instant,
};

#[derive(Default)]
struct Frames {
    records: u64,
    complete: bool,
}
impl Write for Frames {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let frame: serde_json::Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
        match frame["kind"].as_str() {
            Some("record") => self.records += 1,
            Some("complete") => self.complete = true,
            Some("ready") => {}
            _ => return Err(io::Error::other("unexpected synthetic limit-probe frame")),
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn check(path: &Path, expected: u64) -> Result<serde_json::Value, Error> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut frames = Frames::default();
    let start = Instant::now();
    let error = irmind_evtx::decode(file, &mut frames)
        .err()
        .ok_or("record-limit probe was unexpectedly accepted")?;
    if error.kind() != io::ErrorKind::InvalidData
        || frames.complete
        || frames.records != irmind_evtx::MAX_RECORDS
        || expected <= frames.records
    {
        return Err("record-limit probe did not stop at the exact configured bound".into());
    }
    Ok(
        serde_json::json!({"profile":"release", "status":"expected-rejection",
        "scope":"in-process production decoder, synthetic source only; not the contained ingestion memory/throughput measurement",
        "source_bytes":size, "expected_records":expected, "emitted_records":frames.records,
        "complete":false, "limit":"records-per-file", "seconds":start.elapsed().as_secs_f64()}),
    )
}
