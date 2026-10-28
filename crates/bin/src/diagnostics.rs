//! Operational diagnostics are separate from signed case custody.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use tracing_subscriber::prelude::*;

const MAX_TRACE_BYTES: u64 = 10_000_000;
static INITIALIZED: OnceLock<()> = OnceLock::new();

fn operational_target(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.target() == "irmind::operations"
}

struct TraceWriter(Arc<Mutex<File>>);

impl Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut file = self
            .0
            .lock()
            .map_err(|_| io::Error::other("trace writer unavailable"))?;
        if file.metadata()?.len() >= MAX_TRACE_BYTES {
            return Ok(bytes.len());
        }
        file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("trace writer unavailable"))?
            .flush()
    }
}

pub(super) fn init(home: &Path) -> anyhow::Result<()> {
    if INITIALIZED.get().is_some() {
        return Ok(());
    }
    let path = home.join("diagnostics.log");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => irmind_fs::private_file(&path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    irmind_fs::private_file(&path)?;
    let shared = Arc::new(Mutex::new(file));
    let layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(move || TraceWriter(Arc::clone(&shared)))
        .with_filter(tracing_subscriber::filter::filter_fn(operational_target));
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| anyhow::anyhow!("operational trace subscriber unavailable"))?;
    let _ = INITIALIZED.set(());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn only_whitelisted_operational_events_reach_the_diagnostic_sink() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&buffer);
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(move || BufferWriter(Arc::clone(&captured)))
            .with_filter(tracing_subscriber::filter::filter_fn(operational_target));
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            tracing::info!(target: "irmind::operations", tool = "siem_get_alert", "tool finished");
            tracing::info!(target: "remote_dependency", secret = "synthetic-secret", "request");
        });
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("siem_get_alert"));
        assert!(!output.contains("synthetic-secret"));
        assert!(!output.contains("remote_dependency"));
    }
}
