//! Identical filesystem sampling for each side of the release comparison.
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

pub(super) struct StagingProbe {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<(u64, usize)>>,
}
impl StagingProbe {
    pub(super) fn start(root: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut peak = 0;
            let mut errors = 0;
            loop {
                match bytes(&root, false, 0) {
                    Ok(value) => peak = peak.max(value),
                    Err(_) => errors += 1,
                }
                if signal.load(Ordering::Relaxed) {
                    return (peak, errors);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }
    pub(super) fn finish(mut self) -> (u64, usize) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for StagingProbe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn bytes(root: &Path, spool: bool, depth: usize) -> std::io::Result<u64> {
    if depth > 10 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut total = 0u64;
    let entries = match std::fs::read_dir(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        other => other?,
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let kind = match entry.file_type() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            other => other?,
        };
        if kind.is_dir() {
            total += bytes(&path, spool || entry.file_name() == "spool", depth + 1)?;
        } else if kind.is_file() && (spool || path.extension().is_some_and(|s| s == "tmp")) {
            match entry.metadata() {
                Ok(metadata) => total += metadata.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(total)
}
