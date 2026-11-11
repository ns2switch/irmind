//! Optional I/O attribution; neither buffer boundaries nor bytes change.
use crate::parquet_store::{ParquetProfile, profile::ConcurrencyPhase};
use std::{
    fs::File,
    io::{self, Write},
    sync::Arc,
    time::Instant,
};
pub(super) struct ProfiledFile {
    inner: File,
    profile: Option<Arc<ParquetProfile>>,
}
impl ProfiledFile {
    pub(super) fn new(inner: File, profile: Option<Arc<ParquetProfile>>) -> Self {
        Self { inner, profile }
    }
    fn measure<T>(&mut self, operation: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
        let Some(profile) = &self.profile else {
            return operation(&mut self.inner);
        };
        let started = Instant::now();
        let result = operation(&mut self.inner);
        profile.record_concurrency(ConcurrencyPhase::FileWrite, started.elapsed());
        result
    }
}
impl Write for ProfiledFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.measure(|file| file.write(bytes))
    }
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.measure(|file| file.write_all(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.measure(Write::flush)
    }
}
