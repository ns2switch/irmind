use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Default)]
pub struct ParserProfile {
    total: AtomicU64,
    extraction: AtomicU64,
    emit: AtomicU64,
    hash: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub struct ParserTiming {
    pub total: Duration,
    pub extraction: Duration,
    pub emit: Duration,
    pub hash: Duration,
}

impl ParserProfile {
    pub fn snapshot(&self) -> ParserTiming {
        ParserTiming {
            total: Duration::from_nanos(self.total.load(Ordering::Relaxed)),
            extraction: Duration::from_nanos(self.extraction.load(Ordering::Relaxed)),
            emit: Duration::from_nanos(self.emit.load(Ordering::Relaxed)),
            hash: Duration::from_nanos(self.hash.load(Ordering::Relaxed)),
        }
    }

    pub(crate) fn total(&self, elapsed: Duration) {
        self.total.fetch_add(nanos(elapsed), Ordering::Relaxed);
    }

    pub(crate) fn extraction(&self, elapsed: Duration) {
        self.extraction.fetch_add(nanos(elapsed), Ordering::Relaxed);
    }

    pub(crate) fn emit(&self, elapsed: Duration) {
        self.emit.fetch_add(nanos(elapsed), Ordering::Relaxed);
    }

    pub(crate) fn hash(&self, elapsed: Duration) {
        self.hash.fetch_add(nanos(elapsed), Ordering::Relaxed);
    }
}

fn nanos(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}
