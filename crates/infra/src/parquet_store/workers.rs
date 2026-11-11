//! Budget scheduler reservations for source and file workers. Decoder, row
//! group, batch and writer limits still apply independently of this policy.
use crate::LocalStore;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU16, Ordering};

const OPERATION_BUDGET_MIB: usize = 4096;
// Includes the partition writers, the coordinator and transient batches.
const COORDINATOR_MIB: usize = 512;
// Reserve space for an input row group, mapped rows and both sides of the
// bounded queue. Reserve the same amount for each Parquet scan worker.
const WORKER_MIB: usize = 512;

#[derive(Default)]
pub(super) struct WorkerSettings(AtomicU16);

impl WorkerSettings {
    pub(super) fn set_limit(&self, limit: Option<NonZeroU16>) {
        self.0
            .store(limit.map_or(0, NonZeroU16::get), Ordering::Relaxed);
    }

    pub(super) fn count(&self) -> usize {
        let available = std::thread::available_parallelism().map_or(1, usize::from);
        let configured = NonZeroU16::new(self.0.load(Ordering::Relaxed));
        worker_count(available, configured, OPERATION_BUDGET_MIB)
    }
}

impl LocalStore {
    /// Set the execution cap from the verified session configuration.
    pub fn set_parallel_worker_limit(&self, limit: Option<NonZeroU16>) {
        self.parquet.workers.set_limit(limit);
    }
}

fn worker_count(available: usize, configured: Option<NonZeroU16>, budget: usize) -> usize {
    let cpu_limit = configured.map_or_else(
        || available.saturating_sub(1),
        |cap| usize::from(cap.get()).min(available),
    );
    let memory_limit = budget.saturating_sub(COORDINATOR_MIB) / WORKER_MIB;
    cpu_limit.min(memory_limit).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_one_core_free_by_default_and_respects_explicit_and_memory_caps() {
        assert_eq!(worker_count(1, None, OPERATION_BUDGET_MIB), 1);
        assert_eq!(worker_count(4, None, OPERATION_BUDGET_MIB), 3);
        assert_eq!(worker_count(4, NonZeroU16::new(4), OPERATION_BUDGET_MIB), 4);
        assert_eq!(worker_count(2, NonZeroU16::new(4), OPERATION_BUDGET_MIB), 2);
        assert_eq!(
            worker_count(12, NonZeroU16::new(2), OPERATION_BUDGET_MIB),
            2
        );
        assert_eq!(worker_count(12, None, 1536), 2);
    }
}
