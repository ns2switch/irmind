//! Optional in-process timing counters; no evidence content is recorded.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct ParquetProfile {
    hash: AtomicU64,
    conversion: AtomicU64,
    row: AtomicU64,
    parquet: AtomicU64,
    partition_finalize: AtomicU64,
    staged_sources: AtomicU64,
    query_verify: AtomicU64,
    query_scan: AtomicU64,
    query_normalize: AtomicU64,
    query_aggregate: AtomicU64,
    staging_peak: AtomicU64,
    pub(super) staging_live: AtomicU64,
    partition_phases: [AtomicU64; 5],
    mapping_phases: [AtomicU64; 3],
}

impl ParquetProfile {
    fn nanos(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    }

    pub(super) fn record_hash(&self, duration: Duration) {
        self.hash
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_conversion(&self, duration: Duration) {
        self.conversion
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_row(&self, duration: Duration) {
        self.row.fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_parquet(&self, duration: Duration) {
        self.parquet
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_staged_source(&self) {
        self.staged_sources.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn staged_sources(&self) -> u64 {
        self.staged_sources.load(Ordering::Relaxed)
    }

    pub(super) fn record_partition_finalize(&self, duration: Duration) {
        self.partition_finalize
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn partition_finalize_time(&self) -> Duration {
        Duration::from_nanos(self.partition_finalize.load(Ordering::Relaxed))
    }

    pub(super) fn record_query_verify(&self, duration: Duration) {
        self.query_verify
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_query_scan(&self, duration: Duration) {
        self.query_scan
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_query_normalize(&self, duration: Duration) {
        self.query_normalize
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn record_query_aggregate(&self, duration: Duration) {
        self.query_aggregate
            .fetch_add(Self::nanos(duration), Ordering::Relaxed);
    }

    pub(super) fn mapping_timer(&self, phase: MappingPhase) -> MappingTimer<'_> {
        MappingTimer {
            profile: self,
            phase,
            started: Instant::now(),
        }
    }
    #[cfg(test)]
    pub(crate) fn mapping_snapshot(&self) -> [Duration; 3] {
        std::array::from_fn(|i| {
            Duration::from_nanos(self.mapping_phases[i].load(Ordering::Relaxed))
        })
    }

    #[cfg(test)]
    pub(crate) fn query_detail_snapshot(&self) -> [Duration; 4] {
        [
            &self.query_verify,
            &self.query_scan,
            &self.query_normalize,
            &self.query_aggregate,
        ]
        .map(|counter| Duration::from_nanos(counter.load(Ordering::Relaxed)))
    }

    pub(super) fn query_timer(&self, phase: QueryPhase) -> QueryTimer<'_> {
        QueryTimer {
            profile: self,
            phase,
            started: Instant::now(),
        }
    }

    pub(super) fn record_staging_peak(&self, bytes: u64) {
        self.staging_peak.fetch_max(bytes, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn temporary_disk_peak(&self) -> u64 {
        self.staging_peak.load(Ordering::Relaxed)
    }

    pub(super) fn measure(&self, phase: PartitionPhase) -> PhaseTimer<'_> {
        PhaseTimer {
            profile: self,
            phase,
            started: Instant::now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn partition_snapshot(&self) -> [Duration; 5] {
        std::array::from_fn(|i| {
            Duration::from_nanos(self.partition_phases[i].load(Ordering::Relaxed))
        })
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> [Duration; 6] {
        [
            Duration::from_nanos(self.hash.load(Ordering::Relaxed)),
            Duration::from_nanos(self.conversion.load(Ordering::Relaxed)),
            Duration::from_nanos(self.row.load(Ordering::Relaxed)),
            Duration::from_nanos(self.parquet.load(Ordering::Relaxed)),
            Duration::from_nanos(self.query_verify.load(Ordering::Relaxed)),
            Duration::from_nanos(self.query_scan.load(Ordering::Relaxed)),
        ]
    }
}

#[derive(Clone, Copy)]
pub(super) enum PartitionPhase {
    Stage,
    Sort,
    Replay,
    SourceVerify,
    Publish,
}

pub(super) struct PhaseTimer<'a> {
    profile: &'a ParquetProfile,
    phase: PartitionPhase,
    started: Instant,
}

impl Drop for PhaseTimer<'_> {
    fn drop(&mut self) {
        self.profile.partition_phases[self.phase as usize].fetch_add(
            ParquetProfile::nanos(self.started.elapsed()),
            Ordering::Relaxed,
        );
    }
}

#[derive(Clone, Copy)]
pub(super) enum QueryPhase {
    Scan,
    Normalize,
    Aggregate,
}

pub(super) struct QueryTimer<'a> {
    profile: &'a ParquetProfile,
    phase: QueryPhase,
    started: Instant,
}
impl Drop for QueryTimer<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        match self.phase {
            QueryPhase::Scan => self.profile.record_query_scan(elapsed),
            QueryPhase::Normalize => self.profile.record_query_normalize(elapsed),
            QueryPhase::Aggregate => self.profile.record_query_aggregate(elapsed),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum MappingPhase {
    ValidateAndMap,
    Project,
    InputCommit,
}
pub(super) struct MappingTimer<'a> {
    profile: &'a ParquetProfile,
    phase: MappingPhase,
    started: Instant,
}
impl Drop for MappingTimer<'_> {
    fn drop(&mut self) {
        self.profile.mapping_phases[self.phase as usize].fetch_add(
            ParquetProfile::nanos(self.started.elapsed()),
            Ordering::Relaxed,
        );
    }
}
