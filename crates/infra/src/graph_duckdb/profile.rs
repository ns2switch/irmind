use irmind_app::AppError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) enum GraphPhase {
    Connect,
    Transaction,
    IndexLookup,
    Events,
    Texts,
    Terms,
    Observations,
    Relations,
    Finish,
    Commit,
}

impl GraphPhase {
    #[cfg(test)]
    const ALL: [Self; 10] = [
        Self::Connect,
        Self::Transaction,
        Self::IndexLookup,
        Self::Events,
        Self::Texts,
        Self::Terms,
        Self::Observations,
        Self::Relations,
        Self::Finish,
        Self::Commit,
    ];

    fn index(self) -> usize {
        self as usize
    }

    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Transaction => "transaction",
            Self::IndexLookup => "index_lookup",
            Self::Events => "events",
            Self::Texts => "texts",
            Self::Terms => "terms",
            Self::Observations => "observations",
            Self::Relations => "relations",
            Self::Finish => "finish",
            Self::Commit => "commit",
        }
    }
}

pub(crate) struct GraphInsertProfile {
    nanos: [AtomicU64; 10],
}

impl Default for GraphInsertProfile {
    fn default() -> Self {
        Self {
            nanos: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl GraphInsertProfile {
    fn record(&self, phase: GraphPhase, elapsed: Duration) {
        self.nanos[phase.index()].fetch_add(
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<(&'static str, Duration)> {
        GraphPhase::ALL
            .into_iter()
            .map(|phase| {
                (
                    phase.label(),
                    Duration::from_nanos(self.nanos[phase.index()].load(Ordering::Relaxed)),
                )
            })
            .collect()
    }
}

pub(crate) fn measure<T>(
    profile: Option<&GraphInsertProfile>,
    phase: GraphPhase,
    action: impl FnOnce() -> Result<T, AppError>,
) -> Result<T, AppError> {
    let Some(profile) = profile else {
        return action();
    };
    let started = Instant::now();
    let result = action();
    profile.record(phase, started.elapsed());
    result
}
