use irmind_app::{AppError, Clock};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, AppError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| AppError::Storage("system clock is before the Unix epoch".into()))
    }
}
