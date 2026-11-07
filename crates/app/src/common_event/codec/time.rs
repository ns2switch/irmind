use super::{AppError, invalid};
use irmind_domain::{IndexedInstant, IndexedTime, TimePrecision};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::common_event) struct WireTime {
    unix_micros: i64,
    submicro_nanos: u16,
    precision: u8,
    inferred: bool,
}
impl From<IndexedTime> for WireTime {
    fn from(time: IndexedTime) -> Self {
        Self {
            unix_micros: time.instant().unix_micros(),
            submicro_nanos: time.instant().submicro_nanos(),
            precision: time.precision().code(),
            inferred: time.inferred(),
        }
    }
}
impl WireTime {
    pub(in crate::common_event) fn checked(self) -> Result<IndexedTime, AppError> {
        IndexedTime::new(
            IndexedInstant::new(self.unix_micros, self.submicro_nanos).map_err(|_| invalid())?,
            TimePrecision::from_code(self.precision).map_err(|_| invalid())?,
            self.inferred,
        )
        .map_err(|_| invalid())
    }
}
