use irmind_app::{IndexedInstant, IndexedTime, TimePrecision};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(super) fn serialize<S: Serializer>(
    time: impl std::borrow::Borrow<Option<IndexedTime>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    time.borrow()
        .map(|t| {
            (
                t.instant().unix_micros(),
                t.instant().submicro_nanos(),
                t.precision().code(),
                t.inferred(),
            )
        })
        .serialize(serializer)
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<IndexedTime>, D::Error> {
    let raw = Option::<(i64, u16, u8, bool)>::deserialize(deserializer)?;
    raw.map(|(micros, residual, code, inferred)| {
        let instant = IndexedInstant::new(micros, residual)
            .map_err(|_| serde::de::Error::custom("invalid staged time"))?;
        let precision = TimePrecision::from_code(code)
            .map_err(|_| serde::de::Error::custom("invalid staged time"))?;
        IndexedTime::new(instant, precision, inferred)
            .map_err(|_| serde::de::Error::custom("invalid staged time"))
    })
    .transpose()
}
