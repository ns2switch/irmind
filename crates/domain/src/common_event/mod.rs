//! Validated logical projection. Mapping is explicit and never grants authority.
mod codes;
mod context;
mod entity;
mod error;
mod field_kind;
mod fields;
mod filter;
mod header;
mod observation;
mod origin;
mod sets;
mod text;
mod value;

pub use codes::*;
pub use context::*;
pub use entity::*;
pub use error::*;
pub use field_kind::CommonFieldType;
pub use fields::*;
pub use filter::*;
pub use header::*;
pub use observation::*;
pub use origin::*;
pub use sets::*;
pub use text::*;
pub use value::*;

use crate::IndexedTime;
pub const COMMON_DOMAIN_LOOKUP_POLICY: &str = "ascii-dns-lowercase-strip-root-v1";
pub const COMMON_EVENT_V1: &str = "irmind-common-event-v1";
pub const COMMON_EVENT_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonEventV1 {
    origin: EventOrigin,
    timestamp: Option<IndexedTime>,
    event: EventHeaderV1,
    context: EventContextV1,
    observations: BoundedObservations,
}
impl CommonEventV1 {
    pub fn try_new(
        origin: EventOrigin,
        timestamp: Option<IndexedTime>,
        event: EventHeaderV1,
        context: EventContextV1,
        observations: BoundedObservations,
    ) -> Result<Self, EventSchemaError> {
        observations.validate_origin(&origin)?;
        observations.validate_context(&context)?;
        let bytes = 512
            + origin.json_bytes()
            + event.json_bytes()
            + context.json_bytes()
            + observations.json_bytes();
        if bytes > COMMON_EVENT_MAX_BYTES {
            return Err(EventSchemaError::LimitExceeded);
        }
        Ok(Self {
            origin,
            timestamp,
            event,
            context,
            observations,
        })
    }
    pub const fn origin(&self) -> &EventOrigin {
        &self.origin
    }
    pub const fn timestamp(&self) -> Option<IndexedTime> {
        self.timestamp
    }
    pub const fn event(&self) -> &EventHeaderV1 {
        &self.event
    }
    pub const fn context(&self) -> &EventContextV1 {
        &self.context
    }
    pub const fn observations(&self) -> &BoundedObservations {
        &self.observations
    }
}

#[cfg(test)]
mod tests;

/// Deterministic construction of the first typed physical schemas.
pub const COMMON_EVENT_BUILDER: &str = "parquet-builder-common-event-v1";
