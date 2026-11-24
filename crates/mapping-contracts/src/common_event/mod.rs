//! Canonical encoders and strict decoders of typed `CommonEvent` projections.
pub mod cluster_audit;
mod codec;
mod values;

use crate::IndexedGraphRecord;
pub use codec::{decode_common_event, encode_common_event};
use irmind_domain::CommonEventV1;
pub use irmind_domain::EntityIdentityScope;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCommonEvent;

impl std::fmt::Display for InvalidCommonEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid common event")
    }
}
impl std::error::Error for InvalidCommonEvent {}

const fn invalid() -> InvalidCommonEvent {
    InvalidCommonEvent
}

pub fn encode_identity_scope(scope: &EntityIdentityScope) -> Result<String, InvalidCommonEvent> {
    codec::encode_scope(scope)
}
pub fn decode_identity_scope(input: &str) -> Result<EntityIdentityScope, InvalidCommonEvent> {
    codec::decode_scope(input)
}

#[derive(Clone, Eq, PartialEq)]
pub struct CommonGraphRecord {
    pub indexed: IndexedGraphRecord,
    pub common: CommonEventV1,
}

impl std::fmt::Debug for CommonGraphRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonGraphRecord")
            .field("origin", self.common.origin())
            .finish_non_exhaustive()
    }
}
