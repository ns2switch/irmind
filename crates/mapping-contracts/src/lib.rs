#![forbid(unsafe_code)]

//! The production dependency boundary for deterministic source mappings.
pub mod common_event;
pub mod modules;
mod records;
pub mod source_mapping;

pub use common_event::{CommonGraphRecord, InvalidCommonEvent, encode_common_event};
pub use irmind_domain::{ClusterIdentity, IndexedTime};
pub use records::{GraphRecord, GraphRelation, IndexedGraphRecord, PartitionProfile};
pub use source_mapping::SourceMapper;

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
