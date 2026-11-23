mod framing;
pub use framing::{JsonFrame, JsonFrames};
pub use irmind_mapping_contracts::source_mapping::json::*;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
