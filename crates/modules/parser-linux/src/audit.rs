//! Audit framing limits and bounded original-record grouping.
mod encoding;
mod fields;
pub(crate) mod source;
use fields::Line;

const MAX_GROUPS: usize = 64;
const MAX_GROUP_BYTES: usize = 256 * 1024;
const MAX_GROUP_RECORDS: usize = 128;
const END_OF_EVENT_SECONDS: i64 = 2;

pub(super) fn detect(line: &str) -> bool {
    Line::parse(line).is_ok()
}
