use super::{SkillSnapshotId, decode, encode, hash, invalid};
use crate::{AppError, AuditEventKind, hex, sha256};
use irmind_domain::SkillResourcePath;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillLoadResult {
    Loaded,
    Blocked,
    Unavailable,
    Limit,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillLoadV1 {
    format_version: u32,
    snapshot_sha256: String,
    turn_id: String,
    call_id: String,
    resource: String,
    byte_start: u64,
    byte_end: u64,
    guard_id: String,
    guarded_text: String,
    guarded_text_sha256: String,
    guarded_bytes: u64,
    guard_detection_count: u32,
    result: SkillLoadResult,
}
/// Input for one bounded range. Construct only from the pinned original resource.
pub struct SkillReadReceipt<'a> {
    pub snapshot: SkillSnapshotId,
    pub turn: uuid::Uuid,
    pub call: &'a str,
    pub resource: &'a str,
    pub range: std::ops::Range<usize>,
    pub guard: &'a str,
    pub text: String,
    pub detections: u32,
    pub result: SkillLoadResult,
}
impl SkillLoadV1 {
    pub fn new(input: SkillReadReceipt<'_>) -> Result<Self, AppError> {
        let receipt = Self {
            format_version: 1,
            snapshot_sha256: hex(input.snapshot.as_bytes()),
            turn_id: input.turn.to_string(),
            call_id: input.call.into(),
            resource: input.resource.into(),
            byte_start: u64::try_from(input.range.start).map_err(|_| invalid())?,
            byte_end: u64::try_from(input.range.end).map_err(|_| invalid())?,
            guard_id: input.guard.into(),
            guarded_text_sha256: hex(&sha256(input.text.as_bytes())),
            guarded_bytes: input.text.len() as u64,
            guarded_text: input.text,
            guard_detection_count: input.detections,
            result: input.result,
        };
        receipt.validate()?;
        Ok(receipt)
    }
    pub fn encode(&self) -> Result<String, AppError> {
        self.validate()?;
        encode(AuditEventKind::SkillLoadV1, self)
    }
    pub fn decode(value: &str) -> Result<Self, AppError> {
        let decoded: Self = decode(AuditEventKind::SkillLoadV1, value)?;
        decoded.validate()?;
        Ok(decoded)
    }
    fn validate(&self) -> Result<(), AppError> {
        SkillSnapshotId::parse(&self.snapshot_sha256)?;
        SkillResourcePath::parse(&self.resource)?;
        let turn = uuid::Uuid::parse_str(&self.turn_id).map_err(|_| invalid())?;
        if self.format_version != 1
            || turn.to_string() != self.turn_id
            || self.call_id.is_empty()
            || self.call_id.len() > 128
            || !self
                .call_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            || self.guard_id.is_empty()
            || self.guard_id.len() > 128
            || !self.guard_id.bytes().all(|b| b.is_ascii_graphic())
            || self.byte_end < self.byte_start
            || self.byte_end > 32 * 1024
            || self.guarded_bytes != self.guarded_text.len() as u64
            || self.guarded_bytes > 64 * 1024
            || hash(&self.guarded_text_sha256)? != sha256(self.guarded_text.as_bytes())
            || (self.result != SkillLoadResult::Loaded && !self.guarded_text.is_empty())
            || (self.result == SkillLoadResult::Loaded && self.guard_detection_count != 0)
            || self.guard_detection_count > 1024
            || (self.result == SkillLoadResult::Blocked && self.guard_detection_count == 0)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Result<SkillSnapshotId, AppError> {
        SkillSnapshotId::parse(&self.snapshot_sha256)
    }
    pub fn turn(&self) -> &str {
        &self.turn_id
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn range(&self) -> Result<std::ops::Range<usize>, AppError> {
        Ok(usize::try_from(self.byte_start).map_err(|_| invalid())?
            ..usize::try_from(self.byte_end).map_err(|_| invalid())?)
    }
    pub fn text(&self) -> &str {
        &self.guarded_text
    }
    pub fn guard(&self) -> &str {
        &self.guard_id
    }
    pub const fn result(&self) -> SkillLoadResult {
        self.result
    }
    pub const fn bytes(&self) -> u64 {
        self.guarded_bytes
    }
}
impl std::fmt::Debug for SkillLoadV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillLoadV1")
            .field("snapshot", &self.snapshot_sha256)
            .field("bytes", &self.guarded_bytes)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}
