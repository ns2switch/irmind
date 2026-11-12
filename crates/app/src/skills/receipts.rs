//! Current-version skill methodology receipts; these are not evidence identities.
mod load;
mod snapshot;
mod verification;
use super::SkillServiceError;
use crate::{AppError, AuditEventKind, hex};
pub use load::{SkillLoadResult, SkillLoadV1, SkillReadReceipt};
use serde::{Serialize, de::DeserializeOwned};
pub use snapshot::{SkillSnapshotId, SkillSnapshotV1};
pub use verification::{SkillReceiptVerifier, skill_admission_references, verify_skill_admission};
const MAX_PAYLOAD: usize = 768 * 1024;
pub(super) fn invalid() -> AppError {
    SkillServiceError::InvalidReceipt.into()
}
fn encode<T: Serialize>(kind: AuditEventKind, value: &T) -> Result<String, AppError> {
    let raw = serde_json::to_vec(value).map_err(|_| invalid())?;
    let encoded = format!("{}:{}", kind.as_str(), hex(&raw));
    if encoded.len() > MAX_PAYLOAD {
        return Err(invalid());
    }
    Ok(encoded)
}
fn decode<T: Serialize + DeserializeOwned>(
    kind: AuditEventKind,
    value: &str,
) -> Result<T, AppError> {
    if value.len() > MAX_PAYLOAD {
        return Err(invalid());
    }
    let (label, data) = value.split_once(':').ok_or_else(invalid)?;
    if label != kind.as_str() {
        return Err(invalid());
    }
    let bytes = hex::decode(data).map_err(|_| invalid())?;
    if hex(&bytes) != data {
        return Err(invalid());
    }
    let decoded: T = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if serde_json::to_vec(&decoded).map_err(|_| invalid())? != bytes {
        return Err(invalid());
    }
    Ok(decoded)
}
pub(super) fn hash(value: &str) -> Result<[u8; 32], AppError> {
    let bytes = hex::decode(value).map_err(|_| invalid())?;
    let raw: [u8; 32] = bytes.try_into().map_err(|_| invalid())?;
    if hex(&raw) != value {
        return Err(invalid());
    }
    Ok(raw)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
