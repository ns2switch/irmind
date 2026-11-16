use super::{CaseDeletionInventory, CaseLifecycleError};
use crate::{AppError, CaseId, SignedOperation, hex};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "case-deleted-v1:";
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseDeletedV1 {
    pub version: u8,
    pub case_id: String,
    pub title: String,
    pub created_at: u64,
    pub last_chain_hash: String,
    pub entry_count: u64,
    pub source_count: u64,
    pub owned_file_bytes: u64,
    pub shared_blob_bytes: u64,
    pub logical_metadata_bytes: u64,
    pub reason: Option<String>,
    pub deleted_at: u64,
}
impl CaseDeletedV1 {
    pub fn new(
        inventory: &CaseDeletionInventory,
        reason: Option<String>,
        deleted_at: u64,
    ) -> Result<Self, AppError> {
        let value = Self {
            version: 1,
            case_id: inventory.case_id.as_str().into(),
            title: inventory.title.clone(),
            created_at: inventory.created_at,
            last_chain_hash: inventory.last_chain_hash.clone(),
            entry_count: inventory.entry_count,
            source_count: inventory.source_count,
            owned_file_bytes: inventory.owned_file_bytes,
            shared_blob_bytes: inventory.shared_blob_bytes,
            logical_metadata_bytes: inventory.logical_metadata_bytes,
            reason,
            deleted_at,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        if self.version != 1
            || CaseId::parse(&self.case_id).is_err()
            || self.title.trim().is_empty()
            || self.title.len() > 200
            || self.last_chain_hash.len() != 64
            || !self
                .last_chain_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.entry_count == 0
            || self.source_count > self.entry_count
            || self.reason.as_ref().is_some_and(|r| r.len() > 1024)
            || self.deleted_at < self.created_at
        {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        Ok(())
    }
    pub fn inventory(&self) -> Result<CaseDeletionInventory, AppError> {
        self.validate()?;
        Ok(CaseDeletionInventory {
            case_id: CaseId::parse(&self.case_id)
                .map_err(|_| CaseLifecycleError::InvalidReceipt)?,
            title: self.title.clone(),
            created_at: self.created_at,
            last_chain_hash: self.last_chain_hash.clone(),
            entry_count: self.entry_count,
            source_count: self.source_count,
            owned_file_bytes: self.owned_file_bytes,
            shared_blob_bytes: self.shared_blob_bytes,
            logical_metadata_bytes: self.logical_metadata_bytes,
        })
    }
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| CaseLifecycleError::InvalidReceipt.into())
    }
    pub fn payload(&self) -> Result<String, AppError> {
        Ok(format!("{PREFIX}{}", hex(&self.canonical()?)))
    }
    pub fn decode(operation: &SignedOperation) -> Result<Option<Self>, AppError> {
        let Some(encoded) = operation.operation.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        if encoded.len() > 16 * 1024 {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        let bytes = hex::decode(encoded).map_err(|_| CaseLifecycleError::InvalidReceipt)?;
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|_| CaseLifecycleError::InvalidReceipt)?;
        if hex(&value.canonical()?) != encoded || value.deleted_at != operation.at {
            return Err(CaseLifecycleError::InvalidReceipt.into());
        }
        Ok(Some(value))
    }
}
