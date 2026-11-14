use super::{CheckedBranchChunk, SubagentDigest, SubagentRecordError};
use crate::{AppError, CancellationToken};
use irmind_domain::CaseId;

/// Immutable content reference. A reference by itself conveys no case authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchChunkRef {
    hash: SubagentDigest,
    bytes: u64,
}
impl BranchChunkRef {
    pub fn new(hash: SubagentDigest, bytes: u64) -> Result<Self, SubagentRecordError> {
        if bytes == 0 || bytes > 1024 * 1024 {
            return Err(SubagentRecordError);
        }
        Ok(Self { hash, bytes })
    }
    pub const fn hash(&self) -> SubagentDigest {
        self.hash
    }
    pub const fn len(&self) -> u64 {
        self.bytes
    }
    pub const fn is_empty(&self) -> bool {
        self.bytes == 0
    }
    pub fn relative_path(&self) -> String {
        format!("branches/{}.json", crate::hex(self.hash.as_bytes()))
    }
}

/// The owned private pending file is removed on drop, including error paths.
pub struct StagedBranchChunk {
    case: CaseId,
    reference: BranchChunkRef,
    file: tempfile::NamedTempFile,
    cancel: CancellationToken,
}
impl StagedBranchChunk {
    pub fn new(
        case: CaseId,
        reference: BranchChunkRef,
        file: tempfile::NamedTempFile,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            case,
            reference,
            file,
            cancel,
        }
    }
    pub fn into_parts(
        self,
    ) -> (
        CaseId,
        BranchChunkRef,
        tempfile::NamedTempFile,
        CancellationToken,
    ) {
        (self.case, self.reference, self.file, self.cancel)
    }
}

pub struct PublishedBranchChunk {
    pub case: CaseId,
    pub reference: BranchChunkRef,
}

/// Hash-checked storage bytes; signatures and checkpoint linkage remain separate.
pub struct BoundedBranchBytes(Vec<u8>);
impl BoundedBranchBytes {
    pub fn checked(
        bytes: Vec<u8>,
        reference: &BranchChunkRef,
    ) -> Result<Self, SubagentRecordError> {
        if bytes.len() as u64 != reference.len()
            || SubagentDigest::from_bytes(crate::sha256(&bytes)) != reference.hash()
        {
            return Err(SubagentRecordError);
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub trait SubagentBranchStore: Send + Sync {
    fn stage(
        &self,
        case: &CaseId,
        chunk: &CheckedBranchChunk,
        cancel: &CancellationToken,
    ) -> Result<StagedBranchChunk, AppError>;
    fn publish(&self, staged: StagedBranchChunk) -> Result<PublishedBranchChunk, AppError>;
    fn read(
        &self,
        case: &CaseId,
        reference: &BranchChunkRef,
        cancel: &CancellationToken,
    ) -> Result<BoundedBranchBytes, AppError>;
    fn discard(&self, staged: StagedBranchChunk) -> Result<(), AppError>;
}
