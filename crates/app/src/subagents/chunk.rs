use super::{
    SubagentBranchEntry, SubagentBranchPayload, SubagentCheckpointV1, SubagentDigest,
    SubagentRecord, SubagentRecordError,
};
use crate::Verifier;

pub struct CheckedBranchChunk {
    entries: Vec<SubagentBranchEntry>,
    bytes: Vec<u8>,
    hash: SubagentDigest,
    entries_hash: SubagentDigest,
}
impl CheckedBranchChunk {
    pub fn decode(
        bytes: &[u8],
        agent: &[u8],
        verifier: &dyn Verifier,
    ) -> Result<Self, SubagentRecordError> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(SubagentRecordError);
        }
        let entries: Vec<SubagentBranchEntry> =
            serde_json::from_slice(bytes).map_err(|_| SubagentRecordError)?;
        if entries.is_empty()
            || entries.len() > 64
            || serde_json::to_vec(&entries).map_err(|_| SubagentRecordError)? != bytes
        {
            return Err(SubagentRecordError);
        }
        let first = &entries[0].body;
        let mut prior = None::<&SubagentBranchEntry>;
        let mut commitment = b"irmind-subagent-entry-set-v1\0".to_vec();
        commitment.extend_from_slice(&(entries.len() as u64).to_be_bytes());
        for entry in &entries {
            entry.verify(agent, verifier)?;
            let body = &entry.body;
            if body.case_id != first.case_id
                || body.turn_id != first.turn_id
                || body.task_id != first.task_id
                || body.nonce != first.nonce
                || prior.is_some_and(|p| {
                    p.body.seq.checked_add(1) != Some(body.seq)
                        || p.hash != body.prev
                        || matches!(p.body.payload, SubagentBranchPayload::Terminal(_))
                })
            {
                return Err(SubagentRecordError);
            }
            commitment.extend_from_slice(entry.hash.as_bytes());
            prior = Some(entry);
        }
        Ok(Self {
            entries,
            bytes: bytes.into(),
            hash: SubagentDigest::from_bytes(crate::sha256(bytes)),
            entries_hash: SubagentDigest::from_bytes(crate::sha256(&commitment)),
        })
    }
    pub fn from_entries(
        entries: &[SubagentBranchEntry],
        agent: &[u8],
        verifier: &dyn Verifier,
    ) -> Result<Self, SubagentRecordError> {
        if entries.is_empty() || entries.len() > 64 {
            return Err(SubagentRecordError);
        }
        Self::decode(
            &serde_json::to_vec(entries).map_err(|_| SubagentRecordError)?,
            agent,
            verifier,
        )
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub const fn hash(&self) -> SubagentDigest {
        self.hash
    }
    pub fn entries(&self) -> &[SubagentBranchEntry] {
        &self.entries
    }
    pub fn checkpoint(
        &self,
        previous: Option<SubagentDigest>,
        admitted_sources: Vec<SubagentDigest>,
    ) -> Result<SubagentCheckpointV1, SubagentRecordError> {
        let first = self.entries.first().ok_or(SubagentRecordError)?;
        let last = self.entries.last().ok_or(SubagentRecordError)?;
        let value = SubagentCheckpointV1 {
            format_version: 1,
            case_id: first.body.case_id.clone(),
            task_id: first.body.task_id,
            first: first.body.seq,
            last: last.body.seq,
            count: self.entries.len() as u64,
            previous_checkpoint: previous,
            entries_sha256: self.entries_hash,
            chunk_sha256: self.hash,
            chunk_bytes: self.bytes.len() as u64,
            admitted_sources,
            terminal: matches!(last.body.payload, SubagentBranchPayload::Terminal(_)),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Verifies one task's committed prefixes; this state grants no execution rights.
pub struct SubagentBranchCursor {
    case_id: String,
    turn_id: String,
    task_id: SubagentDigest,
    nonce: String,
    last_hash: SubagentDigest,
    next: u64,
    bytes: u64,
    previous: Option<SubagentDigest>,
    terminal: bool,
}
impl SubagentBranchCursor {
    pub fn new(
        case_id: &str,
        turn_id: &str,
        task_id: SubagentDigest,
        nonce: &str,
    ) -> Result<Self, SubagentRecordError> {
        super::codec::uuid(case_id)?;
        super::codec::uuid(turn_id)?;
        super::codec::uuid(nonce)?;
        Ok(Self {
            case_id: case_id.into(),
            turn_id: turn_id.into(),
            task_id,
            nonce: nonce.into(),
            last_hash: SubagentDigest::from_bytes([0; 32]),
            next: 1,
            bytes: 0,
            previous: None,
            terminal: false,
        })
    }
    pub fn accept(
        &mut self,
        chunk: &CheckedBranchChunk,
        checkpoint: &SubagentCheckpointV1,
    ) -> Result<(), SubagentRecordError> {
        checkpoint.validate()?;
        let expected = chunk.checkpoint(self.previous, checkpoint.admitted_sources.clone())?;
        let first = chunk.entries.first().ok_or(SubagentRecordError)?;
        if self.terminal
            || checkpoint.canonical()? != expected.canonical()?
            || checkpoint.first != self.next
            || checkpoint.case_id != self.case_id
            || checkpoint.task_id != self.task_id
            || first.body.turn_id != self.turn_id
            || first.body.nonce != self.nonce
            || first.body.prev != self.last_hash
        {
            return Err(SubagentRecordError);
        }
        let bytes = self
            .bytes
            .checked_add(checkpoint.chunk_bytes)
            .ok_or(SubagentRecordError)?;
        if bytes > 16 * 1024 * 1024 {
            return Err(SubagentRecordError);
        }
        self.previous = Some(checkpoint.identity()?);
        self.next = checkpoint.last.checked_add(1).ok_or(SubagentRecordError)?;
        self.last_hash = chunk.entries.last().ok_or(SubagentRecordError)?.hash;
        self.bytes = bytes;
        self.terminal = checkpoint.terminal;
        Ok(())
    }
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }
    pub const fn previous_checkpoint(&self) -> Option<SubagentDigest> {
        self.previous
    }
}
