use super::{SubagentJournal, SubagentRecord, SubagentRecordError, ledger::PlanLedger};
use crate::subagents::{
    BranchChunkRef, BranchTerminal, CheckedBranchChunk, SubagentBranchCursor, SubagentCheckpointV1,
    SubagentDigest, SubagentTaskSpec,
};
use crate::{AppError, CancellationToken, SkillCompiler, SkillReceiptVerifier, Verifier};
use serde::Serialize;

mod task;
use task::TaskMaterial;

struct Expected<'a> {
    plan: &'a PlanLedger,
    task: &'a SubagentTaskSpec,
    checkpoint: &'a SubagentCheckpointV1,
}

#[derive(Serialize)]
struct Descriptor {
    task_id: SubagentDigest,
    first: u64,
    last: u64,
    chunk_sha256: SubagentDigest,
    chunk_bytes: u64,
}
impl Descriptor {
    fn bytes(checkpoint: &SubagentCheckpointV1) -> Result<Vec<u8>, SubagentRecordError> {
        let value = Self {
            task_id: checkpoint.task_id,
            first: checkpoint.first,
            last: checkpoint.last,
            chunk_sha256: checkpoint.chunk_sha256,
            chunk_bytes: checkpoint.chunk_bytes,
        };
        super::super::codec::bounded_json(&value, 1024)
    }
}

/// Consumes exactly the committed chunks in V8 descriptor order. No execution
/// capability is produced; model calls and network access are never needed.
pub struct BranchMaterialVerifier<'a> {
    journal: &'a SubagentJournal,
    expected: Vec<Expected<'a>>,
    next: usize,
    current: Option<TaskMaterial<'a>>,
    failed: bool,
}
impl<'a> BranchMaterialVerifier<'a> {
    pub fn new(journal: &'a SubagentJournal) -> Result<Self, SubagentRecordError> {
        if journal.failed {
            return Err(SubagentRecordError);
        }
        let mut expected = Vec::new();
        let mut bytes = 0u64;
        for plan in journal.plans.values() {
            for task in &plan.plan.tasks {
                for checkpoint in plan.checkpoints.get(&task.task_id).into_iter().flatten() {
                    bytes = bytes
                        .checked_add(checkpoint.chunk_bytes)
                        .ok_or(SubagentRecordError)?;
                    if bytes > 256 * 1024 * 1024 || expected.len() >= 16_384 {
                        return Err(SubagentRecordError);
                    }
                    expected.push(Expected {
                        plan,
                        task,
                        checkpoint,
                    });
                }
            }
        }
        expected.sort_by_key(|item| (item.task.task_id, item.checkpoint.first));
        Ok(Self {
            journal,
            expected,
            next: 0,
            current: None,
            failed: false,
        })
    }

    pub fn next_reference(&self) -> Result<Option<BranchChunkRef>, SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        self.expected
            .get(self.next)
            .map(|item| {
                BranchChunkRef::new(item.checkpoint.chunk_sha256, item.checkpoint.chunk_bytes)
            })
            .transpose()
    }
    pub fn next_descriptor(&self) -> Result<Option<Vec<u8>>, SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        self.expected
            .get(self.next)
            .map(|item| Descriptor::bytes(item.checkpoint))
            .transpose()
    }
    pub fn count(&self) -> usize {
        self.expected.len()
    }

    pub fn accept(
        &mut self,
        descriptor: &[u8],
        bytes: &[u8],
        verifier: &dyn Verifier,
        skills: &mut SkillReceiptVerifier,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), SubagentRecordError> {
        if self.failed {
            return Err(SubagentRecordError);
        }
        let result = self.accept_inner(descriptor, bytes, verifier, skills, compiler);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn accept_inner(
        &mut self,
        descriptor: &[u8],
        bytes: &[u8],
        verifier: &dyn Verifier,
        skills: &mut SkillReceiptVerifier,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), SubagentRecordError> {
        let expected = self.expected.get(self.next).ok_or(SubagentRecordError)?;
        if descriptor != Descriptor::bytes(expected.checkpoint)? {
            return Err(SubagentRecordError);
        }
        let key = verifier
            .trusted_public_key(self.journal.agent.as_ref().ok_or(SubagentRecordError)?)
            .map_err(|_| SubagentRecordError)?;
        let chunk = CheckedBranchChunk::decode(bytes, &key, verifier)?;
        if self
            .current
            .as_ref()
            .is_none_or(|current| current.task_id() != expected.task.task_id)
        {
            if let Some(prior) = self.current.take() {
                prior.finish()?;
            }
            self.current = Some(TaskMaterial::new(
                self.journal,
                expected.plan,
                expected.task,
                skills,
                compiler,
            )?);
        }
        let current = self.current.as_mut().ok_or(SubagentRecordError)?;
        current.accept(&chunk, expected.checkpoint, skills, compiler)?;
        self.next += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<(), SubagentRecordError> {
        if self.failed || self.next != self.expected.len() {
            return Err(SubagentRecordError);
        }
        if let Some(current) = self.current {
            current.finish()?;
        }
        Ok(())
    }
}

impl SubagentJournal {
    pub fn verify_stored_branches(
        &self,
        store: &dyn super::super::SubagentBranchStore,
        verifier: &dyn Verifier,
        skills: &mut SkillReceiptVerifier,
        compiler: &dyn SkillCompiler,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(self.seq);
        let mut material = BranchMaterialVerifier::new(self).map_err(|_| invalid())?;
        while let Some(reference) = material.next_reference().map_err(|_| invalid())? {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let descriptor = material
                .next_descriptor()
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?;
            let bytes = store.read(&self.case, &reference, cancel)?;
            material
                .accept(&descriptor, bytes.as_bytes(), verifier, skills, compiler)
                .map_err(|_| invalid())?;
        }
        material.finish().map_err(|_| invalid())
    }
}

fn compare_terminal(
    terminal: &BranchTerminal,
    checkpoint: &SubagentCheckpointV1,
    result: &crate::subagents::SubagentResultV1,
) -> Result<(), SubagentRecordError> {
    if crate::subagents::SubagentResultV1::from_terminal(checkpoint, terminal)?.canonical()?
        != result.canonical()?
    {
        return Err(SubagentRecordError);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn subagent_chunk_descriptors_match_both_approved_golden_frames() {
        for (checkpoint, descriptor) in [
            (include_bytes!("../../../../../docs/development/subagent-format-vectors/checkpoint-proposal.json").as_slice(),
             include_bytes!("../../../../../docs/development/subagent-format-vectors/branch-chunk-0-descriptor.json").as_slice()),
            (include_bytes!("../../../../../docs/development/subagent-format-vectors/checkpoint-final.json").as_slice(),
             include_bytes!("../../../../../docs/development/subagent-format-vectors/branch-chunk-1-descriptor.json").as_slice()),
        ] {
            let value = SubagentCheckpointV1::decode(checkpoint).unwrap();
            assert_eq!(Descriptor::bytes(&value).unwrap(), descriptor);
        }
    }
}
