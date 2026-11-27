use super::{
    EngineEvent, EngineEventBatch, EngineEventSubscription, EventCursor, invalid, position,
    projection,
};
use crate::subagents::{
    BranchChunkRef, CheckedBranchChunk, SubagentCheckpointV1, SubagentJournal, SubagentRecord,
};
use crate::{AppError, AuditEventKind, CancellationToken, CaseId, Engine, SignedEntry};

pub(super) struct Subscription {
    engine: Engine<'static>,
    case: CaseId,
    generation: Option<[u8; 32]>,
    tasks: std::collections::BTreeMap<super::SubagentDigest, TaskPresentation>,
}
impl Subscription {
    pub(super) const fn new(engine: Engine<'static>, case: CaseId) -> Self {
        Self {
            engine,
            case,
            generation: None,
            tasks: std::collections::BTreeMap::new(),
        }
    }
    fn authenticate(
        &mut self,
        entries: &[SignedEntry],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let generation = fingerprint(entries, cancel)?;
        if self.generation == Some(generation) {
            return Ok(());
        }
        let mut journal =
            SubagentJournal::for_verification(self.case.clone()).map_err(|_| invalid())?;
        let mut skills = crate::SkillReceiptVerifier::default();
        let services = self.engine.skills.as_ref().ok_or_else(invalid)?;
        for entry in entries {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            journal.accept(entry, self.engine.verifier.as_ref())?;
            skills.accept(entry, services.compiler.as_ref())?;
        }
        let ports = self.engine.subagents.as_ref().ok_or_else(invalid)?;
        journal.verify_stored_branches(
            ports.branches.as_ref(),
            self.engine.verifier.as_ref(),
            &mut skills,
            services.compiler.as_ref(),
            cancel,
        )?;
        self.tasks = presentations(entries)?;
        self.generation = Some(generation);
        Ok(())
    }
    fn events(
        &self,
        entry: &SignedEntry,
        cancel: &CancellationToken,
    ) -> Result<Vec<EngineEvent>, AppError> {
        let mut events = Vec::new();
        if entry.kind == AuditEventKind::SubagentCheckpointV1 {
            let checkpoint: SubagentCheckpointV1 = projection::decode(entry)?;
            let reference = BranchChunkRef::new(checkpoint.chunk_sha256, checkpoint.chunk_bytes)
                .map_err(|_| invalid())?;
            let ports = self.engine.subagents.as_ref().ok_or_else(invalid)?;
            let bytes = ports.branches.read(&self.case, &reference, cancel)?;
            let key = self.engine.verifier.trusted_public_key(&entry.actor)?;
            let chunk =
                CheckedBranchChunk::decode(bytes.as_bytes(), &key, self.engine.verifier.as_ref())
                    .map_err(|_| invalid())?;
            if chunk
                .checkpoint(
                    checkpoint.previous_checkpoint,
                    checkpoint.admitted_sources.clone(),
                )
                .map_err(|_| invalid())?
                .canonical()
                .map_err(|_| invalid())?
                != checkpoint.canonical().map_err(|_| invalid())?
            {
                return Err(invalid());
            }
            for (index, item) in chunk.entries().iter().enumerate() {
                events.push(projection::branch(&self.engine, entry, item, index)?);
            }
        }
        if let Some(event) = projection::main(&self.engine, entry)? {
            events.push(event);
        }
        for event in &mut events {
            if let Some(task) = event.task_id.and_then(|id| self.tasks.get(&id)) {
                event.plan_id = Some(task.plan);
                event.task_type = Some(task.type_id.clone());
                event.objective = Some(self.engine.guard.screen(&task.objective)?.text);
            }
        }
        Ok(events)
    }
}
impl EngineEventSubscription for Subscription {
    fn poll(
        &mut self,
        cursor: EventCursor,
        max: u16,
        cancel: &CancellationToken,
    ) -> Result<EngineEventBatch, AppError> {
        if cursor.session != self.engine.subagent_runtime.session
            || cursor.case != crate::sha256(self.case.as_str().as_bytes())
            || !(1..=1024).contains(&max)
        {
            return Err(invalid());
        }
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let entries = self.engine.audit_log.entries(&self.case)?;
        self.authenticate(&entries, cancel)?;
        let last = position(entries.last().ok_or_else(invalid)?.seq, 64)?;
        if cursor.position > last {
            return Err(invalid());
        }
        let mut result = EngineEventBatch {
            events: Vec::new(),
            next: cursor,
            more: false,
        };
        let mut bytes = 0;
        for entry in entries
            .iter()
            .filter(|entry| position(entry.seq, 64).is_ok_and(|at| at > cursor.position))
        {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            for event in self.events(entry, cancel)? {
                if event.cursor.position <= cursor.position {
                    continue;
                }
                if result.events.len() == usize::from(max)
                    || bytes + event.buffered_bytes() > 1024 * 1024
                {
                    result.more = true;
                    return Ok(result);
                }
                bytes += event.buffered_bytes();
                result.next = event.cursor;
                result.events.push(event);
            }
            result.next.position = position(entry.seq, 64)?;
        }
        Ok(result)
    }
}

fn fingerprint(entries: &[SignedEntry], cancel: &CancellationToken) -> Result<[u8; 32], AppError> {
    use sha2::{Digest, Sha256};
    let mut state = Sha256::new();
    state.update(b"irmind-event-cache-v1\0");
    for entry in entries {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        for bytes in [
            entry.canonical().as_slice(),
            entry.hash.as_slice(),
            entry.sig.as_slice(),
            entry.public_key.as_slice(),
        ] {
            state.update((bytes.len() as u64).to_be_bytes());
            state.update(bytes);
        }
    }
    Ok(state.finalize().into())
}

struct TaskPresentation {
    plan: super::SubagentDigest,
    type_id: String,
    objective: String,
}
fn presentations(
    entries: &[SignedEntry],
) -> Result<std::collections::BTreeMap<super::SubagentDigest, TaskPresentation>, AppError> {
    use crate::subagents::{SubagentPlanV2, SubagentTypeSnapshotV1};
    let mut types = std::collections::BTreeMap::new();
    let mut tasks = std::collections::BTreeMap::new();
    for entry in entries {
        if entry.kind == AuditEventKind::SubagentTypeSnapshotV1 {
            let snapshot: SubagentTypeSnapshotV1 = projection::decode(entry)?;
            types.insert(
                snapshot.identity().map_err(|_| invalid())?,
                snapshot.definition().id().to_owned(),
            );
        } else if entry.kind == AuditEventKind::SubagentPlanV2 {
            let plan: SubagentPlanV2 = projection::decode(entry)?;
            for task in &plan.tasks {
                let type_id = types
                    .get(&task.type_snapshot_sha256)
                    .ok_or_else(invalid)?
                    .clone();
                tasks.insert(
                    task.task_id,
                    TaskPresentation {
                        plan: plan.plan_id,
                        type_id,
                        objective: task.objective.clone(),
                    },
                );
            }
        }
    }
    Ok(tasks)
}
