use super::{
    BranchTerminal, CheckedBranchChunk, PlanLedger, SubagentBranchCursor, SubagentCheckpointV1,
    SubagentDigest, SubagentJournal, SubagentRecord, SubagentRecordError, SubagentTaskSpec,
    compare_terminal,
};
use crate::subagents::{
    BranchModelReply, BranchModelRequest, BranchToolProposal, BranchToolResult, ReservationPurpose,
    SubagentBranchPayload, SubagentResources,
};
use crate::{SkillCompiler, SkillReceiptVerifier, Tool};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct TaskMaterial<'a> {
    journal: &'a SubagentJournal,
    plan: &'a PlanLedger,
    task: &'a SubagentTaskSpec,
    cursor: SubagentBranchCursor,
    sources: BTreeSet<SubagentDigest>,
    requests: BTreeMap<String, SubagentDigest>,
    replies: BTreeSet<String>,
    proposals: BTreeMap<SubagentDigest, (u64, BranchToolProposal)>,
    results: BTreeSet<SubagentDigest>,
    usage: SubagentResources,
    terminal: Option<BranchTerminal>,
    partial: bool,
    parent_tools: Option<BTreeSet<String>>,
    child_tools: Option<BTreeSet<String>>,
    checkpoint: Option<SubagentCheckpointV1>,
}
impl<'a> TaskMaterial<'a> {
    pub(super) fn new(
        journal: &'a SubagentJournal,
        plan: &'a PlanLedger,
        task: &'a SubagentTaskSpec,
        skills: &SkillReceiptVerifier,
        compiler: &dyn SkillCompiler,
    ) -> Result<Self, SubagentRecordError> {
        let sources = journal
            .sets
            .get(&task.source_set_sha256)
            .ok_or(SubagentRecordError)?;
        let parent_tools = plan
            .parent_skill
            .map(|id| {
                skills
                    .snapshot_method(id, plan.seq, compiler)
                    .map(|(_, tools)| tools)
                    .map_err(|_| SubagentRecordError)
            })
            .transpose()?;
        if let Some(snapshot) = task.skill_snapshot_sha256 {
            let identity = crate::SkillSnapshotId::parse(&crate::hex(snapshot.as_bytes()))
                .map_err(|_| SubagentRecordError)?;
            let (name, _) = skills
                .snapshot_method(identity, plan.seq, compiler)
                .map_err(|_| SubagentRecordError)?;
            if !journal
                .types
                .get(&task.type_snapshot_sha256)
                .ok_or(SubagentRecordError)?
                .definition()
                .skills()
                .contains(&name)
            {
                return Err(SubagentRecordError);
            }
        }
        Ok(Self {
            journal,
            plan,
            task,
            cursor: SubagentBranchCursor::new(
                &plan.plan.case_id,
                &plan.plan.turn_id,
                task.task_id,
                &task.nonce,
            )?,
            sources: sources.iter().copied().collect(),
            requests: BTreeMap::new(),
            replies: BTreeSet::new(),
            proposals: BTreeMap::new(),
            results: BTreeSet::new(),
            usage: SubagentResources::default(),
            terminal: None,
            partial: false,
            parent_tools,
            child_tools: None,
            checkpoint: None,
        })
    }
    pub(super) const fn task_id(&self) -> SubagentDigest {
        self.task.task_id
    }

    pub(super) fn accept(
        &mut self,
        chunk: &CheckedBranchChunk,
        checkpoint: &SubagentCheckpointV1,
        skills: &mut SkillReceiptVerifier,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), SubagentRecordError> {
        self.cursor.accept(chunk, checkpoint)?;
        let sequence = *self
            .journal
            .checkpoint_sequences
            .get(&checkpoint.identity()?)
            .ok_or(SubagentRecordError)?;
        let effects = self
            .journal
            .checkpoint_admissions
            .get(&checkpoint.identity()?)
            .cloned()
            .unwrap_or_default();
        let mut admitted = BTreeSet::new();
        for entry in chunk.entries() {
            if entry.body.at > self.task.deadline_at
                && !matches!(
                    entry.body.payload,
                    SubagentBranchPayload::Terminal(_) | SubagentBranchPayload::BudgetNotice(_)
                )
            {
                return Err(SubagentRecordError);
            }
            match &entry.body.payload {
                SubagentBranchPayload::ModelRequest(value) => {
                    self.model_request(value, sequence)?;
                }
                SubagentBranchPayload::ModelReply(value) => self.model_reply(value)?,
                SubagentBranchPayload::ToolProposal(value) => {
                    if value.allocation_sha256
                        != self.plan.allocation().ok_or(SubagentRecordError)?
                        || value
                            .source
                            .is_some_and(|source| !self.sources.contains(&source.hash))
                        || self
                            .proposals
                            .values()
                            .any(|(_, p)| p.call_id == value.call_id)
                    {
                        return Err(SubagentRecordError);
                    }
                    self.finding_effect(entry.hash, value, sequence)?;
                    self.proposals.insert(entry.hash, (sequence, value.clone()));
                }
                SubagentBranchPayload::ToolResult(value) => {
                    for effect in effects.iter().filter(|effect| {
                        effect.attribution.proposal_sha256 == value.proposal_sha256
                    }) {
                        if effect.decision != value.decision_audit_sha256
                            || effect.attribution.task_id != self.task.task_id
                            || effect.attribution.call_id != value.call_id
                            || effect.attribution.reservation_sha256 != value.reservation_sha256
                            || !self.sources.insert(effect.source)
                            || !admitted.insert(effect.source)
                        {
                            return Err(SubagentRecordError);
                        }
                    }
                    self.tool_result(value, sequence)?;
                }
                SubagentBranchPayload::SkillLoad(value) => {
                    self.skill_load(value, sequence, skills, compiler)?;
                }
                SubagentBranchPayload::Compaction(value) => {
                    if value.replaced_last >= entry.body.seq {
                        return Err(SubagentRecordError);
                    }
                }
                SubagentBranchPayload::BudgetNotice(value) => {
                    self.partial |= value.partial;
                }
                SubagentBranchPayload::Terminal(value) => self.terminal(value)?,
            }
        }
        if admitted.len() != checkpoint.admitted_sources.len() {
            return Err(SubagentRecordError);
        }
        self.checkpoint = Some(checkpoint.clone());
        Ok(())
    }
    fn finding_effect(
        &self,
        proposal: SubagentDigest,
        value: &BranchToolProposal,
        proposal_sequence: u64,
    ) -> Result<(), SubagentRecordError> {
        let Some(effect) = self.journal.findings.get(&proposal) else {
            return Ok(());
        };
        let accounted = self
            .journal
            .accounting
            .get(&effect.decision)
            .ok_or(SubagentRecordError)?;
        let attr = accounted.attribution.as_ref().ok_or(SubagentRecordError)?;
        if attr.task_id != self.task.task_id
            || attr.proposal_sha256 != proposal
            || attr.call_id != value.call_id
            || attr.tool != value.tool
            || attr.source_set_sha256 != self.task.source_set_sha256
            || attr.arguments_sha256.as_bytes()
                != &crate::sha256(
                    &serde_json::to_vec(&value.arguments).map_err(|_| SubagentRecordError)?,
                )
            || effect.at > self.task.deadline_at
            || effect.seq <= accounted.seq
        {
            return Err(SubagentRecordError);
        }
        let rules = self.plan.plan.policy.rules()?;
        self.require_method_allow(value, &rules)?;
        self.require_policy_allow(value, &rules, &accounted.scope)?;
        self.require_tool_reservation(attr.reservation_sha256, proposal_sequence, accounted.seq)?;
        let sources = self
            .sources
            .iter()
            .map(|hash| crate::hex(hash.as_bytes()))
            .collect();
        let call = crate::subagents::BranchToolCall {
            id: value.call_id.clone(),
            tool: value.tool.clone(),
            arguments: value.arguments.clone(),
        };
        let expected =
            crate::subagents::finding::proposed_finding(self.task.task_id, &call, &sources)?;
        if &crate::sha256(&serde_json::to_vec(&expected).map_err(|_| SubagentRecordError)?)
            != effect.canonical_sha256.as_bytes()
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    fn skill_load(
        &mut self,
        value: &str,
        sequence: u64,
        skills: &mut SkillReceiptVerifier,
        compiler: &dyn SkillCompiler,
    ) -> Result<(), SubagentRecordError> {
        let load = crate::SkillLoadV1::decode(value).map_err(|_| SubagentRecordError)?;
        if load.turn() != self.task.nonce {
            return Err(SubagentRecordError);
        }
        let identity = load.snapshot().map_err(|_| SubagentRecordError)?;
        let (name, tools) = skills
            .snapshot_method(identity, sequence, compiler)
            .map_err(|_| SubagentRecordError)?;
        if !self
            .journal
            .types
            .get(&self.task.type_snapshot_sha256)
            .ok_or(SubagentRecordError)?
            .definition()
            .skills()
            .contains(&name)
            || (self.child_tools.is_none()
                && self
                    .task
                    .skill_snapshot_sha256
                    .is_some_and(|expected| expected.as_bytes() != identity.as_bytes()))
        {
            return Err(SubagentRecordError);
        }
        skills
            .accept_task_load(&load, &self.plan.plan.turn_id)
            .map_err(|_| SubagentRecordError)?;
        if load.result() == crate::SkillLoadResult::Loaded {
            self.child_tools = Some(tools);
        } else {
            self.partial = true;
        }
        Ok(())
    }
    fn model_request(
        &mut self,
        value: &BranchModelRequest,
        sequence: u64,
    ) -> Result<(), SubagentRecordError> {
        let (request, admitted) = self.plan.request_by_identity(value.reservation_sha256)?;
        if request.task_id != Some(self.task.task_id)
            || request.purpose != ReservationPurpose::Model
            || admitted >= sequence
            || value.output_limit > request.amount.tokens
            || value.round != self.requests.len() as u64 + 1
            || value.round > self.task.budget.rounds
            || self
                .requests
                .insert(value.call_id.clone(), value.reservation_sha256)
                .is_some()
        {
            return Err(SubagentRecordError);
        }
        self.usage.rounds = self
            .usage
            .rounds
            .checked_add(1)
            .ok_or(SubagentRecordError)?;
        Ok(())
    }
    fn model_reply(&mut self, value: &BranchModelReply) -> Result<(), SubagentRecordError> {
        let identity = self
            .requests
            .get(&value.call_id)
            .ok_or(SubagentRecordError)?;
        let (request, _) = self.plan.request_by_identity(*identity)?;
        let tokens = value
            .usage
            .map_or(Some(request.amount.tokens), |usage| {
                usage.input_tokens.checked_add(usage.output_tokens)
            })
            .ok_or(SubagentRecordError)?;
        if tokens > request.amount.tokens || !self.replies.insert(value.call_id.clone()) {
            return Err(SubagentRecordError);
        }
        self.usage.tokens = self
            .usage
            .tokens
            .checked_add(tokens)
            .ok_or(SubagentRecordError)?;
        if !self.usage.within(self.task.budget) {
            return Err(SubagentRecordError);
        }
        self.partial |= value.truncated;
        Ok(())
    }
    fn tool_result(
        &mut self,
        value: &BranchToolResult,
        sequence: u64,
    ) -> Result<(), SubagentRecordError> {
        let (proposal_sequence, proposal) = self
            .proposals
            .get(&value.proposal_sha256)
            .ok_or(SubagentRecordError)?;
        let accounted = self
            .journal
            .accounting
            .get(&value.decision_audit_sha256)
            .ok_or(SubagentRecordError)?;
        let attribution = accounted.attribution.as_ref().ok_or(SubagentRecordError)?;
        let rules = self.plan.plan.policy.rules()?;
        self.require_method_allow(proposal, &rules)?;
        if proposal_sequence >= &accounted.seq
            || accounted.seq >= sequence
            || accounted.at > self.task.deadline_at
            || attribution.task_id != self.task.task_id
            || attribution.call_id != proposal.call_id
            || value.call_id != proposal.call_id
            || attribution.tool != proposal.tool
            || attribution.source_set_sha256 != self.task.source_set_sha256
            || attribution.proposal_sha256 != value.proposal_sha256
            || attribution.reservation_sha256 != value.reservation_sha256
            || attribution.arguments_sha256.as_bytes()
                != &crate::sha256(
                    &serde_json::to_vec(&proposal.arguments).map_err(|_| SubagentRecordError)?,
                )
            || value
                .sources
                .iter()
                .any(|source| !self.sources.contains(&source.hash))
            || !self.results.insert(value.proposal_sha256)
        {
            return Err(SubagentRecordError);
        }
        self.require_policy_allow(proposal, &rules, &accounted.scope)?;
        if proposal.tool == Tool::CaseAddFinding.as_str()
            && !value.partial
            && !self.journal.findings.contains_key(&value.proposal_sha256)
        {
            return Err(SubagentRecordError);
        }
        self.partial |= value.partial;
        self.require_tool_reservation(value.reservation_sha256, *proposal_sequence, accounted.seq)?;
        self.usage.calls = self.usage.calls.checked_add(1).ok_or(SubagentRecordError)?;
        self.usage.cloud_bytes = self
            .usage
            .cloud_bytes
            .checked_add(accounted.amount.cloud_bytes)
            .ok_or(SubagentRecordError)?;
        if !self.usage.within(self.task.budget) {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
    fn require_tool_reservation(
        &self,
        id: SubagentDigest,
        proposal_seq: u64,
        decision_seq: u64,
    ) -> Result<(), SubagentRecordError> {
        let (request, admitted) = self.plan.request_by_identity(id)?;
        if request.task_id != Some(self.task.task_id)
            || request.purpose != ReservationPurpose::Tool
            || admitted <= proposal_seq
            || admitted >= decision_seq
            || self.journal.checkpoint_sequences.get(&request.cause_sha256) != Some(&proposal_seq)
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    fn require_method_allow(
        &self,
        proposal: &BranchToolProposal,
        rules: &irmind_domain::PolicyRules,
    ) -> Result<(), SubagentRecordError> {
        let tool = Tool::parse(&proposal.tool).map_err(|_| SubagentRecordError)?;
        let kind = self
            .journal
            .types
            .get(&self.task.type_snapshot_sha256)
            .ok_or(SubagentRecordError)?;
        if tool.risk() != irmind_domain::RiskLevel::Read
            || !kind.definition().permits_tool(&tool)
            || tool != Tool::SkillRead
                && self
                    .parent_tools
                    .as_ref()
                    .is_some_and(|tools| !tools.contains(tool.as_str()))
            || tool != Tool::SkillRead
                && self
                    .child_tools
                    .as_ref()
                    .is_some_and(|tools| !tools.contains(tool.as_str()))
            || (tool != Tool::SkillRead
                && self.task.skill_snapshot_sha256.is_some()
                && self.child_tools.is_none())
            || rules.denied_tools.contains(&tool)
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    fn require_policy_allow(
        &self,
        proposal: &BranchToolProposal,
        rules: &irmind_domain::PolicyRules,
        effect_scope: &crate::CaseScope,
    ) -> Result<(), SubagentRecordError> {
        let case = irmind_domain::Case {
            id: self.journal.case.clone(),
            title: "Delegated task".into(),
            severity: irmind_domain::Severity::Low,
            scope: match &self.task.remote_scope {
                Some(scope) => scope.clone(),
                None => crate::subagents::queries::scope_text(&self.plan.case_scope)?,
            },
            sealed: false,
        };
        if !crate::CaseScope::parse(&case.scope)
            .map_err(|_| SubagentRecordError)?
            .is_within(effect_scope)
        {
            return Err(SubagentRecordError);
        }
        let call = irmind_domain::ProposedCall {
            tool: Tool::parse(&proposal.tool).map_err(|_| SubagentRecordError)?,
            args: proposal.arguments.clone(),
        };
        let completed = self
            .plan
            .plan
            .usage
            .calls
            .checked_add(self.usage.calls)
            .ok_or(SubagentRecordError)?;
        rules
            .permits(
                &call.tool,
                usize::try_from(completed).map_err(|_| SubagentRecordError)?,
            )
            .map_err(|_| SubagentRecordError)?;
        if !matches!(
            irmind_domain::evaluate_with_rules(
                &case,
                call,
                1,
                irmind_domain::ExecutionMode::Attended,
                0,
                rules
            ),
            irmind_domain::Decision::Allow(_)
        ) {
            return Err(SubagentRecordError);
        }
        for field in [
            "hash",
            "evidence_hash",
            "supporting_evidence",
            "refuting_evidence",
        ] {
            if let Some(value) = proposal.arguments.get(field) {
                for hash in value.split(',') {
                    if !self.sources.contains(&SubagentDigest::parse(hash)?) {
                        return Err(SubagentRecordError);
                    }
                }
            }
        }
        Ok(())
    }
    fn terminal(&mut self, value: &BranchTerminal) -> Result<(), SubagentRecordError> {
        if self.terminal.is_some()
            || (value.status == crate::subagents::SubagentStatus::Completed
                && (self.requests.len() != self.replies.len() || self.partial))
            || !self.usage.within(value.usage)
            || !value.usage.within(self.task.budget)
            || value
                .sources
                .iter()
                .any(|source| !self.sources.contains(&source.hash))
        {
            return Err(SubagentRecordError);
        }
        for operation in &value.reservation_ids {
            if self.plan.request(*operation)?.0.task_id != Some(self.task.task_id) {
                return Err(SubagentRecordError);
            }
        }
        self.terminal = Some(value.clone());
        Ok(())
    }
    pub(super) fn finish(self) -> Result<(), SubagentRecordError> {
        if let Some(result) = self.plan.results.get(&self.task.task_id) {
            compare_terminal(
                self.terminal.as_ref().ok_or(SubagentRecordError)?,
                self.checkpoint.as_ref().ok_or(SubagentRecordError)?,
                result,
            )?;
        }
        Ok(())
    }
}
