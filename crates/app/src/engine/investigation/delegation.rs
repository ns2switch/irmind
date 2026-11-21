//! Parent control flow hands off the case lock only after a durable plan hold.
use super::TurnContext;
use crate::subagents::{
    PreparedSubagentPlan, StartedSubagentPlan, SubagentResources, SubagentResultV1,
    SubagentTaskProposal,
};
use crate::{
    AppError, AuditEventKind, AuditOrigin, CancellationToken, Case, Engine, LlmPort, ModelToolCall,
    Tool,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposedTask {
    type_id: String,
    objective: String,
    sources: Vec<String>,
    remote_scope: Option<String>,
    skill: Option<String>,
    budget: SubagentResources,
}

impl Engine<'_> {
    pub(super) async fn shared_round_number(
        &self,
        id: &crate::CaseId,
        turn: &TurnContext,
        fallback: (usize, usize),
    ) -> Result<(usize, usize), AppError> {
        if self.subagents.is_none() {
            return Ok(fallback);
        }
        let case = id.clone();
        let nonce = turn.nonce.to_string();
        let used = self
            .blocking_local(move |local| local.turn_model_rounds_unlocked(&case, &nonce))
            .await?;
        Ok((
            usize::try_from(used)
                .map_err(|_| invalid())?
                .saturating_add(1),
            fallback.1,
        ))
    }

    pub(super) async fn delegate_turn_plan(
        &self,
        case: &Case,
        model: &dyn LlmPort,
        turn: &mut TurnContext,
        calls: &[ModelToolCall],
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if !turn.catalog.iter().any(|tool| tool.name == "delegate_task") {
            return Ok("Delegation is unavailable in this turn.".into());
        }
        let key = delegation_key(calls)?;
        if let Some(previous) = turn.previous.get(&key) {
            return Ok(format!(
                "Repeated delegation; cached result: {}",
                previous.text
            ));
        }
        let Ok(tasks) = proposed_tasks(calls) else {
            return Ok("The task plan was rejected: use 1–16 bounded tasks with exact source hashes, closed types and explicit budgets; approval fields are not accepted.".into());
        };
        let activity = self.acquire_turn_plan_activity(case, turn).await?;
        let prepared = self
            .prepare_turn_plan(case, turn.nonce, calls, tasks, cancel, activity)
            .await?;
        let shared_budget = turn.skills.lock().map_err(|_| invalid())?.budget.clone();
        // No provider, UI or child wait may retain the parent transaction lock.
        let held = turn
            .case_lock
            .lock()
            .map_err(|_| invalid())?
            .take()
            .ok_or_else(invalid)?;
        drop(held);
        let (started, outcome) = self
            .review_and_execute_plan(&prepared, model, shared_budget, cancel)
            .await;
        let id = case.id.clone();
        let held = self
            .blocking_local(move |local| local.repo.lock_case(&id))
            .await?;
        *turn.case_lock.lock().map_err(|_| invalid())? = Some(held);
        if let Some(started) = started {
            let id = case.id.clone();
            self.blocking_local(move |local| local.finish_subagent_plan_unlocked(&id, &started))
                .await?;
        }
        let results = outcome?;
        turn.delegated_rounds = turn.delegated_rounds.saturating_add(
            results
                .iter()
                .map(|result| usize::try_from(result.usage.rounds).unwrap_or(usize::MAX))
                .sum::<usize>(),
        );
        let text = summarized_results(&results)?;
        let screened = self.guard.screen(&text)?;
        self.audit_local(
            &case.id,
            AuditOrigin::Model,
            AuditEventKind::ToolResult,
            &screened.text,
            None,
        )
        .await?;
        turn.previous.insert(key, screened.text.clone().into());
        Ok(screened.text)
    }

    async fn acquire_turn_plan_activity(
        &self,
        case: &Case,
        turn: &TurnContext,
    ) -> Result<crate::subagents::PlanActivity, AppError> {
        // Recovery never waits on this transaction while we wait for its gate.
        // Reacquire the transaction even on a busy gate before normal turn cleanup.
        drop(
            turn.case_lock
                .lock()
                .map_err(|_| invalid())?
                .take()
                .ok_or_else(invalid)?,
        );
        let id = case.id.clone();
        let (activity, held) = self
            .blocking_local(move |local| {
                let activity = local.plan_activity(&id);
                let held = local.repo.lock_case(&id)?;
                local.verify_unlocked(&id)?;
                Ok((activity, held))
            })
            .await?;
        *turn.case_lock.lock().map_err(|_| invalid())? = Some(held);
        activity
    }

    async fn prepare_turn_plan(
        &self,
        case: &Case,
        nonce: uuid::Uuid,
        calls: &[ModelToolCall],
        tasks: Vec<SubagentTaskProposal>,
        cancel: &CancellationToken,
        activity: crate::subagents::PlanActivity,
    ) -> Result<PreparedSubagentPlan, AppError> {
        for call in calls
            .iter()
            .filter(|call| call.proposal().tool == Tool::DelegateTask)
        {
            if !matches!(
                self.evaluate_proposal(case, call.proposal().clone(), AuditOrigin::Model)
                    .await?,
                crate::Decision::Allow(_)
            ) {
                return Err(invalid());
            }
            self.audit_local(
                &case.id,
                AuditOrigin::Policy,
                AuditEventKind::Allowed,
                "delegate_task: bounded plan proposal",
                None,
            )
            .await?;
        }
        let id = case.id.clone();
        let signal = cancel.clone();
        self.blocking_local(move |local| {
            local.prepare_subagent_plan_unlocked(
                &id,
                nonce,
                tasks,
                SubagentResources::default(),
                &signal,
                activity,
            )
        })
        .await
    }

    async fn review_and_execute_plan(
        &self,
        prepared: &PreparedSubagentPlan,
        model: &dyn LlmPort,
        shared_budget: std::sync::Arc<std::sync::Mutex<crate::skills::runtime::SkillReadBudget>>,
        cancel: &CancellationToken,
    ) -> (
        Option<StartedSubagentPlan>,
        Result<Vec<SubagentResultV1>, AppError>,
    ) {
        let choice = match self.review_plan_choice(prepared, cancel).await {
            Ok(choice) => choice,
            Err(error) => {
                let expired = self.expire_subagent_preview(prepared);
                return (None, expired.and(Err(error)));
            }
        };
        let mut started = match self.admit_subagent_plan(prepared, &choice, cancel) {
            Ok(Some(started)) => started,
            Ok(None) => return (None, Ok(vec![])),
            Err(error) => {
                let expired = self.expire_subagent_preview(prepared);
                return (None, expired.and(Err(error)));
            }
        };
        let outcome = match started.share_parent_skill_budget(shared_budget) {
            Ok(()) => {
                self.execute_subagent_plan(&started, model, Self::subagent_workers(), cancel)
                    .await
            }
            Err(error) => Err(error),
        };
        if outcome.is_err() {
            for task in &started.plan().tasks {
                if let Err(error) = self.cancel_subagent_task(&started, task.task_id) {
                    return (Some(started), Err(error));
                }
            }
        }
        (Some(started), outcome)
    }

    async fn review_plan_choice(
        &self,
        prepared: &PreparedSubagentPlan,
        cancel: &CancellationToken,
    ) -> Result<crate::subagents::AnalystPlanChoice, AppError> {
        let interaction = &self.subagents.as_ref().ok_or_else(invalid)?.analyst;
        let remaining = prepared
            .preview()
            .tasks()
            .iter()
            .map(|task| task.deadline_at)
            .min()
            .ok_or_else(invalid)?
            .saturating_sub(self.clock.now()?)
            .min(600);
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AppError::Cancelled),
            result = tokio::time::timeout(std::time::Duration::from_secs(remaining), interaction.review(prepared.preview(), cancel)) => result.map_err(|_| AppError::Cancelled)?,
        }
    }

    fn subagent_workers() -> usize {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(2)
    }
}

fn proposed_tasks(calls: &[ModelToolCall]) -> Result<Vec<SubagentTaskProposal>, AppError> {
    let mut tasks = Vec::new();
    for call in calls
        .iter()
        .filter(|call| call.proposal().tool == Tool::DelegateTask)
    {
        if call.proposal().args.len() != 1 {
            return Err(invalid());
        }
        let text = call.proposal().args.get("tasks").ok_or_else(invalid)?;
        if text.len() > 16 * 1024 {
            return Err(invalid());
        }
        let proposed: Vec<ProposedTask> = serde_json::from_str(text).map_err(|_| invalid())?;
        if proposed.is_empty() || proposed.len() + tasks.len() > 16 {
            return Err(invalid());
        }
        for task in proposed {
            tasks.push(SubagentTaskProposal {
                type_id: task.type_id,
                objective: task.objective,
                sources: task
                    .sources
                    .iter()
                    .map(|hash| irmind_domain::EvidenceHash::parse(hash).map_err(|_| invalid()))
                    .collect::<Result<_, _>>()?,
                remote_scope: task
                    .remote_scope
                    .as_deref()
                    .map(irmind_domain::CaseScope::parse)
                    .transpose()
                    .map_err(|_| invalid())?,
                skill: task
                    .skill
                    .as_deref()
                    .map(irmind_domain::SkillName::parse)
                    .transpose()
                    .map_err(|_| invalid())?,
                budget: task.budget,
            });
        }
    }
    Ok(tasks)
}

fn summarized_results(results: &[SubagentResultV1]) -> Result<String, AppError> {
    if results.is_empty() {
        return Ok("The plan did not start; no child provider request was made.".into());
    }
    let bounded: Vec<_> = results
        .iter()
        .map(|result| {
            let end = result
                .guarded_summary
                .floor_char_boundary(result.guarded_summary.len().min(512));
            (
                crate::hex(result.task_id.as_bytes()),
                result.status,
                &result.guarded_summary[..end],
                result.sources.iter().take(4).collect::<Vec<_>>(),
                &result.usage,
            )
        })
        .collect();
    serde_json::to_string(&bounded).map_err(|_| invalid())
}

fn invalid() -> AppError {
    AppError::Policy("The delegated plan could not be admitted or reconciled".into())
}

fn delegation_key(calls: &[ModelToolCall]) -> Result<String, AppError> {
    let args = calls
        .iter()
        .filter(|call| call.proposal().tool == Tool::DelegateTask)
        .map(|call| &call.proposal().args)
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&args).map_err(|_| invalid())?;
    Ok(format!(
        "subagent-plan:{}",
        crate::hex(&crate::sha256(&bytes))
    ))
}
