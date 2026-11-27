//! A graphical presentation and the actual decision share an authenticated state.
use crate::{
    Actor, AppError, AuthorizedCall, CancellationToken, Case, CaseId, CaseScope, Engine,
    ExecutionMode, PendingApproval, Tool,
    subagents::{SubagentDigest, SubagentPolicySnapshot, runtime::approvals::TaskApprovalDecision},
};

use std::{sync::Mutex, time::Instant};

const DENIAL_REASON: &str = "Declined by the analyst in the graphical client.";

pub(crate) struct GuiApproval {
    pub request: super::ApprovalRequest,
    pub effective_scope: String,
    pub analyst_key: Vec<u8>,
    pub expires_at: u64,
    policy: Vec<u8>,
    case_budget: crate::CaseBudgetLimits,
    task: Option<(SubagentDigest, (uuid::Uuid, uuid::Uuid))>,
}

impl Engine<'_> {
    pub(crate) fn prepare_gui_approval(
        &self,
        id: &CaseId,
        request_id: Option<&str>,
    ) -> Result<GuiApproval, AppError> {
        let _lock = self.repo.lock_case(id)?;
        self.gui_approval_unlocked(id, request_id)
            .map(|(_, approval)| approval)
    }

    fn gui_approval_unlocked(
        &self,
        id: &CaseId,
        request_id: Option<&str>,
    ) -> Result<(Case, GuiApproval), AppError> {
        self.require_attended_analyst("resolve approval")?;
        self.verify_unlocked(id)?;
        let mut case = self.repo.get_case(id)?;
        if case.sealed || self.case_scope_exceeds_policy(&case)? {
            return Err(unavailable());
        }
        let mut requests = self.pending_requests_unlocked(&case, &self.audit_log.entries(id)?)?;
        requests.sort_unstable_by_key(|request| request.decision_seq);
        let request = requests
            .into_iter()
            .find(|request| request_id.is_none_or(|id| request.id == id))
            .ok_or_else(unavailable)?;
        if request.mode != ExecutionMode::Attended || request.tool == Tool::SourceQuery {
            return Err(unavailable());
        }
        let task = self
            .task_pending_binding_unlocked(id, &request)?
            .map(|task| {
                case.scope = self.live_task_scope_unlocked(id, &request, task)?;
                let lease = self
                    .live_task_approval_identity(id, &request.id, task)?
                    .ok_or_else(unavailable)?;
                Ok::<_, AppError>((task, lease))
            })
            .transpose()?;
        let scope = CaseScope::parse(&case.scope).map_err(|_| unavailable())?;
        let effective_scope = if scope == CaseScope::LocalOnly {
            "local".into()
        } else {
            scope.to_current_string().map_err(|_| unavailable())?
        };
        let now = self.clock.now()?;
        PendingApproval::recover_with_rules(
            &case,
            request.mode,
            &request.challenge,
            now,
            &self.policy,
        )
        .map_err(|_| unavailable())?;
        // The authenticated challenge codec ends in the big-endian deadline.
        let expires_at = u64::from_be_bytes(
            *request
                .challenge
                .last_chunk::<8>()
                .ok_or_else(unavailable)?,
        );
        if expires_at <= now {
            return Err(unavailable());
        }
        for text in std::iter::once(&effective_scope)
            .chain(request.args.iter().flat_map(|(key, value)| [key, value]))
        {
            let screened = self.guard.screen(text)?;
            if screened.text != *text {
                return Err(unavailable());
            }
        }
        let analyst_key = self.verifier.trusted_public_key(&Actor::Analyst)?;
        if self.signer.public_key() != analyst_key {
            return Err(unavailable());
        }
        let effective_policy = self.policy_for_case_unlocked(id)?;
        let policy = serde_json::to_vec(
            &SubagentPolicySnapshot::new(&effective_policy).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
        let case_budget = self.case_budget_unlocked(id)?.require_effective()?;
        Ok((
            case,
            GuiApproval {
                request,
                effective_scope,
                analyst_key,
                expires_at,
                policy,
                case_budget,
                task,
            },
        ))
    }

    pub(crate) fn commit_gui_approval(
        &self,
        id: &CaseId,
        prepared: &GuiApproval,
        deny: bool,
        gate: &GuiApprovalGate,
    ) -> Result<(), AppError> {
        let _lock = self.repo.lock_case(id)?;
        let check = || {
            gate.check(self.clock.now()?)?;
            if let Some((task, lease)) = prepared.task
                && self.live_task_approval_identity(id, &prepared.request.id, task)? != Some(lease)
            {
                return Err(unavailable());
            }
            Ok(())
        };
        check()?;
        let (case, current) = self.gui_approval_unlocked(id, Some(&prepared.request.id))?;
        if !current.binds(prepared) {
            return Err(unavailable());
        }
        let mut state = gate.state.lock().map_err(|_| unavailable())?;
        if *state != DecisionState::Authenticating {
            return Err(AppError::Cancelled);
        }
        let reason = deny.then_some(DENIAL_REASON);
        let call =
            self.record_gated_resolution_unlocked(id, &case, &current.request, reason, &check)?;
        *state = if deny {
            DecisionState::Denied
        } else {
            DecisionState::Approved
        };
        drop(state);
        self.deliver_gui_approval(id, &current, call, &gate.cancel)
    }

    fn deliver_gui_approval(
        &self,
        id: &CaseId,
        current: &GuiApproval,
        call: Option<AuthorizedCall>,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        if let Some((task, _)) = current.task {
            let choice = call.map_or(TaskApprovalDecision::Denied, TaskApprovalDecision::Granted);
            self.deliver_task_approval(id, &current.request.id, task, choice)?;
        } else if let Some(call) = call {
            crate::run_async(async {
                if let Some(reason) = self.unavailable_reason(&call) {
                    return self
                        .audit_local(
                            id,
                            crate::AuditOrigin::Policy,
                            crate::AuditEventKind::Denied,
                            reason,
                            None,
                        )
                        .await;
                }
                self.execute_authorized(id, &call, true, cancel)
                    .await
                    .map(|_| ())
            })?;
        }
        Ok(())
    }
}

impl GuiApproval {
    fn binds(&self, expected: &Self) -> bool {
        self.request.challenge == expected.request.challenge
            && self.effective_scope == expected.effective_scope
            && self.analyst_key == expected.analyst_key
            && self.policy == expected.policy
            && self.case_budget == expected.case_budget
            && self.task == expected.task
    }
}

fn unavailable() -> AppError {
    AppError::Fixed(crate::FixedAppError::PolicyPendingApprovalNotFound)
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionState {
    Ready,
    Authenticating,
    Approved,
    Denied,
    ReauthFailed,
    Expired,
    Stale,
    Cancelled,
}

pub(crate) struct GuiApprovalGate {
    pub state: Mutex<DecisionState>,
    pub expires_at: u64,
    pub end: Instant,
    pub cancel: CancellationToken,
}

impl GuiApprovalGate {
    pub(crate) fn check(&self, now: u64) -> Result<(), AppError> {
        if self.cancel.is_cancelled() || self.expired(now) {
            return Err(AppError::Cancelled);
        }
        Ok(())
    }

    pub(crate) fn expired(&self, now: u64) -> bool {
        now >= self.expires_at || Instant::now() >= self.end
    }
}
