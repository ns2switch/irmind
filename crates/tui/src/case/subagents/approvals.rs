//! Analyst controls run separately from the live investigation worker.
use irmind_app::{AppError, ApprovalRequest, ApprovalSource, CancellationToken, CaseId, Engine};
use std::{
    collections::BTreeMap,
    thread::{Scope, ScopedJoinHandle},
};

pub(super) enum Intent {
    Refresh,
    Approve(String),
    Deny(String, String),
    Edit(String, BTreeMap<String, String>),
}
impl Intent {
    pub(super) fn request_id(&self) -> Option<&str> {
        match self {
            Self::Refresh => None,
            Self::Approve(id) | Self::Deny(id, _) | Self::Edit(id, _) => Some(id),
        }
    }
    pub(super) fn parse(prompt: &str) -> Option<anyhow::Result<Self>> {
        if prompt == "/approvals" {
            return Some(Ok(Self::Refresh));
        }
        if let Some(id) = prompt.strip_prefix("/approve ") {
            return Some(Ok(Self::Approve(id.trim().into())));
        }
        if let Some(rest) = prompt.strip_prefix("/deny ") {
            return Some(
                rest.split_once(' ')
                    .map(|(id, reason)| Self::Deny(id.into(), reason.into()))
                    .ok_or_else(|| anyhow::anyhow!("Use /deny <id> <reason>")),
            );
        }
        if let Some(rest) = prompt.strip_prefix("/edit ") {
            return Some(
                rest.split_once(' ')
                    .ok_or_else(|| anyhow::anyhow!("Use /edit <id> {{\"ioc\":\"example.com\"}}"))
                    .and_then(|(id, args)| {
                        super::super::operation::parse_approval_args(args)
                            .map(|args| Self::Edit(id.into(), args))
                    }),
            );
        }
        None
    }
    fn execute(
        self,
        engine: &Engine<'_>,
        case: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<Option<String>, AppError> {
        match self {
            Self::Refresh => Ok(None),
            Self::Approve(id) => engine.approve_with_cancel(case, &id, cancel).map(Some),
            Self::Deny(id, reason) => engine.deny(case, &id, &reason).map(Some),
            Self::Edit(id, args) => engine.edit_approval(case, &id, args).map(Some),
        }
    }
}
pub(super) fn is_task_request(state: &super::super::state::CaseState, id: &str) -> bool {
    let Some(request) = state.approvals.iter().find(|request| request.id == id) else {
        return false;
    };
    state.entries.windows(2).any(|entries| {
        entries[0].kind == irmind_app::AuditEventKind::SubagentCheckpointV1
            && entries[0].seq.checked_add(1) == Some(request.decision_seq)
            && entries[1].seq == request.decision_seq
            && entries[1].kind == irmind_app::AuditEventKind::NeedsApproval
            && entries[1].origin == "Agent"
    })
}
pub(super) struct Snapshot {
    pub requests: Vec<ApprovalRequest>,
    pub sources: BTreeMap<String, ApprovalSource>,
    pub entries: Vec<irmind_app::SignedEntry>,
}
pub(super) struct Update {
    pub message: Result<Option<String>, AppError>,
    pub snapshot: Result<Snapshot, AppError>,
}
pub(super) struct Work<'scope> {
    token: CancellationToken,
    worker: Option<ScopedJoinHandle<'scope, Update>>,
}
impl<'scope> Work<'scope> {
    pub(super) fn start<'env>(
        scope: &'scope Scope<'scope, 'env>,
        engine: &'env Engine<'_>,
        case: &'env CaseId,
        intent: Intent,
    ) -> Self {
        let token = CancellationToken::new();
        let signal = token.clone();
        let worker = scope.spawn(move || {
            let message = intent.execute(engine, case, &signal);
            let snapshot = snapshot(engine, case, &signal);
            Update { message, snapshot }
        });
        Self {
            token,
            worker: Some(worker),
        }
    }
    pub(super) fn finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(ScopedJoinHandle::is_finished)
    }
    pub(super) fn take(&mut self) -> Option<Update> {
        self.worker.take().and_then(|worker| worker.join().ok())
    }
}
impl Drop for Work<'_> {
    fn drop(&mut self) {
        self.token.cancel();
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}
fn snapshot(
    engine: &Engine<'_>,
    case: &CaseId,
    cancel: &CancellationToken,
) -> Result<Snapshot, AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    let requests = engine.pending_approvals(case)?;
    let mut bytes = 0usize;
    let mut sources = BTreeMap::new();
    for request in &requests {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        bytes = bytes.saturating_add(
            request
                .args
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
                + 512,
        );
        if bytes > 1024 * 1024 {
            return Err(AppError::Policy("Approval display exceeds its bounded snapshot. Stop the turn and inspect /approvals before resolving further requests.".into()));
        }
        let source = engine.approval_source(case, request)?;
        bytes = bytes.saturating_add(source.excerpt.len() + source.source_label.len());
        if bytes > 1024 * 1024 {
            return Err(AppError::Policy("Approval source display exceeds its bounded snapshot. Stop the turn and inspect /approvals.".into()));
        }
        sources.insert(request.id.clone(), source);
    }
    Ok(Snapshot {
        requests,
        sources,
        entries: engine.audit_log.entries(case)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_complete_commands_create_analyst_control_intents() {
        for text in [
            "approve",
            "1",
            "/confirm x",
            "/approve",
            "hello",
            "/settings",
        ] {
            assert!(Intent::parse(text).is_none());
        }
        assert!(matches!(
            Intent::parse("/approve request"),
            Some(Ok(Intent::Approve(_)))
        ));
        assert!(matches!(
            Intent::parse("/deny request bounded reason"),
            Some(Ok(Intent::Deny(_, _)))
        ));
        assert!(matches!(
            Intent::parse(r#"/edit request {"ioc":"example.com"}"#),
            Some(Ok(Intent::Edit(_, _)))
        ));
        assert!(matches!(
            Intent::parse("/edit request invalid"),
            Some(Err(_))
        ));
    }
}
